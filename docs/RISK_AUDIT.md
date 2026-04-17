# Risk Audit — Amnezia Web Panel

Open security findings against the current codebase. Line numbers refer to `src/amnezia_panel/` unless noted.

---

## Open

_(none — all tracked findings resolved)_

---

## Resolved

- **C-1 (`perform_toggle_user` undefined)** — function defined; `F821` ruff suppression removed from `pyproject.toml`.
- **C-2 (unsanitized port / tls_domain)** — Pydantic `field_validator`s on `InstallProtocolRequest.port` (digits, 1–65535) and `tls_domain` (hostname regex, max 253 chars).
- **C-3 (blocking Paramiko on event loop)** — every SSH-touching route handler now wraps its `ssh.connect()` / manager calls in `asyncio.to_thread`.
- **C-4 (no CSRF protection)** — `SessionMiddleware` now uses `same_site="strict"` and `https_only=` is set from the startup SSL config.
- **C-5 (non-atomic `save_data`; lock-bypassing call sites)** — `save_data` now writes via `tempfile.mkstemp` + `os.replace`; every route-level caller now uses `await save_data_async(...)`; call sites inside `DATA_LOCK` use `await asyncio.to_thread(save_data, ...)`.
- **H-1 (concurrent `exec_command` on shared SSH client)** — `api_check_server` opens one SSH transport per protocol-check thread.
- **H-2 (SSL private key 0o644)** — `_write_secret` in `__main__.py` uses `os.open(..., 0o600)`.
- **H-3 (no login rate limit)** — per-IP exponential backoff via `_LOGIN_FAILURES` dict; capped at 30s, 15-minute window, cleared on success.
- **H-4 (non-constant-time password compare)** — `hmac.compare_digest` in `verify_password`.
- **H-5 (dead dependencies)** — retired with the `uv` migration.
- **H-6 (event-loop-blocking save inside background lock)** — traffic sync save runs via `asyncio.to_thread(save_data, ...)` inside the lock.
- **M-1 (`perform_delete_user` blocked event loop)** — SSH calls wrapped in `asyncio.to_thread`.
- **M-2 (Remnawave username collision overwrites local hash)** — username fallback match restricted to users with empty `password_hash`.
- **M-3 (peer config appended via `echo "..."` inside double-quoted bash)** — both AWG peer-append sites (`add_client`, toggle) now fetch the current config, append the new `[Peer]` section in Python, upload via SFTP, and `docker cp` the full file into the container — matching the pattern already used by `save_server_config` / `_save_clients_table`. No remote-shell interpolation of peer content remains.
- **M-4 (AWG params shell injection via restored backup)** — `sanitize_awg_params` coerces every param to a non-negative integer string before `_configure_container` interpolates them.
- **M-5 (Xray Dockerfile pulls unverified binary)** — Dockerfile now verifies SHA256 `2a855f610008a598b88424435aefaee1df2c1b0fa1296d4f8f60080b528c9971` (from the upstream `Xray-linux-64.zip.dgst`) with `sha256sum -c` before unzipping; build fails fast if the archive is tampered with.
- **L-1 (open redirect via `Referer`)** — `set_lang` forces redirects to same-origin paths only.
- **L-2 (backup restore bypassed migrations)** — restore runs `_apply_schema_migrations` before persisting.
- **L-3 (`sudo -S` password piping breaks on newlines / backslashes)** — `SSHManager.run_command` now accepts `stdin_data`; `run_sudo_command` / `run_sudo_script` write the password to paramiko's channel stdin instead of interpolating it into an `echo '...' |` pipeline, so arbitrary bytes (newlines, backslashes, `$(...)`) in the password cannot break out of the shell. `_sudo_prefix` helper was deleted.
- **L-4 (AWG `_next_ip` walks past `.254`)** — allocator raises `RuntimeError` when the /24 is exhausted.
