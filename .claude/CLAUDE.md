# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Run & Build

```bash
pip install -r requirements.txt
python app.py                        # local run, binds 0.0.0.0:5000 (or ssl.panel_port)
docker compose up -d                 # prebuilt image prvtpro/amnezia-panel
```

The GitHub Actions workflow at `.github/workflows/build.yml` packages single-file binaries with PyInstaller for Linux/Windows/macOS on pushes to `main` and tag pushes (`v*`). When editing bundled resources, update the `--add-data` list there (`static`, `templates`, `translations` are currently bundled).

No test suite, linter, or formatter is configured — `pytest`, `ruff`, `mypy` etc. are not dependencies.

## Architecture

This is a single-process FastAPI control plane that manages remote VPN servers **over SSH**. It ships no database, no background worker, no REST client SDK — everything lives in `app.py` plus a handful of protocol-specific manager modules.

### Request → SSH pipeline

1. `app.py` (~2.3k LOC) defines FastAPI routes, Pydantic request models, session auth (Starlette `SessionMiddleware`), Jinja2 rendering, and i18n.
2. A request that touches a remote server constructs `SSHManager(host, port, user, password|private_key)` via `get_ssh(server)`.
3. `get_protocol_manager(ssh, protocol)` dispatches to the protocol module. Supported `protocol` strings: `awg`, `awg2`, `awg_legacy` (all AWGManager), `wireguard`, `xray`, `telemt`, `dns`.
4. `_manager_call(manager, method, protocol, ...)` is the call shim — **`WireGuardManager` methods don't take `protocol_type` as the first arg, every other manager does.** Always go through this helper instead of calling manager methods directly; otherwise one protocol family will break.
5. Paramiko calls are blocking. Anywhere they're invoked from an async handler, wrap in `asyncio.to_thread(...)` (see `_scrape_server_traffic` for the pattern).

### Protocol managers

Each manager file installs/configures its protocol on the remote host by uploading files via SFTP (`SSHManager.upload_file_sudo` writes to `/tmp` then `sudo mv`s into place) and running `docker` / `docker compose` under sudo. They all expose a roughly uniform surface: `install_protocol`, `remove_container`, `get_server_status`, `get_clients`, `add_client`, `remove_client` — but WireGuard is the one that drops the `protocol_type` arg, which is why `_manager_call` exists.

- `awg_manager.py` — AmneziaWG (standard, AWG 2.0, and legacy) with configurable obfuscation params.
- `wireguard_manager.py` — classic WireGuard.
- `xray_manager.py` — Xray VLESS-Reality under Docker container `amnezia-xray`.
- `telemt_manager.py` — Telegram MTProxy; remote-side Docker assets live in `protocol_telemt/` and are uploaded at install time.
- `dns_manager.py` — Unbound-based AmneziaDNS with its own Docker network (`amnezia-dns-net`) that VPN containers get attached to.
- `ssh_manager.py` — wraps Paramiko with sudo-password piping (`sudo -S`), SFTP helpers, and a `with` context manager. Use `run_sudo_command` / `upload_file_sudo` — never raw `run_command` when root is needed.

### Persistence

Single file: `data.json` at the application directory (next to `sys.executable` when frozen, else next to `app.py`). Gitignored. Schema is seeded and migrated in `startup()` — when you add a new field to users/servers/settings, add the migration there, because existing installs won't have it.

All writes go through `save_data_async` which serializes behind `DATA_LOCK` (an `asyncio.Lock`). Direct `save_data` is used only at startup and inside code already holding the lock. Race conditions here are real: the traffic sync loop and request handlers both mutate `data.json`.

### Background loop

`periodic_background_tasks()` is kicked off in `startup()` and runs every 10 minutes: it scrapes per-client byte counters via SSH, updates `traffic_used` / `traffic_total`, checks `traffic_limit` and `expiration_date`, auto-disables users that hit their cap, and optionally syncs users from Remnawave. Traffic-reset strategies (`daily`/`weekly`/`monthly`/`never`) are applied in this loop.

### Telegram bot

`telegram_bot.py` uses raw Telegram Bot API via `httpx` (not `python-telegram-bot`, despite the dep being in `requirements.txt`). It runs as an `asyncio.Task` alongside FastAPI — `launch_bot()` is called from `startup()` if `settings.telegram.enabled`, and can be toggled at runtime. `is_running()` / `stop_bot()` are the control surface.

### Auth & API shape

Cookie sessions only; there is **no token-based public API**. `get_current_user(request)` reads `request.session['user_id']` and is the gate on every protected route. `_check_admin(request)` layers a role check on top. Share links (`/share/<token>`) are the one unauthenticated path — they generate password-protected config downloads without panel access.

### SSL

TLS is opt-in via `settings.ssl` in `data.json` (not env vars). Cert/key can be supplied as file paths **or** inline text — inline text is written to `./ssl_temp/` at startup and passed to uvicorn. `panel_port` lives in the same settings block and overrides the default 5000.

### Frontend

Server-rendered Jinja2 (`templates/`) + vanilla JS (`static/js/`, only `qrcode.min.js` is vendored) + one hand-written `style.css`. No build step, no bundler, no framework. i18n strings are flat JSON in `translations/{en,ru,fr,zh,fa}.json`, loaded once at startup into `TRANSLATIONS`; `_t(id, lang)` is the lookup. Persian is RTL — template/CSS changes need to respect `dir="rtl"`.

## Conventions worth knowing

- Secrets: `SECRET_KEY` env var seeds session signing; if unset, a random one is generated per-process (sessions invalidate on restart).
- Default credentials on first run: `admin` / `admin` — seeded in `startup()` when `data.users` is empty.
- When adding a new protocol, you must: (1) create a manager, (2) add it to `get_protocol_manager`, (3) add its string to the `['awg', 'awg2', 'awg_legacy', 'xray', 'telemt', 'wireguard']` list in `_scrape_server_traffic`, and (4) decide whether it takes `protocol_type` (keep `_manager_call` working).
- Remote SSH operations must not block the event loop — wrap in `asyncio.to_thread` or run inside an already-threaded helper.
- Target servers are Ubuntu 20.04/22.04/24.04 (x86_64 or ARM64); install scripts assume `apt`, `docker`, and systemd.
