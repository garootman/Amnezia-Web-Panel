# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Run & Build

Dependency and tool management is **uv-only**. There is no `requirements.txt`, no `pip install`, no `venv`/`virtualenv` ceremony — `uv sync` reads `pyproject.toml` + `uv.lock` and provisions `.venv/` itself. Every dev command runs through `uv run …` (or `uvx` for one-shots).

```bash
uv sync                              # resolve + install runtime + dev deps from uv.lock
task dev                             # uvicorn --reload on PANEL_HOST/PANEL_PORT (src/amnezia_panel/app.py:app)
task run                             # one-shot: uv run python -m amnezia_panel
docker compose up -d                 # prebuilt image ghcr.io/garootman/amnezia-web-panel
```

Common tasks live in `Taskfile.yml` (`dev`, `run`, `lint`, `fmt`, `fmt-check`, `audit`, `check`, `lock`, `upgrade`, `docker-build`, `docker-run`, `pre-commit-install`). Use them rather than reinventing flags.

Tooling that **is** configured:

- **ruff** — lint + format; config lives in `[tool.ruff]` in `pyproject.toml` (line-length 120, py312 target, curated rule set). `uv run ruff check` / `uv run ruff format`.
- **uv audit** — OSV vulnerability scan on resolved deps. `uv audit --no-group dev --preview-features audit`. Wired in CI and `task audit`.
- **pre-commit** — hook optionally installed via `uvx pre-commit install` (`task pre-commit-install`).

Tooling that is **not** wired — do not assume it exists: no `pytest` (no test suite), no type checker (`mypy`/`ty`/`pyright`). If you add one, register it in `[dependency-groups].dev`, add a `Taskfile.yml` entry, and wire it into `.github/workflows/build.yml` alongside `lint` + `audit`.

The GitHub Actions workflow at `.github/workflows/build.yml` runs `lint` → `audit` → `build` → `publish` (GHCR only — no Docker Hub). It does **not** produce PyInstaller single-file binaries; if you resurrect that job, bundle `assets/static`, `assets/templates`, `assets/translations` via `--add-data`.

## Layout

```
src/amnezia_panel/          # the package (project.scripts: amnezia-panel)
  app.py                    # ~3.2k LOC — FastAPI app, routes, startup/migration, background loop
  ext_api.py                # public HMAC-authenticated REST API at /api/v1/ext
  config.py                 # pydantic-settings Settings() — .env + env vars
  secrets_store.py          # Fernet encryption-at-rest for secrets in data.json
  ssh_manager.py            # Paramiko wrapper with sudo + SFTP helpers
  telegram_bot.py           # raw Telegram Bot API over httpx, runs as asyncio.Task
  protocols/                # per-protocol remote installers/managers
    awg.py wireguard.py xray.py telemt.py dns.py
assets/                     # static/ templates/ translations/   (served from settings.assets_dir)
protocol_telemt/            # remote-side Docker assets uploaded at telemt install time
data.json                   # runtime state (gitignored)        — settings.data_file
data.key                    # Fernet key for secrets_store       — next to data.json, 0o600
```

## Architecture

This is a single-process FastAPI control plane that manages remote VPN servers **over SSH**. There is no database and no background worker beyond one in-process task — everything lives in `app.py` plus the `protocols/` package.

### Request → SSH pipeline

1. `app.py` defines FastAPI routes, Pydantic request models, session auth (Starlette `SessionMiddleware`), Jinja2 rendering, and i18n. `ext_api.router` is mounted last under `/api/v1/ext`.
2. A request that touches a remote server constructs `SSHManager(host, port, user, password|private_key)` via `get_ssh(server)`.
3. `get_protocol_manager(ssh, protocol)` dispatches to a manager class. Supported `protocol` strings: `awg`, `awg2`, `awg_legacy` (all `AWGManager`), `wireguard`, `xray`, `telemt`, `dns`.
4. **Callers invoke manager methods directly** (no shim anymore). Pass the protocol string as the first positional arg — most signatures are `(protocol_type, ...)`; `xray.py` names it `protocol`; `WireGuardManager.get_clients` defaults it to `"wireguard"`. `install_protocol` is **not** uniform across managers — `telemt` uses keyword-only args, `xray`/`wireguard` take `port=` only, others take `(protocol_type, port=)`; branch on the protocol string at the call site.
5. Paramiko calls are blocking. Anywhere they're invoked from an async handler, wrap in `asyncio.to_thread(...)` (see `_scrape_server_traffic` for the pattern).

### Protocol managers

Each manager installs/configures its protocol on the remote host by uploading files via SFTP (`SSHManager.upload_file_sudo` writes to `/tmp` then `sudo mv`s into place) and running `docker` / `docker compose` under sudo. Roughly uniform surface: `install_protocol`, `remove_container`, `get_server_status`, `get_clients`, `add_client`, `remove_client`.

- `protocols/awg.py` — AmneziaWG (standard, AWG 2.0, and legacy) with configurable obfuscation params.
- `protocols/wireguard.py` — classic WireGuard.
- `protocols/xray.py` — Xray VLESS-Reality under Docker container `amnezia-xray`.
- `protocols/telemt.py` — Telegram MTProxy; remote-side Docker assets live in `protocol_telemt/` and are uploaded at install time.
- `protocols/dns.py` — Unbound-based AmneziaDNS with its own Docker network (`amnezia-dns-net`) that VPN containers get attached to.
- `ssh_manager.py` — wraps Paramiko with sudo-password piping (`sudo -S`), SFTP helpers, and a `with` context manager. Use `run_sudo_command` / `upload_file_sudo` — never raw `run_command` when root is needed.

### Persistence

Single file: `data.json` at `settings.data_dir` (set by `DATA_DIR` env, else next to `sys.executable` when frozen, else repo root). Gitignored. Schema is seeded and migrated in `startup()` — when you add a new field to users/servers/settings, add the migration there, because existing installs won't have it.

All writes go through `save_data_async` which serializes behind `DATA_LOCK` (an `asyncio.Lock`). Direct `save_data` is used only at startup and inside code already holding the lock. Race conditions here are real: the traffic sync loop, request handlers, and the external-API sweeper all mutate `data.json`.

### Secrets at rest

`secrets_store.py` encrypts a fixed set of paths in `data.json` with Fernet (prefix `enc:v1:`), key at `settings.data_dir / "data.key"` (0o600, generated on first run). Encrypted paths: `servers[*].password`, `servers[*].private_key`, `settings.sync.remnawave_api_key`, `settings.telegram.token`. Encrypt/decrypt are idempotent (safe across migration). `load_data` decrypts; `save_data_async` re-encrypts — if you add a new credential field, extend `SECRET_PATHS`.

### Background loop

`periodic_background_tasks()` is kicked off in `startup()` and runs every 10 minutes: scrapes per-client byte counters via SSH, updates `traffic_used` / `traffic_total`, checks `traffic_limit` and `expiration_date`, auto-disables users that hit their cap, and optionally syncs users from Remnawave. It also fires `ext_api.fire_server_unreachable_event` / `fire_quota_exhausted_event` and calls `ext_api.run_external_sweeper()` — so anything new that should generate a webhook belongs there. Traffic-reset strategies (`daily`/`weekly`/`monthly`/`never`) are applied in this loop.

### Telegram bot

`telegram_bot.py` uses the raw Telegram Bot API via `httpx` (there is no `python-telegram-bot` dep). It runs as an `asyncio.Task` alongside FastAPI — `launch_bot()` is called from `startup()` if `settings.telegram.enabled`, and can be toggled at runtime. `is_running()` / `stop_bot()` are the control surface.

### Auth & API shape

Two surfaces, different auth models:

- **Panel (cookie sessions).** `get_current_user(request)` reads `request.session['user_id']` and gates every protected HTML/JSON route. `_check_admin(request)` layers a role check on top. Share links (`/share/<token>`) are the only unauthenticated panel path — they serve password-protected config downloads without panel access.
- **External API (`/api/v1/ext`, `ext_api.py`).** HMAC-SHA256 signed requests: `X-API-Key` + `X-Timestamp` + `X-Signature` over `method\npath\ntimestamp\nbody_sha256`. ±300 s clock skew. Per-key token-bucket rate limits (60/min reads, 10/min writes). Idempotency, rate-limit state, and webhook delivery state are **in-process only and lost on restart** (documented there). Intended for an upstream billing portal; external API keys are stored encrypted (hashed) in `data.json`. When you add an endpoint here, route state changes through `save_data_async` and SSH calls through the same `get_protocol_manager` pipeline — don't build a parallel one.

### SSL

TLS is opt-in via `settings.ssl` in `data.json` (not env vars). Cert/key can be supplied as file paths **or** inline text — inline text is written to `settings.data_dir / "ssl_temp"` at startup and passed to uvicorn. `panel_port` in `data.json`'s settings overrides the env default 5000.

### Frontend

Server-rendered Jinja2 (`assets/templates/`) + vanilla JS (`assets/static/js/`, only `qrcode.min.js` is vendored) + one hand-written `style.css`. No build step, no bundler, no framework. i18n strings are flat JSON in `assets/translations/{en,ru,fr,zh,fa}.json`, loaded once at startup into `TRANSLATIONS`; `_t(id, lang)` is the lookup. Persian is RTL — template/CSS changes need to respect `dir="rtl"`.

## Conventions worth knowing

- **Settings**: `Settings` in `config.py` reads from `.env` (at repo root) and env vars. Useful keys: `PANEL_HOST`, `PANEL_PORT`, `SECRET_KEY`, `DATA_DIR`, `ASSETS_DIR`. If `SECRET_KEY` is unset, a per-process one is generated — sessions invalidate on restart.
- **Default credentials on first run**: `admin` / `admin` — seeded in `startup()` when `data.users` is empty.
- **Adding a protocol** requires: (1) a new module under `src/amnezia_panel/protocols/`, (2) registration in `get_protocol_manager`, (3) adding the string to the `["awg", "awg2", "awg_legacy", "xray", "telemt", "wireguard"]` list in `_scrape_server_traffic` in `app.py`, (4) matching whatever `protocol_type`/`protocol` first-arg convention the existing managers use (callers pass it positionally), and (5) if any new credential fields are stored in `data.json`, extending `SECRET_PATHS` in `secrets_store.py`.
- **Never block the event loop** from async handlers — wrap SSH/Paramiko calls in `asyncio.to_thread` or run inside an already-threaded helper.
- **Target servers** are Ubuntu 20.04/22.04/24.04 (x86_64 or ARM64); install scripts assume `apt`, `docker`, and systemd.
