# Modernization Plan

Companion to `RISK_AUDIT.md`. That doc fixes bugs and security holes. This doc fixes *developer experience* — packaging, layout, tooling, and the accumulated grit that makes the repo feel unloved. Nothing here changes runtime behaviour; it's all dev ergonomics and supply-chain hygiene.

Do these in the order below. Each phase is independently shippable — don't try to land it all in one PR.

---

## Status

- [x] **Phase 1** — uv migration (`pyproject.toml`, `uv.lock`, `.python-version`, dead deps pruned; `itsdangerous` added — plan missed it, required by `SessionMiddleware`)
- [x] **Phase 3.1** — Multistage uv Dockerfile, non-root `app` user, `/app/data` volume
- [x] **Phase 3.2** — CI rewritten: single Docker build job replaces 3-OS PyInstaller matrix; `publish` job pushes to GHCR, disabled via `if: false` until enabled
- [x] **Configurable port/host** — `PANEL_PORT` / `PANEL_HOST` / `DATA_DIR` env vars honoured by `app.py`, Dockerfile, compose
- [x] **Partial Phase 4.5** — unreachable `return True` removed, dead `CaptchaGenerator` import fallback removed, Russian Dockerfile comments gone
- [x] **Starlette 1.x fix** (collateral) — `TemplateResponse(request, name, ctx)` signature update, silently broken after dep upgrade
- [ ] Phase 2 — `src/` layout + `app.py` split *(deferred — the "scary PR" per plan)*
- [ ] Phase 4.1–4.4, 4.6, 4.7 — ruff wiring, `.editorconfig`, Taskfile, CHANGELOG, version from metadata

---

## Phase 1 — uv migration

### 1.1 Replace `requirements.txt` with `pyproject.toml`

The current `requirements.txt` is **UTF-16 LE with CRLF** (`file requirements.txt` → `Unicode text, UTF-16, little-endian text, with CRLF line terminators`). That's a footgun — many tools choke on it, and the file was almost certainly produced by a Windows shell redirect by accident. Replace wholesale with a utf-8 `pyproject.toml`.

Target layout:

```toml
[project]
name = "amnezia-web-panel"
version = "1.4.2"
description = "Web panel for managing AmneziaWG / WireGuard / Xray / Telegram-MTProxy servers over SSH."
readme = "README.md"
requires-python = ">=3.11"
license = { file = "LICENSE" }
dependencies = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.34",
    "starlette>=0.46",
    "jinja2>=3.1",
    "pydantic>=2.10",
    "python-multipart>=0.0.20",
    "paramiko>=3.5",
    "cryptography>=44",
    "httpx>=0.27",
    "python-dotenv>=1",
    "pyyaml>=6",
    "bcrypt>=5",          # keep only if still referenced; see §3.2
    "multicolorcaptcha>=1.2",
    "pillow>=11",
]

[project.scripts]
amnezia-panel = "amnezia_panel.__main__:main"

[build-system]
requires = ["uv_build>=0.11.6,<0.12"]
build-backend = "uv_build"

[dependency-groups]
dev = [
    "ruff>=0.8",
    "mypy>=1.13",
    "pytest>=8",
    "pyinstaller>=6",
]
```

Generate `uv.lock` with `uv lock` and commit it.

### 1.2 Delete dead dependencies

`requirements.txt` ships libraries the code does not use. Verified by grep:

- **`Flask` / `Werkzeug` / `blinker` / `itsdangerous` / `click` / `colorama`** — the app is FastAPI. Flask is never imported. (`grep -r "from flask\|import flask"` returns nothing.)
- **`python-telegram-bot==20.7`** — `telegram_bot.py:1-12` declares *"Uses raw Telegram Bot API via httpx — no library version conflicts"*. The dep is imported nowhere.
- **`watchfiles` / `httptools` / `websockets`** — pulled in only because `uvicorn[standard]` wants them. Let uvicorn declare them transitively; don't pin them top-level.
- **`pillow`** — used by `multicolorcaptcha`; keep only if you verify a direct usage in your own code, otherwise let captcha pull it.
- **`h11` / `sniffio` / `anyio` / `idna` / `certifi` / `h2` / `typing-extensions` / `annotated-types` / `markupsafe` / `pycparser` / `cffi` / `PyNaCl` / `pydantic_core` / `typing-inspection`** — transitive pins. Drop them; let the resolver handle it. Pinning transitives is what `uv.lock` is for.

End state: ~12 direct deps instead of 37. Lockfile guarantees reproducibility.

### 1.3 Update `.python-version`

Add a top-level `.python-version` file containing `3.12` (or whichever you settle on). CI currently uses 3.11, Dockerfile uses 3.14-slim — pick one and stop drifting.

---

## Phase 2 — `src/` layout

### 2.1 New layout

```
Amnezia-Web-Panel/
├── pyproject.toml
├── uv.lock
├── .python-version
├── README.md
├── LICENSE
├── Dockerfile
├── docker-compose.yml
├── docs/
├── src/
│   └── amnezia_panel/
│       ├── __init__.py
│       ├── __main__.py          # uvicorn launcher (was tail of app.py)
│       ├── app.py               # FastAPI routes + startup
│       ├── auth.py              # hash_password, verify_password, get_current_user, _check_admin
│       ├── data.py              # load_data, save_data_async, DATA_LOCK, migrations
│       ├── i18n.py              # load_translations, _t
│       ├── background.py        # periodic_background_tasks, _scrape_server_traffic
│       ├── sync.py              # sync_users_with_remnawave
│       ├── telegram_bot.py
│       ├── ssh_manager.py
│       └── protocols/
│           ├── __init__.py      # get_protocol_manager, _manager_call
│           ├── awg.py           # was awg_manager.py
│           ├── wireguard.py
│           ├── xray.py
│           ├── telemt.py
│           └── dns.py
├── assets/                      # previously ./static, ./templates, ./translations
│   ├── static/
│   ├── templates/
│   └── translations/
└── protocol_telemt/             # stays — it's Docker artifacts for remote hosts, not app code
```

Why move static/templates/translations up to `assets/`? Because they're not Python and shouldn't live inside a Python package. PyInstaller will still pick them up via `--add-data`.

### 2.2 Break up `app.py`

Right now `app.py` is **2,290 lines** and holds FastAPI routes, 20+ Pydantic models, password hashing, SSH orchestration, Remnawave sync, background tasks, i18n, template rendering, migrations, and the uvicorn bootstrap. That's why every audit item in `RISK_AUDIT.md` points back to this one file.

Split targets (rough LOC after split):

| Module | What goes there |
|---|---|
| `app.py` | FastAPI app init, route registration, Pydantic request models. ~900 LOC. |
| `auth.py` | `hash_password`, `verify_password`, `get_current_user`, `_check_admin`, session helpers. ~80 LOC. |
| `data.py` | `load_data`, `save_data`, `save_data_async`, `DATA_LOCK`, the startup migrations block. ~250 LOC. Atomic writes land here when `RISK_AUDIT.md` H-1 is fixed. |
| `background.py` | `periodic_background_tasks`, `_scrape_server_traffic`, `perform_mass_operations`, `perform_delete_user`. ~350 LOC. |
| `sync.py` | `sync_users_with_remnawave`. ~150 LOC. |
| `i18n.py` | `TRANSLATIONS`, `load_translations`, `_t`. ~30 LOC. |
| `__main__.py` | The SSL/uvicorn bootstrap block currently at the tail of `app.py`. ~50 LOC. |

Route grouping is optional but nice: `routes/auth.py`, `routes/servers.py`, `routes/users.py`, `routes/connections.py`, `routes/settings.py` using FastAPI `APIRouter`. Defer to phase 4 if the initial split is already painful.

### 2.3 Delete duplicate imports

`app.py` imports the same manager classes **four to five times**:

```
27: from ssh_manager import SSHManager
28: from awg_manager import AWGManager
29: from xray_manager import XrayManager           # top of file
30: from wireguard_manager import WireGuardManager
...
134:     from xray_manager import XrayManager        # inside get_protocol_manager
137:     from telemt_manager import TelemtManager
140:     from dns_manager import DNSManager
143:     from wireguard_manager import WireGuardManager
145:     from awg_manager import AWGManager
...
1339, 1345, 1349, 1375, 1385, 1389: more of the same
```

After the `src/` move, put all protocol-manager imports once at the top of `protocols/__init__.py` and delete every in-function import. Python import is idempotent but the noise hides bugs and makes refactors scary.

### 2.4 Normalize manager signatures

`_manager_call` only exists because `WireGuardManager` methods don't take `protocol_type` but every other manager does. Fix the cause, not the symptom: give `WireGuardManager.get_clients` / `add_client` / etc. a `protocol_type='wireguard'` no-op parameter and delete `_manager_call`. Any new contributor reading `app.py` currently has to understand the shim before they can read a single call site.

---

## Phase 3 — Docker & CI

### 3.1 Multistage Dockerfile with uv

Replace `Dockerfile` (currently 16 lines, `python:3.14-slim`, Russian comments that nobody's going to update) with the standard uv pattern:

```dockerfile
# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

FROM python:3.12-slim-bookworm
RUN groupadd --system --gid 999 app && useradd --system --gid 999 --uid 999 --create-home app
COPY --from=builder --chown=app:app /app /app
ENV PATH="/app/.venv/bin:$PATH"
USER app
WORKDIR /app
EXPOSE 5000
CMD ["python", "-m", "amnezia_panel"]
```

Wins: smaller image (no uv in final), non-root user (currently runs as root — implicit in the base image), deterministic installs via `uv.lock`, build-cache mounts for 10x faster rebuilds.

**Caveat:** the app writes `data.json` and `ssl_temp/` to the working directory. With a non-root user you need a mounted volume (`/app/data`) and a settings change to put `data.json` there — see `RISK_AUDIT.md` H-1 for the atomic-write fix; bundle the volume move with that.

### 3.2 GitHub Actions: use `astral-sh/setup-uv`

Current `.github/workflows/build.yml` does `pip install pyinstaller && pip install -r requirements.txt` on every OS. Replace with:

```yaml
- uses: actions/checkout@v4
- uses: astral-sh/setup-uv@v7
  with:
    python-version: "3.12"
    enable-cache: true
- run: uv sync --locked
- run: uv run pyinstaller ...
```

`setup-uv` handles caching automatically and restores `uv.lock`-based installs in seconds. Drop the explicit `pip install --upgrade pip` dance.

Also: the PyInstaller `--add-data` paths change once `assets/` moves — update all three OS branches.

---

## Phase 4 — Tooling & housekeeping

### 4.1 Add ruff + pre-commit

```toml
# pyproject.toml
[tool.ruff]
line-length = 120
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "B", "UP", "SIM", "RUF"]
ignore = ["E501"]  # line length handled by formatter
```

Current code has **no linter, no formatter, no type checker**. Adopt ruff (fast, single tool for lint+format) and wire it into pre-commit. Don't bother with Black — ruff does the formatting now.

Start with `uv run ruff check --fix` on a throwaway branch to see the scale. Expect ~200 auto-fixable issues (unused imports, old-style string formatting, mutable defaults).

### 4.2 Add `mypy --strict` in report-only mode

Type hints already exist in Pydantic models but not on the hundreds of helper functions. Run `mypy src/` with `--strict` but start with `--no-error-summary` in CI; fix modules incrementally over several PRs rather than turning it on all at once.

### 4.3 Add a `Taskfile.yml` or `justfile`

New contributors currently have to read the README + Dockerfile + GitHub Actions to figure out how to run the app. One file of shorthand:

```yaml
# Taskfile.yml
version: '3'
tasks:
  dev: uv run python -m amnezia_panel
  lint: uv run ruff check
  fmt: uv run ruff format
  test: uv run pytest
  build-docker: docker build -t amnezia-panel .
  freeze: uv lock --upgrade
```

### 4.4 Add `.editorconfig`

Current repo has no editorconfig. The existing code mixes 2-space JSON, 4-space Python, and occasional tabs in templates. Pin it down:

```
root = true
[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
[*.py]
indent_style = space
indent_size = 4
[*.{yml,yaml,json,toml,html}]
indent_style = space
indent_size = 2
```

### 4.5 Remove dead code and stale comments

Grep-verified items:

- `app.py:199-200` — `perform_delete_user` has `return True` after a prior `return True`. Unreachable. Delete.
- Dockerfile — all comments are in Russian (`# Копируем requirements.txt и устанавливаем зависимости`). Either translate to English (this is an English-language README) or remove them entirely — the commands are self-documenting.
- `app.py` has `try: from multicolorcaptcha import CaptchaGenerator except ImportError: CaptchaGenerator = None`. If captcha is a declared dep, the fallback is dead code and masks installation bugs. Pick: require it, or move to an extras group.
- `awg_manager.py` has comments like `Replicates the logic from: client/server_scripts/awg/ ...` pointing at paths that don't exist in this repo. Either vendor the reference or delete the pointer — as-is they're link rot.

### 4.6 Add `CHANGELOG.md` and `CONTRIBUTING.md`

Current release process is "bump `CURRENT_VERSION` constant in `app.py:50` and push a git tag." No changelog exists; release notes are GitHub-auto-generated. A hand-curated `CHANGELOG.md` following Keep-a-Changelog is ~30 min of work and makes version bumps traceable.

`CONTRIBUTING.md` should capture: `uv sync` to install, `task dev` to run, `task lint fmt test` before pushing, how to add a new protocol (referencing the `CLAUDE.md` checklist).

### 4.7 Move hard-coded version to package metadata

`app.py:50` has `CURRENT_VERSION = "v1.4.2"`. This drifts from `pyproject.toml`, `docker-compose.yml` (`prvtpro/amnezia-panel:1.4.0`), and git tags. Source of truth should be `pyproject.toml`; read it at runtime via `importlib.metadata.version("amnezia-web-panel")`.

---

## Suggested PR breakdown

| PR | Scope | Ships |
|---|---|---|
| #1 | Phase 1.1 + 1.2 | `pyproject.toml`, `uv.lock`, delete `requirements.txt`, delete dead deps. No code moves. |
| #2 | Phase 1.3 + 3.2 | `.python-version`, CI switches to `setup-uv`. |
| #3 | Phase 3.1 | New multistage Dockerfile. Coordinate with `RISK_AUDIT.md` H-1 (data dir volume). |
| #4 | Phase 2.1 + 2.2 | `src/` layout move, split `app.py` into modules. **This PR is the scary one** — land it when no feature work is in flight. |
| #5 | Phase 2.3 + 2.4 | Clean imports, normalize manager signatures, delete `_manager_call`. |
| #6 | Phase 4.1 + 4.4 + 4.5 | ruff config, `.editorconfig`, dead-code sweep. |
| #7 | Phase 4.3 + 4.6 + 4.7 | Taskfile, CHANGELOG, version single-sourcing. |
| #8 | Phase 4.2 | mypy adoption, incremental. |

Ship PRs #1–#3 first — they're cheap wins with near-zero diff in application code. Save the `src/` move for when the repo is quiet.

---

## Non-goals

- **Poetry / PDM / Hatch.** uv is the decision; don't relitigate.
- **Monorepo / workspace split.** The app is ~6k LOC and one deployable. Single package is correct.
- **Frontend build pipeline.** Vanilla JS + Jinja templates is a fine product choice for an admin panel; resist the urge to add Vite/webpack.
- **Database migration.** `data.json` is called out in `RISK_AUDIT.md` but replacing it is a product decision, not a cleanup task. Out of scope here.
