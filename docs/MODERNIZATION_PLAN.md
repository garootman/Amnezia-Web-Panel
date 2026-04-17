# Modernization Plan

Companion to `RISK_AUDIT.md`. That doc fixes bugs and security holes. This doc fixes *developer experience* — packaging, layout, tooling, and the accumulated grit that makes the repo feel unloved. Nothing here changes runtime behaviour; it's all dev ergonomics and supply-chain hygiene.

Do these in the order below. Each phase is independently shippable — don't try to land it all in one PR.

---

## Status

- [x] **Phase 1** — uv migration (`pyproject.toml`, `uv.lock`, `.python-version`, dead deps pruned; `itsdangerous` added — plan missed it, required by `SessionMiddleware`)
- [x] **Phase 2.1** — `src/amnezia_panel/` layout, `assets/` holds static/templates/translations, `protocols/` subpackage, `__main__.py` + `amnezia-panel` script entrypoint via hatchling
- [x] **Phase 2.3** — Duplicate in-function manager imports consolidated to top-of-file (kept `TelemtManager`/`DNSManager` lazy to avoid cycles)
- [x] **Phase 3.1** — Multistage uv Dockerfile, non-root `app` user, `/app/data` volume, CMD is `python -m amnezia_panel`
- [x] **Phase 3.2** — CI rewritten: single Docker build job replaces 3-OS PyInstaller matrix; `publish` job pushes to GHCR, disabled via `if: false` until enabled
- [x] **Pydantic-settings** (collateral) — `config.py` replaces scattered `os.environ.get(...)` reads; `PANEL_HOST` / `PANEL_PORT` / `SECRET_KEY` / `DATA_DIR` / `ASSETS_DIR` now a single typed `Settings` object with `.env` file support
- [x] **Configurable port/host** — env > data.json > default, honoured by package entrypoint, Dockerfile, compose
- [x] **Partial Phase 4.5** — unreachable `return True` removed, dead `CaptchaGenerator` import fallback removed, Russian Dockerfile comments gone
- [x] **Starlette 1.x fix** (collateral) — `TemplateResponse(request, name, ctx)` signature update, silently broken after dep upgrade
- [x] **Partial Phase 4.1** — ruff config lives in `pyproject.toml` with the planned rule set; *not* wired into pre-commit or CI yet, so nothing fails a run that ignores it
- [ ] Phase 2.2 — `app.py` split into `auth.py` / `data.py` / `background.py` / `sync.py` / route modules *(deferred — the 2.2k-LOC file still lives as one module under the package)*
- [ ] Phase 2.4 — Normalize `WireGuardManager` signatures and delete `_manager_call`
- [ ] Phase 4.1 (remainder) — pre-commit hook + CI gate for `ruff check`/`ruff format --check`
- [ ] Phase 4.3, 4.4, 4.6, 4.7 — Taskfile, `.editorconfig`, CHANGELOG, version from metadata
- [~] Phase 4.2 — Type checking intentionally **skipped**. We don't use `mypy`; if we ever add one, it'd be `ty` (Astral). Revisit only if a concrete type-safety incident motivates it.

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

> **Shipped note:** we ended up using `hatchling` as the build backend instead of `uv_build`. `hatchling` was already battle-tested, knows how to find `src/amnezia_panel` via `[tool.hatch.build.targets.wheel]`, and doesn't tie the build step to a specific uv version. `uv_build` is fine but adds a pin without a payoff here. Dev deps also shrank to `ruff` + `pyinstaller`; `mypy` and `pytest` were dropped — see Phase 4.2. `itsdangerous` had to come back as a direct dep because `SessionMiddleware` imports it without declaring it transitively.

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

> **Shipped note:** settled on 3.12. `.python-version`, `pyproject.toml` (`requires-python = ">=3.12"`), and the Dockerfile (`ghcr.io/astral-sh/uv:python3.12-bookworm-slim` + `python:3.12-slim-bookworm`) all agree. If you touch any one of them, touch the other two.

### 1.4 Typed settings via `pydantic-settings` *(collateral, shipped)*

`app.py` used to pluck `os.environ.get("SECRET_KEY")`, `os.environ.get("PANEL_PORT")`, etc. from whatever part of the file they were needed in, with string defaults inline and no validation. That's fine for two env vars; we have five, with more coming.

Landed:

- `src/amnezia_panel/config.py` defines a `Settings(BaseSettings)` with `PANEL_HOST`, `PANEL_PORT`, `SECRET_KEY`, `DATA_DIR`, `ASSETS_DIR`. `.env` is read in local dev; in Docker we pass env vars directly (see `.dockerignore` — `.env` is excluded from the image).
- Resolution order is **env > `data.json` > built-in default** for host/port: env wins for container deploys, `data.json` lets an operator pin things from the panel UI, default (`0.0.0.0:5000`) is the fallback. This is asymmetric with how most settings flow but is deliberate: we want ops to be able to set the listen port without editing JSON, and we want the UI to be able to pin it if they prefer that.
- `DATA_DIR` defaults to `Path(sys.executable).parent` when frozen, else repo root. Override to `/app/data` in Docker. `ASSETS_DIR` does the same for `assets/`.
- `.env.example` committed, `.env` gitignored. The launcher (`__main__.py`) reads `Settings()` once and hands it to uvicorn.

This is the one place where the modernization pass added a real abstraction rather than deleting one. Worth it: it gives us a single place to document and validate runtime config, and makes the Docker image env-pure.

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

### 3.2 GitHub Actions: collapse the PyInstaller matrix into one Docker build

Current `.github/workflows/build.yml` did `pip install pyinstaller && pip install -r requirements.txt` on Linux **and** Windows **and** macOS, producing three single-file binaries as release artifacts. That made sense before Docker was the primary distribution channel. It doesn't now — compose/Dockerfile is the documented path, the frozen binaries carried a stale list of bundled `--add-data` paths, and nobody downloads the macOS build.

Shipped replacement: a single `build` job on `ubuntu-latest` that runs `docker/build-push-action@v6` against the new multistage Dockerfile. Cache via GHA cache backend. A second `publish` job pushes to GHCR under `ghcr.io/<repo>` but is gated on `if: false` until we're ready to flip the switch (needs: a Docker Hub or GHCR decision, tagging rules, and whoever owns the release to say go).

> **Shipped note:** if you ever want to resurrect the PyInstaller binaries (e.g., for an ops team that can't run Docker), the `--add-data` list needs `assets/static`, `assets/templates`, `assets/translations` — not the pre-`src/` paths. Use `uv run pyinstaller` via `astral-sh/setup-uv@v7`. But the default assumption is: Docker is the artifact, PyInstaller is gone.

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

Config above has already shipped in `pyproject.toml`. What's **missing** is any mechanism that actually enforces it — a dev can push without ever running `ruff check`, and CI never notices. Two cheap steps to close that gap:

1. **Pre-commit hook** — add `.pre-commit-config.yaml` pinning `ruff` and `ruff-format`, tell `CONTRIBUTING.md` to run `pre-commit install`. Don't force pre-commit on contributors who don't want it; the CI gate catches everything the hook would.
2. **CI gate** — add a `lint` job to `.github/workflows/build.yml` that runs `uv run ruff check` and `uv run ruff format --check`. Make it a required status check once the baseline is clean.

Before landing either, run `uv run ruff check --fix` on a throwaway branch to see the scale — expect ~200 auto-fixable issues (unused imports, old-style string formatting, mutable defaults). Fix them in a single "ruff baseline" commit so `git blame` still works for real changes.

Don't bother with Black, isort, or flake8 — ruff replaces all of them.

### 4.2 Type checking — decision: skip

We don't run a type checker on this codebase and the modernization pass isn't going to add one. Concretely: no `mypy` (it was never a fit and it's not in dev deps), and no `ty` either for now — even though `ty` would be the natural choice given the rest of the toolchain is Astral.

Why skip: `app.py` is 2.2k LOC of route handlers with Pydantic-validated inputs at the boundary, and the real failure modes (SSH injection, missing `perform_toggle_user`, torn `data.json` writes — see `RISK_AUDIT.md`) aren't things a type checker would have caught. The cost of retrofitting annotations across the codebase far exceeds the expected bug-catch value at the current size.

Revisit if one of these happens:
- A production incident is traceable to a type error a checker would have caught.
- Phase 2.2 lands and the resulting modules are small enough that annotating them is a few hours per module. At that point reach for `ty`, not `mypy`.
- A contributor volunteers to own it. Don't introduce a type checker as a drive-by — a half-annotated codebase with blanket ignores is worse than none.

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

### Already shipped (for reference)

| Commit(s) | Scope |
|---|---|
| `8ced98e`, `0ad6d42` | Phase 1.1 + 1.2 + 1.3 + 2.1 + 2.3 + 3.1 — uv migration, `src/` layout, multistage Dockerfile, dead deps dropped. |
| `0ad6d42` (collateral) | Phase 1.4 — `pydantic-settings`, typed `Settings`, `.env` support. |
| `f832e9f`, `5db3dc0`, `3fc8beb` | Env-vs-`data.json` resolution for `PANEL_HOST`/`PANEL_PORT`, `.env` in dev / env-only in Docker, launcher honours `PANEL_PORT`. |
| (part of the same arc) | Phase 3.2 — PyInstaller matrix removed, single Docker `build` job, `publish`-to-GHCR job gated behind `if: false`. |
| (inline) | Partial Phase 4.5 — unreachable `return True`, dead `CaptchaGenerator` fallback, Russian Dockerfile comments. |
| (inline) | Starlette 1.x fix (`TemplateResponse(request, name, ctx)` signature). |

### Remaining

| PR | Scope | Notes |
|---|---|---|
| #A | Phase 2.4 | Give `WireGuardManager.get_clients`/`add_client`/etc. a `protocol_type='wireguard'` no-op parameter; delete `_manager_call`; rewrite the ~10 call sites in `app.py` (see `app.py:139`, plus lines 181/230/240/258/718/1160/1399/1490). Pure mechanical refactor, near-zero risk. Ship first — it pays off every time someone reads Phase 2.2. |
| #B | Phase 4.1 (remainder) + 4.4 | `.editorconfig`, `pre-commit-config.yaml`, a `lint` job in the workflow, and the one-shot `uv run ruff check --fix` baseline commit. Keep baseline as its own commit so `git blame` survives. |
| #C | Phase 4.7 | `CURRENT_VERSION` in `app.py:42` → `importlib.metadata.version("amnezia-web-panel")`. Bump `docker-compose.yml` image tag in the same PR so the three version strings actually align. |
| #D | Phase 4.3 + 4.6 | `Taskfile.yml` (or `justfile`), `CHANGELOG.md`, `CONTRIBUTING.md`. Backfill the changelog from `git log` — don't try to reconstruct pre-modernization history, start from `v1.4.2`. |
| #E | Phase 2.2 | **The scary one.** Split `app.py` into `auth.py` / `data.py` / `background.py` / `sync.py` / `i18n.py` / `__main__.py` (+ optional `routes/*.py`). Do it when no feature work is in flight; land in a single PR rather than drip-feeding (partial splits leak circular imports). Coordinate with `RISK_AUDIT.md` H-1 — the atomic-write fix naturally belongs in the new `data.py`, so pull both into the same PR. |

Order: **A → B → C → D → E.** A/B/C/D are each a focused afternoon. E is a day of careful work and needs a quiet window on `main`.

Phase 4.2 (mypy) is **not** in this list — see §4.2.

---

## Non-goals

- **Poetry / PDM / Hatch.** uv is the decision; don't relitigate.
- **Monorepo / workspace split.** The app is ~6k LOC and one deployable. Single package is correct.
- **Frontend build pipeline.** Vanilla JS + Jinja templates is a fine product choice for an admin panel; resist the urge to add Vite/webpack.
- **Database migration.** `data.json` is called out in `RISK_AUDIT.md` but replacing it is a product decision, not a cleanup task. Out of scope here.
