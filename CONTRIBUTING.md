# Contributing

Thanks for looking at the code. This doc covers the dev loop; architecture and
deeper conventions live in [`.claude/CLAUDE.md`](.claude/CLAUDE.md) and
[`docs/`](docs/).

## Setup

```bash
uv sync          # install runtime + dev deps into .venv
task pre-commit-install   # optional: install the git hook
```

Copy `.env.example` to `.env` and tweak. In Docker, env vars come from the host
instead — `.env` is excluded from the image via `.dockerignore`.

## Dev loop

```bash
task dev       # hot-reload uvicorn on ${PANEL_PORT:-5000}
task lint      # ruff check
task fmt       # ruff format
task audit     # uv audit — scan for known vulns
task check     # lint + fmt-check + audit (what CI runs)
```

Run `task check` before pushing. CI runs the same three steps plus a Docker build.

## Adding a new VPN protocol

Four touch-points (see `.claude/CLAUDE.md` for detail):

1. Create `src/amnezia_panel/protocols/<name>.py` exporting a manager class.
2. Register it in `get_protocol_manager()` in `app.py`.
3. Add its string to the protocol list in `_scrape_server_traffic()` so the
   background loop polls traffic for it.
4. Make sure its `get_clients` / `add_client` / `remove_client` / `toggle_client`
   / `get_server_status` / `remove_container` methods accept `protocol_type` as
   the first positional argument — even if unused. This keeps dispatch uniform
   and lets us avoid reintroducing the `_manager_call` shim.

## Changing runtime config

Settings live in `src/amnezia_panel/config.py` (a `pydantic_settings.BaseSettings`).
Env vars win over `data.json`, which wins over the built-in default. When
adding a new setting:

- Add it to the `Settings` model.
- Document it in `.env.example`.
- If it's also editable from the panel UI, hook it up in the settings routes.

## Ruff

The baseline config in `pyproject.toml` ignores a few noisy rules (`RUF059`,
`B007`, `B008`, `SIM102/105/108`, etc.). If a rule repeatedly fires with no
signal, open a PR to add it to `[tool.ruff.lint] ignore` with a one-line reason.

## Release

Bump `version` in `pyproject.toml` and `image:` in `docker-compose.yml` (they
must match), update `CHANGELOG.md`, and tag `vX.Y.Z`. The `build.yml` workflow
builds on every push and publishes on `main`.
