# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Added
- `uv audit` job in CI that fails on any known vulnerability in a resolved runtime dependency.
- `ruff check` / `ruff format --check` gate in CI; matching `.pre-commit-config.yaml`.
- `.editorconfig` codifying indent and newline conventions.
- `Taskfile.yml` with `dev`, `lint`, `fmt`, `audit`, `check`, `docker-build` shorthands.
- `CONTRIBUTING.md` capturing the dev loop.

### Changed
- `WireGuardManager` methods now accept `protocol_type` as the first positional argument for uniform dispatch, and the `_manager_call` shim in `app.py` was removed.
- `XrayManager.remove_container` gained the same no-op `protocol_type` parameter.
- `CURRENT_VERSION` is now sourced from `importlib.metadata.version("amnezia-web-panel")` rather than a hard-coded constant.
- Initial `ruff` baseline applied across the codebase: imports sorted, blank-line whitespace cleaned, trailing whitespace removed, bare `except:` clauses replaced with `except Exception:`.

### Fixed
- Two `asyncio.create_task(...)` call sites now hold strong references to their tasks; without this, the GC could cancel them mid-flight.

## [1.4.2] — 2026-04-17

First release after the modernization pass. See `docs/MODERNIZATION_PLAN.md` for
the ground-up rewrite of packaging and tooling (uv, `src/` layout, multistage
Docker, pydantic-settings). No user-visible changes in runtime behaviour.
