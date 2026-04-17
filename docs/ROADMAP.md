# Roadmap — Non-Security Follow-ups

Scope note: these items are **not** in `RISK_AUDIT.md` because that file is scoped to security findings only. The four items below are feature / UX / ops / housekeeping work.

Order of implementation suggested: (4) screen move → (3) Docker trim → (2) update checker → (1) public API (largest).

---

## 1. Public Remote API for external VPN provisioning

### Motivation

A separate product (premium tier) needs to provision AmneziaWG/WireGuard/Xray clients on demand per premium user. Today the panel only exposes session-cookie routes; there is no machine-to-machine surface. README already flags this gap.

### Requirements

- Caller is another backend, not a browser. No CORS, no cookies.
- Must survive replay and body tampering on the open internet.
- Must be **strictly additive**: do not touch the existing session-authed routes or the Swagger surface shape for the panel UI.
- Key revocation must not require a restart.

### Design

**Transport:** same process, new router mounted at `/api/v1/ext/*`. Shared FastAPI app, shared `data.json`, shared SSH/manager pipeline via `get_protocol_manager` + `_manager_call`. Separate auth dependency (`require_api_key`) — never composes with `get_current_user`.

**Auth:** HMAC-SHA256 signed requests. Symmetric key, simple for the caller to integrate.

Headers required on every request:

| Header         | Value                                                                         |
| -------------- | ----------------------------------------------------------------------------- |
| `X-API-Key`    | Key id (public part — looked up server-side)                                  |
| `X-Timestamp`  | Unix seconds, integer                                                         |
| `X-Signature`  | `hex(HMAC_SHA256(secret, f"{ts}\n{method}\n{path}\n{sha256(body)}"))`         |

Server-side checks (in order, constant-time where relevant):
1. `abs(now - ts) <= 300` (5-min window, rejects replay).
2. Key id resolves to an active, non-revoked record in `data.json → api_keys[]`.
3. HMAC matches with `hmac.compare_digest`.
4. Scope on the key includes the route's required scope.
5. Per-key token bucket (e.g. 30 req/s, 10k/day). Reuse the in-memory pattern from `_LOGIN_FAILURES`.

**Key record shape** (new in `data.json`, migration in `startup()`):

```json
{
  "api_keys": [
    {
      "id": "ak_live_…",          // public, sent in X-API-Key
      "secret_hash": "argon2…",   // store hash only; show full secret once at creation
      "scopes": ["clients:write", "clients:read", "servers:read"],
      "label": "premium-backend prod",
      "created_at": "…",
      "revoked_at": null,
      "last_used_at": null
    }
  ]
}
```

**Scopes (v1):**
- `servers:read` — list available servers + their installed protocols.
- `clients:read` — read client status, traffic, expiry, config download.
- `clients:write` — create / update / delete clients.

**Endpoints (v1):**

| Method | Path                                 | Scope          | Purpose                                         |
| ------ | ------------------------------------ | -------------- | ----------------------------------------------- |
| GET    | `/api/v1/ext/servers`                | servers:read   | List servers with available protocols + load    |
| POST   | `/api/v1/ext/clients`                | clients:write  | Provision client (server_id, protocol, limits)  |
| GET    | `/api/v1/ext/clients/{id}`           | clients:read   | Status + traffic counters                       |
| PATCH  | `/api/v1/ext/clients/{id}`           | clients:write  | Update expiration / traffic_limit / enabled    |
| DELETE | `/api/v1/ext/clients/{id}`           | clients:write  | Revoke                                          |
| GET    | `/api/v1/ext/clients/{id}/config`    | clients:read   | Return config file + share-link-equivalent     |

All endpoints return JSON, all write endpoints are idempotent via an optional `Idempotency-Key` header (store last response by key for 24h).

**Provisioning flow** for `POST /api/v1/ext/clients`: reuse `_manager_call(manager, "add_client", protocol, …)`, wrap in `asyncio.to_thread` per CLAUDE.md, persist via `save_data_async`, return the manager-generated config plus the existing share-token flow so the caller can forward a URL to their end user.

**Admin UX:** new section in `settings.html` to mint keys. On mint, show the full secret once with a copy button; store only the Argon2 hash. List/revoke thereafter.

**Network exposure:**
- Default: same port as panel. Recommend TLS (already supported via `settings.ssl`).
- Document reverse-proxy + IP allowlist in the README integration section.
- Do **not** add a second listener — keep single-process model intact.

**Non-goals for v1:** OAuth, webhooks, pagination cursors, SDK packages. Ship the smallest safe surface first.

### Acceptance

- [ ] `api_keys` migration runs on existing installs, idempotent.
- [ ] HMAC verification rejects: stale ts, wrong body hash, revoked key, wrong scope.
- [ ] Rate limiter drops 31st req/s per key with `429`.
- [ ] End-to-end test (real SSH, real panel): caller provisions → reads traffic → deletes.
- [ ] Integration docs with a 30-line Python example caller.

---

## 2. Update checker — make informational, source from GHCR

### Current behaviour

`assets/templates/settings.html:541` runs browser-side against `api.github.com/repos/PRVTPRO/Amnezia-Web-Panel/releases/latest` and surfaces a "Download" button pointing at the GitHub release page. No server-side code involved.

### Problems

- "Download update" CTA from a self-hosted panel is misleading — Docker users don't download binaries; they pull an image.
- Browser-side GitHub API calls hit the 60 req/h unauth limit on the user's IP.
- Source of truth for this project's releases should be GHCR, not hub.docker.com and not a binary download.

### Target behaviour

Passive info strip in Settings:

> Running `v1.4.2`. Latest on GHCR: `v1.5.0` (released 2026-03-12). [release notes]

No download button. No automatic action. If up-to-date: "You're on the latest release."

### Design

- Add `GET /api/internal/version-check` (session-authed, admin-only).
- Server queries `https://ghcr.io/v2/prvtpro/amnezia-panel/tags/list` (no auth needed for public packages) + `https://api.github.com/repos/PRVTPRO/Amnezia-Web-Panel/releases/latest` for the release notes URL.
- Cache result in-process for 1h to avoid hammering GHCR and to keep the settings page snappy.
- Return `{ current, latest, released_at, notes_url, up_to_date }`.
- Template renders the strip on page load; no button, no spinner.

### Fallback

If both APIs fail: render "Version check unavailable" in muted text and log once. Never block page render.

### Acceptance

- [ ] No "Download" / "Check" button in Settings.
- [ ] Version strip loads on page open without user action.
- [ ] Failure mode is silent (no toast, no error banner).
- [ ] Cache respected — second page load in same hour issues zero outbound HTTP.

---

## 3. Lighter multi-stage Docker image

### Current state

`Dockerfile` is already two-stage (`uv` builder → `python:3.12-slim-bookworm`). Image size is dominated by: full slim-bookworm base (~80 MB), the venv including tests and `__pycache__` duplicates, and paramiko/cryptography's bundled shared libs.

### Candidate optimisations (in order of payoff / risk)

1. **Strip the venv in the builder stage before copy:** remove `tests/`, `*.dist-info/RECORD`-only leftovers, `__pycache__` stubs for files we rebuild with `UV_COMPILE_BYTECODE`.
2. **Drop `uv` binary from final image** — already done (only the venv is copied), verify.
3. **Use `python:3.12-slim-bookworm` + `--no-install-recommends`** for any `apt` we add — currently none, keep it that way.
4. **Try `gcr.io/distroless/python3-debian12:nonroot` as runtime.** Pros: ~40 MB vs ~110 MB, no shell, no package manager, nonroot by default. Cons: no shell means healthcheck must be a Python one-liner (already is), and debugging a running container requires `kubectl debug` / `docker run --entrypoint`. Cryptography and paramiko wheels must link against glibc that distroless ships — verify with a build test before committing.
5. **Alpine is not worth it here**: cryptography/paramiko would need musl wheels or a full build toolchain, which defeats the "light" goal.

### Plan

- Step 1: measure current image size (`docker image ls` after build). Record in this doc.
- Step 2: add a `.dockerignore` audit pass — make sure `screen/` (post-move: `docs/screen/`), `*.md` except `README.md`, tests, and `.github/` are excluded from the build context.
- Step 3: add venv-cleanup step in builder:
  ```dockerfile
  RUN find /app/.venv -type d -name '__pycache__' -exec rm -rf {} + \
   && find /app/.venv -type d -name 'tests' -prune -exec rm -rf {} + \
   && find /app/.venv -name '*.pyc' -delete
  ```
- Step 4: prototype distroless runtime on a branch. If cryptography imports clean and the healthcheck passes, adopt. If not, stay on slim-bookworm with step-3 trimming.
- Step 5: publish `prvtpro/amnezia-panel:<tag>` **and** `ghcr.io/prvtpro/amnezia-panel:<tag>` — required by item (2) anyway.

### Acceptance

- [ ] Final image size reduced by at least 30% vs current.
- [ ] Container boots, serves `/`, passes the existing healthcheck.
- [ ] GHCR tag is published alongside Docker Hub from the same build workflow.

---

## 4. Move `screen/` → `docs/screen/`

### Why

Project root should hold source and config, not marketing assets. `docs/` already exists.

### Changes

- `git mv screen/ docs/screen/`
- `README.md` lines 20, 30, 38: image URLs currently point to `main/screen/…` on github.com — update to `main/docs/screen/…`. Keep absolute URLs so images render on PyPI / GHCR / Docker Hub descriptions too.
- `.dockerignore:21` — update `screen/` → `docs/screen/` (or just `docs/` if docs don't ship in the image, which they don't).
- Grep the tree one more time for any stray `screen/` references before committing.

### Acceptance

- [ ] No `screen/` directory at repo root.
- [ ] README images still render on github.com.
- [ ] Docker build context does not include the screenshots.
