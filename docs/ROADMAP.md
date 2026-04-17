# Roadmap — Non-Security Follow-ups

Scope note: these items are **not** in `RISK_AUDIT.md` because that file is scoped to security findings only. The four items below are feature / UX / ops / housekeeping work.

Order of implementation suggested: (4) screen move → (3) Docker trim → (2) update checker → (1) public API (largest). This order matters: item 2 requires item 3's GHCR publishing.

This document was updated after a design review. Findings from that review are captured inline under **Review findings** in each section and the **Design / Plan** sections reflect the corrected approach.

---

## 1. Public Remote API for external VPN provisioning

### Motivation

A separate product (premium tier) needs to provision AmneziaWG/WireGuard/Xray clients on demand per premium user. Today the panel only exposes session-cookie routes; there is no machine-to-machine surface. README already flags this gap.

### Requirements

- Caller is another backend, not a browser. No CORS, no cookies.
- Must survive replay and body tampering on the open internet.
- Must be **strictly additive**: do not touch the existing session-authed routes or the Swagger surface shape for the panel UI.
- Key revocation must not require a restart.

### Review findings

1. **Argon2/PBKDF2 for secret hashing is wrong here.** Those KDFs are deliberately slow (100 ms–1 s). Applied per-request they block a worker thread before any business logic runs. For a machine-to-machine HMAC scheme the secret is already high-entropy random — a KDF buys nothing. Store the secret as-is and compare with `hmac.compare_digest`.
2. **The rate limiter cannot share state with `_LOGIN_FAILURES` (app.py:1038).** That dict is per-IP exponential backoff; what we need is a per-key token bucket. Different algorithm, different state. Keep them separate.
3. **30 req/s per key is meaningless for writes.** SSH round-trips are 200 ms–2 s, so writes naturally serialize to 1–5 req/s per server. Rate limiting mostly matters for read endpoints.
4. **Idempotency storage in `data.json` is a landmine.** `save_data` (app.py:136) rewrites the entire JSON document on every call, under `DATA_LOCK`. Storing response bodies there would make it unbounded and serialize every write behind the traffic loop. Keep idempotency state in-process only; a restart-and-retry model is acceptable for v1.
5. **Scopes are over-engineered for v1.** One caller, one scope. Ship the `scopes` field in the schema so it's migratable; enforce only revocation in v1 code.
6. **`server_id` is an array index (app.py:1156), not a stable id.** Deleting server 1 shifts server 2 into its slot — any cached `server_id` in the external backend now silently points at the wrong server. Must be fixed before the API ships: add a UUID to each server record, key the API off that.
7. **`POST /clients` is not atomically idempotent even with the header.** If SSH succeeds and `save_data_async` fails (or the process dies between the two), the VPN server has a client the panel doesn't know about. This is a pre-existing flaw in `api_add_connection` (app.py:1636). Document as a known limitation: on 5xx, callers must `GET /clients/{id}` before retrying.
8. **`DATA_LOCK` is a single asyncio.Lock shared with the traffic loop.** Not a v1 blocker, but document that external API writes contend with the 10-min scrape loop on slow disks.
9. **`load_data()` runs on every request with no cache.** `require_api_key` reads `data.json` off disk before any business logic. Fine for tens of KB; worth revisiting if usage grows.
10. **The external API widens the SSH-credentials blast radius.** SSH passwords are stored plaintext in `data.json` (app.py:1134). A leaked API key is equivalent to a leaked admin password. Document IP-allowlisting at the reverse proxy as **strongly recommended, not optional**.

### Design

**Transport:** same process, new router mounted at `/api/v1/ext/*`. Shared FastAPI app, shared `data.json`, shared SSH/manager pipeline via `get_protocol_manager` + `_manager_call`. Separate auth dependency (`require_api_key`) — never composes with `get_current_user`.

**File placement:** new module `src/amnezia_panel/ext_api.py` exporting an `APIRouter(prefix="/api/v1/ext")`. Mounted on `app` in `app.py` after existing routes. `app.py` is already 2.5k LOC; do not add routes there directly.

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
3. HMAC matches with `hmac.compare_digest`. **No KDF on the stored secret** — it is random high-entropy material, compared directly.
4. Per-key token bucket: **60 req/min for reads, 10 req/min for writes**. Separate bucket from `_LOGIN_FAILURES`, stored in a module-level dict `_API_RATE: dict[str, tuple[float, float]]` (key_id → (last_check, tokens)). Returns `429` on exhaustion.
5. Scope field is stored and returned but not enforced in v1 (see finding 5).

**Key record shape** (new in `data.json`, migration in `_apply_schema_migrations`):

```json
{
  "api_keys": [
    {
      "id": "ak_live_…",            // public, sent in X-API-Key
      "secret": "hex64…",           // random 32-byte hex, shown once at creation
      "scopes": ["full"],           // reserved for v2; v1 treats any non-revoked key as full
      "label": "premium-backend prod",
      "created_at": "…",
      "revoked": false,
      "last_used_at": null
    }
  ]
}
```

Migration snippet (add to `_apply_schema_migrations`):
```python
if "api_keys" not in data:
    data["api_keys"] = []
    changed = True
```

**Prerequisite migration — stable server IDs (finding 6):**
```python
for srv in data.get("servers", []):
    if "id" not in srv:
        srv["id"] = str(uuid.uuid4())
        changed = True
```
Also update `user_connections[].server_id` references during the same migration pass if any are still integer indices. External API endpoints key off `srv["id"]`; the internal UI can continue using indices for now.

**Endpoints (v1):**

| Method | Path                                 | Scope (reserved) | Purpose                                         |
| ------ | ------------------------------------ | ---------------- | ----------------------------------------------- |
| GET    | `/api/v1/ext/servers`                | servers:read     | List servers (UUID + installed protocols)       |
| POST   | `/api/v1/ext/clients`                | clients:write    | Provision client (server_id, protocol, limits)  |
| GET    | `/api/v1/ext/clients/{id}`           | clients:read     | Status + traffic counters                       |
| PATCH  | `/api/v1/ext/clients/{id}`           | clients:write    | Update expiration / traffic_limit / enabled     |
| DELETE | `/api/v1/ext/clients/{id}`           | clients:write    | Revoke                                          |

**Cut: `GET /clients/{id}/config`.** Duplicates the existing share-link mechanism. Return a share token URL from `POST /clients` and let the caller forward it.

All endpoints return JSON. Writes accept an optional `Idempotency-Key` header backed by an in-process dict:
```python
_IDEMPOTENCY: dict[str, tuple[float, int, bytes]] = {}  # key -> (expires_at, status, body)
```
TTL = 24 h, cleaned lazily on lookup. **Does not survive restarts** — documented, not stored to disk.

**Provisioning flow** for `POST /api/v1/ext/clients`: reuse `_manager_call(manager, "add_client", protocol, …)`, wrap in `asyncio.to_thread` per CLAUDE.md, persist via `save_data_async`, return the manager-generated config plus a share token URL so the caller can forward it.

**Auth dependency sketch** (the corrected shape — no KDF, constant-time, in-process rate limit):
```python
async def require_api_key(request: Request) -> dict:
    key_id = request.headers.get("X-API-Key", "")
    ts_str = request.headers.get("X-Timestamp", "")
    sig = request.headers.get("X-Signature", "")
    if not (key_id and ts_str and sig):
        raise HTTPException(401)
    try:
        ts = int(ts_str)
    except ValueError:
        raise HTTPException(401)
    if abs(time.time() - ts) > 300:
        raise HTTPException(401, "Stale timestamp")
    data = load_data()
    key = next(
        (k for k in data.get("api_keys", []) if k["id"] == key_id and not k.get("revoked")),
        None,
    )
    if not key:
        raise HTTPException(401)
    body = await request.body()
    body_hash = hashlib.sha256(body).hexdigest()
    expected = f"{ts_str}\n{request.method}\n{request.url.path}\n{body_hash}"
    expected_sig = hmac.new(key["secret"].encode(), expected.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(401)
    _check_rate_limit(key_id, request.method)   # 429 on exhaustion
    return key
```

**Admin UX:** new section in `settings.html` to mint keys. On mint, show the full secret once with a copy button; store it in `data.json` as-is (consistent with how SSH passwords are already stored — finding 10). List / revoke thereafter.

**Network exposure:**
- Default: same port as panel. Recommend TLS (already supported via `settings.ssl`).
- README integration section **must state**: treat the key as equivalent to admin credentials; IP-allowlist at the reverse proxy.
- Do **not** add a second listener — keep single-process model intact.

**Non-goals for v1:** OAuth, webhooks, pagination cursors, SDK packages, scope enforcement, config-download endpoint, disk-persisted idempotency. Ship the smallest safe surface first.

### Acceptance

- [ ] `api_keys` and `servers[].id` migrations run on existing installs, idempotent.
- [ ] HMAC verification rejects: stale ts, wrong body hash, revoked key, missing header.
- [ ] Rate limiter drops over-limit requests with `429` (60/min read, 10/min write).
- [ ] Idempotency-Key replays within 24h return the stored response; process restart resets the store (documented).
- [ ] End-to-end test (real SSH, real panel): caller provisions → reads traffic → patches expiry → deletes.
- [ ] Integration docs with a 30-line Python example caller and an explicit IP-allowlist recommendation.
- [ ] `POST /clients` 5xx path documented: "requery before retry, provisioning is not atomic with persistence."

---

## 2. Update checker — make informational, source from GitHub releases

### Current behaviour

`assets/templates/settings.html:541` runs browser-side against `api.github.com/repos/PRVTPRO/Amnezia-Web-Panel/releases/latest` and surfaces a "Download" button pointing at the GitHub release page. No server-side code involved.

### Problems

- "Download update" CTA from a self-hosted panel is misleading — Docker users don't download binaries; they pull an image.
- Browser-side GitHub API calls hit the 60 req/h unauth limit on the user's IP.
- No server-side cache means every settings page load hits GitHub.

### Review findings

1. **GHCR `tags/list` is the wrong source.** It returns a flat list of tag strings (including `latest`, `main`, SHAs). It has no `published_at`, no release notes URL, and requires client-side semver sorting. The original plan also called GitHub for notes metadata — so it was two APIs for what one API already returns. **Use GitHub releases exclusively.** GHCR publishing (item 3 step 5) is still required, just not as the version-check source.
2. **`/api/internal/version-check` violates naming convention.** No other route uses `/api/internal/`. Use `/api/version`.
3. **Dev builds break comparison.** `CURRENT_VERSION == "v0.0.0-dev"` when the package is not installed (app.py:68). Direct string comparison always shows "update available". The endpoint must short-circuit this.
4. **`functools.lru_cache` is the wrong primitive** — no TTL. Use explicit module-level cache variables.

### Target behaviour

Passive info strip in Settings:

> Running `v1.4.2`. Latest release: `v1.5.0` (2026-03-12). [release notes]

No download button. No automatic action. If up-to-date: "You're on the latest release." If dev build: "Development build; version check skipped."

### Design

Endpoint `GET /api/version` (session-authed, admin-only via `_check_admin`).

```python
_version_cache: dict | None = None
_version_cache_at: float = 0.0
_VERSION_CACHE_TTL = 3600.0

@app.get("/api/version")
async def api_version_check(request: Request):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    global _version_cache, _version_cache_at
    if _version_cache and (time.time() - _version_cache_at) < _VERSION_CACHE_TTL:
        return _version_cache
    if CURRENT_VERSION == "v0.0.0-dev":
        return {"current": CURRENT_VERSION, "dev_build": True}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                "https://api.github.com/repos/PRVTPRO/Amnezia-Web-Panel/releases/latest",
                headers={"Accept": "application/vnd.github+json"},
            )
            resp.raise_for_status()
            d = resp.json()
        _version_cache = {
            "current": CURRENT_VERSION,
            "latest": d["tag_name"],
            "released_at": d["published_at"],
            "notes_url": d["html_url"],
            "up_to_date": d["tag_name"] == CURRENT_VERSION,
        }
        _version_cache_at = time.time()
        return _version_cache
    except Exception:
        logger.debug("Version check failed", exc_info=True)
        return {"current": CURRENT_VERSION, "check_failed": True}
```

Template change in `settings.html`: remove `id="checkUpdateBtn"`, `id="downloadUpdateBtn"`, the `onclick` wiring, the `showToast` error path, and the entire `checkForUpdates()` JS block. Replace with a single `fetch('/api/version')` on `DOMContentLoaded` that renders the strip (or the dev-build / failed messages).

### Fallback

If the GitHub API fails or times out: render "Version check unavailable" in muted text and `logger.debug` once. Never block page render, never toast.

### Acceptance

- [ ] No "Download" / "Check" button in Settings.
- [ ] Version strip loads on page open without user action.
- [ ] Dev builds render "Development build; version check skipped" with no outbound call.
- [ ] Failure mode is silent (no toast, no error banner).
- [ ] Cache respected — second page load within an hour issues zero outbound HTTP.

---

## 3. Lighter multi-stage Docker image

### Current state

`Dockerfile` is already two-stage (`uv` builder → `python:3.12-slim-bookworm`). Image size is dominated by: full slim-bookworm base (~80 MB), the venv including tests and wheel metadata, and paramiko/cryptography's bundled shared libs.

### Review findings

1. **The proposed `__pycache__` cleanup is counterproductive.** `UV_COMPILE_BYTECODE=1` is set (Dockerfile:3). The `__pycache__` dirs contain pre-compiled `.pyc` files. Deleting them forces recompilation on first import in the container. **Cut this step.** Instead, strip `*.dist-info` directories (wheel metadata, several MB) and vendored `test*` directories inside site-packages — both safe.
2. **Distroless has a hard Python-version blocker.** `gcr.io/distroless/python3-debian12:nonroot` ships Python **3.11**. `pyproject.toml` requires `>=3.12`. The `:debug` tag ships newer Python but also ships busybox, defeating the security argument. Verify with `docker run --rm gcr.io/distroless/python3-debian12:nonroot python3 --version` before committing any distroless work. If 3.11, stay on `python:3.12-slim-bookworm`.
3. **cryptography/paramiko link against bundled OpenSSL, not system OpenSSL.** So the plan's concern about distroless glibc linkage is a non-issue. The real compatibility wall is the Python version.
4. **The `.dockerignore` audit is already done.** `docs/` is excluded; `screen/` is excluded (line 21); after item 4's move the `screen/` entry becomes a harmless no-op. Nothing to change there.
5. **`COPY --from=builder /app /app` brings along `pyproject.toml`, `uv.lock`, `CHANGELOG.md`, `CONTRIBUTING.md`, `LICENSE`** — small but unnecessary. Split into explicit COPY lines for `.venv/`, `src/`, and `assets/`.

### Plan (revised)

1. **Measure baseline** — `docker image ls` after a clean build; record the number in the PR description.
2. **`.dockerignore` audit** — done, no change needed. After item 4's move, optionally drop the dangling `screen/` line as cleanup.
3. **Safe venv trimming in builder** (replaces the counterproductive `__pycache__` step):
   ```dockerfile
   RUN find /app/.venv -name '*.dist-info' -type d -exec rm -rf {} + \
    && find /app/.venv/lib -type d -name 'tests' -prune -exec rm -rf {} + \
    && find /app/.venv/lib -type d -name 'test' -prune -exec rm -rf {} +
   ```
   Do **not** delete `__pycache__`.
4. **Selective COPY in final stage:**
   ```dockerfile
   COPY --from=builder --chown=app:app /app/.venv /app/.venv
   COPY --from=builder --chown=app:app /app/src /app/src
   COPY --from=builder --chown=app:app /app/assets /app/assets
   ```
   instead of `COPY --from=builder --chown=app:app /app /app`.
5. **Distroless investigation (time-boxed).** Run the Python-version check above. If 3.12 is available on a tagged distroless image, prototype on a branch and verify `import paramiko, cryptography` + healthcheck passes. Otherwise abandon distroless for this cycle.
6. **GHCR publish** — required by item 2 anyway:
   ```yaml
   - uses: docker/login-action@v3
     with:
       registry: ghcr.io
       username: ${{ github.actor }}
       password: ${{ secrets.GITHUB_TOKEN }}
   - uses: docker/build-push-action@v5
     with:
       push: true
       tags: |
         prvtpro/amnezia-panel:${{ github.ref_name }}
         ghcr.io/prvtpro/amnezia-panel:${{ github.ref_name }}
   ```
7. Alpine is not worth it here (musl wheel story for cryptography/paramiko). Skipped.

### Acceptance

- [ ] Final image size reduced vs baseline (target: ≥15% with slim-bookworm + trimming alone; ≥30% if distroless works).
- [ ] Container boots, serves `/`, passes the existing healthcheck.
- [ ] No `__pycache__` deletion in the Dockerfile.
- [ ] Final image contains only `.venv/`, `src/`, `assets/` (no `pyproject.toml`, `uv.lock`, `CHANGELOG.md`, `LICENSE`, `CONTRIBUTING.md`).
- [ ] GHCR tag is published alongside Docker Hub from the same build workflow.

---

## 4. Move `screen/` → `docs/screen/`

### Why

Project root should hold source and config, not marketing assets. `docs/` already exists.

### Review findings

1. **README URL update must be atomic with the `git mv`** — the current URLs use raw `main/screen/…` GitHub paths and will 404 the instant the move lands. Single commit, no two-step.
2. **`.dockerignore` already excludes `docs/` (line 18).** The `screen/` line on 21 becomes a harmless no-op after the move; either leave it or delete as cleanup, but no functional change is required.
3. **No other references to `screen/` exist outside README and `.dockerignore`** (confirmed by grep — no template, Python, or workflow references).

### Changes

- `git mv screen/ docs/screen/`.
- In the same commit: update `README.md` lines 20, 30, 38 from `main/screen/…` → `main/docs/screen/…`. Keep absolute URLs so images render on PyPI / GHCR / Docker Hub descriptions.
- `.dockerignore:21` — optional cleanup: drop the now-stale `screen/` entry.
- Final grep for stray `screen/` references before committing.

### Acceptance

- [ ] No `screen/` directory at repo root.
- [ ] README images still render on github.com (verify by viewing the commit on github.com after push).
- [ ] Docker build context does not include the screenshots (`docs/` is already ignored).
