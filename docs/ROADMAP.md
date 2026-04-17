# Roadmap — Non-Security Follow-ups

Scope note: these items are **not** in `RISK_AUDIT.md` because that file is scoped to security findings only. The four items below are feature / UX / ops / housekeeping work.

Order of implementation suggested: (4) screen move → (3) Docker trim → (2) update checker → (1) public API (largest). This order matters: item 2 requires item 3's GHCR publishing.

This document was updated after a design review and a product-model pivot. Findings from that review are captured inline under **Review findings** in each section. Item 1 was rewritten around a **user-lifecycle** model (one external user → many connections, subscription-driven) instead of the flat admin-CRUD surface originally sketched.

---

## 1. Public Remote API — user-lifecycle model

### Motivation

A separate product (main portal) sells premium subscriptions. Premium users get VPN access. The main portal's backend calls this panel to:

- Issue a VPN connection when a user clicks "Get VPN".
- Let the user add more connections, rotate keys, migrate to a different server (banned location), switch protocol, or buy an extra slot.
- Extend expiry when the subscription is renewed; suspend on expiry.
- Read user/connection stats for the main portal's dashboard.

The panel also keeps its existing admin UI (one admin, many users managed through the panel directly), and adds a new **Users** tab + stats page that mirror what the API exposes.

### Product shape — decisions captured

| Decision                         | Choice                                                                                   |
| -------------------------------- | ---------------------------------------------------------------------------------------- |
| User → connection cardinality    | 1 user → many connections                                                                |
| Expiry source of truth           | User-level `expires_at`; connections inherit                                             |
| Prolong                          | `PATCH /users/{id}` with absolute `expires_at` (no relative-days endpoint)               |
| On expiry                        | Suspend (disable connections, keep records); hard-delete after 90-day grace              |
| Server selection                 | Caller may specify; otherwise panel picks least-loaded within optional region hint        |
| Telegram SOCKS                   | Not in v1 (built-in Amnezia SOCKS deferred); MTProto via existing `telemt_manager.py`    |
| Webhooks                         | Per API key; HMAC-signed; in-memory retry queue                                          |
| Traffic limits                   | Per connection (main portal sets equal values if it wants a user-level cap)              |

### Review findings (from design pass on the previous draft)

1. **Argon2/PBKDF2 for API secret hashing is wrong.** KDFs block a worker thread for 100 ms–1 s per request. For an HMAC scheme with a random high-entropy secret, KDFs buy nothing. Store secrets as-is, compare with `hmac.compare_digest`.
2. **Rate limiter cannot share state with `_LOGIN_FAILURES` (app.py:1038).** Different algorithm (per-IP exponential backoff vs. per-key token bucket). Separate dicts.
3. **Idempotency storage in `data.json` is unsafe.** `save_data` (app.py:136) rewrites the whole file under `DATA_LOCK`. Persisting response bodies makes the file unbounded and serializes all writers. Keep idempotency state in-process; restart drops it (documented).
4. **`server_id` is an array index (app.py:1156), not stable.** Delete server 1 and server 2 shifts to slot 1; any cached caller now points at the wrong server silently. Introduce `servers[].id` UUID before the API ships.
5. **`POST` is not atomically idempotent with persistence.** SSH-then-save is two steps; a crash between them leaves the VPN server with a client the panel doesn't know. Document: callers must `GET` before retrying on 5xx.
6. **Scopes are over-engineered for v1.** Ship the `scopes` field in the schema for migratability; enforce only revocation in v1 code.
7. **`load_data()` per request has no cache.** Fine at current data volume (tens of KB); revisit if API load grows.
8. **SSH credentials blast radius.** SSH passwords live plaintext in `data.json` (app.py:1134). A leaked API key ≡ leaked admin password. README **must mandate** reverse-proxy IP allowlisting, not merely suggest.
9. **Scope creep risk.** "External config download endpoint" duplicates the existing share-link flow. Use share tokens; don't build a parallel path.

### Data model

Three new top-level keys in `data.json`, one FK added to an existing structure.

```json
{
  "external_users": [
    {
      "external_id": "portal_user_42",     // caller-supplied stable ID; primary key
      "label": "user@example.com",          // optional, for admin UI
      "expires_at": "2026-05-01T00:00:00Z",
      "status": "active",                   // active | expired | suspended
      "created_at": "…",
      "updated_at": "…",
      "expiring_soon_notified_at": null     // idempotency marker for webhooks
    }
  ],

  "user_connections": [
    {
      "id": "…",                            // existing
      "external_user_id": "portal_user_42", // NEW FK (nullable for legacy panel-created connections)
      "server_id": "srv_uuid",              // NEW: now a UUID from servers[].id
      "protocol": "wireguard",
      "traffic_limit": 107374182400,
      "traffic_used": 0,
      "enabled": true,
      "label": null,
      "created_at": "…"
    }
  ],

  "api_keys": [
    {
      "id": "ak_live_…",                    // public; sent in X-API-Key
      "secret": "hex64…",                   // random 32-byte hex; shown once at creation
      "scopes": ["full"],                   // reserved; v1 treats any non-revoked key as full
      "label": "main-portal prod",
      "created_at": "…",
      "revoked": false,
      "last_used_at": null,
      "webhook": {                          // per-key webhook config (finding: per-key chosen)
        "url": "https://portal.example.com/vpn-webhook",
        "secret": "hex64…",
        "events": ["user.expired", "connection.quota_exhausted", …]
      }
    }
  ]
}
```

Existing `data.users` (panel admins) is unrelated and unrenamed. `external_users` is deliberately named to avoid collision.

### Schema migrations (add to `_apply_schema_migrations`)

```python
# 1. External users table
if "external_users" not in data:
    data["external_users"] = []
    changed = True

# 2. Stable UUIDs on servers (prerequisite for the API, finding 4)
for srv in data.get("servers", []):
    if "id" not in srv:
        srv["id"] = str(uuid.uuid4())
        changed = True
    if "region" not in srv:
        srv["region"] = ""                   # free-form tag; e.g. "eu-west", "us-east"
        changed = True

# 3. API keys
if "api_keys" not in data:
    data["api_keys"] = []
    changed = True

# 4. Existing connections: external_user_id defaults to null
for conn in data.get("user_connections", []):
    conn.setdefault("external_user_id", None)
```

Internal panel UI keeps using integer indices where it already does; API endpoints key off `servers[].id` exclusively.

### Transport & auth

- New module `src/amnezia_panel/ext_api.py` exporting `APIRouter(prefix="/api/v1/ext")`. Mount on `app` after existing routes. `app.py` stays under its current size.
- Same process, same `data.json`, same SSH pipeline (`get_protocol_manager` + `_manager_call`). Never compose with `get_current_user`.

**HMAC-SHA256 signed requests.** Required headers:

| Header         | Value                                                                 |
| -------------- | --------------------------------------------------------------------- |
| `X-API-Key`    | Key ID (public part)                                                  |
| `X-Timestamp`  | Unix seconds (integer)                                                |
| `X-Signature`  | `hex(HMAC_SHA256(secret, f"{ts}\n{method}\n{path}\n{sha256(body)}"))` |

Server-side checks, in order:

1. `abs(now - ts) <= 300`.
2. Key ID resolves to a non-revoked record.
3. HMAC matches via `hmac.compare_digest`. **No KDF on the stored secret.**
4. Per-key token bucket: 60 req/min read, 10 req/min write. Module-level dict, not sharing `_LOGIN_FAILURES` state.
5. `scopes` stored but not enforced in v1.

Auth dependency sketch:

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

### API surface (v1)

All paths under `/api/v1/ext`. All JSON. All writes accept optional `Idempotency-Key` header backed by in-process dict (TTL 24 h, no disk).

**Users**

| Method | Path                         | Purpose                                                   |
| ------ | ---------------------------- | --------------------------------------------------------- |
| POST   | `/users`                     | Upsert by `external_id`. `{external_id, expires_at, label?}` |
| GET    | `/users`                     | Paginated. `?status=&expiring_before=&page=&limit=`        |
| GET    | `/users/{external_id}`       | User + connection summary                                 |
| PATCH  | `/users/{external_id}`       | `{expires_at?, label?, status?}` (absolute values)        |
| DELETE | `/users/{external_id}`       | Cascade delete all their connections                      |

**Connections** (nested under user)

| Method | Path                                                | Purpose                                                      |
| ------ | --------------------------------------------------- | ------------------------------------------------------------ |
| POST   | `/users/{external_id}/connections`                  | Issue. `{protocol, server_id?, region?, traffic_limit?, label?}`. Omitted `server_id` → panel picks. Returns `{id, config_url, server, protocol, …}` |
| GET    | `/users/{external_id}/connections`                  | List                                                         |
| GET    | `/users/{external_id}/connections/{id}`             | Detail + live stats                                          |
| PATCH  | `/users/{external_id}/connections/{id}`             | `{traffic_limit?, label?, enabled?}`                         |
| DELETE | `/users/{external_id}/connections/{id}`             | Revoke                                                       |
| POST   | `/users/{external_id}/connections/{id}/rotate`      | New keys, same server + protocol                             |
| POST   | `/users/{external_id}/connections/{id}/migrate`     | Move to different server; implicit rotate. `{server_id?, region?}` |

**Flat lookup** (for webhook consumers):

| Method | Path                  | Purpose                                       |
| ------ | --------------------- | --------------------------------------------- |
| GET    | `/connections/{id}`   | Reverse lookup; returns connection + user ref |

**Servers & stats**

| Method | Path                               | Purpose                                                            |
| ------ | ---------------------------------- | ------------------------------------------------------------------ |
| GET    | `/servers`                         | List. Returns `{id, label, region, protocols[], active_connections, reachable}` |
| GET    | `/stats/summary`                   | `{active_users, total_users, total_connections, traffic_24h_bytes, per_server[]}` |
| GET    | `/users/{external_id}/stats`       | Aggregate bytes + per-connection breakdown                          |

**Webhook management**

| Method | Path         | Purpose                                                |
| ------ | ------------ | ------------------------------------------------------ |
| PUT    | `/webhooks`  | Set `{url, secret, events[]}` on the caller's API key  |
| GET    | `/webhooks`  | Read current config                                    |
| DELETE | `/webhooks`  | Clear                                                  |

**Cut from v1** (deferred):
- Standalone config-download endpoint — returned inline as `config_url` (share token) from `POST /connections`.
- OAuth, SDK packages, cursor pagination (offset/limit is enough for expected scale).
- Scope enforcement.

### Server selection logic

When `POST /connections` omits `server_id`:

1. Filter servers where `reachable == true` and the requested `protocol` is installed.
2. If `region` is provided, filter to matching region; if empty set, fall back to any region.
3. Rank by ascending `active_connections` (simple load proxy; no bandwidth weighting in v1).
4. Break ties randomly.
5. Empty candidate set → `503` with structured error `{code: "no_server_available", region, protocol}`.

`reachable` is updated by the existing 10-min background loop (`periodic_background_tasks`). On SSH failure during scrape, mark `reachable=false` and fire `server.unreachable` webhook once per transition.

### Webhooks

**Delivery:** `POST` to the configured URL with headers `X-Webhook-Timestamp`, `X-Webhook-Signature` (`hex(HMAC_SHA256(webhook_secret, f"{ts}\n{sha256(body)}"))`), body is event JSON.

**Retries:** 3 attempts with backoff 1 s → 10 s → 60 s. Queue is an in-memory `asyncio.Queue` with a single consumer task launched from `startup()`. Failed deliveries after 3 attempts are logged; **no disk persistence in v1**. Process restart drops the queue — documented.

**Events:**

| Event                           | Fired when                                                                 |
| ------------------------------- | -------------------------------------------------------------------------- |
| `user.expiring_soon`            | `expires_at` within 7 days; fired once (idempotency via `expiring_soon_notified_at`) |
| `user.expired`                  | `expires_at` passed; user transitioned to `expired` by the sweeper          |
| `user.suspended`                | Manually set `status=suspended` via `PATCH`                                 |
| `connection.provisioned`        | Successful `POST /connections`                                              |
| `connection.rotated`            | `POST /rotate` succeeded                                                    |
| `connection.migrated`           | `POST /migrate` succeeded                                                   |
| `connection.quota_exhausted`    | Existing auto-disable path in `periodic_background_tasks`                   |
| `connection.revoked`            | `DELETE` succeeded                                                          |
| `server.unreachable`            | SSH scrape failed on a previously reachable server                          |

Payload shape (example):

```json
{
  "event": "user.expired",
  "ts": 1775472000,
  "data": {
    "external_id": "portal_user_42",
    "expired_at": "2026-05-01T00:00:00Z",
    "connections_suspended": ["conn_uuid1", "conn_uuid2"]
  }
}
```

### Expiry & suspension flow

`periodic_background_tasks()` already runs every 10 min. Extend it:

1. Walk `external_users`. For each with `status == "active"` and `expires_at <= now`:
   - Set `status = "expired"`.
   - For each of their `user_connections`: set `enabled = false`; call `_manager_call(manager, "disable_client", …)` via `asyncio.to_thread`.
   - Fire `user.expired`.
2. For each with `status == "active"` and `expires_at` within 7 days, `expiring_soon_notified_at` null:
   - Fire `user.expiring_soon`; set `expiring_soon_notified_at`.
3. For each with `status == "expired"` and `expires_at` + 90 d < now:
   - Cascade-delete user and their connections (real revoke on SSH side).
4. Extending `expires_at` via `PATCH`:
   - If old status was `expired`, re-enable all connections, reset `status = "active"`, clear `expiring_soon_notified_at`.

All state transitions go through `save_data_async` behind `DATA_LOCK`.

### Admin UI additions

New **Users** tab in the panel (separate from the existing panel-admin accounts UI):

- Table columns: `external_id` | `label` | `status` | `expires_at` | `# connections` | `total GB used` | actions.
- Filter by status / expiry / free-text search on label + external_id.
- Drill-down: connection list per user, with per-connection actions (rotate, migrate, revoke).
- Add-user and manual-extend controls for the admin who's managing users directly without going through the main portal API.

**Stats page**: totals strip (active users, total connections, 24 h traffic) + per-server load bars. Reuses `/stats/summary` endpoint internally via session auth (not HMAC).

**Settings → API Keys** section:
- Mint key: `{label}` → returns `{id, secret}` shown once with a copy button.
- List keys: id, label, created, last_used, revoke button.
- Per-key webhook block: URL, secret (generate or paste), event checkboxes, "send test event" button.

**Server row:** add `region` field (editable), shown alongside existing columns.

### Non-atomicity & caller contract

`POST /connections` is not atomically idempotent: the SSH side can succeed while the subsequent `save_data_async` fails. Documented contract:

- On HTTP 5xx from a write endpoint, the caller **must** `GET /connections/{id}` (if ID was returned) or `GET /users/{external_id}/connections` before retrying.
- `Idempotency-Key` replays the stored response body within 24 h of the first successful response; does not protect against process restart.

### Network exposure

- Same port as panel; TLS via existing `settings.ssl`.
- README integration section **must** state: treat API keys as equivalent to admin credentials; **mandatory** IP allowlisting at reverse proxy.
- No second listener.

### Acceptance

- [ ] Migrations run idempotently on existing installs: `external_users`, `servers[].id`, `servers[].region`, `api_keys`, `user_connections[].external_user_id`.
- [ ] HMAC dependency rejects: missing headers, stale `ts`, wrong body hash, revoked key.
- [ ] Rate limiter: 60/min reads, 10/min writes; 429 on exhaustion; separate state from `_LOGIN_FAILURES`.
- [ ] `Idempotency-Key` replays within 24 h; process restart clears; behavior documented.
- [ ] Server-selection fallback: empty region → any region; no match → 503 with structured error.
- [ ] Expiry sweeper: transitions `active → expired`, disables connections, fires `user.expired`; 7-day `expiring_soon` fires once; 90-day grace deletes.
- [ ] `PATCH /users` re-enables connections when extending a previously expired user.
- [ ] Webhook delivery: HMAC-signed, 3 retries with backoff, in-memory queue, no disk persistence; all 9 events listed above fire at the right trigger.
- [ ] Admin UI: Users tab with table + drill-down; API-keys section with mint/revoke; webhook config with test-send button; servers table shows `region`.
- [ ] End-to-end test (real SSH, real panel): mint key → create external user → provision connection → read stats → migrate → rotate → PATCH expiry → let expiry pass → confirm webhooks and suspension → restore.
- [ ] README integration section with a 30–40 line Python caller example and mandatory IP-allowlist guidance.

---

## 2. Update checker — make informational, source from GitHub releases

### Current behaviour

`assets/templates/settings.html:541` runs browser-side against `api.github.com/repos/PRVTPRO/Amnezia-Web-Panel/releases/latest` and surfaces a "Download" button pointing at the GitHub release page. No server-side code involved.

### Problems

- "Download update" CTA from a self-hosted panel is misleading — Docker users don't download binaries; they pull an image.
- Browser-side GitHub API calls hit the 60 req/h unauth limit on the user's IP.
- No server-side cache means every settings page load hits GitHub.

### Review findings

1. **GHCR `tags/list` is the wrong source.** Flat list of tag strings, no `published_at`, no notes URL, requires client-side semver sorting. Use GitHub releases exclusively. GHCR publishing (item 3 step 5) is still required for the image registry, just not as the version-check source.
2. **`/api/internal/version-check` violates naming convention.** Rename to `/api/version`.
3. **Dev builds break comparison.** `CURRENT_VERSION == "v0.0.0-dev"` (app.py:68) always reports "update available" against any real tag. Short-circuit it.
4. **`functools.lru_cache` has no TTL.** Use explicit module-level cache variables.

### Design

Endpoint `GET /api/version` (session-authed; admin-only via `_check_admin`).

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

GitHub API fails or times out → "Version check unavailable" in muted text; `logger.debug` once. Never block page render, never toast.

### Acceptance

- [ ] No "Download" / "Check" button in Settings.
- [ ] Version strip loads on page open without user action.
- [ ] Dev builds render "Development build; version check skipped" with no outbound call.
- [ ] Failure mode silent (no toast, no error banner).
- [ ] Cache respected — second page load within an hour issues zero outbound HTTP.

---

## 3. Lighter multi-stage Docker image

### Current state

`Dockerfile` is already two-stage (`uv` builder → `python:3.12-slim-bookworm`). Image size is dominated by: slim-bookworm base (~80 MB), the venv including tests and wheel metadata, and paramiko/cryptography's bundled shared libs.

### Review findings

1. **Proposed `__pycache__` cleanup is counterproductive.** `UV_COMPILE_BYTECODE=1` is set (Dockerfile:3). `__pycache__` dirs contain pre-compiled `.pyc`. Deleting them forces recompilation at container start. Cut this step. Strip `*.dist-info` and vendored `test*` directories instead — both safe.
2. **Distroless has a Python-version blocker.** `gcr.io/distroless/python3-debian12:nonroot` ships Python 3.11; `pyproject.toml` requires `>=3.12`. `:debug` tag has newer Python but also busybox, defeating the security argument. Verify before committing: `docker run --rm gcr.io/distroless/python3-debian12:nonroot python3 --version`. If 3.11, stay on `python:3.12-slim-bookworm`.
3. **cryptography/paramiko link against bundled OpenSSL**, not system OpenSSL. Plan's concern about distroless glibc linkage is a non-issue; the real wall is the Python version.
4. **`.dockerignore` audit already correct.** `docs/` excluded; `screen/` excluded (line 21). After item 4's move, the `screen/` line becomes a harmless no-op.
5. **`COPY --from=builder /app /app` brings `pyproject.toml`, `uv.lock`, `CHANGELOG.md`, `CONTRIBUTING.md`, `LICENSE`** into the final image. Split into explicit COPY lines for `.venv/`, `src/`, `assets/`.

### Plan (revised)

1. Measure baseline with `docker image ls` after a clean build; record in the PR description.
2. `.dockerignore` audit — done. Optionally drop dangling `screen/` line post-item-4.
3. Safe venv trimming in builder:
   ```dockerfile
   RUN find /app/.venv -name '*.dist-info' -type d -exec rm -rf {} + \
    && find /app/.venv/lib -type d -name 'tests' -prune -exec rm -rf {} + \
    && find /app/.venv/lib -type d -name 'test' -prune -exec rm -rf {} +
   ```
   **No** `__pycache__` deletion.
4. Selective COPY in the final stage:
   ```dockerfile
   COPY --from=builder --chown=app:app /app/.venv /app/.venv
   COPY --from=builder --chown=app:app /app/src /app/src
   COPY --from=builder --chown=app:app /app/assets /app/assets
   ```
   Replace the current `COPY --from=builder --chown=app:app /app /app`.
5. Distroless investigation — time-boxed. Run the Python-version check above. If 3.12 is available on a tagged distroless image, prototype on a branch and verify `import paramiko, cryptography` + healthcheck passes. Otherwise abandon for this cycle.
6. GHCR publish — required by item 2 anyway:
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
7. Alpine — skipped (musl wheel story for cryptography/paramiko).

### Acceptance

- [ ] Final image reduced vs baseline (target: ≥15% with slim-bookworm + trimming; ≥30% if distroless works).
- [ ] Container boots, serves `/`, passes existing healthcheck.
- [ ] No `__pycache__` deletion in the Dockerfile.
- [ ] Final image contains only `.venv/`, `src/`, `assets/`.
- [ ] GHCR tag published alongside Docker Hub from the same build workflow.

---

## 4. Move `screen/` → `docs/screen/`

### Why

Project root should hold source and config, not marketing assets. `docs/` already exists.

### Review findings

1. **README URL update must be atomic with the `git mv`.** Current URLs are raw `main/screen/…` GitHub paths; they 404 the instant the move lands. Single commit.
2. **`.dockerignore` already excludes `docs/` (line 18).** The `screen/` line on 21 becomes a no-op post-move; either leave or remove as cleanup.
3. **No other references to `screen/`** exist outside README and `.dockerignore` (confirmed by grep).

### Changes

- `git mv screen/ docs/screen/`.
- Same commit: update `README.md` lines 20, 30, 38 from `main/screen/…` → `main/docs/screen/…`. Keep absolute URLs.
- `.dockerignore:21` — optional cleanup: drop the stale `screen/` entry.
- Final grep for stray `screen/` references before committing.

### Acceptance

- [ ] No `screen/` directory at repo root.
- [ ] README images still render on github.com (verify on the commit view after push).
- [ ] Docker build context does not include screenshots (`docs/` already ignored).
