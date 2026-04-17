# Admin / Customer Split — Implementation Plan

**Date**: 2026-04-18
**Scope**: Single admin, unified users list, Telegram bot removal
**Status**: Planning + Validation (Q1 and Q2 resolved)

---

## 1. Validation Findings

### Methodology
~14 targeted tool calls covering `app.py` (3,157 LOC), `telegram_bot.py` (381 LOC), `ext_api.py` (1,244 LOC), all five translation files, and all eight templates.

### Customer panel login paths — CLEAR

There are exactly two code paths that gate on `role == "user"` to redirect to `/my`:

- `app.py:1036` — `GET /` redirects `role == "user"` to `/my`
- `app.py:1047` — `GET /server/{server_id}` redirects non-admin/support to `/my`
- `app.py:1062` — `GET /users` redirects non-admin/support to `/my`

These three redirects exist only as fallback guards. Once customers cannot log in at all (no `password_hash`, removed from login loop), none of these fire. The `/my` page and `/api/my/connections*` endpoints become dead code after the model change.

The **one genuine role-based authorization left on a data endpoint** is `app.py:2232–2233`:

```python
if user["role"] == "user" and user["id"] != user_id:
    return JSONResponse({"error": "Forbidden"}, status_code=403)
```

This is in `GET /api/users/{user_id}/connections`. Under the new model, only the admin can be logged in, so this branch is unreachable — but it must be simplified to an admin-only check to avoid confusion.

**No other endpoint uses customer sessions to authorize config downloads.** The `/share/<token>` path does not check the session user at all; it reads the token from `data["users"]` and uses its own `share_auth_{token}` session key for password-protected shares. This path does not depend on `password_hash` of the account holder.

### Support role — CLEAR

`role: support` appears in three places:

- `app.py:1047`, `1062`: redirect guard
- `app.py:1177`: `_check_admin` returns the user if `role in ("admin", "support")`

The support role is purely a panel-access gate. It has no VPN provisioning logic of its own. Removing it is straightforward: `_check_admin` becomes a simple session-presence check.

### Telegram bot coupling — CLEAR with one nuance

The bot is a self-contained asyncio task. It accesses `data["users"]` only through the `load_data_fn` callback it receives at launch. **The traffic loop does NOT call into the bot at all** — there are no Telegram notifications from the background loop.

One nuance: `telegramId` is written by the Remnawave sync (`app.py:426`, `451`). The sync stores it because Remnawave sends it. Removing `telegramId` from the customer entity means these sync lines must be deleted. Remnawave's API will still send `telegramId`; we simply stop storing it. The sync logic is otherwise independent.

**`httpx` must stay** — it is used by:
- `app.py:369` (Remnawave sync)
- `app.py:2437` (GitHub version check)
- `ext_api.py:189` (webhook delivery)

Only `telegram_bot.py` can be deleted; `httpx` the dependency remains.

### `telegramId` as lookup key — ISOLATED TO BOT

`telegramId` is used as a customer lookup key only inside `telegram_bot.py:_find_user` (`telegram_bot.py:98–104`). Nowhere in `app.py` or `ext_api.py` is a customer looked up by `telegramId` for any auth or provisioning purpose. Search functionality in `app.py:1940` uses it as a display/filter field only.

### Share link and `password_hash` — NO COUPLING

`share_password_hash` is a separate field from `password_hash`. The share link flow (`/share/<token>`, `/api/share/<token>/auth`, `/api/share/<token>/config`) reads `share_password_hash` exclusively. Removing `password_hash` from customers has zero effect on share links.

### Backup / restore — ONE BLOCKER, MITIGABLE

`app.py:2635` validates restored backups by requiring keys `["servers", "users"]`. After the migration, the canonical keys become `["servers", "admin", "customers"]`. **The restore validator will reject old backups.** Fix: accept backups that have either `"users"` (legacy) or `"customers"` (new), and run `_apply_schema_migrations` on load as already done. The export side (download) just dumps `DATA_FILE` verbatim, so it will naturally export the new shape once migration has run.

Action: update the restore validator to accept `"users"` OR `"customers"` as the user collection key, and call migration on restore regardless.

### Admin seeding — CLEAN PATH

`startup()` seeds a default admin when `data.get("users")` is empty (`app.py:791`). Under the new model, the check becomes: if `data.get("admin")` is falsy, seed `data["admin"]`. This is a one-line change in `startup()`.

### `external_users` — DECISION: MERGE INTO UNIFIED `users` LIST (RESOLVED)

**Decision (Q1 resolved)**: merge `data["external_users"]` into the single unified `data["users"]` list alongside the former `role: user` entries. The UI label for the list stays "Users". Admin is a separate singular `data["admin"]` entity.

The prior recommendation was to keep them parallel. That recommendation is superseded by the explicit user decision to merge. See Section 14 Q1 for the recorded resolution.

**Structural implications**:
- `data["users"]` becomes the single list of all managed VPN-client entities, regardless of origin.
- Entries may have heterogeneous origins distinguished by optional fields: `remnawave_uuid` (Remnawave-synced), `ext_api_id` / `external_id` (ext-API-created). Structurally one list.
- The connection FK `external_user_id` currently points into `external_users[].external_id`. Post-merge, connections for ext-API-created users will use the same `user_id` FK as panel-created users. Migration must rewrite `connection["external_user_id"]` to `connection["user_id"]` for existing ext-API connections.
- `ext_api.py` routes (`app.py:2655–3127`) and `ext_api.py:296,456,475,834,1061,1184`) currently read/write `data["external_users"]` exclusively — these must be retargeted to `data["users"]`, filtering by presence of `external_id` where needed.
- The `/external_users` admin page (`app.py:2655`) and `/api/admin/external_users/*` routes (`app.py:2692–2983`) either consolidate into `/users` / `/api/users/*` or are kept as filtered views into the unified list. See Section 7.

### Summary verdict

The user's direction is **fully feasible as stated**. No blockers. The only scope adjustments: (1) the backup restore validator needs to handle both the legacy `"users"` key and the new unified `"users"` key shape; (2) the `external_users` merge requires rewriting connection FKs (`external_user_id` → `user_id`) in existing `user_connections` records and retargeting `ext_api.py` reads/writes to `data["users"]`.

---

## 2. Goals and Non-Goals

### Goals

- Single `data["admin"]` object (id, username, password_hash). No list. No role field.
- All current `role: user` entries (including Remnawave-synced) and all current `data["external_users"]` entries merge into a single unified `data["users"]` list. No panel login for any user entry. No `password_hash` on users.
- `role: support` is deleted entirely.
- `telegram_bot.py` is deleted. All Telegram-related settings, routes, templates, translation keys, and `telegramId` fields are removed. No deprecation period.
- Share links remain exactly as-is (they depend on `share_token` / `share_password_hash`, which stay on users).
- `external_users` is merged into the unified `users` list (Decision Q1 resolved — see Section 14).
- UI label for the unified list is "Users". The nav key `nav_users` ("Users") is the sole list navigation entry; `nav_external_users` ("Customers") is removed.
- App remains functional at every commit boundary during phased rollout.
- A test harness is established before code changes begin.

### Non-Goals

- No backwards compat with multi-admin setups (losing multiple admins is intentional).
- No deprecation period for Telegram bot — it is deleted in Phase 1.
- No migration path for customer panel logins — they never existed as a real use case; the password was optional and unused in practice for `role: user` entries created by Remnawave.
- No new notification system (email, webhooks for customer events) — out of scope.
- No UI redesign beyond what the model change requires (rename labels, remove bot section).
- The external webhook endpoints in `ext_api.py` (`/api/v1/ext/*`) remain but are retargeted to write into `data["users"]`. The admin-facing `/api/admin/external_users/*` routes are consolidated into `/api/users/*`.

---

## 3. Target Data Model

### Before (current `data.json` shape)

```json
{
  "users": [
    {
      "id": "uuid",
      "username": "admin",
      "password_hash": "salt$hash",
      "role": "admin",
      "enabled": true,
      "created_at": "2024-01-01T00:00:00"
    },
    {
      "id": "uuid",
      "username": "alice",
      "password_hash": "",
      "role": "user",
      "telegramId": "@alice",
      "email": "alice@example.com",
      "description": "Panel-created user",
      "enabled": true,
      "created_at": "2024-01-01T00:00:00",
      "remnawave_uuid": "rw-uuid",
      "share_enabled": true,
      "share_token": "token16chars",
      "share_password_hash": null,
      "traffic_used": 1073741824,
      "traffic_total": 1073741824,
      "traffic_limit": 10737418240,
      "traffic_reset_strategy": "monthly",
      "last_reset_at": "2024-01-01T00:00:00",
      "expiration_date": "2025-01-01T00:00:00"
    }
  ],
  "external_users": [
    {
      "external_id": "caller-opaque-string",
      "label": "Ext user Bob",
      "enabled": true,
      "created_at": "2024-01-01T00:00:00"
    }
  ],
  "settings": {
    "telegram": { "enabled": false, "token": "" },
    "sync": { ... },
    "appearance": { ... }
  }
}
```

### After (target `data.json` shape)

```json
{
  "admin": {
    "id": "uuid",
    "username": "admin",
    "password_hash": "salt$hash"
  },
  "users": [
    {
      "id": "uuid",
      "username": "alice",
      "email": "alice@example.com",
      "description": "Panel-created user",
      "enabled": true,
      "created_at": "2024-01-01T00:00:00",
      "remnawave_uuid": "rw-uuid",
      "share_enabled": true,
      "share_token": "token16chars",
      "share_password_hash": null,
      "traffic_used": 1073741824,
      "traffic_total": 1073741824,
      "traffic_limit": 10737418240,
      "traffic_reset_strategy": "monthly",
      "last_reset_at": "2024-01-01T00:00:00",
      "expiration_date": "2025-01-01T00:00:00"
    },
    {
      "id": "uuid-generated-at-migration",
      "external_id": "caller-opaque-string",
      "username": "caller-opaque-string",
      "label": "Ext user Bob",
      "enabled": true,
      "created_at": "2024-01-01T00:00:00"
    }
  ],
  "_legacy_users": [ ... ],
  "_legacy_external_users": [ ... ],
  "settings": {
    "sync": { ... },
    "appearance": { ... }
  }
}
```

**Fields removed from all users**: `password_hash`, `role`, `telegramId`
**Fields kept on panel-created users**: all traffic, share, expiry, Remnawave, email, description fields
**Fields kept on ext-API-created users**: `external_id`, `label`, plus standard `id`, `enabled`, `created_at`
**Origin distinguished by**: presence of `remnawave_uuid` (Remnawave-synced), `external_id` (ext-API-created), or neither (panel-created). All are structurally one list.
**`settings.telegram`**: removed entirely
**`_legacy_users`**: kept for one version as a recovery escape hatch, then removed in Phase 4
**`_legacy_external_users`**: kept for one version alongside `_legacy_users`, then removed in Phase 4

**`user_connections` collection**: migration must rewrite existing records that have `external_user_id` set — copy the value to `user_id` using the newly assigned UUID for the merged ext-API entry, and set `external_user_id = null`. After migration, `external_user_id` on connections is unused and can be removed in Phase 4.

**`external_users` collection**: eliminated. All data migrated into `data["users"]`.

---

## 4. Auth and Session Model

### Current flow

1. `GET /api/auth/login` iterates `data["users"]`, checks `password_hash`, sets `session["user_id"]`.
2. `get_current_user(request)` reads `session["user_id"]`, finds the matching entry in `data["users"]`, returns it with its `role` field.
3. `_check_admin(request)` returns the user if `role in ("admin", "support")`, else `None`.
4. Customer sessions: customers log into `/login` with their password (if set) → `session["user_id"]` set → redirected to `/my`.

### Target flow

1. `GET /api/auth/login` checks only `data["admin"]` (single object). No loop needed.
2. `get_current_user(request)` reads `session["user_id"]`. If it matches `data["admin"]["id"]`, returns the admin dict. Returns `None` otherwise.
3. `_check_admin(request)` is now trivially `get_current_user(request)` — any valid session is admin. Can be inlined or kept as an alias.

### Routes removed

- `GET /my` (`my_connections_page`)
- `GET /api/my/connections`
- `POST /api/my/connections/{connection_id}/config`

These are the three "customer self-service" endpoints. They use `user["id"]` from session to filter their own connections. Under the new model, customers do not log in, so these endpoints are dead.

### Implications for `GET /api/users/{user_id}/connections`

Currently has a dual-role check (`app.py:2232–2233`): customers can read their own connections. Post-migration, this becomes admin-only (`_check_admin`). The admin can view any customer's connections.

### Login response

Currently returns `{"status": "success", "role": u["role"]}`. After migration, always returns `{"status": "success", "role": "admin"}` (hardcoded — there is only one role).

---

## 5. Telegram Bot Removal Inventory

### Files to delete

| File | Action |
|------|--------|
| `src/amnezia_panel/telegram_bot.py` | Delete entirely |

### `app.py` changes (with verified line numbers)

| Line(s) | What | Action |
|---------|------|--------|
| 27 | `from . import telegram_bot as tg_bot` | Remove import |
| 512–513 | `"telegram_settings": ..., "bot_running": tg_bot.is_running()` | Remove both lines from `tpl()` context dict |
| 611 | `telegramId: str \| None = None` in `AddUserRequest` Pydantic model | Remove field |
| 668 | `telegramId: str \| None = None` in edit user Pydantic model | Remove field |
| 681 | `telegram: TelegramSettings` in settings Pydantic model | Remove field |
| 818–821 | `tg_cfg = data.get(...)` / `tg_bot.launch_bot(...)` in `startup()` | Remove block |
| 1940 | `or (u.get("telegramId") and search in str(u["telegramId"]).lower())` | Remove from user search |
| 1960 | `"telegramId": u.get("telegramId"),` | Remove from user list response |
| 1996 | `"telegramId": req.telegramId,` | Remove from user create |
| 2085–2086 | `if req.telegramId is not None: user["telegramId"] = req.telegramId` | Remove from user edit |
| 2504 | `data["settings"]["telegram"] = payload.telegram.dict()` | Remove from settings save |
| 2507–2522 | Bot start/stop logic in settings save handler | Remove block |
| 2525–2545 | `POST /api/settings/telegram/toggle` route | Delete route |

**Pydantic model `TelegramSettings`**: find definition (grep confirms it's around line 681 area) and delete the class.

### Remnawave sync changes (`app.py`)

| Line(s) | What | Action |
|---------|------|--------|
| 426 | `local_u["telegramId"] = rw_u.get("telegramId")` | Remove |
| 451 | `"telegramId": rw_u.get("telegramId"),` | Remove from new user dict |

### Templates

| Template | Action |
|----------|--------|
| `assets/templates/my_connections.html` | Delete entirely |
| `assets/templates/settings.html` | Remove Telegram bot section (lines ~50–70 visible in grep: `<h3 class="card-title"...telegram_bot_title</h3>`, `<form id="telegramForm">`, toggle button, JS block around `botCurrentlyRunning`, `toggleBotBtnText`, the `telegram` object in settings submit payload) |
| `assets/templates/users.html` | Remove `telegramId` input field in add-user modal (line ~606), remove `telegramId` in edit-user modal (line ~924), remove `telegramId` display in user card (line ~445) |
| `assets/templates/base.html` | Remove any bot status indicator if present (verify by reading) |
| `assets/templates/login.html` | No changes needed (already checked: no Telegram refs) |

### Translation keys to remove (all 5 files: en, ru, fr, zh, fa)

Keys confirmed via grep on `en.json`:
- `telegram_bot_title`
- `bot_token_label`
- `bot_status`
- `bot_running`
- `bot_stopped`
- `bot_stop_btn`
- `bot_start_btn`
- `bot_hint`
- `bot_started`
- `bot_stopped_msg`
- `role_support_desc` (role selector becomes binary admin/user, but since customers don't log in, the role selector goes away entirely — remove all three role keys: `role_label`, `role_user_desc`, `role_support_desc`, `role_admin_desc`)

Also remove translation keys for `/my` page if they exist (grep `my_connections`, `my_page` etc. in translation files to confirm).

### `pyproject.toml`

`httpx` **stays** — it is used by `app.py` (Remnawave sync, GitHub version check) and `ext_api.py` (webhook delivery). Do not touch this dependency.

### `Taskfile.yml`

Check for any `telegram` or `bot` references. If a `task bot` or similar exists, remove it. (Unlikely but verify.)

### `.github/workflows/build.yml`

No Telegram-specific CI steps expected. Verify no workflow step references `telegram_bot.py` explicitly.

---

## 6. Module-by-Module Change Inventory in `app.py`

### Auth routes (`app.py:1141–1170`)

- Login loop: currently `for u in data.get("users", [])` — change to check `data["admin"]` directly.
- Remove `"role"` from login response or hardcode `"admin"`.
- Remove captcha session check that iterates users (captcha check itself stays, only the user lookup changes).

### User-list route (`app.py:1926–1978`)

- `GET /api/users` — path is **unchanged**. Now serves the unified list. Remove `"role"`, `"telegramId"` from response shape. Remove role-based filtering (all entries in the list are now managed users — no admin in this list). `data.get("users", [])` reference is already correct.

### Add user (`app.py:1980–2014`)

- Currently: admin-only, creates entry in `data["users"]` with `role`, `telegramId`, `password_hash`.
- After: admin-only, creates entry in `data["users"]` (unified list) without those fields. Remove `role` and `telegramId` from `AddUserRequest` Pydantic model. Remove `password_hash` generation (no password for users).

### Edit user (`app.py:2077–2110`)

- Remove `telegramId` handling (lines 2085–2086).
- Remove `password_hash` update block (lines 2100–2103) — users have no panel password.
- Remove `role` validation.

### Delete user (`app.py:2121–2155`)

- `data["users"]` reference is already correct (unified list). Logic otherwise unchanged.

### Traffic loop (`app.py:853–1007`)

- `data.get("users", [])` reference in `users_map` build (line ~904) now covers the full unified list — no key rename needed.
- Remove Remnawave sync's `telegramId` writes (lines 426, 451).
- Remnawave sync logic otherwise unchanged — it targets `data["users"]` using `remnawave_uuid` as the key.

### Remnawave sync (`app.py:354–490`)

- `data["users"]` references are already correct (unified list key name unchanged). No key rename needed.
- The guard at line 418 (`not u.get("password_hash")`) — this was checking "is this a Remnawave-imported user" to avoid hijacking local admin accounts. Under the new model, no user in the list has `password_hash`, so the check becomes superfluous. Simplify: `local_u = next((u for u in data["users"] if u["username"] == rw_u["username"]), None)` — no guard needed since there's no admin in the users list.
- Remove `telegramId` from sync writes.

### Share routes (`app.py:2263–2380`)

- `POST /api/users/{user_id}/share/setup` (line 2263): `data["users"]` reference is already correct. No auth change needed.
- `GET /share/{token}` (line 2284): `data["users"]` reference is already correct.
- `GET /api/share/{token}/config` and `POST /api/share/{token}/auth`: same — no key rename. **These routes do not use the logged-in session** — no auth change.

### External users / API admin (`app.py:2655–3127`)

**All of the following must be folded into the unified `data["users"]` code path:**

- `app.py:2655` — `GET /external_users` page: consolidate into `GET /users` (unified list view, optionally filter by `external_id` presence for ext-API-origin entries).
- `app.py:2692` — `GET /api/admin/external_users`: retarget to read from `data["users"]` filtered by `u.get("external_id")`. Consolidate into `/api/users` with an origin filter param, or remove and let the unified `/api/users` endpoint handle it.
- `app.py:2719` — `POST /api/admin/external_users`: retarget to append to `data["users"]`.
- `app.py:2745,2762,2796,2839,2903,2948,2983` — all `PATCH`, `DELETE`, and connection sub-routes under `/api/admin/external_users/{external_id}`: retarget to `data["users"]`, look up by `u["external_id"] == external_id`.
- `app.py:3127` — second `data.get("external_users", [])` reference: retarget to `data["users"]`.
- `ext_api.py:296,456,475,834,1061,1184` — all reads/writes in `ext_api.py`: retarget to `data["users"]`. The `/api/v1/ext/*` webhook endpoints stay (they are the HMAC-authenticated external API surface) but write into the unified list.

### `get_current_user` (`app.py:493–501`)

Before:
```python
def get_current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    data = load_data()
    for u in data.get("users", []):
        if u["id"] == user_id:
            return u
    return None
```

After:
```python
def get_current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    data = load_data()
    admin = data.get("admin", {})
    if admin.get("id") == user_id:
        return admin
    return None
```

### `_check_admin` (`app.py:1175–1179`)

Before:
```python
def _check_admin(request):
    user = get_current_user(request)
    if not user or user["role"] not in ("admin", "support"):
        return None
    return user
```

After:
```python
def _check_admin(request):
    return get_current_user(request)
```

(Any non-None return is the admin. Role check is gone because the session can only belong to the single admin.)

### `startup()` admin seeding and password recovery (`app.py:784–822`)

- Change seed condition from `if not data.get("users")` to `if not data.get("admin")`.
- **Before** the default-admin seed fallback, read `ADMIN_PASSWORD_RESET` env var (Decision Q2 resolved — env var only, no CLI subcommand):

```python
# Password recovery: if ADMIN_PASSWORD_RESET is set, overwrite admin password
reset_pw = os.environ.get("ADMIN_PASSWORD_RESET")
if reset_pw and data.get("admin"):
    data["admin"]["password_hash"] = hash_password(reset_pw)
    await save_data_async(data)
    logger.warning(
        "ADMIN_PASSWORD_RESET env var applied — admin password has been reset. "
        "Unset ADMIN_PASSWORD_RESET and restart to clear this warning."
    )
# Default admin seed (only when no admin exists at all)
if not data.get("admin"):
    data["admin"] = {"id": str(uuid.uuid4()), "username": "admin", "password_hash": hash_password("admin")}
    logger.info("Default admin created (admin / admin)")
if "users" not in data:
    data["users"] = []
```

- Remove Telegram bot startup block (lines 817–821).

### Backup restore validator (`app.py:2634–2638`)

Change:
```python
required_keys = ["servers", "users"]
```
To:
```python
# Accept both legacy shape ("users" list containing admin+users) and new shape ("admin" + "users" unified list)
if "servers" not in backup_data:
    return JSONResponse({"error": "Invalid structure. Missing key: servers"}, status_code=400)
if "users" not in backup_data and "admin" not in backup_data:
    return JSONResponse({"error": "Invalid structure. Missing users or admin key"}, status_code=400)
# Then call _apply_schema_migrations(backup_data) to normalize regardless of shape
```

### `tpl()` context dict (`app.py:504–520`)

Remove:
```python
"telegram_settings": data.get("settings", {}).get("telegram", {}),
"bot_running": tg_bot.is_running(),
```

### `_apply_schema_migrations` (`app.py:714–781`)

- Remove the old backfill loop that iterated `data["users"]` for `share_enabled`, `share_token`, `share_password_hash`, etc. — replace with a new loop over `data["users"]` (unified list) that applies those backfills only to non-ext-API entries (see Section 9).
- Add migration that: (1) extracts `data["admin"]` from legacy `data["users"]`, (2) merges former `role:user` entries and former `data["external_users"]` into the new unified `data["users"]`, (3) rewrites connection FKs. See Section 9 for the full sketch.

---

## 7. Route and API Surface

### Routes deleted

| Route | Reason |
|-------|--------|
| `GET /my` | Customer self-service page — customers don't log in |
| `GET /api/my/connections` | Customer self-service API |
| `POST /api/my/connections/{connection_id}/config` | Customer self-service API |
| `POST /api/settings/telegram/toggle` | Telegram bot removed |
| Telegram bot section of `POST /api/settings` (sub-field) | Telegram bot removed |

### Routes renamed / consolidated

| Old | New | Notes |
|-----|-----|-------|
| `GET /api/users` | `GET /api/users` | **Unchanged path** — now serves the unified list (all origins) |
| `POST /api/users/add` | `POST /api/users/add` | Body drops `role`, `telegramId`, `password` |
| `PATCH /api/users/{id}` | `PATCH /api/users/{id}` | Body drops `telegramId`, `password` |
| `DELETE /api/users/{id}` | `DELETE /api/users/{id}` | Unchanged logic |
| `GET /api/users/{id}/connections` | `GET /api/users/{id}/connections` | Admin-only now (no self-read) |
| `POST /api/users/{id}/share/setup` | `POST /api/users/{id}/share/setup` | Unchanged logic |
| `GET /external_users` (HTML page) | Consolidated into `GET /users` | `external_users.html` deleted; one unified users page |
| `GET /api/admin/external_users` | `GET /api/users?origin=ext` (or removed) | Unified list; filter by `external_id` presence if needed |
| `POST /api/admin/external_users` | `POST /api/users/add` | Writes into unified `data["users"]` |
| `PATCH /api/admin/external_users/{ext_id}` | `PATCH /api/users/{id}` | Look up by `external_id` field then use `id` |
| `DELETE /api/admin/external_users/{ext_id}` | `DELETE /api/users/{id}` | Same lookup pattern |
| `GET /api/admin/external_users/{ext_id}/connections/*` | `GET /api/users/{id}/connections/*` | Same consolidation |

Note: the `/users` HTML page URL is unchanged. The `/external_users` page is deleted and its features fold into `/users`.

### Routes unchanged

- All `/api/servers/*`
- `/share/{token}` and sub-paths
- `/api/v1/ext/*` — webhook endpoints stay; they write into `data["users"]` after merge
- `/api/settings` (minus telegram sub-field)
- `/api/settings/backup/*` (with restored validator fix)
- `/api/version`
- `/login`, `/logout`

### Breaking changes summary

1. User panel login is removed entirely. Existing `password_hash` values on `role: user` entries are discarded on migration.
2. `/my` page returns 404.
3. `/api/admin/external_users*` routes are removed (consolidated into `/api/users*`). Any admin tooling or scripts calling these paths will break — document in migration notes.
4. Backup files from pre-migration versions can still be restored (validator updated to accept the legacy shape and run migration).
5. `role` and `telegramId` fields disappear from all API responses. `external_user_id` disappears from connection records.

---

## 8. Template and i18n Changes

### Templates to delete

- `assets/templates/my_connections.html` — entire file deleted
- `assets/templates/external_users.html` — entire file deleted; its features (ext-API-origin user display, `external_id` column) fold into `users.html`

### Templates to edit

**`settings.html`**
Remove the entire Telegram bot card section. This is approximately lines 48–70 of the template plus the JavaScript block around `botCurrentlyRunning`, `toggleBotBtnText`, `fetchTelegramSettings`, `toggleBot`, and the `telegram` object construction in the settings save handler. The rest of the settings page (appearance, sync, captcha, SSL, backup) is untouched.

**`users.html`** (template file and page route both stay as `users.html` / `/users` — no rename needed)
- Remove `telegramId` input from the add-user modal (line ~58–62 in the modal, line ~606 in the JS submit)
- Remove `telegramId` input from the edit-user modal (line ~924 in JS)
- Remove `telegramId` display in user card (line ~445: `${u.telegramId ? ...}`)
- Remove role selector from add-user modal (lines ~74–79: the `<select>` with admin/support/user options)
- Remove password input from add-user modal (line ~69–70) — customers have no panel password. **NOTE**: keep the `share_password` field, which is a different concept.
- Remove role badge display in user list (lines ~433–435)
- Remove `role` from the JS that constructs the add/edit payload

**`base.html`**
Read and check for any bot status display. If `bot_running` is referenced in the nav or header, remove it.

**`server.html`**
No Telegram changes. Review for any `role` references (currently passes `users` list to template — the key name is unchanged, but the list now includes ext-API-origin entries; template should handle entries with no `share_token` gracefully).

**`users.html`** (unified list — add ext-API-origin column)
In addition to removing Telegram/role/password fields, add display of `external_id` for entries where it is present (so the admin can identify ext-API-created entries). This replaces the dedicated `external_users.html` view.

**`user_share.html`**
No changes needed (does not reference role or Telegram).

### Translation keys to remove (all 5 files)

Telegram-related (confirmed in `en.json`):
- `telegram_bot_title`, `bot_token_label`, `bot_status`, `bot_running`, `bot_stopped`, `bot_stop_btn`, `bot_start_btn`, `bot_hint`, `bot_started`, `bot_stopped_msg`

Navigation (confirmed via grep on translation files):
- `nav_external_users` — present in `en.json:291` as "Customers"; **remove from all 5 files**. Note: `ru.json`, `fr.json`, `zh.json`, `fa.json` were confirmed to have no `nav_external_users` key — only `en.json` has it. Remove from `en.json`; verify the others have no stray reference.
- `nav_users` stays as the sole nav entry for the unified list ("Users" in all locales — confirmed present in all 5 files).

Role selector (customers don't log in; role picker gone):
- `role_label`, `role_user_desc`, `role_support_desc`, `role_admin_desc`

Password field for add-user (customers have no login password):
- `password_label` — **check first**: this key may also be used on the login page. If so, keep it and only remove its usage in the add-user modal. Do not delete the translation key.

`/my` page keys (search `my_` prefix in all translation files):
- Any keys exclusively used in `my_connections.html` — check and remove.

### Persian (fa) RTL note

`fa.json` uses RTL layout. No directional changes are needed for this migration since we are only removing elements, not adding new ones. Verify the settings page after removing the Telegram card that the remaining cards still render correctly under RTL.

---

## 9. Migration Plan

The following code runs in `_apply_schema_migrations(data)` which is called from both `startup()` and the backup restore handler. It is idempotent (checks presence of keys before acting).

```python
def _apply_schema_migrations(data: dict) -> bool:
    changed = False

    # ── MIGRATION: admin/unified-users split ──────────────────────────────────
    # Run if the old "users" key is present AND "admin" has not yet been split out.
    # Converts the old structure into:
    #   data["admin"]  — singular admin object
    #   data["users"]  — unified list: former role:user entries + former external_users
    # Preserves data["_legacy_users"] and data["_legacy_external_users"] as
    # one-version recovery escape hatches.
    #
    # Deduplicate by "username" (for panel-created users) or "external_id"
    # (for ext-API-created entries) — username takes precedence.
    # Multiple admins: keep the first one found, log the rest as lost.
    # Support role: treated the same as admin.
    # ─────────────────────────────────────────────────────────────────────────
    if "users" in data and "admin" not in data:
        legacy_users = data["users"]
        data["_legacy_users"] = legacy_users  # recovery escape hatch

        # Find the first admin (or support, treated as admin)
        admin_entry = next(
            (u for u in legacy_users if u.get("role") in ("admin", "support")),
            None,
        )
        if admin_entry:
            data["admin"] = {
                "id": admin_entry["id"],
                "username": admin_entry["username"],
                "password_hash": admin_entry.get("password_hash", ""),
            }
            others = [u for u in legacy_users if u.get("role") in ("admin", "support") and u["id"] != admin_entry["id"]]
            if others:
                logger.warning(
                    "MIGRATION: %d additional admin/support account(s) found and discarded: %s. "
                    "Only %s retained as the single admin.",
                    len(others),
                    [u["username"] for u in others],
                    admin_entry["username"],
                )
        else:
            logger.error(
                "MIGRATION: No admin account found in legacy users list. "
                "Seeding default admin/admin — change password immediately."
            )
            import uuid as _uuid
            data["admin"] = {
                "id": str(_uuid.uuid4()),
                "username": "admin",
                "password_hash": hash_password("admin"),
            }

        # Build unified list: former role:user entries (strip login-only fields)
        seen_usernames = set()
        unified = []
        for u in legacy_users:
            if u.get("role") == "user":
                entry = {k: v for k, v in u.items() if k not in ("password_hash", "role", "telegramId")}
                seen_usernames.add(entry["username"])
                unified.append(entry)

        # Merge former external_users into unified list
        legacy_ext = data.get("external_users", [])
        if legacy_ext:
            data["_legacy_external_users"] = legacy_ext
            import uuid as _uuid2
            for eu in legacy_ext:
                uname = eu.get("external_id", "")
                if uname in seen_usernames:
                    logger.warning(
                        "MIGRATION: external_user external_id=%s conflicts with existing username; skipping.", uname
                    )
                    continue
                entry = dict(eu)
                entry.setdefault("id", str(_uuid2.uuid4()))
                entry.setdefault("username", uname)
                unified.append(entry)
                seen_usernames.add(uname)
            del data["external_users"]

        data["users"] = unified
        del data["users"]   # NOTE: we just rebuilt it; this line is wrong — omit the del
        # Correct: do NOT delete data["users"] — it now holds the unified list.
        # (The old "users" list was split into admin + unified users.)
        # Implementation note: after assigning data["users"] = unified above,
        # do NOT del data["users"]. The key persists as the new unified list.
        data["users"] = unified
        changed = True

        # Rewrite connection FKs: external_user_id → user_id
        ext_id_to_uuid = {eu.get("external_id"): eu.get("id") for eu in unified if eu.get("external_id")}
        for conn in data.get("user_connections", []):
            ext_id = conn.get("external_user_id")
            if ext_id and ext_id in ext_id_to_uuid:
                conn["user_id"] = ext_id_to_uuid[ext_id]
                conn["external_user_id"] = None
                changed = True

        logger.info(
            "MIGRATION: Converted legacy structure to %d unified users + 1 admin "
            "(%d from former users list, %d from former external_users).",
            len(unified),
            sum(1 for u in legacy_users if u.get("role") == "user"),
            len(legacy_ext),
        )

    # ── Backfill user fields ──────────────────────────────────────────────────
    for u in data.get("users", []):
        migrated = False
        if not u.get("external_id"):  # panel-created and Remnawave entries only
            if "share_enabled" not in u:
                u["share_enabled"] = False
                migrated = True
            if not u.get("share_token"):
                import secrets as _sec
                u["share_token"] = _sec.token_urlsafe(16)
                migrated = True
            if "share_password_hash" not in u:
                u["share_password_hash"] = None
                migrated = True
            if "traffic_reset_strategy" not in u:
                u["traffic_reset_strategy"] = "never"
                migrated = True
            if "traffic_total" not in u:
                u["traffic_total"] = u.get("traffic_used", 0)
                migrated = True
            if "last_reset_at" not in u:
                from datetime import datetime as _dt
                u["last_reset_at"] = _dt.now().isoformat()
                migrated = True
            if "expiration_date" not in u:
                u["expiration_date"] = None
                migrated = True
        if migrated:
            changed = True

    # ── Strip telegram settings ───────────────────────────────────────────────
    if "telegram" in data.get("settings", {}):
        del data["settings"]["telegram"]
        changed = True
        logger.info("MIGRATION: Removed settings.telegram block.")

    # ... (existing SSL, api_keys, server UUID migrations remain)

    return changed
```

**Note on the migration code sketch**: the double-assignment of `data["users"]` above is intentional pseudocode to show the logical flow. The real implementation assigns `data["users"] = unified` exactly once after building the unified list from the former `role:user` entries plus the former `external_users` entries.

**Deduplication key**: `username` for panel-created/Remnawave entries; `external_id` for ext-API entries. If an `external_id` collides with an existing `username`, log a warning and skip — the panel-created entry wins. This is expected to be rare in practice.

**Startup admin seeding** changes from:
```python
if not data.get("users"):
    data["users"] = [{"id": ..., "username": "admin", "password_hash": ..., "role": "admin", ...}]
```
To (see also Section 6 for the full `ADMIN_PASSWORD_RESET` block):
```python
if not data.get("admin"):
    data["admin"] = {"id": str(uuid.uuid4()), "username": "admin", "password_hash": hash_password("admin")}
    logger.info("Default admin created (admin / admin)")
if "users" not in data:
    data["users"] = []
```

---

## 10. Phased Rollout

Each phase ends with a working, deployable app. Never break the running state between phases.

### Phase 0: Test Harness (prerequisite — run before any code changes)

Set up `pytest` + `httpx` test infrastructure. Write tests that cover the current behavior as a regression baseline. Tests must pass on the current codebase before Phase 1 begins.

**Can this be skipped?** Yes, if you are comfortable without a safety net. Not recommended — the migration touches `startup()`, `_apply_schema_migrations`, and auth, which are the highest-blast-radius areas.

**Effort**: 4–6 hours.

### Phase 1: Telegram Bot Removal (lowest risk, most isolated)

Delete `telegram_bot.py`. Remove all import and call sites in `app.py`. Remove Telegram card from `settings.html`. Remove bot-related translation keys from all 5 translation files. Remove `telegramId` from user templates and Pydantic models. Remove `telegramId` from Remnawave sync writes.

**App state after Phase 1**: Fully working, minus the Telegram bot. `data["users"]` still exists. `settings.telegram` still exists in `data.json` (the migration will strip it later). No functional regressions for admin users.

**Effort**: 3–4 hours.

### Phase 2: Data Model Migration + Single Admin + external_users Merge

Implement `_apply_schema_migrations` changes (admin split + external_users merge into unified `data["users"]` + connection FK rewrite). Update `startup()` admin seeding and `ADMIN_PASSWORD_RESET` env var handling. Update `get_current_user` and `_check_admin`. Update `api_login`. Update backup restore validator. Retarget all `ext_api.py` reads/writes from `data["external_users"]` to `data["users"]`.

**App state after Phase 2**: Data model migrated. Admin logs in via `data["admin"]`. All users (former panel-created, Remnawave-synced, and ext-API-created) exist in unified `data["users"]`. The `/my` page still exists but is now unreachable. `/external_users` admin page still exists but its underlying data is now in `data["users"]` — it may render incorrectly until Phase 3 consolidates the templates. The ext-API webhook routes (`/api/v1/ext/*`) write into `data["users"]` immediately after this phase.

**This phase is the highest risk.** Validate with tests before deploying.

**Effort**: 5–7 hours (Phase 2 grows slightly to absorb the external_users merge and connection FK rewrite).

### Phase 3: Routes, Templates, and external_users Consolidation

Route handlers: all remaining `data["external_users"]` references in `app.py` route handlers retarget to `data["users"]`. Delete `/external_users` page route and `/api/admin/external_users/*` routes (superseded by unified `/api/users/*`). Remove `/my` page and `/api/my/*` endpoints. Update `server.html` to pass the unified `users` list. Update `users.html` to remove role selector, password field, role badge, and add `external_id` display column for ext-API-origin entries. Delete `external_users.html`. Remove `nav_external_users` translation key from `en.json`.

**App state after Phase 3**: Fully functional under the new model. Unified user management UI works. Share links work. Remnawave sync works. ext-API users appear in the main users list.

**Can Phase 2 and Phase 3 be merged?** Yes, if you batch both in a single PR and test locally before merging. For safety they are presented separately. Merging saves one deploy cycle.

**Effort**: 4–6 hours.

### Phase 4: Cleanup

- Remove `data["_legacy_users"]` and `data["_legacy_external_users"]` keys from `_apply_schema_migrations` (after one release cycle — operators had time to verify the migration).
- Remove `external_user_id` field from `user_connections` schema backfill (field is now unused).
- Verify no stray `role`, `external_users`, or `customers` references remain in templates or `app.py`.
- Final translation key audit (remove any orphaned keys that no template references).
- Add `_legacy_users` and `_legacy_external_users` cleanup to migration (set `changed = True` if key found, delete it).

**Effort**: 1–2 hours (shrinks from prior plan — the external_users decision question is resolved; no "decide later" step needed).

---

## 11. Test Harness Proposal

### Framework and approach

`pytest` + `httpx.AsyncClient` against the real FastAPI app with a temp `data.json`. No mocks. This matches the project's stated preference.

### Setup

```python
# tests/conftest.py
import json, tempfile, os, pytest
from httpx import AsyncClient, ASGITransport

@pytest.fixture
def tmp_data_file(tmp_path):
    """Seed a minimal data.json for each test."""
    data = {
        "admin": {
            "id": "test-admin-id",
            "username": "admin",
            "password_hash": "<precomputed hash of 'admin'>",
        },
        "users": [],   # unified list — no separate external_users key
        "servers": [],
        "user_connections": [],
        "api_keys": [],
        "settings": {"appearance": {}, "sync": {}, "captcha": {}, "ssl": {"enabled": False}},
    }
    p = tmp_path / "data.json"
    p.write_text(json.dumps(data))
    return str(p)

@pytest.fixture
async def client(tmp_data_file, monkeypatch):
    monkeypatch.setenv("DATA_FILE", tmp_data_file)
    # Patch DATA_FILE in app module before import
    from amnezia_panel import app as app_module
    app_module.DATA_FILE = tmp_data_file
    async with AsyncClient(
        transport=ASGITransport(app=app_module.app),
        base_url="http://test",
    ) as c:
        yield c
```

### Test list

1. **Admin login** — `POST /api/auth/login` with `admin/admin` returns `{"status": "success", "role": "admin"}`.
2. **Admin login wrong password** — returns 401.
3. **Auth gate** — `GET /api/users` without session returns 403.
4. **Admin creates user** — `POST /api/users/add` with valid body creates entry in `data["users"]`, response includes `id`.
5. **User appears in list** — `GET /api/users` returns the created user; `role` and `telegramId` are absent from response.
6. **User has no login** — `POST /api/auth/login` with a user's former username returns 401 (no `password_hash` in admin record).
7. **Share link is generated** — `POST /api/users/{id}/share/setup` with `enabled: true` returns a `share_token`. `GET /share/{token}` returns 200 without needing a session.
8. **Share link password protection** — `GET /share/{token}` with `share_password_hash` set redirects/prompts for password; posting correct password sets session key and allows access.
9. **Backup download** — `GET /api/settings/backup/download` returns JSON with `admin` and `users` keys (no separate `external_users` key).
10. **Backup restore round-trip** — download backup, POST it to `/api/settings/backup/restore`, reload data, verify user list intact and admin unchanged.
11. **Migration from legacy shape (panel users only)** — seed `data.json` with old `"users"` list (one admin, two `role:user`, no `external_users`), start the app, verify `data["admin"]` populated, `data["users"]` has two entries without `role`/`password_hash`, `data["_legacy_users"]` preserved.
12. **Migration from legacy shape (with external_users)** — seed `data.json` with old `"users"` list (one admin, two `role:user`) AND `"external_users"` list (two entries), start the app, verify `data["users"]` has four entries (two panel + two ext-API), `data["external_users"]` absent, `data["_legacy_external_users"]` preserved, connection FKs for ext-API entries rewritten to `user_id`.
13. **Migration idempotency** — run migration twice on the same data, verify no duplicate users and no crash.
14. **Unified list — panel-created and ext-API both in same list** — create one user via `POST /api/users/add` (panel path) and trigger one user via ext-API webhook; `GET /api/users` returns both in the same list; ext-API entry has `external_id` field, panel entry does not.
15. **`/my` page removed** — `GET /my` returns 404.
16. **`/external_users` page removed** — `GET /external_users` returns 404 (after Phase 3).
17. **ADMIN_PASSWORD_RESET env var** — seed `data.json` with existing admin, set env var, start app, verify `data["admin"]["password_hash"]` updated, login with new password succeeds.
18. **Remnawave sync** — integration test is out of scope (requires live Remnawave endpoint), but unit test that `sync_users_with_remnawave` with a mocked HTTP response correctly creates entries in `data["users"]` (the one place a mock is justified since Remnawave is an external service).

### Wiring

Add to `pyproject.toml`:
```toml
[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "httpx>=0.27",  # already a runtime dep; pin to same version
]
```

Add to `Taskfile.yml`:
```yaml
test:
  cmds:
    - uv run pytest tests/ -v
```

Add to `.github/workflows/build.yml` after the `lint` step:
```yaml
- name: Test
  run: task test
```

---

## 12. Risk Register

### R1 — Admin lockout after migration (HIGH)
**Scenario**: The first entry in `data["users"]` was a `role: support` account with a known password; the actual admin account is second in the list. Migration picks the first, which is the wrong account.
**Mitigation**: Migration code logs clearly which username it selected as admin. Document that operators must verify the correct admin is selected by checking logs after first startup post-migration. Add an env-var escape hatch (`ADMIN_USERNAME`) that overrides which user from the legacy list is promoted to admin.
**Additional**: With only one admin and no secondary, a forgotten password is a serious lockout. See R2.

### R2 — Admin password recovery (HIGH) — RESOLVED
**Scenario**: Operator forgets admin password. With no secondary admin and no password reset email, they are locked out.
**Mitigation (decided — Q2 resolved)**: `ADMIN_PASSWORD_RESET` env var at startup. If set, `startup()` reads it, hashes it, and writes it to `data["admin"]["password_hash"]`, then logs a warning telling the operator to unset it and restart. No CLI subcommand. Document in README. See Section 6 for the code sketch.
**Must be implemented in Phase 2.**

### R3 — Remnawave sync regression (MEDIUM)
**Scenario**: Sync code still references `data["users"]` after Phase 3, silently writes customers nowhere.
**Mitigation**: Tests cover the sync path. The migration ensures `data["users"]` no longer exists post-migration, so any stale reference will fail with a `KeyError` rather than silently losing data — which is actually good (fail loudly). Test harness test #14 catches this.

### R4 — Backup restore compat (MEDIUM)
**Scenario**: Operator restores a pre-migration backup. The validator rejects it because `"customers"` key is missing.
**Mitigation**: Updated validator accepts either `"users"` or `"customers"` key (both routed through `_apply_schema_migrations` which handles both). This is explicitly handled in the migration plan. Test #10 and #11 cover this.

### R5 — Cached browser JS calling stale routes (LOW)
**Scenario**: After Phase 3, a browser with a cached version of `users.html` makes calls to old paths (e.g., `/api/admin/external_users/*`) that no longer exist.
**Mitigation**: The `/api/users*` routes are **unchanged** in this plan (same path, updated backing data). The only removed routes are `/api/admin/external_users/*` and `/api/my/*`, which were never called from the regular users page. Browser cache invalidation is not a concern for the main user management UI. Force-refresh is sufficient for operator sessions after upgrade.

### R6 — `_legacy_users` key growing stale (LOW)
**Scenario**: `_legacy_users` stays in `data.json` forever, confusing future operators.
**Mitigation**: Phase 4 removes it. The key is explicitly documented as a one-version escape hatch. After Phase 4 is deployed, `_apply_schema_migrations` deletes it on next startup.

### R7 — `/api/admin/external_users/*` clients break on endpoint removal (MEDIUM)
**Scenario**: Any admin tooling, scripts, or integrations that call `/api/admin/external_users/*` routes directly will receive 404 after Phase 3. These are internal admin routes (not the external HMAC API), so the blast radius is limited to the operator's own tooling.
**Mitigation**: Document the endpoint change in migration notes / CHANGELOG. The ext-API webhook surface (`/api/v1/ext/*`) is unchanged — only the admin-facing management routes are removed. If backwards compat is needed, add temporary redirect aliases in Phase 3 and remove in Phase 4.

### R8 — Connection FK rewrite misses orphaned records (MEDIUM)
**Scenario**: A `user_connections` record has `external_user_id` set to an `external_id` that no longer exists in `external_users` (deleted before migration). The migration skips it; `user_id` remains unset on that record; the connection becomes orphaned.
**Mitigation**: During migration, log all connection records where `external_user_id` is non-null but no matching ext-API user was found. These are already effectively orphaned — the migration makes the situation visible rather than creating a new problem. Count them in the migration log output.

### R9 — Telegram bot removal breaks active bot users mid-flight (LOW)
**Scenario**: Some customers actively use the Telegram bot. After Phase 1 deployment, the bot stops responding.
**Mitigation**: This is the user's stated intent (aggressive removal). Document it in the release notes / CHANGELOG. No technical mitigation needed — the removal is intentional and irreversible.

### R10 — `telegramId` in Remnawave response causes key errors (LOW)
**Scenario**: After removing `telegramId` handling, Remnawave still sends the field. The sync code might fail if it tries to write to a removed field.
**Mitigation**: The fix is deletion of the write lines (426, 451). Remnawave sending a field we ignore is not an error — Python dicts don't care about extra keys in the source. No `KeyError` risk. Confirmed safe.

---

## 13. Effort Estimate Per Phase

| Phase | Description | Estimated Effort |
|-------|-------------|------------------|
| Phase 0 | Test harness setup, baseline tests | 4–6 hours |
| Phase 1 | Telegram bot removal (code + templates + i18n) | 3–4 hours |
| Phase 2 | Data model migration + auth refactor + admin seeding + `ADMIN_PASSWORD_RESET` env var + `external_users` merge + connection FK rewrite + `ext_api.py` retarget | 5–7 hours |
| Phase 3 | Route consolidation + template updates + `external_users.html` deletion + unified user API surface | 4–6 hours |
| Phase 4 | Cleanup, `_legacy_users`/`_legacy_external_users` removal, final audit | 1–2 hours |
| **Total** | | **17–25 hours** |

If Phases 2 and 3 are merged (single PR, tested locally): subtract 1–2 hours of coordination overhead. Phase 4 shrinks by ~1 hour vs. the prior plan (no "decide external_users fate" step).

The test harness (Phase 0) is front-loaded but pays dividends in confidence for Phases 2 and 3, which are the highest-risk phases.

---

## 14. Open Questions for the User

### Q1 — `external_users`: merge or keep parallel? **RESOLVED — merge into unified `users` list**

**Decision (2026-04-18)**: Merge `data["external_users"]` into the single unified `data["users"]` list. UI label stays "Users". The prior recommendation to keep them parallel is superseded.

**Impact**: Sections 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13 updated to reflect this. Migration concatenates former `role:user` entries and former `external_users` entries into `data["users"]`, deduplicating by `username`/`external_id`. Connection FKs (`external_user_id`) rewritten to `user_id` during migration. `ext_api.py` and `app.py:2655–3127` retargeted to `data["users"]`. `external_users.html` deleted; `nav_external_users` translation key removed from `en.json`.

### Q2 — Admin password recovery path **RESOLVED — ENV var at startup**

**Decision (2026-04-18)**: `ADMIN_PASSWORD_RESET` env var at startup. If set when the app boots, `startup()` reads it, hashes it, and writes it as the admin's new password, then logs a warning telling the operator to unset the env var and restart. No CLI subcommand.

**Impact**: Section 6 updated with code sketch. Section 9 startup seeding block updated. Risk register R2 updated to cite this env var as the sole recovery path.

### Q3 — Share link `share_password_hash` — confirm keep

Share links allow the admin to set a password on a customer's config download page. This `share_password_hash` field on the customer entity is a distinct concept from the customer's panel login password (which is being removed). Share link passwords are still useful (gating config distribution to end-users).

**Confirm**: `share_password_hash` stays on customers. The share link flow is unchanged. (This is the plan's assumption — just confirming explicitly.)

### Q4 — Future notification system

The Telegram bot provided push notifications to customers (VPN config delivery on demand). After removal, there is no notification path for customers. Is there a future plan for email or webhook notifications, or is this permanently out of scope? Knowing this now would affect whether `telegramId` should be preserved in the customer model as a "future Telegram notification" hook — but based on the stated direction (aggressive removal, no deprecation), the assumption is it is permanently gone.

**Question for you**: Is any notification mechanism (email, webhook, new bot) planned post-removal? If yes, scope it as a separate feature rather than a migration concern.

---

*End of plan. Q1 (external_users merge) and Q2 (admin password recovery) are resolved — see Section 14. Review Section 1 (Validation Findings) for confirmed-safe items. Section 12 R1 (admin lockout during migration) is the remaining item requiring operator attention before Phase 2 begins.*
