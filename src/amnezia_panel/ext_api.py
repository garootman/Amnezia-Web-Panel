"""External public REST API for the panel.

Mounted under ``/api/v1/ext``. HMAC-authenticated, intended for the upstream
billing portal that sells subscriptions and provisions VPN access on this panel.

Architecture notes:
- All state lives in the same ``data.json`` as the rest of the panel; reads go
  through ``load_data`` and writes through ``save_data_async`` behind ``DATA_LOCK``.
- SSH calls go through the existing ``get_protocol_manager`` + ``_manager_call``
  pipeline so external provisioning behaves identically to admin-UI provisioning.
- Idempotency, rate-limit, and webhook delivery state are intentionally
  in-process and lost on restart (documented in the README).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import random
import secrets
import time
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ext", tags=["external-api"])


# ======================== Auth & rate limiting ========================

# Per-key token bucket. Separate from `_LOGIN_FAILURES` (different algorithm,
# different scope: per-key rate-limit vs. per-IP login backoff).
_RATE_BUCKETS: dict[tuple[str, str], list[float]] = defaultdict(list)
_RATE_LIMITS = {"read": (60, 60.0), "write": (10, 60.0)}  # (requests, window-seconds)
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_TIMESTAMP_SKEW_S = 300


def _check_rate_limit(key_id: str, method: str) -> None:
    bucket_kind = "write" if method.upper() in _WRITE_METHODS else "read"
    limit, window = _RATE_LIMITS[bucket_kind]
    now = time.time()
    bucket_key = (key_id, bucket_kind)
    bucket = _RATE_BUCKETS[bucket_key]
    cutoff = now - window
    # Trim expired hits in-place to keep memory bounded.
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= limit:
        raise HTTPException(429, "Rate limit exceeded")
    bucket.append(now)


def _generate_secret() -> str:
    return secrets.token_hex(32)


def _generate_key_id() -> str:
    return f"ak_live_{secrets.token_hex(8)}"


async def require_api_key(request: Request) -> dict:
    """Validate the HMAC signature on the request and return the matching key record."""
    # Imported lazily to avoid a circular import at module load.
    from .app import load_data, save_data_async

    key_id = request.headers.get("X-API-Key", "")
    ts_str = request.headers.get("X-Timestamp", "")
    sig = request.headers.get("X-Signature", "")
    if not (key_id and ts_str and sig):
        raise HTTPException(401, "Missing auth headers")
    try:
        ts = int(ts_str)
    except ValueError as e:
        raise HTTPException(401, "Invalid timestamp") from e
    if abs(time.time() - ts) > _TIMESTAMP_SKEW_S:
        raise HTTPException(401, "Stale timestamp")

    data = load_data()
    key = next(
        (k for k in data.get("api_keys", []) if k["id"] == key_id and not k.get("revoked")),
        None,
    )
    if not key:
        raise HTTPException(401, "Unknown or revoked key")

    body = await request.body()
    body_hash = hashlib.sha256(body).hexdigest()
    expected = f"{ts_str}\n{request.method}\n{request.url.path}\n{body_hash}"
    expected_sig = hmac.new(key["secret"].encode(), expected.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(401, "Bad signature")

    _check_rate_limit(key_id, request.method)

    # Best-effort last-used tracking. Don't block the request on save failures.
    try:
        key["last_used_at"] = _now_iso()
        await save_data_async(data)
    except Exception:
        logger.debug("Failed to update api_keys.last_used_at", exc_info=True)

    return key


# ======================== Idempotency cache ========================

# Maps Idempotency-Key → (timestamp, status_code, response_dict). In-process,
# 24h TTL, lost on restart. Documented in the README/integration section.
_IDEMPOTENCY_CACHE: dict[str, tuple[float, int, dict]] = {}
_IDEMPOTENCY_TTL = 24 * 3600


def _idempotency_get(key: str | None) -> tuple[int, dict] | None:
    if not key:
        return None
    entry = _IDEMPOTENCY_CACHE.get(key)
    if not entry:
        return None
    ts, status, body = entry
    if time.time() - ts > _IDEMPOTENCY_TTL:
        _IDEMPOTENCY_CACHE.pop(key, None)
        return None
    return status, body


def _idempotency_put(key: str | None, status: int, body: dict) -> None:
    if not key:
        return
    _IDEMPOTENCY_CACHE[key] = (time.time(), status, body)


# ======================== Webhook delivery ========================

# In-memory async queue. Restart drops pending deliveries — documented contract.
_WEBHOOK_QUEUE: asyncio.Queue | None = None
_WEBHOOK_BACKOFFS = (1.0, 10.0, 60.0)


def _webhook_queue() -> asyncio.Queue:
    global _WEBHOOK_QUEUE
    if _WEBHOOK_QUEUE is None:
        _WEBHOOK_QUEUE = asyncio.Queue()
    return _WEBHOOK_QUEUE


async def enqueue_webhook(api_key: dict, event: str, payload: dict) -> None:
    """Queue a webhook delivery for the given API key.

    No-op if the key has no webhook configured or the event isn't subscribed.
    """
    wh = api_key.get("webhook") or {}
    if not wh.get("url"):
        return
    events = wh.get("events") or []
    if events and event not in events:
        return
    body = {"event": event, "ts": int(time.time()), "data": payload}
    await _webhook_queue().put((wh["url"], wh.get("secret", ""), body))


async def _broadcast_event(event: str, payload: dict) -> None:
    """Fan out an event to every API key subscribed to it."""
    from .app import load_data

    data = load_data()
    for key in data.get("api_keys", []):
        if key.get("revoked"):
            continue
        try:
            await enqueue_webhook(key, event, payload)
        except Exception:
            logger.debug("enqueue_webhook failed", exc_info=True)


async def _webhook_consumer():
    import json as _json

    queue = _webhook_queue()
    async with httpx.AsyncClient(timeout=10.0) as client:
        while True:
            url, secret, body = await queue.get()
            raw = _json.dumps(body, separators=(",", ":")).encode()
            for attempt, backoff in enumerate(_WEBHOOK_BACKOFFS):
                ts = str(int(time.time()))
                signed = f"{ts}\n{hashlib.sha256(raw).hexdigest()}"
                sig = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest() if secret else ""
                try:
                    resp = await client.post(
                        url,
                        content=raw,
                        headers={
                            "Content-Type": "application/json",
                            "X-Webhook-Timestamp": ts,
                            "X-Webhook-Signature": sig,
                        },
                    )
                    if 200 <= resp.status_code < 300:
                        break
                    logger.warning("Webhook %s returned %d", url, resp.status_code)
                except Exception as e:
                    logger.warning("Webhook %s attempt %d failed: %s", url, attempt + 1, e)
                if attempt < len(_WEBHOOK_BACKOFFS) - 1:
                    await asyncio.sleep(backoff)
            else:
                logger.error("Webhook %s permanently failed after %d attempts", url, len(_WEBHOOK_BACKOFFS))
            queue.task_done()


def start_webhook_consumer(background_tasks: set) -> None:
    task = asyncio.create_task(_webhook_consumer())
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)


# ======================== Pydantic models ========================


class ExtUserCreate(BaseModel):
    external_id: str
    expires_at: str
    label: str | None = None

    @field_validator("expires_at")
    @classmethod
    def _validate_iso(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError("expires_at must be ISO 8601") from e
        return v


class ExtUserPatch(BaseModel):
    expires_at: str | None = None
    label: str | None = None
    status: str | None = None

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: str | None) -> str | None:
        if v is not None and v not in ("active", "expired", "suspended"):
            raise ValueError("status must be active|expired|suspended")
        return v


class ConnectionCreate(BaseModel):
    protocol: str = "wireguard"
    server_id: str | None = None
    region: str | None = None
    traffic_limit: int | None = 0
    label: str | None = None


class ConnectionPatch(BaseModel):
    traffic_limit: int | None = None
    label: str | None = None
    enabled: bool | None = None


class MigrateRequest(BaseModel):
    server_id: str | None = None
    region: str | None = None


class WebhookConfig(BaseModel):
    url: str
    secret: str | None = None
    events: list[str] = Field(default_factory=list)


# ======================== Helpers ========================


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _server_by_uuid(data: dict, server_uuid: str) -> tuple[int, dict] | None:
    for idx, srv in enumerate(data.get("servers", [])):
        if srv.get("id") == server_uuid:
            return idx, srv
    return None


def _ext_user_by_id(data: dict, external_id: str) -> dict | None:
    """Return the unified-users entry for an ext-API-origin user, or None."""
    for u in data.get("users", []):
        if u.get("external_id") == external_id:
            return u
    return None


def _conn_by_id(data: dict, conn_id: str) -> dict | None:
    for c in data.get("user_connections", []):
        if c["id"] == conn_id:
            return c
    return None


def _user_conns(data: dict, user_record: dict) -> list[dict]:
    uid = user_record.get("id")
    return [c for c in data.get("user_connections", []) if c.get("user_id") == uid]


def _serialize_user(u: dict, data_or_conns) -> dict:
    """Serialize an ext-API user for external-API responses.

    Accepts either the full ``data`` dict or the bare connections list so both call
    patterns from before the unified-users migration keep working.
    """
    if isinstance(data_or_conns, dict):
        user_conns = _user_conns(data_or_conns, u)
    else:
        uid = u.get("id")
        user_conns = [c for c in data_or_conns if c.get("user_id") == uid]
    return {
        "external_id": u.get("external_id"),
        "label": u.get("label"),
        "expires_at": u.get("expires_at"),
        "status": u.get("status", "active"),
        "created_at": u.get("created_at"),
        "updated_at": u.get("updated_at"),
        "connections_count": len(user_conns),
        "traffic_used_bytes": sum(c.get("last_bytes", 0) for c in user_conns),
    }


def _serialize_connection(c: dict, data: dict) -> dict:
    sid = c.get("server_id")
    server_uuid = None
    server_label = None
    region = None
    # Internal connection records may still hold the legacy integer index — translate.
    if isinstance(sid, int) and 0 <= sid < len(data.get("servers", [])):
        srv = data["servers"][sid]
        server_uuid = srv.get("id")
        server_label = srv.get("name") or srv.get("host")
        region = srv.get("region", "")
    elif isinstance(sid, str):
        match = _server_by_uuid(data, sid)
        if match:
            _, srv = match
            server_uuid = srv["id"]
            server_label = srv.get("name") or srv.get("host")
            region = srv.get("region", "")
    owner = next((u for u in data.get("users", []) if u.get("id") == c.get("user_id")), None)
    return {
        "id": c["id"],
        "external_user_id": owner.get("external_id") if owner else None,
        "server_id": server_uuid,
        "server_label": server_label,
        "region": region,
        "protocol": c["protocol"],
        "client_id": c.get("client_id"),
        "label": c.get("name") or c.get("label"),
        "enabled": c.get("enabled", True),
        "traffic_limit": c.get("traffic_limit", 0),
        "traffic_used": c.get("last_bytes", 0),
        "created_at": c.get("created_at"),
    }


def _build_share_url(request: Request, share_token: str) -> str:
    return str(request.base_url).rstrip("/") + f"/share/{share_token}"


def _ensure_share_token(user_record: dict) -> str:
    token = user_record.get("share_token")
    if not token:
        token = secrets.token_urlsafe(16)
        user_record["share_token"] = token
        user_record.setdefault("share_enabled", True)
    if not user_record.get("share_enabled"):
        user_record["share_enabled"] = True
    return token


# ======================== Server selection ========================


def _select_server(data: dict, protocol: str, requested_id: str | None, region: str | None) -> tuple[int, dict] | None:
    candidates: list[tuple[int, dict]] = []
    if requested_id:
        match = _server_by_uuid(data, requested_id)
        if not match:
            return None
        idx, srv = match
        if protocol not in srv.get("protocols", {}):
            return None
        return idx, srv

    # Build candidate set. `reachable` defaults to True for servers that have
    # never been scraped — better to attempt provisioning than to refuse.
    for idx, srv in enumerate(data.get("servers", [])):
        if srv.get("reachable") is False:
            continue
        if protocol not in srv.get("protocols", {}):
            continue
        candidates.append((idx, srv))

    region_filtered = [c for c in candidates if region and c[1].get("region") == region]
    pool = region_filtered if region_filtered else candidates
    if not pool:
        return None

    conn_counts: dict[int, int] = defaultdict(int)
    for c in data.get("user_connections", []):
        sid = c.get("server_id")
        if isinstance(sid, int):
            conn_counts[sid] += 1
        elif isinstance(sid, str):
            match = _server_by_uuid(data, sid)
            if match:
                conn_counts[match[0]] += 1

    pool.sort(key=lambda x: conn_counts.get(x[0], 0))
    min_load = conn_counts.get(pool[0][0], 0)
    tied = [c for c in pool if conn_counts.get(c[0], 0) == min_load]
    return random.choice(tied)


# ======================== Endpoints: Users ========================


@router.post("/users")
async def create_or_upsert_user(
    request: Request,
    payload: ExtUserCreate,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    api_key: dict = Depends(require_api_key),
):
    cached = _idempotency_get(idempotency_key)
    if cached:
        return cached[1]

    from .app import DATA_LOCK, load_data, save_data

    async with DATA_LOCK:
        data = load_data()
        existing = _ext_user_by_id(data, payload.external_id)
        now = _now_iso()
        if existing:
            existing["expires_at"] = payload.expires_at
            existing["label"] = payload.label if payload.label is not None else existing.get("label")
            existing["updated_at"] = now
            # Re-extension after expiry: re-enable connections + clear notification marker.
            if existing.get("status") == "expired" and _parse_iso(payload.expires_at) > datetime.now(UTC):
                existing["status"] = "active"
                existing["expiring_soon_notified_at"] = None
                existing["enabled"] = True
                await _re_enable_connections(data, payload.external_id)
            user_record = existing
        else:
            user_record = {
                "id": str(uuid.uuid4()),
                "external_id": payload.external_id,
                "username": payload.external_id,
                "label": payload.label,
                "expires_at": payload.expires_at,
                "status": "active",
                "enabled": True,
                "created_at": now,
                "updated_at": now,
                "expiring_soon_notified_at": None,
                "share_enabled": True,
                "share_token": secrets.token_urlsafe(16),
                "share_password_hash": None,
            }
            data["users"].append(user_record)
        await asyncio.to_thread(save_data, data)

    response = _serialize_user(user_record, data)
    _idempotency_put(idempotency_key, 200, response)
    return response


@router.get("/users")
async def list_users(
    status: str | None = None,
    expiring_before: str | None = None,
    page: int = 1,
    limit: int = 50,
    api_key: dict = Depends(require_api_key),
):
    from .app import load_data

    data = load_data()
    users = [u for u in data.get("users", []) if u.get("external_id")]
    if status:
        users = [u for u in users if u.get("status") == status]
    if expiring_before:
        try:
            cutoff = _parse_iso(expiring_before)
            users = [u for u in users if u.get("expires_at") and _parse_iso(u["expires_at"]) <= cutoff]
        except ValueError as e:
            raise HTTPException(400, "expiring_before must be ISO 8601") from e
    total = len(users)
    limit = max(1, min(limit, 200))
    page = max(1, page)
    start = (page - 1) * limit
    page_items = users[start : start + limit]
    return {
        "users": [_serialize_user(u, data) for u in page_items],
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get("/users/{external_id}")
async def get_user(external_id: str, api_key: dict = Depends(require_api_key)):
    from .app import load_data

    data = load_data()
    user = _ext_user_by_id(data, external_id)
    if not user:
        raise HTTPException(404, "User not found")
    summary = _serialize_user(user, data)
    summary["connections"] = [_serialize_connection(c, data) for c in _user_conns(data, user)]
    return summary


@router.patch("/users/{external_id}")
async def patch_user(external_id: str, payload: ExtUserPatch, api_key: dict = Depends(require_api_key)):
    from .app import DATA_LOCK, load_data, save_data

    async with DATA_LOCK:
        data = load_data()
        user = _ext_user_by_id(data, external_id)
        if not user:
            raise HTTPException(404, "User not found")
        prev_status = user.get("status")
        if payload.label is not None:
            user["label"] = payload.label
        if payload.expires_at is not None:
            try:
                _parse_iso(payload.expires_at)
            except ValueError as e:
                raise HTTPException(400, "expires_at must be ISO 8601") from e
            user["expires_at"] = payload.expires_at
            if prev_status == "expired" and _parse_iso(payload.expires_at) > datetime.now(UTC):
                user["status"] = "active"
                user["enabled"] = True
                user["expiring_soon_notified_at"] = None
                await _re_enable_connections(data, external_id)
        if payload.status is not None:
            user["status"] = payload.status
            if payload.status == "suspended" and prev_status != "suspended":
                user["enabled"] = False
                await _disable_connections(data, external_id)
                await _broadcast_event("user.suspended", {"external_id": external_id})
            elif payload.status == "active":
                user["enabled"] = True
        user["updated_at"] = _now_iso()
        await asyncio.to_thread(save_data, data)

    return _serialize_user(user, data)


@router.delete("/users/{external_id}")
async def delete_user(external_id: str, api_key: dict = Depends(require_api_key)):
    from .app import DATA_LOCK, load_data

    async with DATA_LOCK:
        data = load_data()
        user = _ext_user_by_id(data, external_id)
        if not user:
            raise HTTPException(404, "User not found")

    # Cascade-delete real connections (SSH + state) outside the lock so SSH calls
    # don't block other writers.
    await _cascade_delete_user(external_id)
    return {"status": "deleted"}


# ======================== Endpoints: Connections ========================


@router.post("/users/{external_id}/connections")
async def create_connection(
    request: Request,
    external_id: str,
    payload: ConnectionCreate,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    api_key: dict = Depends(require_api_key),
):
    cached = _idempotency_get(idempotency_key)
    if cached:
        return cached[1]

    from .app import (
        DATA_LOCK,
        generate_vpn_link,
        get_protocol_manager,
        get_ssh,
        load_data,
        save_data,
    )

    data = load_data()
    user = _ext_user_by_id(data, external_id)
    if not user:
        raise HTTPException(404, "External user not found")

    selected = _select_server(data, payload.protocol, payload.server_id, payload.region)
    if not selected:
        raise HTTPException(
            503,
            {
                "code": "no_server_available",
                "region": payload.region,
                "protocol": payload.protocol,
            },
        )
    server_idx, server = selected
    proto_info = server.get("protocols", {}).get(payload.protocol, {})
    port = proto_info.get("port", "55424")
    name = payload.label or f"{external_id}_{payload.protocol}"

    def _provision():
        ssh = get_ssh(server)
        ssh.connect()
        try:
            mgr = get_protocol_manager(ssh, payload.protocol)
            return mgr.add_client(payload.protocol, name, server["host"], port)
        finally:
            try:
                ssh.disconnect()
            except Exception:
                pass

    result = await asyncio.to_thread(_provision)
    if not result.get("client_id"):
        raise HTTPException(502, "Provisioning failed on remote server")

    config_text = result.get("config")
    new_conn_id = str(uuid.uuid4())
    async with DATA_LOCK:
        data = load_data()
        user_record = _ext_user_by_id(data, external_id)
        if not user_record:
            raise HTTPException(404, "External user not found")
        share_token = _ensure_share_token(user_record)
        conn = {
            "id": new_conn_id,
            "user_id": user_record["id"],
            "server_id": server_idx,
            "protocol": payload.protocol,
            "client_id": result["client_id"],
            "name": name,
            "enabled": True,
            "traffic_limit": payload.traffic_limit or 0,
            "last_bytes": 0,
            "label": payload.label,
            "created_at": _now_iso(),
        }
        data["user_connections"].append(conn)
        await asyncio.to_thread(save_data, data)

    response = _serialize_connection(conn, data)
    response["config"] = config_text
    response["vpn_link"] = generate_vpn_link(config_text) if config_text else None
    response["share_url"] = _build_share_url(request, share_token)

    await _broadcast_event(
        "connection.provisioned",
        {"external_id": external_id, "connection_id": new_conn_id, "protocol": payload.protocol},
    )

    _idempotency_put(idempotency_key, 200, response)
    return response


@router.get("/users/{external_id}/connections")
async def list_connections(external_id: str, api_key: dict = Depends(require_api_key)):
    from .app import load_data

    data = load_data()
    user = _ext_user_by_id(data, external_id)
    if not user:
        raise HTTPException(404, "User not found")
    conns = _user_conns(data, user)
    return {"connections": [_serialize_connection(c, data) for c in conns]}


def _conn_belongs_to_ext(data: dict, conn: dict, external_id: str) -> bool:
    owner = next((u for u in data.get("users", []) if u.get("id") == conn.get("user_id")), None)
    return bool(owner and owner.get("external_id") == external_id)


@router.get("/users/{external_id}/connections/{conn_id}")
async def get_connection(external_id: str, conn_id: str, api_key: dict = Depends(require_api_key)):
    from .app import load_data

    data = load_data()
    conn = _conn_by_id(data, conn_id)
    if not conn or not _conn_belongs_to_ext(data, conn, external_id):
        raise HTTPException(404, "Connection not found")
    return _serialize_connection(conn, data)


@router.patch("/users/{external_id}/connections/{conn_id}")
async def patch_connection(
    external_id: str, conn_id: str, payload: ConnectionPatch, api_key: dict = Depends(require_api_key)
):
    from .app import DATA_LOCK, get_protocol_manager, get_ssh, load_data, save_data

    async with DATA_LOCK:
        data = load_data()
        conn = _conn_by_id(data, conn_id)
        if not conn or not _conn_belongs_to_ext(data, conn, external_id):
            raise HTTPException(404, "Connection not found")
        if payload.label is not None:
            conn["label"] = payload.label
        if payload.traffic_limit is not None:
            conn["traffic_limit"] = payload.traffic_limit
        toggle_target = None
        if payload.enabled is not None and payload.enabled != conn.get("enabled", True):
            toggle_target = payload.enabled
            conn["enabled"] = payload.enabled
        await asyncio.to_thread(save_data, data)

    if toggle_target is not None:
        sid = conn.get("server_id")
        if isinstance(sid, int) and 0 <= sid < len(data["servers"]):
            server = data["servers"][sid]

            def _toggle():
                ssh = get_ssh(server)
                ssh.connect()
                try:
                    get_protocol_manager(ssh, conn["protocol"]).toggle_client(
                        conn["protocol"], conn["client_id"], toggle_target
                    )
                finally:
                    try:
                        ssh.disconnect()
                    except Exception:
                        pass

            try:
                await asyncio.to_thread(_toggle)
            except Exception as e:
                logger.warning("Failed to toggle remote client for %s: %s", conn_id, e)

    return _serialize_connection(conn, data)


@router.delete("/users/{external_id}/connections/{conn_id}")
async def delete_connection(external_id: str, conn_id: str, api_key: dict = Depends(require_api_key)):
    from .app import DATA_LOCK, get_protocol_manager, get_ssh, load_data, save_data

    data = load_data()
    conn = _conn_by_id(data, conn_id)
    if not conn or not _conn_belongs_to_ext(data, conn, external_id):
        raise HTTPException(404, "Connection not found")
    sid = conn.get("server_id")
    if isinstance(sid, int) and 0 <= sid < len(data["servers"]):
        server = data["servers"][sid]

        def _remove():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                get_protocol_manager(ssh, conn["protocol"]).remove_client(conn["protocol"], conn["client_id"])
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        try:
            await asyncio.to_thread(_remove)
        except Exception as e:
            logger.warning("Remote revoke failed for %s: %s", conn_id, e)

    async with DATA_LOCK:
        data = load_data()
        data["user_connections"] = [c for c in data["user_connections"] if c["id"] != conn_id]
        await asyncio.to_thread(save_data, data)

    await _broadcast_event(
        "connection.revoked",
        {"external_id": external_id, "connection_id": conn_id},
    )
    return {"status": "deleted"}


@router.post("/users/{external_id}/connections/{conn_id}/rotate")
async def rotate_connection(request: Request, external_id: str, conn_id: str, api_key: dict = Depends(require_api_key)):
    return await _rotate_or_migrate(request, external_id, conn_id, target_server_id=None, region=None, event="rotated")


@router.post("/users/{external_id}/connections/{conn_id}/migrate")
async def migrate_connection(
    request: Request,
    external_id: str,
    conn_id: str,
    payload: MigrateRequest,
    api_key: dict = Depends(require_api_key),
):
    return await _rotate_or_migrate(
        request, external_id, conn_id, target_server_id=payload.server_id, region=payload.region, event="migrated"
    )


@router.get("/connections/{conn_id}")
async def lookup_connection(conn_id: str, api_key: dict = Depends(require_api_key)):
    from .app import load_data

    data = load_data()
    conn = _conn_by_id(data, conn_id)
    if not conn:
        raise HTTPException(404, "Connection not found")
    return _serialize_connection(conn, data)


# ======================== Endpoints: Servers & stats ========================


@router.get("/servers")
async def list_servers(api_key: dict = Depends(require_api_key)):
    from .app import load_data

    data = load_data()
    conn_counts: dict[int, int] = defaultdict(int)
    for c in data.get("user_connections", []):
        sid = c.get("server_id")
        if isinstance(sid, int):
            conn_counts[sid] += 1
    out = []
    for idx, srv in enumerate(data.get("servers", [])):
        out.append(
            {
                "id": srv.get("id"),
                "label": srv.get("name") or srv.get("host"),
                "region": srv.get("region", ""),
                "protocols": list((srv.get("protocols") or {}).keys()),
                "active_connections": conn_counts.get(idx, 0),
                "reachable": srv.get("reachable", True),
            }
        )
    return {"servers": out}


@router.get("/stats/summary")
async def stats_summary(api_key: dict = Depends(require_api_key)):
    from .app import load_data

    data = load_data()
    users = [u for u in data.get("users", []) if u.get("external_id")]
    conns = data.get("user_connections", [])
    per_server: dict[str, dict[str, Any]] = {}
    conn_counts: dict[int, int] = defaultdict(int)
    bytes_24h_total = 0
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    for c in conns:
        sid = c.get("server_id")
        if isinstance(sid, int):
            conn_counts[sid] += 1
        if c.get("created_at"):
            try:
                if _parse_iso(c["created_at"]) >= cutoff:
                    bytes_24h_total += c.get("last_bytes", 0)
            except ValueError:
                pass
    for idx, srv in enumerate(data.get("servers", [])):
        per_server[srv.get("id") or str(idx)] = {
            "label": srv.get("name") or srv.get("host"),
            "region": srv.get("region", ""),
            "active_connections": conn_counts.get(idx, 0),
        }
    return {
        "active_users": sum(1 for u in users if u.get("status", "active") == "active"),
        "total_users": len(users),
        "total_connections": len(conns),
        "traffic_24h_bytes": bytes_24h_total,
        "per_server": per_server,
    }


@router.get("/users/{external_id}/stats")
async def user_stats(external_id: str, api_key: dict = Depends(require_api_key)):
    from .app import load_data

    data = load_data()
    user = _ext_user_by_id(data, external_id)
    if not user:
        raise HTTPException(404, "User not found")
    conns = _user_conns(data, user)
    breakdown = []
    total = 0
    for c in conns:
        used = c.get("last_bytes", 0)
        total += used
        breakdown.append({"id": c["id"], "protocol": c["protocol"], "bytes": used})
    return {"total_bytes": total, "connections": breakdown}


# ======================== Endpoints: Webhooks ========================


@router.put("/webhooks")
async def set_webhook(payload: WebhookConfig, api_key: dict = Depends(require_api_key)):
    from .app import DATA_LOCK, load_data, save_data

    async with DATA_LOCK:
        data = load_data()
        key = next((k for k in data.get("api_keys", []) if k["id"] == api_key["id"]), None)
        if not key:
            raise HTTPException(404, "API key not found")
        key["webhook"] = {
            "url": payload.url,
            "secret": payload.secret or key.get("webhook", {}).get("secret") or _generate_secret(),
            "events": payload.events,
        }
        await asyncio.to_thread(save_data, data)
    return {"webhook": key["webhook"]}


@router.get("/webhooks")
async def get_webhook(api_key: dict = Depends(require_api_key)):
    return {"webhook": api_key.get("webhook")}


@router.delete("/webhooks")
async def delete_webhook(api_key: dict = Depends(require_api_key)):
    from .app import DATA_LOCK, load_data, save_data

    async with DATA_LOCK:
        data = load_data()
        key = next((k for k in data.get("api_keys", []) if k["id"] == api_key["id"]), None)
        if key:
            key["webhook"] = None
            await asyncio.to_thread(save_data, data)
    return {"status": "deleted"}


# ======================== Internal helpers (also used by sweeper) ========================


def _parse_iso(value: str) -> datetime:
    """Parse ISO 8601, accepting trailing Z. Always returns aware UTC."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


async def _disable_connections(data: dict, external_id: str) -> list[str]:
    """Toggle off every connection for the given external user. Best-effort SSH calls."""
    from .app import get_protocol_manager, get_ssh

    user = _ext_user_by_id(data, external_id)
    if not user:
        return []
    uid = user["id"]
    affected: list[str] = []
    for conn in data.get("user_connections", []):
        if conn.get("user_id") != uid:
            continue
        affected.append(conn["id"])
        sid = conn.get("server_id")
        if isinstance(sid, int) and 0 <= sid < len(data["servers"]):
            server = data["servers"][sid]

            def _toggle(s=server, c=conn):
                ssh = get_ssh(s)
                ssh.connect()
                try:
                    get_protocol_manager(ssh, c["protocol"]).toggle_client(c["protocol"], c["client_id"], False)
                finally:
                    try:
                        ssh.disconnect()
                    except Exception:
                        pass

            try:
                await asyncio.to_thread(_toggle)
            except Exception as e:
                logger.warning("Disable failed for %s: %s", conn["id"], e)
        conn["enabled"] = False
    return affected


async def _re_enable_connections(data: dict, external_id: str) -> None:
    from .app import get_protocol_manager, get_ssh

    user = _ext_user_by_id(data, external_id)
    if not user:
        return
    uid = user["id"]
    for conn in data.get("user_connections", []):
        if conn.get("user_id") != uid:
            continue
        sid = conn.get("server_id")
        if isinstance(sid, int) and 0 <= sid < len(data["servers"]):
            server = data["servers"][sid]

            def _toggle(s=server, c=conn):
                ssh = get_ssh(s)
                ssh.connect()
                try:
                    get_protocol_manager(ssh, c["protocol"]).toggle_client(c["protocol"], c["client_id"], True)
                finally:
                    try:
                        ssh.disconnect()
                    except Exception:
                        pass

            try:
                await asyncio.to_thread(_toggle)
            except Exception as e:
                logger.warning("Re-enable failed for %s: %s", conn["id"], e)
        conn["enabled"] = True


async def _cascade_delete_user(external_id: str) -> None:
    from .app import (
        DATA_LOCK,
        get_protocol_manager,
        get_ssh,
        load_data,
        save_data,
    )

    data = load_data()
    user = _ext_user_by_id(data, external_id)
    if not user:
        return
    uid = user["id"]
    targets = [c for c in data.get("user_connections", []) if c.get("user_id") == uid]
    for conn in targets:
        sid = conn.get("server_id")
        if isinstance(sid, int) and 0 <= sid < len(data["servers"]):
            server = data["servers"][sid]

            def _remove(s=server, c=conn):
                ssh = get_ssh(s)
                ssh.connect()
                try:
                    get_protocol_manager(ssh, c["protocol"]).remove_client(c["protocol"], c["client_id"])
                finally:
                    try:
                        ssh.disconnect()
                    except Exception:
                        pass

            try:
                await asyncio.to_thread(_remove)
            except Exception as e:
                logger.warning("Remote delete failed for %s: %s", conn["id"], e)

    async with DATA_LOCK:
        data = load_data()
        user = _ext_user_by_id(data, external_id)
        if not user:
            return
        uid = user["id"]
        data["user_connections"] = [c for c in data.get("user_connections", []) if c.get("user_id") != uid]
        data["users"] = [u for u in data.get("users", []) if u.get("id") != uid]
        await asyncio.to_thread(save_data, data)


async def _rotate_or_migrate(
    request: Request,
    external_id: str,
    conn_id: str,
    target_server_id: str | None,
    region: str | None,
    event: str,
):
    """Shared implementation: revoke the old client, provision a fresh one (same protocol)."""
    from .app import (
        DATA_LOCK,
        generate_vpn_link,
        get_protocol_manager,
        get_ssh,
        load_data,
        save_data,
    )

    data = load_data()
    conn = _conn_by_id(data, conn_id)
    if not conn or not _conn_belongs_to_ext(data, conn, external_id):
        raise HTTPException(404, "Connection not found")
    protocol = conn["protocol"]

    if event == "rotated":
        sid = conn.get("server_id")
        if isinstance(sid, int) and 0 <= sid < len(data["servers"]):
            new_server_idx, new_server = sid, data["servers"][sid]
        else:
            raise HTTPException(409, "Original server unavailable")
    else:
        selected = _select_server(data, protocol, target_server_id, region)
        if not selected:
            raise HTTPException(503, {"code": "no_server_available", "region": region, "protocol": protocol})
        new_server_idx, new_server = selected

    # Revoke old client. Best-effort: continue even if the old box is offline.
    old_sid = conn.get("server_id")
    if isinstance(old_sid, int) and 0 <= old_sid < len(data["servers"]):
        old_server = data["servers"][old_sid]

        def _remove():
            ssh = get_ssh(old_server)
            ssh.connect()
            try:
                get_protocol_manager(ssh, protocol).remove_client(protocol, conn["client_id"])
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        try:
            await asyncio.to_thread(_remove)
        except Exception as e:
            logger.warning("Old-client revoke failed during %s: %s", event, e)

    proto_info = new_server.get("protocols", {}).get(protocol, {})
    port = proto_info.get("port", "55424")
    name = conn.get("label") or conn.get("name") or f"{external_id}_{protocol}"

    def _provision():
        ssh = get_ssh(new_server)
        ssh.connect()
        try:
            return get_protocol_manager(ssh, protocol).add_client(protocol, name, new_server["host"], port)
        finally:
            try:
                ssh.disconnect()
            except Exception:
                pass

    result = await asyncio.to_thread(_provision)
    if not result.get("client_id"):
        raise HTTPException(502, "Re-provision failed")

    config_text = result.get("config")
    async with DATA_LOCK:
        data = load_data()
        target = _conn_by_id(data, conn_id)
        if not target:
            raise HTTPException(404, "Connection vanished mid-flight")
        target["client_id"] = result["client_id"]
        target["server_id"] = new_server_idx
        target["last_bytes"] = 0
        user = _ext_user_by_id(data, external_id)
        share_token = _ensure_share_token(user) if user else ""
        await asyncio.to_thread(save_data, data)

    response = _serialize_connection(target, data)
    response["config"] = config_text
    response["vpn_link"] = generate_vpn_link(config_text) if config_text else None
    response["share_url"] = _build_share_url(request, share_token)

    await _broadcast_event(
        f"connection.{event}",
        {"external_id": external_id, "connection_id": conn_id, "protocol": protocol},
    )
    return response


# ======================== Sweeper (called from periodic_background_tasks) ========================


async def run_external_sweeper() -> None:
    """Sweep external users once. Idempotent. Safe to call from the existing 10-min loop."""
    from .app import DATA_LOCK, load_data, save_data

    now = datetime.now(UTC)
    soon = now + timedelta(days=7)
    grace_cutoff = now - timedelta(days=90)

    to_expire: list[str] = []
    to_warn: list[str] = []
    to_grace_delete: list[str] = []

    data = load_data()
    for u in data.get("users", []):
        if not u.get("external_id") or not u.get("expires_at"):
            continue
        try:
            expires = _parse_iso(u["expires_at"])
        except ValueError:
            continue
        status = u.get("status", "active")
        if status == "active" and expires <= now:
            to_expire.append(u["external_id"])
        elif status == "active" and expires <= soon and not u.get("expiring_soon_notified_at"):
            to_warn.append(u["external_id"])
        elif status == "expired" and expires < grace_cutoff:
            to_grace_delete.append(u["external_id"])

    for ext_id in to_expire:
        async with DATA_LOCK:
            data = load_data()
            user = _ext_user_by_id(data, ext_id)
            if not user or user.get("status") != "active":
                continue
            user["status"] = "expired"
            user["enabled"] = False
            user["updated_at"] = _now_iso()
            affected = await _disable_connections(data, ext_id)
            await asyncio.to_thread(save_data, data)
        await _broadcast_event(
            "user.expired",
            {
                "external_id": ext_id,
                "expired_at": user["expires_at"],
                "connections_suspended": affected,
            },
        )

    for ext_id in to_warn:
        async with DATA_LOCK:
            data = load_data()
            user = _ext_user_by_id(data, ext_id)
            if not user or user.get("expiring_soon_notified_at"):
                continue
            user["expiring_soon_notified_at"] = _now_iso()
            await asyncio.to_thread(save_data, data)
        await _broadcast_event(
            "user.expiring_soon",
            {"external_id": ext_id, "expires_at": user["expires_at"]},
        )

    for ext_id in to_grace_delete:
        await _cascade_delete_user(ext_id)


async def fire_quota_exhausted_event(external_id: str | None, connection_ids: list[str]) -> None:
    """Hook from the existing traffic sync loop for connections that hit their cap."""
    if not external_id:
        return
    await _broadcast_event(
        "connection.quota_exhausted",
        {"external_id": external_id, "connection_ids": connection_ids},
    )


async def fire_server_unreachable_event(server_id: str, label: str) -> None:
    await _broadcast_event("server.unreachable", {"server_id": server_id, "label": label})
