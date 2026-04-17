import asyncio
import base64
import copy
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import tempfile
import time
import uuid
from datetime import datetime

import httpx
from fastapi import FastAPI, File, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from multicolorcaptcha import CaptchaGenerator
from pydantic import BaseModel, field_validator
from starlette.middleware.sessions import SessionMiddleware

from . import secrets_store, telegram_bot as tg_bot
from .config import settings
from .protocols.awg import AWGManager
from .protocols.wireguard import WireGuardManager
from .protocols.xray import XrayManager
from .ssh_manager import SSHManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Amnezia Web Panel")


def _ssl_enabled_at_boot() -> bool:
    try:
        with open(str(settings.data_file), encoding="utf-8") as f:
            return bool(json.load(f).get("settings", {}).get("ssl", {}).get("enabled", False))
    except (OSError, json.JSONDecodeError):
        return False


app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    same_site="strict",
    https_only=_ssl_enabled_at_boot(),
)

app.mount("/static", StaticFiles(directory=str(settings.assets_dir / "static")), name="static")
templates = Jinja2Templates(directory=str(settings.assets_dir / "templates"))

DATA_FILE = str(settings.data_file)

# Holds strong refs to asyncio tasks that would otherwise be garbage-collected mid-flight.
_BACKGROUND_TASKS: set[asyncio.Task] = set()

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    CURRENT_VERSION = f"v{_pkg_version('amnezia-web-panel')}"
except PackageNotFoundError:
    CURRENT_VERSION = "v0.0.0-dev"


# ======================== Translations ========================
TRANSLATIONS = {}


def load_translations():
    global TRANSLATIONS
    trans_dir = str(settings.assets_dir / "translations")
    if os.path.exists(trans_dir):
        for f in os.listdir(trans_dir):
            if f.endswith(".json"):
                lang = f.split(".")[0]
                try:
                    with open(os.path.join(trans_dir, f), encoding="utf-8") as tf:
                        TRANSLATIONS[lang] = json.load(tf)
                except Exception as e:
                    logger.error(f"Error loading translation {f}: {e}")
    logger.info(f"Loaded translations: {list(TRANSLATIONS.keys())}")


def _t(text_id, lang="en"):
    lang_batch = TRANSLATIONS.get(lang, TRANSLATIONS.get("en", {}))
    return lang_batch.get(text_id, text_id)


load_translations()


# ======================== Helpers ========================

# Global lock for data.json access to prevent race conditions during async operations
DATA_LOCK = asyncio.Lock()


def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = {}
    data.setdefault("servers", [])
    data.setdefault("users", [])
    data.setdefault("user_connections", [])
    data.setdefault(
        "settings",
        {
            "appearance": {"title": "Amnezia", "logo": "❤️", "subtitle": "Web Panel"},
            "sync": {
                "remnawave_url": "",
                "remnawave_api_key": "",
                "remnawave_sync": False,
                "remnawave_sync_users": False,
                "remnawave_create_conns": False,
                "remnawave_server_id": 0,
                "remnawave_protocol": "awg",
            },
        },
    )
    secrets_store.decrypt_in_place(data)
    return data


def save_data(data):
    # Serialize an encrypted copy so the caller's in-memory dict keeps plaintext.
    to_write = copy.deepcopy(data)
    secrets_store.encrypt_in_place(to_write)
    dir_ = os.path.dirname(DATA_FILE) or "."
    fd, tmp = tempfile.mkstemp(prefix=".data.", suffix=".tmp", dir=dir_)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(to_write, f, indent=2, ensure_ascii=False)
        os.replace(tmp, DATA_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


async def save_data_async(data):
    """Save data to file in a thread-safe way."""
    async with DATA_LOCK:
        await asyncio.to_thread(save_data, data)


def get_ssh(server):
    return SSHManager(
        host=server["host"],
        port=server.get("ssh_port", 22),
        username=server["username"],
        password=server.get("password"),
        private_key=server.get("private_key"),
    )


def get_protocol_manager(ssh, protocol: str):
    from .protocols.dns import DNSManager
    from .protocols.telemt import TelemtManager

    if protocol == "xray":
        return XrayManager(ssh)
    if protocol == "telemt":
        return TelemtManager(ssh)
    if protocol == "dns":
        return DNSManager(ssh)
    if protocol == "wireguard":
        return WireGuardManager(ssh)
    return AWGManager(ssh)


def generate_vpn_link(config_text):
    b64 = base64.b64encode(config_text.strip().encode("utf-8")).decode("utf-8")
    return f"vpn://{b64}"


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}${h.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt, h = password_hash.split("$", 1)
        new_h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(new_h.hex(), h)
    except Exception:
        return False


async def perform_delete_user(data: dict, user_id: str):
    user = next((u for u in data["users"] if u["id"] == user_id), None)
    if not user:
        return False
    # Remove user's connections from servers
    user_conns = [c for c in data.get("user_connections", []) if c["user_id"] == user_id]
    for uc in user_conns:
        try:
            sid = uc["server_id"]
            if sid < len(data["servers"]):
                server = data["servers"][sid]
                ssh = get_ssh(server)
                await asyncio.to_thread(ssh.connect)
                manager = get_protocol_manager(ssh, uc["protocol"])
                await asyncio.to_thread(manager.remove_client, uc["protocol"], uc["client_id"])
                await asyncio.to_thread(ssh.disconnect)
        except Exception as e:
            logger.warning(f"Failed to remove connection {uc['client_id']} during user delete: {e}")
    data["user_connections"] = [c for c in data.get("user_connections", []) if c["user_id"] != user_id]
    data["users"] = [u for u in data["users"] if u["id"] != user_id]
    return True


async def perform_toggle_user(data: dict, user_id: str, enabled: bool) -> bool:
    user = next((u for u in data["users"] if u["id"] == user_id), None)
    if not user:
        return False
    user["enabled"] = enabled
    await perform_mass_operations(toggle_uids=[(user_id, enabled)])
    return True


async def perform_mass_operations(
    delete_uids: list[str] = None, toggle_uids: list[tuple] = None, create_conns: list[dict] = None
):
    """
    Executes multiple SSH operations efficiently.
    Reloads data inside to ensure we don't overwrite other changes.
    """
    data = load_data()
    server_ops = {}

    def get_ops(sid):
        if sid not in server_ops:
            server_ops[sid] = {"delete": [], "toggle": [], "create": []}
        return server_ops[sid]

    if delete_uids:
        for uid in delete_uids:
            conns = [c for c in data.get("user_connections", []) if c["user_id"] == uid]
            for c in conns:
                get_ops(c["server_id"])["delete"].append(c)

    if toggle_uids:
        for uid, enabled in toggle_uids:
            conns = [c for c in data.get("user_connections", []) if c["user_id"] == uid]
            for c in conns:
                get_ops(c["server_id"])["toggle"].append((c, enabled))

    if create_conns:
        for req in create_conns:
            get_ops(req["server_id"])["create"].append(req)

    async def run_server_ops(srv_id, ops):
        # We re-load data inside to be absolutely sure about current state
        # but for performance we'll use the passed srv_id
        current_data = load_data()
        if srv_id >= len(current_data["servers"]):
            return
        srv = current_data["servers"][srv_id]

        try:
            ssh = get_ssh(srv)
            await asyncio.to_thread(ssh.connect)

            # 1. Deletes
            for c in ops["delete"]:
                manager = get_protocol_manager(ssh, c["protocol"])
                await asyncio.to_thread(manager.remove_client, c["protocol"], c["client_id"])
                # Incremental delete from data
                async with DATA_LOCK:
                    current_data = load_data()
                    current_data["user_connections"] = [
                        conn for conn in current_data["user_connections"] if conn["id"] != c["id"]
                    ]
                    await asyncio.to_thread(save_data, current_data)

            # 2. Toggles
            for c, enabled in ops["toggle"]:
                manager = get_protocol_manager(ssh, c["protocol"])
                await asyncio.to_thread(manager.toggle_client, c["protocol"], c["client_id"], enabled)
                # Incremental toggle in data
                async with DATA_LOCK:
                    current_data = load_data()
                    # We also need to update user status if it was a user toggle
                    # Wait, mass ops caller usually handles user enabled status.
                    # Here we just toggle the actual wireguard peer.
                    await asyncio.to_thread(save_data, current_data)

            # 3. Creates
            for c_req in ops["create"]:
                proto_info = srv.get("protocols", {}).get(c_req["protocol"], {})
                port = proto_info.get("port", "55424")
                manager = get_protocol_manager(ssh, c_req["protocol"])

                res = await asyncio.to_thread(manager.add_client, c_req["protocol"], c_req["name"], srv["host"], port)

                if res.get("client_id"):
                    new_conn = {
                        "id": str(uuid.uuid4()),
                        "user_id": c_req["user_id"],
                        "server_id": srv_id,
                        "protocol": c_req["protocol"],
                        "client_id": res["client_id"],
                        "name": c_req["name"],
                        "created_at": datetime.now().isoformat(),
                    }
                    async with DATA_LOCK:
                        current_data = load_data()
                        current_data["user_connections"].append(new_conn)
                        await asyncio.to_thread(save_data, current_data)

            await asyncio.to_thread(ssh.disconnect)
        except Exception as e:
            logger.error(f"Mass ops failed for server {srv_id}: {e}")

    # Run all servers in parallel
    tasks = [run_server_ops(sid, ops) for sid, ops in server_ops.items()]
    if tasks:
        await asyncio.gather(*tasks)

    # 4. Final user-level cleanup (delete/toggle users metadata)
    async with DATA_LOCK:
        current_data = load_data()
        if delete_uids:
            current_data["users"] = [u for u in current_data["users"] if u["id"] not in delete_uids]
            current_data["user_connections"] = [
                c for c in current_data.get("user_connections", []) if c["user_id"] not in delete_uids
            ]
        if toggle_uids:
            for uid, enabled in toggle_uids:
                user = next((u for u in current_data["users"] if u["id"] == uid), None)
                if user:
                    user["enabled"] = enabled
        await asyncio.to_thread(save_data, current_data)

    return True


async def sync_users_with_remnawave(data: dict):
    settings = data.get("settings", {}).get("sync", {})
    if not settings.get("remnawave_sync_users"):
        return 0, "Synchronization is disabled in settings"

    url = settings.get("remnawave_url")
    api_key = settings.get("remnawave_api_key")
    if not url or not api_key:
        return 0, "Remnawave URL or API Key not configured"

    api_url = url.rstrip("/") + "/api/users"
    headers = {"Authorization": f"Bearer {api_key}"}

    try:
        rw_users = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            page_size = 50  # Use a smaller page size that is more likely to be accepted
            current_start = 0
            while True:
                resp = await client.get(f"{api_url}?size={page_size}&start={current_start}", headers=headers)
                if resp.status_code != 200:
                    return 0, f"Remnawave API error: {resp.status_code} {resp.text}"

                page_data = resp.json()
                response_obj = page_data.get("response", {})
                page_users = response_obj.get("users", [])
                total_count = response_obj.get("total", 0)

                if not page_users:
                    break

                rw_users.extend(page_users)
                logger.info(f"Fetched {len(rw_users)} / {total_count} users from Remnawave...")

                if len(rw_users) >= total_count or len(page_users) == 0:
                    break

                current_start += len(page_users)

            rw_uuids = {u["uuid"] for u in rw_users}

            # 1. Handle deletion (users that have remnawave_uuid but are no longer in Remnawave)
            to_delete_ids = []
            for u in data["users"]:
                if u.get("remnawave_uuid") and u["remnawave_uuid"] not in rw_uuids:
                    to_delete_ids.append(u["id"])

            if to_delete_ids:
                logger.info(f"Removing {len(to_delete_ids)} users deleted in Remnawave")
                await perform_mass_operations(delete_uids=to_delete_ids)

            # 2. Sync / Create users
            synced_count = 0
            to_toggle = []  # list of (user_id, enabled)
            to_create_conns = []  # list of dicts

            for rw_u in rw_users:
                # We reload data in each loop step to handle concurrency
                data = load_data()
                local_u = next((u for u in data["users"] if u.get("remnawave_uuid") == rw_u["uuid"]), None)
                if not local_u:
                    # Fall back to username match ONLY for users that were already Remnawave-imported
                    # (empty password_hash). Never hijack a local admin account that shares a username.
                    local_u = next(
                        (u for u in data["users"] if u["username"] == rw_u["username"] and not u.get("password_hash")),
                        None,
                    )

                is_active = rw_u.get("status") == "ACTIVE"

                if local_u:
                    local_u["username"] = rw_u["username"]
                    local_u["telegramId"] = rw_u.get("telegramId")
                    local_u["email"] = rw_u.get("email")
                    local_u["description"] = rw_u.get("description")
                    local_u["remnawave_uuid"] = rw_u["uuid"]

                    if local_u.get("enabled", True) != is_active:
                        to_toggle.append((local_u["id"], is_active))

                    # Save metadata immediately
                    async with DATA_LOCK:
                        current = load_data()
                        # Update index
                        idx = next((i for i, u in enumerate(current["users"]) if u["id"] == local_u["id"]), -1)
                        if idx != -1:
                            current["users"][idx] = local_u
                            await asyncio.to_thread(save_data, current)

                    synced_count += 1
                else:
                    new_id = str(uuid.uuid4())
                    new_user = {
                        "id": new_id,
                        "username": rw_u["username"],
                        "password_hash": "",
                        "role": "user",
                        "telegramId": rw_u.get("telegramId"),
                        "email": rw_u.get("email"),
                        "description": rw_u.get("description"),
                        "enabled": is_active,
                        "created_at": datetime.now().isoformat(),
                        "remnawave_uuid": rw_u["uuid"],
                        "share_enabled": False,
                        "share_token": secrets.token_urlsafe(16),
                        "share_password_hash": None,
                    }
                    async with DATA_LOCK:
                        current = load_data()
                        current["users"].append(new_user)
                        await asyncio.to_thread(save_data, current)

                    if settings.get("remnawave_create_conns"):
                        sid = settings.get("remnawave_server_id")
                        if sid is not None:
                            to_create_conns.append(
                                {
                                    "user_id": new_id,
                                    "server_id": sid,
                                    "protocol": settings.get("remnawave_protocol", "awg"),
                                    "name": f"{rw_u['username']}_vpn",
                                }
                            )
                    synced_count += 1

            # Execute all collected mass operations
            if to_toggle or to_create_conns:
                logger.info(
                    f"Executing mass ops for Remnawave sync: toggle={len(to_toggle)}, create={len(to_create_conns)}"
                )
                await perform_mass_operations(toggle_uids=to_toggle, create_conns=to_create_conns)

            return synced_count, "Successfully synchronized with Remnawave"

    except Exception as e:
        logger.exception("Synchronization error")
        return 0, f"Error: {e!s}"


def get_current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    data = load_data()
    for u in data.get("users", []):
        if u["id"] == user_id:
            return u
    return None


def tpl(request, template, **kwargs):
    data = load_data()
    lang = request.cookies.get("lang", "en")
    ctx = {
        "request": request,
        "current_user": get_current_user(request),
        "site_settings": data.get("settings", {}).get("appearance", {}),
        "captcha_settings": data.get("settings", {}).get("captcha", {}),
        "telegram_settings": data.get("settings", {}).get("telegram", {}),
        "bot_running": tg_bot.is_running(),
        "lang": lang,
        "_": lambda text_id: _t(text_id, lang),
        "translations_json": json.dumps(TRANSLATIONS.get(lang, TRANSLATIONS.get("en", {}))),
        "all_translations_json": json.dumps(TRANSLATIONS),
    }
    ctx.update(kwargs)
    return templates.TemplateResponse(request, template, ctx)


# ======================== Pydantic Models ========================


class LoginRequest(BaseModel):
    username: str
    password: str
    captcha: str | None = None


class AddServerRequest(BaseModel):
    host: str = ""
    ssh_port: int = 22
    username: str = ""
    password: str = ""
    private_key: str = ""
    name: str = ""


_HOSTNAME_LABEL = r"[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_HOSTNAME_LABEL}(\.{_HOSTNAME_LABEL})*$")


class InstallProtocolRequest(BaseModel):
    protocol: str = "awg"
    port: str = "55424"
    tls_emulation: bool | None = None
    tls_domain: str | None = None
    max_connections: int | None = None

    @field_validator("port")
    @classmethod
    def _validate_port(cls, v: str) -> str:
        if not v.isdigit() or not (1 <= int(v) <= 65535):
            raise ValueError("port must be a number between 1 and 65535")
        return v

    @field_validator("tls_domain")
    @classmethod
    def _validate_tls_domain(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return v
        if len(v) > 253 or not _HOSTNAME_RE.match(v):
            raise ValueError("tls_domain must be a valid hostname")
        return v


class ProtocolRequest(BaseModel):
    protocol: str = "awg"


class AddConnectionRequest(BaseModel):
    protocol: str = "awg"
    name: str = "Connection"
    user_id: str | None = None
    telemt_quota: str | None = None
    telemt_max_ips: int | None = None
    telemt_expiry: str | None = None
    telemt_secret: str | None = None
    telemt_ad_tag: str | None = None
    telemt_max_conns: int | None = None


class EditConnectionRequest(BaseModel):
    protocol: str = "telemt"
    client_id: str = ""
    telemt_quota: str | None = None
    telemt_max_ips: int | None = None
    telemt_expiry: str | None = None
    telemt_secret: str | None = None
    telemt_ad_tag: str | None = None
    telemt_max_conns: int | None = None


class ConnectionActionRequest(BaseModel):
    protocol: str = "awg"
    client_id: str = ""


class ToggleConnectionRequest(BaseModel):
    protocol: str = "awg"
    client_id: str = ""
    enable: bool = True


class AddUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"
    telegramId: str | None = None
    email: str | None = None
    description: str | None = None
    traffic_limit: float | None = 0
    traffic_reset_strategy: str | None = "never"
    server_id: int | None = None
    protocol: str | None = None
    connection_name: str | None = None
    expiration_date: str | None = None
    telemt_quota: str | None = None
    telemt_max_ips: int | None = None
    telemt_expiry: str | None = None
    telemt_secret: str | None = None
    telemt_ad_tag: str | None = None
    telemt_max_conns: int | None = None


class ServerConfigSaveRequest(BaseModel):
    protocol: str
    config: str


class AppearanceSettings(BaseModel):
    title: str = "Amnezia"
    logo: str = "🛡"
    subtitle: str = "Web Panel"


class SyncSettings(BaseModel):
    remnawave_url: str = ""
    remnawave_api_key: str = ""
    remnawave_sync: bool = False
    remnawave_sync_users: bool = False
    remnawave_create_conns: bool = False
    remnawave_server_id: int = 0
    remnawave_protocol: str = "awg"


class CaptchaSettings(BaseModel):
    enabled: bool = False


class SSLSettings(BaseModel):
    enabled: bool = False
    domain: str = ""
    cert_path: str = ""
    key_path: str = ""
    cert_text: str = ""
    key_text: str = ""


class TelegramSettings(BaseModel):
    token: str = ""
    enabled: bool = False


class UpdateUserRequest(BaseModel):
    telegramId: str | None = None
    email: str | None = None
    description: str | None = None
    traffic_limit: float | None = 0
    traffic_reset_strategy: str | None = None
    expiration_date: str | None = None
    password: str | None = None


class SaveSettingsRequest(BaseModel):
    appearance: AppearanceSettings
    sync: SyncSettings
    captcha: CaptchaSettings
    telegram: TelegramSettings
    ssl: SSLSettings


class ToggleUserRequest(BaseModel):
    enabled: bool


class AddUserConnectionRequest(BaseModel):
    server_id: int
    protocol: str = "awg"
    name: str = "VPN Connection"
    client_id: str | None = None
    telemt_quota: str | None = None
    telemt_max_ips: int | None = None
    telemt_expiry: str | None = None
    telemt_secret: str | None = None
    telemt_ad_tag: str | None = None
    telemt_max_conns: int | None = None


class ShareSetupRequest(BaseModel):
    enabled: bool
    password: str | None = None


class ShareAuthRequest(BaseModel):
    password: str


# ======================== Startup ========================


def _apply_schema_migrations(data: dict) -> bool:
    """Backfill fields on users/settings for older data.json schemas. Returns True if anything changed."""
    changed = False
    for u in data.get("users", []):
        migrated = False
        if "share_enabled" not in u:
            u["share_enabled"] = False
            migrated = True
        if not u.get("share_token"):
            u["share_token"] = secrets.token_urlsafe(16)
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
            u["last_reset_at"] = datetime.now().isoformat()
            migrated = True
        if "expiration_date" not in u:
            u["expiration_date"] = None
            migrated = True
        if migrated:
            changed = True
            logger.info(f"Migrated user {u['username']} to new traffic/sharing fields")

    if "ssl" not in data.get("settings", {}):
        data.setdefault("settings", {})
        data["settings"]["ssl"] = {
            "enabled": False,
            "domain": "",
            "cert_path": "",
            "key_path": "",
            "cert_text": "",
            "key_text": "",
        }
        changed = True
        logger.info("Migrated SSL settings")

    if "panel_port" in data.get("settings", {}).get("ssl", {}):
        data["settings"]["ssl"].pop("panel_port", None)
        changed = True
        logger.info("Removed legacy ssl.panel_port from data.json (use PANEL_PORT env instead)")

    return changed


@app.on_event("startup")
async def startup():
    needs_secrets_migration = secrets_store.has_plaintext_secrets_on_disk()
    data = load_data()
    changed = needs_secrets_migration
    if needs_secrets_migration:
        logger.info("Encrypting credential fields in data.json at rest")
    if not data.get("users"):
        data["users"] = [
            {
                "id": str(uuid.uuid4()),
                "username": "admin",
                "password_hash": hash_password("admin"),
                "role": "admin",
                "enabled": True,
                "created_at": datetime.now().isoformat(),
            }
        ]
        changed = True
        logger.info("Default admin created (admin / admin)")

    if _apply_schema_migrations(data):
        changed = True

    if changed:
        await save_data_async(data)

    # Start periodic background tasks. Keep a reference so the task isn't garbage-collected.
    _BACKGROUND_TASKS.add(asyncio.create_task(periodic_background_tasks()))

    # Start Telegram bot if enabled
    tg_cfg = data.get("settings", {}).get("telegram", {})
    if tg_cfg.get("enabled") and tg_cfg.get("token"):
        logger.info("Starting Telegram bot from saved settings...")
        tg_bot.launch_bot(tg_cfg["token"], load_data, generate_vpn_link)


def _scrape_server_traffic(server, sid, my_conns):
    server_updates = []
    try:
        ssh = get_ssh(server)
        ssh.connect()
        for proto in ["awg", "awg2", "awg_legacy", "xray", "telemt", "wireguard"]:
            if proto in server.get("protocols", {}):
                manager = get_protocol_manager(ssh, proto)
                clients = manager.get_clients(proto)
                client_bytes = {}
                for c in clients:
                    rx = c.get("userData", {}).get("dataReceivedBytes", 0)
                    tx = c.get("userData", {}).get("dataSentBytes", 0)
                    client_bytes[c.get("clientId")] = rx + tx

                for uc in my_conns:
                    if uc["protocol"] == proto and uc["client_id"] in client_bytes:
                        curr_bytes = client_bytes[uc["client_id"]]
                        last_bytes = uc.get("last_bytes", 0)
                        delta = curr_bytes - last_bytes if curr_bytes >= last_bytes else curr_bytes
                        server_updates.append((uc["id"], delta, curr_bytes))
        ssh.disconnect()
    except Exception as e:
        logger.error(f"Traffic sync err server {sid}: {e}")
    return server_updates


async def periodic_background_tasks():
    """Background task to sync traffic limits and Remnawave every 10 minutes"""
    while True:
        try:
            # We wait before the first sync to let the app settle
            await asyncio.sleep(60)

            # --- 1. TRAFFIC SYNC & LIMITS ---
            logger.info("Starting background traffic sync...")
            data = load_data()

            conns_by_server = {}
            for uc in data.get("user_connections", []):
                sid = uc["server_id"]
                conns_by_server.setdefault(sid, []).append(uc)

            updates = []

            for sid, server in enumerate(data.get("servers", [])):
                if sid not in conns_by_server:
                    continue

                # Run the blocking SSH traffic scraping in a background thread!
                server_updates = await asyncio.to_thread(_scrape_server_traffic, server, sid, conns_by_server[sid])
                if server_updates:
                    updates.extend(server_updates)

            to_disable_uids = []
            if updates:
                async with DATA_LOCK:
                    curr_data = load_data()
                    users_map = {u["id"]: u for u in curr_data.get("users", [])}
                    uc_list = curr_data.get("user_connections", [])
                    uc_map = {uc["id"]: uc for uc in uc_list}

                    # Current date/time for reset checking
                    now = datetime.now()

                    for uc_id, delta, curr_bytes in updates:
                        if uc_id in uc_map:
                            uc_map[uc_id]["last_bytes"] = curr_bytes
                            uid = uc_map[uc_id]["user_id"]
                            if uid in users_map:
                                u = users_map[uid]
                                # Check if reset is needed BEFORE adding new consumption
                                strategy = u.get("traffic_reset_strategy", "never")
                                last_reset_iso = u.get("last_reset_at")

                                reset_needed = False
                                if strategy != "never" and last_reset_iso:
                                    try:
                                        last = datetime.fromisoformat(last_reset_iso)
                                        if strategy == "daily":
                                            reset_needed = now.date() > last.date()
                                        elif strategy == "weekly":
                                            reset_needed = (
                                                now.isocalendar()[1] != last.isocalendar()[1] or now.year != last.year
                                            )
                                        elif strategy == "monthly":
                                            reset_needed = now.month != last.month or now.year != last.year
                                    except Exception:
                                        pass

                                if reset_needed:
                                    logger.info(f"Resetting traffic for user {u['username']} (strategy: {strategy})")
                                    u["traffic_used"] = 0
                                    u["last_reset_at"] = now.isoformat()

                                # Update both resettable and total traffic
                                u["traffic_used"] = u.get("traffic_used", 0) + delta
                                u["traffic_total"] = u.get("traffic_total", 0) + delta

                                limit = u.get("traffic_limit", 0)
                                if limit > 0 and u["traffic_used"] >= limit and u.get("enabled", True):
                                    if uid not in to_disable_uids:
                                        to_disable_uids.append(uid)

                                # Check expiration date
                                exp_str = u.get("expiration_date")
                                if exp_str and u.get("enabled", True):
                                    try:
                                        exp_date = datetime.fromisoformat(exp_str)
                                        if now > exp_date:
                                            logger.info(
                                                f"Subscription expired for user {u['username']} (expired at {exp_str})"
                                            )
                                            if uid not in to_disable_uids:
                                                to_disable_uids.append(uid)
                                    except Exception:
                                        pass
                    await asyncio.to_thread(save_data, curr_data)

            if to_disable_uids:
                logger.info(f"Traffic limit reached, disabling users: {to_disable_uids}")
                await perform_mass_operations(toggle_uids=[(uid, False) for uid in to_disable_uids])

            # --- 2. REMNAWAVE SYNC ---
            logger.info("Starting background Remnawave sync...")
            data = load_data()
            if data.get("settings", {}).get("sync", {}).get("remnawave_sync_users"):
                count, msg = await sync_users_with_remnawave(data)
                logger.info(f"Background Remnawave sync finished: {count} users updated. {msg}")
            else:
                logger.info("Background Remnawave sync skipped (disabled in settings)")

        except Exception as e:
            logger.error(f"Error in periodic_background_tasks: {e}")

        # Wait 10 minutes before next sync
        await asyncio.sleep(600)


# ======================== PAGE ROUTES ========================


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if get_current_user(request):
        return RedirectResponse(url="/", status_code=302)
    return tpl(request, "login.html")


@app.get("/set_lang/{lang}")
async def set_lang(lang: str, request: Request):
    ref = request.headers.get("referer", "/")
    # Only allow same-origin redirects — prevents Referer-driven open redirect.
    if not ref.startswith("/"):
        ref = "/"
    response = RedirectResponse(url=ref)
    response.set_cookie(key="lang", value=lang, max_age=31536000)
    return response


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    if user["role"] == "user":
        return RedirectResponse(url="/my", status_code=302)
    data = load_data()
    return tpl(request, "index.html", servers=data["servers"])


@app.get("/server/{server_id}", response_class=HTMLResponse)
async def server_detail(request: Request, server_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    if user["role"] not in ("admin", "support"):
        return RedirectResponse(url="/my", status_code=302)
    data = load_data()
    if server_id >= len(data["servers"]):
        return RedirectResponse(url="/")
    server = data["servers"][server_id]
    users_list = data.get("users", [])
    return tpl(request, "server.html", server=server, server_id=server_id, users=users_list)


@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    if user["role"] not in ("admin", "support"):
        return RedirectResponse(url="/my", status_code=302)
    data = load_data()
    users_list = data.get("users", [])
    # Count connections per user
    conns = data.get("user_connections", [])
    for u in users_list:
        u["connections_count"] = sum(1 for c in conns if c["user_id"] == u["id"])
    servers = data["servers"]
    return tpl(request, "users.html", users=users_list, servers=servers)


@app.get("/my", response_class=HTMLResponse)
async def my_connections_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    data = load_data()
    conns = [c for c in data.get("user_connections", []) if c["user_id"] == user["id"]]
    # Enrich with server names
    for c in conns:
        sid = c.get("server_id", 0)
        if sid < len(data["servers"]):
            c["server_name"] = data["servers"][sid].get("name", data["servers"][sid].get("host", ""))
        else:
            c["server_name"] = "Unknown"
    return tpl(request, "my_connections.html", connections=conns)


# ======================== AUTH API ========================


@app.get("/api/auth/captcha")
async def api_captcha(request: Request):
    generator = CaptchaGenerator(2)
    captcha = generator.gen_captcha_image(difficult_level=2)
    request.session["captcha_answer"] = captcha.characters

    img_bytes = io.BytesIO()
    captcha.image.save(img_bytes, format="PNG")
    img_bytes.seek(0)

    return StreamingResponse(img_bytes, media_type="image/png")


# Per-IP login failure tracking. Exponential backoff caps at 30s. Resets on successful login.
_LOGIN_FAILURES: dict[str, tuple[int, float]] = {}
_LOGIN_FAILURE_WINDOW = 900  # 15 minutes
_LOGIN_BACKOFF_MAX = 30.0


def _client_ip(request: Request) -> str:
    # SessionMiddleware sits behind the reverse proxy in production; fall back to the socket peer.
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _login_backoff_seconds(ip: str) -> float:
    entry = _LOGIN_FAILURES.get(ip)
    if not entry:
        return 0.0
    count, last = entry
    if time.time() - last > _LOGIN_FAILURE_WINDOW:
        _LOGIN_FAILURES.pop(ip, None)
        return 0.0
    return min(_LOGIN_BACKOFF_MAX, 0.5 * (2 ** max(0, count - 1)))


def _record_login_failure(ip: str) -> None:
    count = _LOGIN_FAILURES.get(ip, (0, 0.0))[0] + 1
    _LOGIN_FAILURES[ip] = (count, time.time())


def _clear_login_failures(ip: str) -> None:
    _LOGIN_FAILURES.pop(ip, None)


@app.post("/api/auth/login")
async def api_login(request: Request, req: LoginRequest):
    ip = _client_ip(request)
    backoff = _login_backoff_seconds(ip)
    if backoff > 0:
        await asyncio.sleep(backoff)

    data = load_data()
    captcha_settings = data.get("settings", {}).get("captcha", {})
    if captcha_settings.get("enabled") is True:
        answer = request.session.get("captcha_answer")
        lang = request.cookies.get("lang", "ru")
        if not answer or not req.captcha or answer.lower() != req.captcha.lower():
            request.session.pop("captcha_answer", None)
            _record_login_failure(ip)
            return JSONResponse({"error": _t("invalid_captcha", lang)}, status_code=400)
        request.session.pop("captcha_answer", None)

    for u in data.get("users", []):
        if u["username"] == req.username and verify_password(req.password, u["password_hash"]):
            lang = request.cookies.get("lang", "ru")
            if not u.get("enabled", True):
                return JSONResponse({"error": _t("account_disabled", lang)}, status_code=403)
            request.session["user_id"] = u["id"]
            _clear_login_failures(ip)
            return {"status": "success", "role": u["role"]}
    lang = request.cookies.get("lang", "ru")
    _record_login_failure(ip)
    return JSONResponse({"error": _t("invalid_login", lang)}, status_code=401)


# ======================== SERVER API (admin/support) ========================


def _check_admin(request):
    user = get_current_user(request)
    if not user or user["role"] not in ("admin", "support"):
        return None
    return user


@app.post("/api/servers/add")
async def api_add_server(request: Request, req: AddServerRequest):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        host = req.host.strip()
        username = req.username.strip()
        name = req.name.strip() or host
        if not host or not username:
            return JSONResponse({"error": "Host and username are required"}, status_code=400)
        if not req.password and not req.private_key:
            return JSONResponse({"error": "Password or SSH key is required"}, status_code=400)

        ssh = SSHManager(host, req.ssh_port, username, req.password, req.private_key)
        try:
            await asyncio.to_thread(ssh.connect)
            server_info = await asyncio.to_thread(ssh.test_connection)
            await asyncio.to_thread(ssh.disconnect)
        except Exception as e:
            return JSONResponse({"error": f"Connection failed: {e!s}"}, status_code=400)

        server = {
            "name": name,
            "host": host,
            "ssh_port": req.ssh_port,
            "username": username,
            "password": req.password,
            "private_key": req.private_key,
            "server_info": server_info,
            "protocols": {},
        }
        data = load_data()
        data["servers"].append(server)
        await save_data_async(data)
        return {"status": "success", "server_id": len(data["servers"]) - 1, "server_info": server_info}
    except Exception as e:
        logger.exception("Error adding server")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/delete")
async def api_delete_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        data["servers"].pop(server_id)
        # Clean up connections for this server
        data["user_connections"] = [c for c in data.get("user_connections", []) if c.get("server_id") != server_id]
        # Adjust server_ids for connections pointing to higher indices
        for c in data.get("user_connections", []):
            if c.get("server_id", 0) > server_id:
                c["server_id"] -= 1
        await save_data_async(data)
        return {"status": "success"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/reboot")
async def api_reboot_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]
        ssh = get_ssh(server)
        await asyncio.to_thread(ssh.connect)
        try:
            await asyncio.to_thread(ssh.run_sudo_command, "nohup reboot > /dev/null 2>&1 &")
        except Exception:
            pass
        try:
            await asyncio.to_thread(ssh.disconnect)
        except Exception:
            pass
        return {"status": "success"}
    except Exception as e:
        logger.exception("Error rebooting server")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/clear")
async def api_clear_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]

        def _clear():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                containers = [
                    "amnezia-awg",
                    "amnezia-awg2",
                    "amnezia-awg-legacy",
                    "amnezia-xray",
                    "telemt",
                    "amnezia-dns",
                ]
                for c in containers:
                    ssh.run_sudo_command(f"docker stop {c} || true")
                    ssh.run_sudo_command(f"docker rm {c} || true")
                ssh.run_sudo_command("docker network rm amnezia-dns-net || true")
                ssh.run_sudo_command("rm -rf /opt/amnezia")
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        await asyncio.to_thread(_clear)
        server["protocols"] = {}
        await save_data_async(data)
        return {"status": "success"}
    except Exception as e:
        logger.exception("Error clearing server")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/stats")
async def api_server_stats(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]

        def _collect_stats():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                stats = {}
                out, _, _ = ssh.run_command(
                    "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || "
                    "awk '{u=$2+$4; t=$2+$4+$5; if(NR==1){pu=u;pt=t} else printf \"%.1f\", (u-pu)/(t-pt)*100}' "
                    "<(grep 'cpu ' /proc/stat) <(sleep 0.5 && grep 'cpu ' /proc/stat) 2>/dev/null"
                )
                try:
                    stats["cpu"] = round(float(out.strip().split("\n")[0]), 1)
                except (ValueError, IndexError):
                    stats["cpu"] = 0
                out, _, _ = ssh.run_command("free -b | awk 'NR==2{printf \"%d %d\", $3, $2}'")
                try:
                    parts = out.strip().split()
                    used, total = int(parts[0]), int(parts[1])
                    ram_pct = round(used / total * 100, 1) if total > 0 else 0
                    stats.update(ram_used=used, ram_total=total, ram_percent=ram_pct)
                except (ValueError, IndexError):
                    stats.update(ram_used=0, ram_total=0, ram_percent=0)
                out, _, _ = ssh.run_command("df -B1 / | awk 'NR==2{printf \"%d %d\", $3, $2}'")
                try:
                    parts = out.strip().split()
                    used, total = int(parts[0]), int(parts[1])
                    stats.update(
                        disk_used=used, disk_total=total, disk_percent=round(used / total * 100, 1) if total > 0 else 0
                    )
                except (ValueError, IndexError):
                    stats.update(disk_used=0, disk_total=0, disk_percent=0)
                out, _, _ = ssh.run_command(
                    "DEV=$(ip route | awk '/default/ {print $5}' | head -1); "
                    'cat /proc/net/dev | awk -v dev="$DEV:" \'$1==dev{printf "%d %d", $2, $10}\''
                )
                try:
                    parts = out.strip().split()
                    stats["net_rx"], stats["net_tx"] = int(parts[0]), int(parts[1])
                except (ValueError, IndexError):
                    stats["net_rx"] = stats["net_tx"] = 0
                out, _, _ = ssh.run_command("uptime -p 2>/dev/null || uptime")
                stats["uptime"] = out.strip()
                return stats
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        return await asyncio.to_thread(_collect_stats)
    except Exception as e:
        logger.exception("Error getting server stats")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/check")
async def api_check_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]

        docker_ssh = get_ssh(server)
        await asyncio.to_thread(docker_ssh.connect)
        try:
            manager = get_protocol_manager(docker_ssh, "awg")
            docker_installed = await asyncio.to_thread(manager.check_docker_installed)
        finally:
            await asyncio.to_thread(docker_ssh.disconnect)

        status = {"connection": "ok", "docker_installed": docker_installed, "protocols": {}}
        changed = False
        if "protocols" not in server:
            server["protocols"] = {}

        import concurrent.futures

        # Each thread gets its own SSH transport — paramiko's exec_command is not safe to call
        # concurrently on a shared client.
        def check_proto(proto):
            proto_ssh = get_ssh(server)
            try:
                proto_ssh.connect()
                p_manager = get_protocol_manager(proto_ssh, proto)
                result = p_manager.get_server_status(proto)
                db_proto = server.get("protocols", {}).get(proto, {})
                if not result.get("port") and db_proto.get("port"):
                    result["port"] = db_proto["port"]
                return proto, result, None
            except Exception as e:
                return proto, None, str(e)
            finally:
                try:
                    proto_ssh.disconnect()
                except Exception:
                    pass

        protocols = ["awg", "awg2", "awg_legacy", "xray", "telemt", "dns", "wireguard"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(protocols)) as executor:
            results = await asyncio.to_thread(lambda: list(executor.map(check_proto, protocols)))

        for proto, result, err in results:
            if err:
                status["protocols"][proto] = {"error": err}
            else:
                status["protocols"][proto] = result
                if result.get("container_exists"):
                    if proto not in server["protocols"]:
                        server["protocols"][proto] = {
                            "installed": True,
                            "port": result.get("port", "55424"),
                            "awg_params": result.get("awg_params", {}),
                        }
                        changed = True
                else:
                    if proto in server["protocols"]:
                        del server["protocols"][proto]
                        changed = True

        if changed:
            await save_data_async(data)

        return status
    except Exception as e:
        logger.exception("Error checking server")
        return JSONResponse({"error": str(e), "connection": "failed"}, status_code=500)


@app.post("/api/servers/{server_id}/install")
async def api_install_protocol(request: Request, server_id: int, req: InstallProtocolRequest):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        if req.protocol not in ["awg", "awg2", "awg_legacy", "xray", "telemt", "dns", "wireguard"]:
            return JSONResponse({"error": "Invalid protocol type"}, status_code=400)

        server = data["servers"][server_id]

        def _install():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, req.protocol)
                if req.protocol == "telemt":
                    return manager.install_protocol(
                        protocol_type=req.protocol,
                        port=req.port,
                        tls_emulation=req.tls_emulation if req.tls_emulation is not None else True,
                        tls_domain=req.tls_domain,
                        max_connections=req.max_connections if req.max_connections is not None else 0,
                    )
                if req.protocol in ("xray", "wireguard"):
                    return manager.install_protocol(port=req.port)
                return manager.install_protocol(req.protocol, port=req.port)
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        result = await asyncio.to_thread(_install)

        server["protocols"][req.protocol] = {
            "installed": True,
            "port": req.port,
            "awg_params": result.get("awg_params", {}),
        }
        await save_data_async(data)
        return result
    except Exception as e:
        logger.exception("Error installing protocol")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/uninstall")
async def api_uninstall_protocol(request: Request, server_id: int, req: ProtocolRequest):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]

        def _uninstall():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, req.protocol)
                manager.remove_container(req.protocol)
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        await asyncio.to_thread(_uninstall)
        if req.protocol in server.get("protocols", {}):
            del server["protocols"][req.protocol]
            await save_data_async(data)
        return {"status": "success"}
    except Exception as e:
        logger.exception("Error uninstalling protocol")
        return JSONResponse({"error": str(e)}, status_code=500)


CONTAINER_NAMES = {
    "awg": "amnezia-awg",
    "awg2": "amnezia-awg2",
    "awg_legacy": "amnezia-awg-legacy",
    "xray": "amnezia-xray",
    "telemt": "telemt",
    "dns": "amnezia-dns",
    "wireguard": "amnezia-wireguard",
}


@app.post("/api/servers/{server_id}/container/toggle")
async def api_container_toggle(request: Request, server_id: int, req: ProtocolRequest):
    """Start or stop a protocol Docker container."""
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        container = CONTAINER_NAMES.get(req.protocol)
        if not container:
            return JSONResponse({"error": "Unknown protocol"}, status_code=400)
        server = data["servers"][server_id]

        def _toggle():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                out, _, _ = ssh.run_sudo_command(f"docker inspect -f '{{{{.State.Running}}}}' {container} 2>/dev/null")
                is_running = out.strip().lower() == "true"
                if is_running:
                    ssh.run_sudo_command(f"docker stop {container}")
                    return "stopped"
                ssh.run_sudo_command(f"docker start {container}")
                return "started"
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        action = await asyncio.to_thread(_toggle)
        return {"status": "success", "action": action, "container": container}
    except Exception as e:
        logger.exception("Error toggling container")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/server_config")
async def api_server_config(request: Request, server_id: int, req: ProtocolRequest):
    """Get the raw server-side WireGuard/Xray configuration."""
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]

        def _get_config():
            from .protocols.telemt import TelemtManager

            ssh = get_ssh(server)
            ssh.connect()
            try:
                if req.protocol == "xray":
                    mgr = XrayManager(ssh)
                    data_json = mgr._get_server_json()
                    return json.dumps(data_json, indent=2, ensure_ascii=False) if data_json else ""
                if req.protocol == "telemt":
                    return TelemtManager(ssh)._get_server_config()
                if req.protocol == "wireguard":
                    return WireGuardManager(ssh)._get_server_config()
                return AWGManager(ssh)._get_server_config(req.protocol)
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        config = await asyncio.to_thread(_get_config)
        return {"config": config}
    except Exception as e:
        logger.exception("Error getting server config")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/server_config/save")
async def api_server_config_save(request: Request, server_id: int, req: ServerConfigSaveRequest):
    """Save the raw server-side WireGuard/Xray configuration and apply changes."""
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]

        if req.protocol == "xray":
            try:
                parsed_json = json.loads(req.config)
            except Exception as e:
                return JSONResponse({"error": f"Invalid JSON format: {e!s}"}, status_code=400)

        def _save_config():
            from .protocols.telemt import TelemtManager

            ssh = get_ssh(server)
            ssh.connect()
            try:
                if req.protocol == "xray":
                    XrayManager(ssh)._save_server_json(parsed_json)
                elif req.protocol == "telemt":
                    TelemtManager(ssh).save_server_config(req.protocol, req.config)
                elif req.protocol == "wireguard":
                    WireGuardManager(ssh).save_server_config(req.config)
                else:
                    AWGManager(ssh).save_server_config(req.protocol, req.config)
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        await asyncio.to_thread(_save_config)
        return {"status": "success"}
    except Exception as e:
        logger.exception("Error saving server config")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/servers/{server_id}/connections")
async def api_get_connections(request: Request, server_id: int, protocol: str = Query(default="awg")):
    if not protocol:
        protocol = "awg"
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]

        def _get_clients():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                return get_protocol_manager(ssh, protocol).get_clients(protocol)
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        clients = await asyncio.to_thread(_get_clients)

        # Enrich with user info from user_connections
        user_conns = data.get("user_connections", [])
        users = data.get("users", [])
        users_map = {u["id"]: u for u in users}
        for client in clients:
            cid = client.get("clientId", "")
            for uc in user_conns:
                if uc.get("client_id") == cid and uc.get("server_id") == server_id and uc.get("protocol") == protocol:
                    uid = uc.get("user_id")
                    u = users_map.get(uid)
                    if u:
                        client["assigned_user"] = u["username"]
                        client["assigned_user_id"] = uid
                    break
        return {"clients": clients}
    except Exception as e:
        logger.exception("Error getting connections")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/connections/add")
async def api_add_connection(request: Request, server_id: int, req: AddConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]
        proto_info = server.get("protocols", {}).get(req.protocol, {})
        port = proto_info.get("port", "55424")

        def _add_client():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, req.protocol)
                if req.protocol == "telemt":
                    return manager.add_client(
                        req.protocol,
                        req.name,
                        server["host"],
                        port,
                        telemt_quota=req.telemt_quota,
                        telemt_max_ips=req.telemt_max_ips,
                        telemt_expiry=req.telemt_expiry,
                        secret=req.telemt_secret,
                        user_ad_tag=req.telemt_ad_tag,
                        max_tcp_conns=req.telemt_max_conns,
                    )
                return manager.add_client(req.protocol, req.name, server["host"], port)
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        result = await asyncio.to_thread(_add_client)

        if result.get("config"):
            result["vpn_link"] = generate_vpn_link(result["config"])

        # Link connection to user if specified
        if req.user_id and result.get("client_id"):
            conn = {
                "id": str(uuid.uuid4()),
                "user_id": req.user_id,
                "server_id": server_id,
                "protocol": req.protocol,
                "client_id": result["client_id"],
                "name": req.name,
                "created_at": datetime.now().isoformat(),
            }
            data["user_connections"].append(conn)
            await save_data_async(data)

        return result
    except Exception as e:
        logger.exception("Error adding connection")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/connections/remove")
async def api_remove_connection(request: Request, server_id: int, req: ConnectionActionRequest):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]
        if not req.client_id:
            return JSONResponse({"error": "Client ID is required"}, status_code=400)

        def _remove():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                get_protocol_manager(ssh, req.protocol).remove_client(req.protocol, req.client_id)
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        await asyncio.to_thread(_remove)
        data["user_connections"] = [
            c
            for c in data.get("user_connections", [])
            if not (c.get("client_id") == req.client_id and c.get("server_id") == server_id)
        ]
        await save_data_async(data)
        return {"status": "success"}
    except Exception as e:
        logger.exception("Error removing connection")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/connections/edit")
async def api_edit_connection(request: Request, server_id: int, req: EditConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]

        edit_params = {}
        if req.protocol == "telemt":
            edit_params["telemt_quota"] = req.telemt_quota
            edit_params["telemt_max_ips"] = req.telemt_max_ips
            edit_params["telemt_expiry"] = req.telemt_expiry
            edit_params["secret"] = req.telemt_secret
            edit_params["user_ad_tag"] = req.telemt_ad_tag
            edit_params["max_tcp_conns"] = req.telemt_max_conns

        def _edit():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                return get_protocol_manager(ssh, req.protocol).edit_client(req.protocol, req.client_id, edit_params)
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        return await asyncio.to_thread(_edit)
    except Exception as e:
        logger.exception("Error editing connection")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/connections/config")
async def api_get_connection_config(request: Request, server_id: int, req: ConnectionActionRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        # Users can only view their own connections
        if user["role"] == "user":
            owned = any(
                c
                for c in data.get("user_connections", [])
                if c.get("client_id") == req.client_id
                and c.get("server_id") == server_id
                and c.get("user_id") == user["id"]
            )
            if not owned:
                return JSONResponse({"error": "Forbidden"}, status_code=403)
        server = data["servers"][server_id]
        if not req.client_id:
            return JSONResponse({"error": "Client ID is required"}, status_code=400)
        proto_info = server.get("protocols", {}).get(req.protocol, {})
        port = proto_info.get("port", "55424")

        def _get_config():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                return get_protocol_manager(ssh, req.protocol).get_client_config(
                    req.protocol, req.client_id, server["host"], port
                )
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        config = await asyncio.to_thread(_get_config)
        vpn_link = generate_vpn_link(config) if config else ""
        return {"config": config, "vpn_link": vpn_link}
    except Exception as e:
        logger.exception("Error getting connection config")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/servers/{server_id}/connections/toggle")
async def api_toggle_connection(request: Request, server_id: int, req: ToggleConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]
        if not req.client_id:
            return JSONResponse({"error": "Client ID is required"}, status_code=400)

        def _toggle():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                get_protocol_manager(ssh, req.protocol).toggle_client(req.protocol, req.client_id, req.enable)
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        await asyncio.to_thread(_toggle)
        status = "enabled" if req.enable else "disabled"
        return {"status": "success", "enabled": req.enable, "message": f"Connection {status}"}
    except Exception as e:
        logger.exception("Error toggling connection")
        return JSONResponse({"error": str(e)}, status_code=500)


# ======================== USER API (admin only) ========================


@app.get("/api/users")
async def api_list_users(request: Request, search: str = "", page: int = 1, size: int = 10):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    data = load_data()
    all_users = data.get("users", [])
    conns = data.get("user_connections", [])

    # Filter
    filtered = []
    search = search.lower()
    for u in all_users:
        if search:
            match = (
                search in u["username"].lower()
                or (u.get("email") and search in u["email"].lower())
                or (u.get("telegramId") and search in str(u["telegramId"]).lower())
            )
            if not match:
                continue
        filtered.append(u)

    total = len(filtered)
    start = (page - 1) * size
    end = start + size
    page_items = filtered[start:end]

    users = []
    for u in page_items:
        users.append(
            {
                "id": u["id"],
                "username": u["username"],
                "role": u["role"],
                "enabled": u.get("enabled", True),
                "created_at": u.get("created_at", ""),
                "telegramId": u.get("telegramId"),
                "email": u.get("email"),
                "description": u.get("description"),
                "connections_count": sum(1 for c in conns if c["user_id"] == u["id"]),
                "traffic_used": u.get("traffic_used", 0),
                "traffic_total": u.get("traffic_total", 0),
                "traffic_limit": u.get("traffic_limit", 0),
                "traffic_reset_strategy": u.get("traffic_reset_strategy", "never"),
                "last_reset_at": u.get("last_reset_at"),
                "share_enabled": u.get("share_enabled", False),
                "share_token": u.get("share_token"),
                "has_share_password": bool(u.get("share_password_hash")),
                "source": "Remnawave" if u.get("remnawave_uuid") else "Local",
            }
        )
    return {"users": users, "total": total, "page": page, "size": size, "pages": (total + size - 1) // size}


@app.post("/api/users/add")
async def api_add_user(request: Request, req: AddUserRequest):
    cur = get_current_user(request)
    if not cur or cur["role"] != "admin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        lang = request.cookies.get("lang", "ru")
        # Check duplicate
        if any(u["username"] == req.username for u in data.get("users", [])):
            return JSONResponse({"error": _t("user_exists", lang)}, status_code=400)
        if req.role not in ("admin", "support", "user"):
            return JSONResponse({"error": "Invalid role"}, status_code=400)
        new_user = {
            "id": str(uuid.uuid4()),
            "username": req.username,
            "password_hash": hash_password(req.password),
            "role": req.role,
            "telegramId": req.telegramId,
            "email": req.email,
            "description": req.description,
            "traffic_limit": int(req.traffic_limit * 1024**3) if req.traffic_limit else 0,
            "traffic_reset_strategy": req.traffic_reset_strategy or "never",
            "traffic_used": 0,
            "traffic_total": 0,
            "last_reset_at": datetime.now().isoformat(),
            "expiration_date": req.expiration_date,
            "enabled": True,
            "created_at": datetime.now().isoformat(),
            "remnawave_uuid": None,
            "share_enabled": False,
            "share_token": secrets.token_urlsafe(16),
            "share_password_hash": None,
        }
        data["users"].append(new_user)
        await save_data_async(data)

        result = {"status": "success", "user_id": new_user["id"]}

        # Auto-create connection if server & protocol specified
        if req.server_id is not None and req.protocol:
            if req.server_id < len(data["servers"]):
                server = data["servers"][req.server_id]
                proto_info = server.get("protocols", {}).get(req.protocol, {})
                port = proto_info.get("port", "55424")
                conn_name = req.connection_name or f"{req.username}_vpn"

                def _add_conn():
                    ssh = get_ssh(server)
                    ssh.connect()
                    try:
                        manager = get_protocol_manager(ssh, req.protocol)
                        if req.protocol == "telemt":
                            return manager.add_client(
                                req.protocol,
                                conn_name,
                                server["host"],
                                port,
                                telemt_quota=req.telemt_quota,
                                telemt_max_ips=req.telemt_max_ips,
                                telemt_expiry=req.telemt_expiry,
                                secret=req.telemt_secret,
                                user_ad_tag=req.telemt_ad_tag,
                                max_tcp_conns=req.telemt_max_conns,
                            )
                        return manager.add_client(req.protocol, conn_name, server["host"], port)
                    finally:
                        try:
                            ssh.disconnect()
                        except Exception:
                            pass

                conn_result = await asyncio.to_thread(_add_conn)

                if conn_result.get("client_id"):
                    conn = {
                        "id": str(uuid.uuid4()),
                        "user_id": new_user["id"],
                        "server_id": req.server_id,
                        "protocol": req.protocol,
                        "client_id": conn_result["client_id"],
                        "name": conn_name,
                        "created_at": datetime.now().isoformat(),
                    }
                    data = load_data()  # reload
                    data["user_connections"].append(conn)
                    await save_data_async(data)
                    result["connection_created"] = True
                    if conn_result.get("config"):
                        result["config"] = conn_result["config"]
                        result["vpn_link"] = generate_vpn_link(conn_result["config"])
        return result
    except Exception as e:
        logger.exception("Error adding user")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/users/{user_id}/update")
async def api_update_user(request: Request, user_id: str, req: UpdateUserRequest):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        user = next((u for u in data["users"] if u["id"] == user_id), None)
        if not user:
            return JSONResponse({"error": "User not found"}, status_code=404)

        if req.telegramId is not None:
            user["telegramId"] = req.telegramId
        if req.email is not None:
            user["email"] = req.email
        if req.description is not None:
            user["description"] = req.description
        if req.traffic_limit is not None:
            new_limit = int(req.traffic_limit * 1024**3)
            user["traffic_limit"] = new_limit

        if req.traffic_reset_strategy is not None:
            user["traffic_reset_strategy"] = req.traffic_reset_strategy
            user["last_reset_at"] = datetime.now().isoformat()

        if req.expiration_date is not None:
            user["expiration_date"] = req.expiration_date or None

        if req.password:
            user["password_hash"] = hash_password(req.password)

        await save_data_async(data)

        # Auto re-enable if traffic limit increased beyond usage
        if req.traffic_limit is not None:
            if new_limit > 0 and user.get("traffic_used", 0) < new_limit and not user.get("enabled", True):
                await perform_toggle_user(data, user_id, True)
                await save_data_async(data)

        return {"status": "success"}
    except Exception as e:
        logger.exception("Error updating user")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/users/{user_id}/delete")
async def api_delete_user(request: Request, user_id: str):
    cur = get_current_user(request)
    if not cur or cur["role"] != "admin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    lang = request.cookies.get("lang", "ru")
    if cur["id"] == user_id:
        return JSONResponse({"error": _t("cannot_delete_self", lang)}, status_code=400)
    try:
        data = load_data()
        success = await perform_delete_user(data, user_id)
        if not success:
            return JSONResponse({"error": "User not found"}, status_code=404)
        await save_data_async(data)
        return {"status": "success"}
    except Exception as e:
        logger.exception("Error deleting user")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/users/{user_id}/toggle")
async def api_toggle_user(request: Request, user_id: str, req: ToggleUserRequest):
    cur = get_current_user(request)
    if not cur or cur["role"] != "admin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        success = await perform_toggle_user(data, user_id, req.enabled)
        if not success:
            return JSONResponse({"error": "User not found"}, status_code=404)
        await save_data_async(data)
        return {"status": "success", "enabled": req.enabled}
    except Exception as e:
        logger.exception("Error toggling user")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/users/{user_id}/connections/add")
async def api_add_user_connection(request: Request, user_id: str, req: AddUserConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        user = next((u for u in data["users"] if u["id"] == user_id), None)
        if not user:
            return JSONResponse({"error": "User not found"}, status_code=404)
        if req.server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][req.server_id]
        proto_info = server.get("protocols", {}).get(req.protocol, {})
        port = proto_info.get("port", "55424")
        ssh = get_ssh(server)
        await asyncio.to_thread(ssh.connect)
        manager = get_protocol_manager(ssh, req.protocol)

        if req.client_id:
            # Use existing client
            target_client_id = req.client_id
            # Retrieve config for existing client
            config = await asyncio.to_thread(
                manager.get_client_config, req.protocol, req.client_id, server["host"], port
            )
            result = {"client_id": target_client_id, "config": config}
        else:
            # Create new client
            if req.protocol == "telemt":
                result = await asyncio.to_thread(
                    manager.add_client,
                    req.protocol,
                    req.name,
                    server["host"],
                    port,
                    telemt_quota=req.telemt_quota,
                    telemt_max_ips=req.telemt_max_ips,
                    telemt_expiry=req.telemt_expiry,
                    secret=req.telemt_secret,
                    user_ad_tag=req.telemt_ad_tag,
                    max_tcp_conns=req.telemt_max_conns,
                )
            else:
                result = await asyncio.to_thread(manager.add_client, req.protocol, req.name, server["host"], port)

        await asyncio.to_thread(ssh.disconnect)

        if result.get("client_id"):
            conn = {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "server_id": req.server_id,
                "protocol": req.protocol,
                "client_id": result["client_id"],
                "name": req.name,
                "created_at": datetime.now().isoformat(),
            }
            data = load_data()
            data["user_connections"].append(conn)
            await save_data_async(data)

        resp = {"status": "success"}
        if result.get("config"):
            resp["config"] = result["config"]
            resp["vpn_link"] = generate_vpn_link(result["config"])
        return resp
    except Exception as e:
        logger.exception("Error adding user connection")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/users/{user_id}/connections")
async def api_get_user_connections(request: Request, user_id: str):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    # Users can only see their own, admin/support can see all
    if user["role"] == "user" and user["id"] != user_id:
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    data = load_data()
    conns = [c for c in data.get("user_connections", []) if c["user_id"] == user_id]
    for c in conns:
        sid = c.get("server_id", 0)
        if sid < len(data["servers"]):
            c["server_name"] = data["servers"][sid].get("name", "")
    return {"connections": conns}


# ======================== MY CONNECTIONS API (for user role) ========================


@app.get("/api/my/connections")
async def api_my_connections(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    data = load_data()
    conns = [c for c in data.get("user_connections", []) if c["user_id"] == user["id"]]
    for c in conns:
        sid = c.get("server_id", 0)
        if sid < len(data["servers"]):
            c["server_name"] = data["servers"][sid].get("name", "")
        else:
            c["server_name"] = "Unknown"
    return {"connections": conns}


@app.post("/api/users/{user_id}/share/setup")
async def api_user_share_setup(user_id: str, req: ShareSetupRequest, request: Request):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    data = load_data()
    user = next((u for u in data["users"] if u["id"] == user_id), None)
    if not user:
        return JSONResponse({"error": "User not found"}, status_code=404)

    user["share_enabled"] = req.enabled
    if not user.get("share_token"):
        user["share_token"] = secrets.token_urlsafe(16)
    if req.password:
        user["share_password_hash"] = hash_password(req.password)
    elif req.password == "":  # Clear
        user["share_password_hash"] = None

    await save_data_async(data)
    return {"status": "success", "share_token": user.get("share_token")}


@app.get("/share/{token}", response_class=HTMLResponse)
async def share_page(token: str, request: Request):
    data = load_data()
    user = next((u for u in data["users"] if u.get("share_token") == token), None)
    if not user or not user.get("share_enabled"):
        lang = request.cookies.get("lang", "ru")
        return HTMLResponse(
            f"<h1>{_t('share_not_found', lang)}</h1><p>{_t('share_not_found_desc', lang)}</p>", status_code=404
        )

    auth_session_key = f"share_auth_{token}"
    need_password = bool(user.get("share_password_hash")) and not request.session.get(auth_session_key)

    return tpl(request, "user_share.html", share_user=user, need_password=need_password, token=token)


@app.post("/api/share/{token}/auth")
async def api_share_auth(token: str, req: ShareAuthRequest, request: Request):
    data = load_data()
    user = next((u for u in data["users"] if u.get("share_token") == token), None)
    if not user or not user.get("share_enabled"):
        return JSONResponse({"error": "Link expired or disabled"}, status_code=404)

    if verify_password(req.password, user.get("share_password_hash", "")):
        request.session[f"share_auth_{token}"] = True
        return {"status": "success"}
    else:
        lang = request.cookies.get("lang", "ru")
        return JSONResponse({"error": _t("wrong_share_password", lang)}, status_code=401)


@app.get("/api/share/{token}/connections")
async def api_share_connections(token: str, request: Request):
    data = load_data()
    user = next((u for u in data["users"] if u.get("share_token") == token), None)
    if not user or not user.get("share_enabled"):
        return JSONResponse({"error": "Forbidden"}, status_code=403)

    if user.get("share_password_hash"):
        if not request.session.get(f"share_auth_{token}"):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conns = [dict(c) for c in data.get("user_connections", []) if c["user_id"] == user["id"]]
    for c in conns:
        sid = c["server_id"]
        if sid < len(data["servers"]):
            c["server_name"] = data["servers"][sid].get("name") or data["servers"][sid]["host"]
        else:
            c["server_name"] = "Unknown"

    return {"connections": conns, "username": user["username"]}


@app.post("/api/share/{token}/config/{connection_id}")
async def api_share_config(token: str, connection_id: str, request: Request):
    data = load_data()
    user = next((u for u in data["users"] if u.get("share_token") == token), None)
    if not user or not user.get("share_enabled"):
        return JSONResponse({"error": "Forbidden"}, status_code=403)

    if user.get("share_password_hash"):
        if not request.session.get(f"share_auth_{token}"):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = next(
        (c for c in data.get("user_connections", []) if c["id"] == connection_id and c["user_id"] == user["id"]), None
    )
    if not conn:
        return JSONResponse({"error": "Not found"}, status_code=404)

    try:
        sid = conn["server_id"]
        server = data["servers"][sid]
        proto_info = server.get("protocols", {}).get(conn["protocol"], {})
        port = proto_info.get("port", "55424")

        def _get_config():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                return get_protocol_manager(ssh, conn["protocol"]).get_client_config(
                    conn["protocol"], conn["client_id"], server["host"], port
                )
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        config = await asyncio.to_thread(_get_config)
        vpn_link = generate_vpn_link(config) if config else ""
        return {"config": config, "vpn_link": vpn_link}
    except Exception as e:
        logger.exception("Error getting shared config")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/my/connections/{connection_id}/config")
async def api_my_connection_config(request: Request, connection_id: str):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        conn = next(
            (c for c in data.get("user_connections", []) if c["id"] == connection_id and c["user_id"] == user["id"]),
            None,
        )
        if not conn:
            return JSONResponse({"error": "Connection not found"}, status_code=404)
        sid = conn["server_id"]
        if sid >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][sid]
        proto_info = server.get("protocols", {}).get(conn["protocol"], {})
        port = proto_info.get("port", "55424")

        def _get_config():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                return get_protocol_manager(ssh, conn["protocol"]).get_client_config(
                    conn["protocol"], conn["client_id"], server["host"], port
                )
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        config = await asyncio.to_thread(_get_config)
        vpn_link = generate_vpn_link(config) if config else ""
        return {"config": config, "vpn_link": vpn_link}
    except Exception as e:
        logger.exception("Error getting my connection config")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/settings")
async def settings_page(request: Request):
    user = _check_admin(request)
    if not user:
        return RedirectResponse("/login")
    data = load_data()
    return tpl(
        request,
        "settings.html",
        settings=data.get("settings", {}),
        servers=data.get("servers", []),
        current_version=CURRENT_VERSION,
    )


@app.get("/api/settings")
async def api_get_settings(request: Request):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    data = load_data()
    return data.get("settings", {})


# @app.post('/api/settings/save')
# async def api_save_settings(request: Request, body: SaveSettingsRequest):
#     _check_admin(request)
#     data = load_data()
#     data['settings'] = body.dict()
#     await save_data_async(data)

#     # Trigger sync if enabled
#     if body.sync.remnawave_sync_users:
#         await sync_users_with_remnawave(data)
#         await save_data_async(data)

#     return {'status': 'success'}


@app.post("/api/settings/save")
async def save_settings(request: Request, payload: SaveSettingsRequest):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    data = load_data()
    data["settings"]["appearance"] = payload.appearance.dict()
    data["settings"]["sync"] = payload.sync.dict()
    data["settings"]["captcha"] = payload.captcha.dict()
    data["settings"]["telegram"] = payload.telegram.dict()
    data["settings"]["ssl"] = payload.ssl.dict()
    await save_data_async(data)
    logger.info("Settings saved (including captcha and telegram)")

    # Handle bot start/stop based on new telegram settings
    tg_cfg = payload.telegram
    if tg_cfg.enabled and tg_cfg.token:
        if not tg_bot.is_running():
            logger.info("Starting Telegram bot (settings save)...")
            tg_bot.launch_bot(tg_cfg.token, load_data, generate_vpn_link)
    else:
        if tg_bot.is_running():
            logger.info("Stopping Telegram bot (settings save)...")
            task = asyncio.create_task(tg_bot.stop_bot())
            _BACKGROUND_TASKS.add(task)
            task.add_done_callback(_BACKGROUND_TASKS.discard)

    return {"status": "success", "bot_running": tg_bot.is_running()}


@app.post("/api/settings/telegram/toggle")
async def api_telegram_toggle(request: Request):
    """Quick enable/disable of the bot without a full settings save."""
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    data = load_data()
    tg_cfg = data.get("settings", {}).get("telegram", {})
    token = tg_cfg.get("token", "")
    if not token:
        return JSONResponse({"error": "Telegram token not set in settings"}, status_code=400)

    if tg_bot.is_running():
        await tg_bot.stop_bot()
        tg_cfg["enabled"] = False
        data["settings"]["telegram"] = tg_cfg
        await save_data_async(data)
        return {"status": "stopped", "bot_running": False}
    else:
        tg_bot.launch_bot(token, load_data, generate_vpn_link)
        tg_cfg["enabled"] = True
        data["settings"]["telegram"] = tg_cfg
        await save_data_async(data)
        return {"status": "started", "bot_running": True}


@app.post("/api/settings/sync_now")
async def api_sync_now(request: Request):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    data = load_data()
    count, msg = await sync_users_with_remnawave(data)
    return {"status": "success", "count": count, "message": msg}


@app.post("/api/settings/sync_delete")
async def api_sync_delete(request: Request):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    data = load_data()
    to_delete_ids = [u["id"] for u in data["users"] if u.get("remnawave_uuid")]
    if to_delete_ids:
        await perform_mass_operations(delete_uids=to_delete_ids)
    return {"status": "success", "count": len(to_delete_ids)}


@app.get("/api/servers/{server_id}/{protocol}/clients")
async def api_get_server_clients(request: Request, server_id: int, protocol: str):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data["servers"]):
            return JSONResponse({"error": "Server not found"}, status_code=404)
        server = data["servers"][server_id]

        def _get_clients():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                return get_protocol_manager(ssh, protocol).get_clients(protocol)
            finally:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        clients = await asyncio.to_thread(_get_clients)

        # Filter: only show clients that are not assigned to anyone in the panel
        assigned_ids = {
            c["client_id"]
            for c in data.get("user_connections", [])
            if c["server_id"] == server_id and c["protocol"] == protocol
        }

        filtered = []
        for c in clients:
            if c["clientId"] not in assigned_ids:
                filtered.append({"id": c["clientId"], "name": c.get("userData", {}).get("clientName", "Unnamed")})

        return {"clients": filtered}
    except Exception as e:
        logger.exception("Error getting server clients")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/settings/backup/download")
async def api_backup_download(request: Request):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    if not os.path.exists(DATA_FILE):
        return JSONResponse({"error": "Data file not found"}, status_code=404)
    return FileResponse(DATA_FILE, media_type="application/json", filename="data.json")


@app.post("/api/settings/backup/restore")
async def api_backup_restore(request: Request, file: UploadFile = File(...)):
    if not _check_admin(request):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    try:
        content = await file.read()
        if not content:
            return JSONResponse({"error": "Empty file"}, status_code=400)

        try:
            backup_data = json.loads(content)
        except json.JSONDecodeError:
            return JSONResponse({"error": "Invalid JSON format"}, status_code=400)

        # Basic structure validation
        required_keys = ["servers", "users"]
        missing = [k for k in required_keys if k not in backup_data]
        if missing:
            return JSONResponse({"error": f"Invalid structure. Missing keys: {', '.join(missing)}"}, status_code=400)

        # Ensure types are correct
        if not isinstance(backup_data["servers"], list) or not isinstance(backup_data["users"], list):
            return JSONResponse({"error": "Invalid structure: servers and users must be lists"}, status_code=400)

        _apply_schema_migrations(backup_data)

        async with DATA_LOCK:
            await asyncio.to_thread(save_data, backup_data)

        return {"status": "success"}
    except Exception as e:
        logger.exception("Error during restore")
        return JSONResponse({"error": str(e)}, status_code=500)
