"""Encryption-at-rest for credential fields stored in data.json.

Load transparently decrypts; save transparently encrypts. Both operations are
idempotent — encrypting an already-encrypted value or decrypting a plaintext
value is a no-op, so mixed-state data (during migration) stays consistent.

The key lives next to data.json in `data.key` (0o600). Threat model covers
leaked backups and data.json being shared in support channels; it does NOT
cover an attacker with filesystem access — they can read data.key too.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .config import settings

logger = logging.getLogger(__name__)

_ENC_PREFIX = "enc:v1:"
_KEY_FILE: Path = settings.data_dir / "data.key"
_cipher: Fernet | None = None

SECRET_PATHS: tuple[tuple[str, ...], ...] = (
    ("servers", "*", "password"),
    ("servers", "*", "private_key"),
    ("settings", "sync", "remnawave_api_key"),
)


def _load_or_create_key() -> Fernet:
    global _cipher
    if _cipher is not None:
        return _cipher
    if _KEY_FILE.exists():
        key = _KEY_FILE.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        fd = os.open(_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        logger.info(f"Generated encryption-at-rest key at {_KEY_FILE}")
    _cipher = Fernet(key)
    return _cipher


def encrypt(value: str) -> str:
    if not value or not isinstance(value, str) or value.startswith(_ENC_PREFIX):
        return value
    token = _load_or_create_key().encrypt(value.encode("utf-8")).decode("ascii")
    return _ENC_PREFIX + token


def decrypt(value: str) -> str:
    if not isinstance(value, str) or not value.startswith(_ENC_PREFIX):
        return value
    payload = value[len(_ENC_PREFIX) :].encode("ascii")
    try:
        return _load_or_create_key().decrypt(payload).decode("utf-8")
    except InvalidToken:
        logger.warning("Credential decryption failed; field cleared. Re-enter the credential.")
        return ""


def _walk(data: dict, path: tuple[str, ...], fn) -> None:
    def _recurse(node, parts):
        if not parts:
            return
        head, *rest = parts
        if head == "*":
            if isinstance(node, list):
                for item in node:
                    _recurse(item, rest)
            return
        if not isinstance(node, dict) or head not in node:
            return
        if not rest:
            val = node[head]
            if isinstance(val, str):
                node[head] = fn(val)
            return
        _recurse(node[head], rest)

    _recurse(data, path)


def encrypt_in_place(data: dict) -> None:
    for path in SECRET_PATHS:
        _walk(data, path, encrypt)


def decrypt_in_place(data: dict) -> None:
    for path in SECRET_PATHS:
        _walk(data, path, decrypt)


def has_plaintext_secrets_on_disk() -> bool:
    """True if data.json contains a non-empty secret field without the encryption prefix."""
    path = settings.data_file
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    found = [False]

    def _check(v: str) -> str:
        if v and not v.startswith(_ENC_PREFIX):
            found[0] = True
        return v

    for p in SECRET_PATHS:
        _walk(data, p, _check)
    return found[0]
