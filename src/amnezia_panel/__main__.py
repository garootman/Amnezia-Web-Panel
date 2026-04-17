import logging
import os

import uvicorn

from .app import app, load_data
from .config import settings

logger = logging.getLogger(__name__)


def _write_secret(path: str, content: str) -> None:
    """Write a file (0o600) — for TLS private keys and other credentials."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)


def main() -> None:
    data = load_data()
    ssl_conf = data.get("settings", {}).get("ssl", {})

    cert_file = ssl_conf.get("cert_path")
    key_file = ssl_conf.get("key_path")

    if ssl_conf.get("enabled") and (ssl_conf.get("cert_text") or ssl_conf.get("key_text")):
        settings.ssl_temp_dir.mkdir(parents=True, exist_ok=True)
        if ssl_conf.get("cert_text"):
            cert_file = str(settings.ssl_temp_dir / "cert.pem")
            _write_secret(cert_file, ssl_conf["cert_text"].strip() + "\n")
        if ssl_conf.get("key_text"):
            key_file = str(settings.ssl_temp_dir / "key.pem")
            _write_secret(key_file, ssl_conf["key_text"].strip() + "\n")

    uvicorn_kwargs = {
        "app": app,
        "host": settings.panel_host,
        "port": settings.panel_port,
    }

    if ssl_conf.get("enabled") and cert_file and key_file:
        if os.path.exists(cert_file) and os.path.exists(key_file):
            logger.info(f"Starting panel with HTTPS on {ssl_conf.get('domain')} at port {settings.panel_port}")
            uvicorn_kwargs["ssl_certfile"] = cert_file
            uvicorn_kwargs["ssl_keyfile"] = key_file
        else:
            logger.error("SSL certificates not found at specified paths. Starting with HTTP.")

    uvicorn.run(**uvicorn_kwargs)


if __name__ == "__main__":
    main()
