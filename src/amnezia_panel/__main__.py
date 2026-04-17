import logging
import os

import uvicorn

from .app import app, load_data
from .config import settings

logger = logging.getLogger(__name__)


def main() -> None:
    data = load_data()
    ssl_conf = data.get("settings", {}).get("ssl", {})

    cert_file = ssl_conf.get("cert_path")
    key_file = ssl_conf.get("key_path")

    if ssl_conf.get("enabled") and (ssl_conf.get("cert_text") or ssl_conf.get("key_text")):
        settings.ssl_temp_dir.mkdir(parents=True, exist_ok=True)
        if ssl_conf.get("cert_text"):
            cert_file = str(settings.ssl_temp_dir / "cert.pem")
            with open(cert_file, "w") as f:
                f.write(ssl_conf["cert_text"].strip() + "\n")
        if ssl_conf.get("key_text"):
            key_file = str(settings.ssl_temp_dir / "key.pem")
            with open(key_file, "w") as f:
                f.write(ssl_conf["key_text"].strip() + "\n")

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
