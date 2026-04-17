import os
import secrets
import sys
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _base_dir() -> Path:
    """Repo root when running from source; extracted bundle root when frozen."""
    if getattr(sys, 'frozen', False):
        return Path(getattr(sys, '_MEIPASS', os.path.dirname(sys.executable)))
    return Path(__file__).resolve().parents[2]


def _application_path() -> Path:
    """Where runtime state (data.json default) lives when DATA_DIR is unset."""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return _base_dir()


class Settings(BaseSettings):
    # env_file is resolved relative to the repo root so `amnezia-panel` works from any CWD.
    # In Docker the file won't exist (we don't COPY it in); pydantic-settings silently falls back to the
    # process environment, which is exactly what docker compose provides via its `environment:` block.
    model_config = SettingsConfigDict(
        env_file=_base_dir() / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    panel_host: str = "0.0.0.0"
    panel_port: int = 5000
    secret_key: str = Field(default_factory=lambda: secrets.token_hex(32))
    data_dir: Path = Field(default_factory=_application_path)
    assets_dir: Path = Field(default_factory=lambda: _base_dir() / "assets")

    @field_validator("secret_key", mode="before")
    @classmethod
    def _regenerate_if_blank(cls, v: str | None) -> str:
        # Treat an unset or empty SECRET_KEY (e.g. `SECRET_KEY=` in .env forwarded by compose)
        # as "not provided" and mint a per-process one. Sessions invalidate on restart.
        return v or secrets.token_hex(32)

    @property
    def data_file(self) -> Path:
        return self.data_dir / "data.json"

    @property
    def ssl_temp_dir(self) -> Path:
        return self.data_dir / "ssl_temp"


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
