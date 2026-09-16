"""Application configuration (PRD 8.4, 9).

Nothing here can widen the scope boundary: the allowed private ranges live in
``app.guard.ranges`` as code constants and are deliberately not configurable.
"""

from __future__ import annotations

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_NAME = "ScanLedger"
APP_VERSION = "0.1.0"
REPOSITORY_URL = "https://github.com/AdrielU2605/ScanLedger"
USER_AGENT = f"{APP_NAME}/{APP_VERSION} (+{REPOSITORY_URL})"

LOOPBACK_BIND_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANLEDGER_", env_file=".env", extra="ignore")

    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    allow_non_loopback_bind: bool = False
    database_url: str = "sqlite+aiosqlite:///./scanledger.db"

    @model_validator(mode="after")
    def _require_acknowledgement_for_non_loopback_bind(self) -> Settings:
        if self.bind_host not in LOOPBACK_BIND_HOSTS and not self.allow_non_loopback_bind:
            raise ValueError(
                f"refusing to bind to {self.bind_host!r}: a non-loopback bind exposes the "
                "scanner's API to your network and requires "
                "SCANLEDGER_ALLOW_NON_LOOPBACK_BIND=true as an explicit "
                "insecure-development acknowledgement (PRD 8.4)"
            )
        return self


class ProviderSettings(BaseSettings):
    """Optional provider credentials. Absence is a supported, tested state."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    nvd_api_key: str | None = None

    @property
    def nvd_key_configured(self) -> bool:
        return bool(self.nvd_api_key)
