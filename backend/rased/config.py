"""Application settings loaded from environment variables (prefix ``RASED_``) or a ``.env`` file.

No secret has a default value: the database URL (which contains the DB password) must be
provided by the operator, e.g. through the ``.env`` file written by ``scripts/setup.ps1``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RASED_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- storage -----------------------------------------------------------------------
    database_url: str = Field(
        description="SQLAlchemy URL, e.g. postgresql+psycopg://rased:<password>@127.0.0.1:5432/rased"
    )
    db_pool_size: int = Field(default=10, ge=1, le=100)
    db_max_overflow: int = Field(default=5, ge=0, le=100)

    # --- web / sessions ------------------------------------------------------------------
    cookie_secure: bool = True
    session_absolute_minutes: int = Field(default=480, ge=5, le=7 * 24 * 60)
    session_idle_minutes: int = Field(default=60, ge=5, le=24 * 60)
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_lockout_minutes: int = Field(default=15, ge=1, le=24 * 60)
    login_rate_per_minute: int = Field(default=10, ge=1, le=1000)
    api_rate_per_minute: int = Field(default=600, ge=10, le=100000)
    password_min_length: int = Field(default=12, ge=8, le=128)
    frontend_dist: Path | None = None

    # --- scanning safety -------------------------------------------------------------------
    allow_public_scopes: bool = False
    max_scope_hosts: int = Field(default=65536, ge=1, le=1 << 20)
    max_concurrent_jobs: int = Field(default=2, ge=1, le=16)
    resume_interrupted: bool = True
    scheduler_enabled: bool = True
    scheduler_tick_seconds: float = Field(default=30.0, ge=1.0, le=3600.0)

    # --- credential vault ------------------------------------------------------------------
    # Fernet key (urlsafe base64, 32 bytes) used to encrypt stored credentials. Generate with:
    #   python -m rased gen-secret-key
    secret_key: str | None = None
    remote_exec_timeout_seconds: int = Field(default=90, ge=5, le=600)

    # --- logging -------------------------------------------------------------------------
    log_level: str = "INFO"
    log_dir: Path | None = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # values come from the environment
