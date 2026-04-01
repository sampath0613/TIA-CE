"""Application configuration using pydantic-settings."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings sourced from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = Field(default="Threat Intel Aggregator")
    app_env: Literal["development", "staging", "production"] = Field(default="development")
    log_level: str = Field(default="INFO")

    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    threat_intel_api_key: str = Field(default="change-me")
    enable_api_key_auth: bool = Field(default=True)

    database_host: str = Field(default="localhost")
    database_port: int = Field(default=5432)
    database_name: str = Field(default="threatintel")
    database_user: str = Field(default="threatintel")
    database_password: str = Field(default="threatintel")
    database_echo: bool = Field(default=False)
    database_url: str | None = Field(default=None)

    otx_api_key: str | None = Field(default=None)

    ingest_interval_otx: int = Field(default=60)
    ingest_interval_urlhaus: int = Field(default=30)
    ingest_interval_feodo: int = Field(default=120)
    ingest_interval_emerging: int = Field(default=240)
    enable_scheduler: bool = Field(default=True)

    default_weight_alienvault_otx: float = Field(default=0.65)
    default_weight_urlhaus: float = Field(default=0.80)
    default_weight_feodo_tracker: float = Field(default=0.90)
    default_weight_emerging_threats: float = Field(default=0.70)

    default_lambda_ip: float = Field(default=0.015)
    default_lambda_domain: float = Field(default=0.008)
    default_lambda_url: float = Field(default=0.020)
    default_lambda_hash: float = Field(default=0.002)

    dashboard_auto_refresh_seconds: int = Field(default=60)

    @property
    def sqlalchemy_async_database_uri(self) -> str:
        """Return the SQLAlchemy async database URI."""
        if self.database_url:
            return self.database_url
        return (
            "postgresql+asyncpg://"
            f"{self.database_user}:{self.database_password}@"
            f"{self.database_host}:{self.database_port}/{self.database_name}"
        )

    @model_validator(mode="after")
    def validate_security_requirements(self) -> Settings:
        """Validate settings combinations that are unsafe for production."""
        if (
            self.app_env == "production"
            and self.enable_api_key_auth
            and not self.threat_intel_api_key
        ):
            raise ValueError("THREAT_INTEL_API_KEY must be set in production.")
        if self.app_env == "production" and not self.otx_api_key:
            # OTX is optional operationally, but if enabled this should be configured.
            pass
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
