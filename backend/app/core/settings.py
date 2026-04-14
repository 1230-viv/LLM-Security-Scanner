from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parents[2]
ENV_FILES = (BACKEND_DIR / ".env", BACKEND_DIR.parent / ".env")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=tuple(str(path) for path in ENV_FILES),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    project_name: str = Field(default="LLM Security Scanner")
    environment: str = Field(default="development")

    backend_host: str = Field(default="0.0.0.0")
    backend_port: int = Field(default=8000)
    backend_cors_origins: str = Field(default="http://localhost:5173,http://localhost:3000")

    database_url: str = Field(
        default=(
            "postgresql+asyncpg://postgres.project-ref:your-db-password@"
            "aws-0-your-region.pooler.supabase.com:6543/postgres"
        )
    )

    api_auth_token: str = Field(default="change-me")
    encryption_key: str = Field(default="")
    api_rate_limit_per_minute: int = Field(default=120)
    log_level: str = Field(default="INFO")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]

    @property
    def resolved_encryption_key(self) -> str:
        if self.encryption_key:
            return self.encryption_key
        # Stable fallback key for local development only.
        return "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="


@lru_cache
def get_settings() -> Settings:
    return Settings()
