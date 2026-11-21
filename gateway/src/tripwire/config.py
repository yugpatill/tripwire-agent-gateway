"""Runtime settings, loaded from environment variables (see .env.example)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://tripwire:tripwire@localhost:5432/tripwire"
    redis_url: str = "redis://localhost:6379/0"

    tripwire_policy_path: str = "policies/demo.yaml"
    tripwire_classifier_dir: str = "models/injection-deberta"
    tripwire_llm_judge_enabled: bool = False
    tripwire_mode: Literal["enforce", "shadow"] = "enforce"

    jwt_secret: SecretStr = SecretStr("change-me")
    admin_email: str = ""
    admin_password: SecretStr = SecretStr("")
    demo_readonly_password: SecretStr = SecretStr("")

    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    playground_provider: Literal["anthropic", "openai"] = "anthropic"
    playground_model: str = ""
    playground_daily_run_cap: int = 200

    anthropic_api_key: SecretStr = SecretStr("")
    openai_api_key: SecretStr = SecretStr("")

    otel_exporter_otlp_endpoint: str = ""
    log_level: str = "INFO"
    log_json: bool = True

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str) and not v.strip().startswith("["):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
