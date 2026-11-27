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
    tripwire_classifier_dir: str = "models/injection-classifier"
    tripwire_llm_judge_enabled: bool = False
    tripwire_llm_judge_model: str = ""  # required when the judge is enabled
    tripwire_llm_judge_timeout_s: float = 5.0
    tripwire_pii_mode: Literal["patterns", "ner", "off"] = "patterns"
    tripwire_classifier_threads: int = 2  # onnxruntime intra_op_num_threads
    tripwire_mode: Literal["enforce", "shadow"] = "enforce"

    # MCP proxy (docs/mcp.md)
    tripwire_mcp_upstreams: str = "mcp/upstreams.yaml"
    tripwire_approval_timeout_s: float = 120.0
    # Host/Origin allow-lists for /v1/mcp (DNS-rebinding protection of the SDK).
    tripwire_mcp_allowed_hosts: list[str] = Field(
        default_factory=lambda: ["localhost:*", "127.0.0.1:*", "[::1]:*", "gateway:*"]
    )
    tripwire_mcp_allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:*", "http://127.0.0.1:*", "http://[::1]:*"]
    )

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

    @field_validator(
        "cors_origins", "tripwire_mcp_allowed_hosts", "tripwire_mcp_allowed_origins", mode="before"
    )
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str) and not v.strip().startswith("["):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
