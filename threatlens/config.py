"""Typed, validated application configuration.

Settings come from environment variables prefixed ``THREATLENS_`` and an optional ``.env``.
Invalid values fail fast at startup with a clear message. No secrets are needed for local
use: session tokens are generated per login and never derived from a static key.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LOOPBACK_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


def _is_loopback(host: str) -> bool:
    if host in LOOPBACK_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="THREATLENS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["development", "test", "production"] = "development"
    data_dir: Path = Path("data")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    session_idle_minutes: int = Field(30, ge=1, le=24 * 60)
    session_absolute_hours: int = Field(8, ge=1, le=72)

    login_max_failures: int = Field(5, ge=1, le=100)
    login_lockout_minutes: int = Field(15, ge=1, le=24 * 60)
    global_login_failures_per_minute: int = Field(30, ge=1, le=10_000)

    max_upload_mb: int = Field(10, ge=1, le=200)
    max_records: int = Field(50_000, ge=1, le=1_000_000)
    max_field_chars: int = Field(4_096, ge=64, le=65_536)
    max_import_seconds: int = Field(60, ge=1, le=3_600)

    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = Field("llama3.2:3b", min_length=1, max_length=128)
    ollama_embed_model: str = Field("nomic-embed-text", min_length=1, max_length=128)
    ollama_timeout_seconds: float = Field(600.0, gt=0, le=1800)
    ollama_max_retries: int = Field(2, ge=0, le=5)
    ollama_num_ctx: int = Field(8192, ge=1024, le=131_072)
    ollama_num_predict: int = Field(2048, ge=128, le=16_384)
    allow_remote_ollama: bool = False

    ai_max_events: int = Field(15, ge=1, le=500)
    ai_max_field_chars: int = Field(300, ge=32, le=4_096)
    ai_requests_per_user_per_hour: int = Field(30, ge=1, le=1_000)

    enable_vector_search: bool = True

    # Separation of duties: the proposer of a response action may not approve it.
    response_require_two_person: bool = True

    @field_validator("ollama_host")
    @classmethod
    def _validate_ollama_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("ollama_host must be an http(s) URL with a hostname")
        if parsed.username or parsed.password:
            raise ValueError("ollama_host must not contain credentials")
        return value.rstrip("/")

    @model_validator(mode="after")
    def _enforce_loopback(self) -> Settings:
        host = urlparse(self.ollama_host).hostname or ""
        if not self.allow_remote_ollama and not _is_loopback(host):
            raise ValueError(
                "ollama_host is not a loopback address; set THREATLENS_ALLOW_REMOTE_OLLAMA=true "
                "only if you deliberately trust that host"
            )
        return self

    @property
    def db_path(self) -> Path:
        return self.data_dir / "threatlens.db"

    @property
    def chroma_dir(self) -> Path:
        return self.data_dir / "chroma"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
