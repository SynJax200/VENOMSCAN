from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(ROOT_DIR / ".env",),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "VENOMSCAN"
    environment: str = "development"
    api_base: str = "http://127.0.0.1:8000"
    seed_target_url: str = ""
    web_base: str = "http://localhost:3000"
    secret_key: str = "dev-only-change-me-venomscan-secret-key"
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    cookie_secure: bool = False
    access_token_minutes: int = 480
    refresh_token_days: int = 14
    login_max_attempts: int = 5
    login_ip_max_attempts: int = 20
    login_window_seconds: int = 300
    login_lockout_seconds: int = 900
    login_state_backend: str = "memory"
    redis_url: str = ""
    allow_registration: bool = True

    database_url: str = "postgresql+psycopg://venom:venom@127.0.0.1:55432/venomscan"

    allow_private_targets: bool = False
    scan_default_profile: str = "safe"
    scan_max_requests: int = 120
    scan_max_seconds: int = 90
    scan_rps: float = 4.0
    scan_osint_enabled: bool = True
    scan_history_enabled: bool = True
    scan_spa_enabled: bool = False
    scan_dirs_enabled: bool = True
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    otx_api_key: str = ""
    oob_enabled: bool = True
    oob_bind_host: str = "127.0.0.1"
    oob_bind_port: int = 0
    oob_public_base_url: str = ""
    task_mode: str = "inline"

    llm_provider: str = "openai_compat"
    llm_model: str = "gpt-4o-mini"
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_timeout: float = 30.0
    llm_retries: int = 1
    ai_cache_ttl_seconds: int = 900
    ai_auto_triage: bool = True
    ai_report_autofill: bool = True

    report_link_hours: int = 168
    upstream_proxy_url: str = ""
    nuclei_enabled: bool = False
    nuclei_binary: str = ""
    nuclei_templates: str = ""
    nuclei_severities: str = "info,low,medium"
    nuclei_rate_limit: int = 10
    nuclei_timeout: int = 60
    plugin_dirs: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
