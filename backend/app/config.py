from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ThreatLens API"
    app_version: str = "0.2.0"
    app_env: str = "development"

    database_url: str = ""
    cors_origins: str = "http://localhost:5173"

    # Threat intelligence source keys
    nvd_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    virustotal_api_key: str = ""
    abusech_auth_key: str = ""

    # AI keys (used from Day 3)
    gemini_api_key: str = ""
    groq_api_key: str = ""

    # Investigation behaviour
    source_timeout_seconds: float = 15.0
    cache_hours_cve: int = 24
    cache_hours_ioc: int = 6
    max_query_length: int = 500

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
