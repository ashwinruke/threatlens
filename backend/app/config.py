"""All settings come from environment variables (or a local .env file).

Keeping settings in one place means secrets never get hard-coded in the code.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ThreatLens API"
    app_version: str = "0.3.0"
    app_env: str = "development"

    database_url: str = ""
    cors_origins: str = "http://localhost:5173"

    # Threat intelligence source keys
    nvd_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    virustotal_api_key: str = ""
    abusech_auth_key: str = ""

    # AI report writer: Gemini first, Groq as backup
    gemini_api_key: str = ""
    groq_api_key: str = ""
    gemini_model: str = "gemini-3-flash-preview"
    groq_model: str = "openai/gpt-oss-120b"
    # Which AI to try first. Change the order if one provider becomes more reliable.
    ai_provider_order: str = "groq,gemini"
    ai_timeout_seconds: float = 45.0
    ai_report_cache_hours: int = 6

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
