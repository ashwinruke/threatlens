from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ThreatLens API"
    app_version: str = "0.1.0"
    app_env: str = "development"

    database_url: str = ""
    cors_origins: str = "http://localhost:5173"

    nvd_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    virustotal_api_key: str = ""
    abusech_auth_key: str = ""
    gemini_api_key: str = ""
    groq_api_key: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
