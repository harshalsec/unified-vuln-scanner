from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_NAME: str = "Unified Vulnerability Scanner"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_PREFIX: str = "/api/v1"

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/vuln_scanner"

    SECRET_KEY: str = "27291531598-Soham-Harshal-Harshwardhan-2005/11/11-2004/03/04-2004/12/30"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    RATE_LIMIT_PER_MINUTE: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

@lru_cache()
def get_settings() -> Settings:
    return Settings()