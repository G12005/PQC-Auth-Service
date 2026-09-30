import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Post-Quantum Authentication Service"
    API_V1_STR: str = "/auth"
    
    # Google Apps Script Web App Integration
    GOOGLE_APPS_SCRIPT_URL: str = os.getenv("GOOGLE_APPS_SCRIPT_URL", "")
    GOOGLE_APPS_SCRIPT_API_KEY: str = os.getenv("GOOGLE_APPS_SCRIPT_API_KEY", "")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
