from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SECRET_KEY = "CHANGE_ME_dev_secret_key"


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    APP_NAME: str = "SentinelTrap - AICD-TIP"
    APP_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    DEBUG: bool = False

    # Security
    SECRET_KEY: str = DEFAULT_SECRET_KEY  # override in production via env
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120
    BCRYPT_ROUNDS: int = 12

    # Database
    DATABASE_URL: str = (
        "postgresql+psycopg://sentinel:sentinel_dev_2026@localhost:5432/sentineltrap"
    )

    # CORS (comma-separated string)
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    @property
    def cors_origins_list(self):
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    # Honeypot
    HONEYPOT_COWRIE_LOG_PATH: str = "honeypot/cowrie/logs"
    HONEYPOT_COWRIE_JSONL: str = "honeypot/cowrie/logs/cowrie.json"
    HONEYPOT_POLL_INTERVAL: int = 5

    # ML
    ML_MODELS_DIR: str = "ml/models"
    ML_FEATURES_DIR: str = "ml/features"
    ML_DATA_DIR: str = "ml/data"
    ACTIVE_CLASSIFIER: str = "random_forest"
    ACTIVE_ANOMALY: str = "isolation_forest"
    ACTIVE_SEQUENCE: str = "markov"

    # Risk engine
    RISK_WEIGHTS: str = (
        "anomaly:0.30,behaviour:0.25,sequence:0.15,resource:0.15,persistence:0.15"
    )


@lru_cache()
def get_settings() -> Settings:
    settings = Settings()
    if not settings.DEBUG and settings.SECRET_KEY == DEFAULT_SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY must be overridden for a non-debug deployment. "
            "Set the SECRET_KEY environment variable to a strong random value."
        )
    return settings
