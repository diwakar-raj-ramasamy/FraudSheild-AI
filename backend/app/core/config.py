import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator

class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True, env_file=".env", extra="ignore")

    PROJECT_NAME: str = "FraudShield AI"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    API_V1_STR: str = "/api"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "fraudshield-super-secret-key-change-in-production-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    @field_validator("SECRET_KEY", mode="after")
    @classmethod
    def validate_production_secret(cls, v: str) -> str:
        """
        Enforces cryptographic entropy in production environments.
        Refuses to start if a default insecure key is used.
        """
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env == "production":
            insecure_defaults = [
                "fraudshield-super-secret-key-change-in-production-2026",
                "secret",
                "changeme",
                "admin",
                "password"
            ]
            if v in insecure_defaults or len(v) < 32:
                raise ValueError(
                    "SECURITY FATAL: Insecure or default SECRET_KEY detected in production environment! "
                    "You must configure a high-entropy secret (minimum 32 bytes) via the SECRET_KEY environment variable."
                )
        return v
    
    # Database (defaults to local SQLite for zero-config run, supports PostgreSQL via env)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./fraudshield.db")

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def resolve_sqlite_path(cls, v: str) -> str:
        """
        Anchors relative SQLite database paths to the project root directory
        so database access is 100% consistent regardless of execution working directory.
        """
        if isinstance(v, str) and v.startswith("sqlite:///./"):
            rel_file = v[len("sqlite:///./"):]
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            db_path = os.path.join(base_dir, rel_file).replace("\\", "/")
            return f"sqlite:///{db_path}"
        elif isinstance(v, str) and v == "sqlite:///fraudshield.db":
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            db_path = os.path.join(base_dir, "fraudshield.db").replace("\\", "/")
            return f"sqlite:///{db_path}"
        return v
    
    # CORS (Strict allowed origins - no wildcard origins)
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]
    
    # Threat Intelligence API keys (Optional - fallback enabled)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    URLHAUS_API_KEY: str = os.getenv("URLHAUS_API_KEY", "")
    GOOGLE_WEBRISK_API_KEY: str = os.getenv("GOOGLE_WEBRISK_API_KEY", "")
    
    # Thresholds
    RISK_THRESHOLD_SAFE: int = 24
    RISK_THRESHOLD_CAUTION: int = 59
    RISK_THRESHOLD_CRITICAL: int = 60
    
    # Multi-Device Campaign Thresholds
    CAMPAIGN_MIN_DETECTIONS: int = 3
    CAMPAIGN_MIN_DEVICES: int = 2
    CAMPAIGN_WINDOW_HOURS: int = 24
    
    # File analysis
    MAX_FILE_SIZE_MB: int = 25
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")

    @field_validator("UPLOAD_DIR", mode="after")
    @classmethod
    def ensure_upload_dir_exists(cls, v: str) -> str:
        """Ensures the upload directory exists with write permissions."""
        os.makedirs(v, exist_ok=True)
        return v
    
settings = Settings()

