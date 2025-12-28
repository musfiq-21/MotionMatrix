"""
Centralized configuration management using Pydantic Settings.

This module provides a singleton Settings class that loads configuration
from environment variables with validation and default values.
"""

from functools import lru_cache
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import (
    Field,
    field_validator,
    validator,
    EmailStr,
    AnyHttpUrl,
    PostgresDsn,
)
from pydantic.networks import AnyUrl

BACKEND_DIR = Path(__file__).resolve().parents[3]
# config.py -> core -> app -> backend

ENV_FILE = BACKEND_DIR / "backend" / "backend.env"

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # ============================================================================
    # Application Settings
    # ============================================================================
    APP_NAME: str = "MotionMatrix"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development")
    DEBUG: bool = Field(default=False)
    API_V1_PREFIX: str = "/api/v1"
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)
    TIMEZONE: str = Field(default="UTC")
    # ============================================================================
    # Database Configuration
    # ============================================================================
    DB_USER: str = Field(..., min_length=1)
    DB_PASSWORD: str = Field(..., min_length=1)
    DB_HOST: str = Field(default="localhost")
    DB_PORT: int = Field(default=5432, ge=1, le=65535)
    DB_NAME: str = Field(..., min_length=1)
    DB_POOL_TIMEOUT: int = Field(default=30, ge=1, le=120)  # seconds
    # Additional database settings
    DB_POOL_SIZE: int = Field(default=5, ge=1, le=100)
    DB_MAX_OVERFLOW: int = Field(default=10, ge=0, le=100)
    DB_ECHO: bool = Field(default=False)  # SQL logging
    DB_POOL_RECYCLE: int = Field(default=1800, ge=0, le=3600)  # seconds

    @property
    def DATABASE_URL(self) -> str:
        """Construct database URL from components."""
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
    # @property
    # def ASYNC_DATABASE_URL(self) -> str:
    #     """Construct async database URL for asyncpg."""
    #     return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
    # ============================================================================
    # JWT Settings
    # ============================================================================
    JWT_SECRET_KEY: str = Field(..., min_length=32)
    JWT_ALGORITHM: str = Field(default="HS256")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, ge=5, le=1440)  # 30 min default, max 24h
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=90)  # 7 days default, max 90 days
    

    BCRYPT_ROUNDS: int = Field(default=12, ge=4, le=31)  # bcrypt cost factor


    SMTP_USERNAME: str = Field(default="your-email@gmail.com")
    SMTP_USE_TLS: bool = Field(default=True)
    SMTP_FROM_EMAIL: EmailStr = Field(default="noreply@motionmatrix.com")
    SMTP_FROM_NAME: str = Field(default="MotionMatrix Support")


    ADMIN_EMAIL: EmailStr = Field(default="motionmatrixadmin@gmail.com")
    ADMIN_PASSWORD: str = Field(default="Admin@123456")


    SHIFT_LUNCH_START: str = Field(default="13:00")
    SHIFT_LUNCH_END: str = Field(default="14:00")

    OVERTIME_MAX_HOURS_PER_DAY: int = Field(default=4, ge=0, le=12)
    #IDLENESS_THRESHOLD_SECONDS: int = Field(default=900, ge=60, le=3600)  # 15 minutes default
    STORAGE_REPORTS_DIR: Path = Field(default=Path("uploads/reports"))
    STORAGE_LOGS_DIR: Path = Field(default=Path("logs"))
    IDLENESS_CHECK_INTERVAL_SECONDS: int = Field(default=300, ge=30, le=1800)  # 5 minutes default

    

    RATE_LIMIT_ENABLED: bool = Field(default=True)
    LOG_FORMAT: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    SECURE_HEADERS_ENABLED: bool = Field(default=True)
    RELOAD: bool = Field(default=False)  # For development server auto-reload

    ML_SERVER_URL: AnyUrl = Field(default="http://localhost:5000")
    ML_SERVICE_URL: AnyUrl = Field(default="http://localhost:6000")
    PUSH_NOTIFICATION_KEY: str = Field(default="your-push-notification-key")

    TEST_DB_NAME: str = Field(default="motionmatrix_test_db")

    @property
    def ACCESS_TOKEN_EXPIRE_SECONDS(self) -> int:
        """Convert access token expiration to seconds for easier use."""
        return self.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    
    @property
    def REFRESH_TOKEN_EXPIRE_SECONDS(self) -> int:
        """Convert refresh token expiration to seconds for easier use."""
        return self.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    
    # ============================================================================
    # SMTP Configuration
    # ============================================================================
    SMTP_HOST: str = Field(default="smtp.gmail.com")
    SMTP_PORT: int = Field(default=587, ge=1, le=65535)
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = Field(default=True)
    SMTP_SSL: bool = Field(default=False)
    
    # Email sender information
    FROM_EMAIL: EmailStr = Field(default="noreply@example.com")
    FROM_NAME: str = Field(default="Employee Management System")
    
    # Email feature toggle
    EMAILS_ENABLED: bool = Field(default=True)
    
    @validator("SMTP_PASSWORD")
    def validate_smtp_config(cls, v, values):
        """Validate SMTP configuration when emails are enabled."""
        if values.get("EMAILS_ENABLED") and not v:
            if values.get("SMTP_USER"):
                raise ValueError("SMTP_PASSWORD is required when SMTP_USER is provided")
        return v
    
    # ============================================================================
    # CORS Settings
    # ============================================================================
    CORS_ORIGINS: List[str] = Field(
        default=[
            "http://localhost:3000",
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8000",
        ]
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True)
    CORS_ALLOW_METHODS: List[str] = Field(default=["*"])
    CORS_ALLOW_HEADERS: List[str] = Field(default=["*"])
    
    @field_validator("CORS_ORIGINS", mode="before")
    def parse_cors_origins(cls, v):
        """Parse CORS origins from string or list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    # ============================================================================
    # Pagination Settings
    # ============================================================================
    DEFAULT_PAGE_SIZE: int = Field(default=50, ge=1, le=100)
    MAX_PAGE_SIZE: int = Field(default=100, ge=1, le=1000)
    
    @validator("MAX_PAGE_SIZE")
    def validate_max_page_size(cls, v, values):
        """Ensure max page size is greater than or equal to default."""
        default_size = values.get("DEFAULT_PAGE_SIZE", 50)
        if v < default_size:
            raise ValueError(f"MAX_PAGE_SIZE must be >= DEFAULT_PAGE_SIZE ({default_size})")
        return v
    
    # ============================================================================
    # File Storage Settings
    # ============================================================================
    STORAGE_TYPE: str = Field(default="local")
    
    # Local storage
    UPLOAD_DIR: Path = Field(default=Path("uploads"))
    REPORTS_DIR: Path = Field(default=Path("uploads/reports"))
    MAX_UPLOAD_SIZE_MB: int = Field(default=10, ge=1, le=100)
    
    # AWS S3 (optional)
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_REGION: str = Field(default="us-east-1")
    S3_BUCKET_NAME: Optional[str] = None
    
    @property
    def MAX_UPLOAD_SIZE_BYTES(self) -> int:
        """Convert max upload size to bytes."""
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    
    @validator("REPORTS_DIR", "UPLOAD_DIR")
    def create_directories(cls, v: Path) -> Path:
        """Ensure upload directories exist."""
        v.mkdir(parents=True, exist_ok=True)
        return v
    
    # ============================================================================
    # System Constants
    # ============================================================================
    
    # Attendance & Activity
    IDLENESS_THRESHOLD_MINUTES: int = Field(default=30, ge=1, le=240)  # 30 minutes default
    ACTIVITY_CHECK_INTERVAL_SECONDS: int = Field(default=60, ge=10, le=300)  # Check every minute
    
    # Shift Configuration
    SHIFT_START_TIME: str = Field(default="09:00", pattern="^([01]?[0-9]|2[0-3]):[0-5][0-9]$")
    SHIFT_END_TIME: str = Field(default="17:00", pattern="^([01]?[0-9]|2[0-3]):[0-5][0-9]$")
    STANDARD_WORK_HOURS: float = Field(default=8.0, ge=1.0, le=24.0)
    
    # Overtime & Salary
    OVERTIME_RATE_MULTIPLIER: float = Field(default=1.5, ge=1.0, le=3.0)  # 1.5x for overtime
    LATE_ARRIVAL_GRACE_MINUTES: int = Field(default=15, ge=0, le=60)  # 15 min grace period
    
    # Break times
    MAX_BREAK_DURATION_MINUTES: int = Field(default=60, ge=0, le=180)  # 1 hour max
    
    @property
    def IDLENESS_THRESHOLD_SECONDS(self) -> int:
        """Convert idleness threshold to seconds."""
        return self.IDLENESS_THRESHOLD_MINUTES * 60
    
    @validator("SHIFT_END_TIME")
    def validate_shift_times(cls, v, values):
        """Ensure shift end time is after start time."""
        start_time = values.get("SHIFT_START_TIME", "09:00")
        if v <= start_time:
            raise ValueError("SHIFT_END_TIME must be after SHIFT_START_TIME")
        return v
    
    # ============================================================================
    # Security Settings
    # ============================================================================
    PASSWORD_MIN_LENGTH: int = Field(default=8, ge=6, le=128)
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_DIGIT: bool = Field(default=True)
    PASSWORD_REQUIRE_SPECIAL: bool = Field(default=True)
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, ge=1, le=1000)
    
    # Session settings
    SESSION_TIMEOUT_MINUTES: int = Field(default=30, ge=5, le=1440)
    
    # ============================================================================
    # Logging Configuration
    # ============================================================================
    LOG_LEVEL: str = Field(default="INFO")
    LOG_FILE: Optional[Path] = Field(default=Path("logs/app.log"))
    
    @validator("LOG_FILE")
    def create_log_directory(cls, v: Optional[Path]) -> Optional[Path]:
        """Ensure log directory exists."""
        if v:
            v.parent.mkdir(parents=True, exist_ok=True)
        return v

    model_config = {
        "env_file": ENV_FILE,       # where to load environment variables
        "env_file_encoding": "utf-8"
    }

@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    This function uses lru_cache to ensure we only load settings once
    and reuse the same instance throughout the application lifecycle.
    
    Returns:
        Settings: Singleton settings instance
        
    Example:
        >>> from backend.app.core.config import get_settings
        >>> settings = get_settings()
        >>> print(settings.DATABASE_URL)
    """
    return Settings()


# Convenience export
settings = get_settings()