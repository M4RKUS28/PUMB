import logging
from typing import Any  # Import Any
from pydantic_settings import BaseSettings
from pydantic import EmailStr, AnyHttpUrl, field_validator  # For URL validation

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """
    Application settings.
    Values are loaded from environment variables and/or a .env file.
    """

    # Core FastAPI settings
    PROJECT_NAME: str = "User Management API"
    API_V1_STR: str = "/api"  # Consistent API prefix
    DEBUG: bool = False  # Set to True for development, False for production

    # JWT settings
    SECRET_KEY: str  # No default, must be set in environment
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # Session settings for OAuth flow
    SESSION_SECRET_KEY: str  # No default, must be set in environment

    # Database settings
    DB_USER: str = "your_db_user"
    DB_PASSWORD: str = "your_db_password"
    DB_HOST: str = "localhost"
    DB_PORT: str = "3306"
    DB_NAME: str = "your_app_db"
    SQLALCHEMY_DATABASE_URL: str | None = None  # Will be constructed

    # Database connection pool settings (optional, with defaults)
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_RECYCLE: int = 3600  # In seconds
    DB_POOL_PRE_PING: bool = True
    DB_CONNECT_TIMEOUT: int = 10  # In seconds

    # Google OAuth settings (optional, can be None if not used)
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    GOOGLE_REDIRECT_URI: AnyHttpUrl | None = None  # Default to None, set in .env
    FRONTEND_BASE_URL: AnyHttpUrl | None = None  # Default to None, set in .env

    # CORS settings
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:8000"]  # Default origins

    # Default dynamic settings (can be overridden by database)
    # These are settings that might be changed at runtime via an admin interface,
    # for example, and stored in the database.
    REGISTER_ENDPOINT_ENABLED: bool = True
    GOOGLE_OAUTH20_ENABLED: bool = True
    SETTINGS_RELOAD_INTERVAL_SECONDS: int = 300  # e.g., 5 minutes

    # Password policy (can also be dynamic if needed)
    MIN_PASSWORD_LENGTH: int = 8
    REQUIRE_UPPERCASE: bool = True
    REQUIRE_LOWERCASE: bool = True
    REQUIRE_DIGIT: bool = True
    REQUIRE_SPECIAL_CHAR: bool = True
    SPECIAL_CHARACTERS_REGEX_PATTERN: str = r"[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?~`]"

    @field_validator('SQLALCHEMY_DATABASE_URL', mode='before')
    def assemble_db_connection(cls, v: str | None, values) -> Any:
        if isinstance(v, str):
            return v
        # Ensure values.data is used to access other field values
        db_user = values.data.get('DB_USER')
        db_password = values.data.get('DB_PASSWORD')
        db_host = values.data.get('DB_HOST')
        db_port = values.data.get('DB_PORT')
        db_name = values.data.get('DB_NAME')
        if all([db_user, db_password, db_host, db_port, db_name]):  # Check if all components are present
            return f"mysql+mysqlconnector://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        return None  # Return None if essential DB components are missing

    class Config:
        env_file = ".env"  # Load .env file if present
        env_file_encoding = 'utf-8'
        case_sensitive = True  # Environment variable names are case-sensitive


# Instantiate settings
settings = Settings()

# Log essential settings on startup (be careful with sensitive data in production logs)
logger.info(f"Project Name: {settings.PROJECT_NAME}")
logger.info(f"API Prefix: {settings.API_V1_STR}")
logger.info(f"Debug Mode: {settings.DEBUG}")
# Avoid logging credentials by splitting the URL
if settings.SQLALCHEMY_DATABASE_URL:
    db_url_parts = settings.SQLALCHEMY_DATABASE_URL.split('@')
    logger.info(f"Database URL (host/db): {db_url_parts[1] if len(db_url_parts) > 1 else 'Not fully configured'}")
else:
    logger.info("Database URL: Not set or not all components provided")
logger.info(f"CORS Origins: {settings.CORS_ORIGINS}")