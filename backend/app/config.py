import os
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from dotenv import load_dotenv


def _load_env_files() -> None:
    env_paths = [
        Path(__file__).resolve().parent.parent.parent.parent / ".env",  # auth-platform/.env
        Path(__file__).resolve().parent.parent.parent / ".env",         # backend/.env
        Path.cwd() / ".env",
        Path.cwd().parent / ".env",
    ]

    for env_path in env_paths:
        if env_path.exists():
            load_dotenv(dotenv_path=env_path)
            return

    load_dotenv()


def _as_bool(value: str, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _split_csv(value: Optional[str], default: list[str]) -> list[str]:
    if not value:
        return default
    values = [item.strip() for item in value.split(",") if item.strip()]
    return values or default


def _is_https_url(value: str) -> bool:
    parsed = urlparse((value or "").strip())
    return parsed.scheme == "https" and bool(parsed.netloc)


_load_env_files()


class Settings:
    # Environment detection
    ENVIRONMENT: str = os.getenv("RAILWAY_ENVIRONMENT", os.getenv("ENVIRONMENT", "development"))
    IS_PRODUCTION: bool = os.getenv("RAILWAY_ENVIRONMENT") == "production"

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./auth.db")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    # JWT Configuration
    JWT_SECRET: str = os.getenv("JWT_SECRET", "your-secret-key-here")
    JWT_ISSUER: str = "auth-platform"
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_PRIVATE_KEY_PEM: str = os.getenv("JWT_PRIVATE_KEY_PEM", "")
    JWT_PUBLIC_KEY_PEM: str = os.getenv("JWT_PUBLIC_KEY_PEM", "")
    JWT_KEYS_DIR: str = os.getenv("JWT_KEYS_DIR", "")
    REQUIRE_PERSISTENT_JWT_KEYS: bool = _as_bool(
        os.getenv("REQUIRE_PERSISTENT_JWT_KEYS"),
        default=IS_PRODUCTION,
    )

    # SMTP Configuration
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_EMAIL: str = os.getenv("SMTP_USER")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD")

    # CORS Configuration
    ALLOWED_ORIGINS: list[str] = _split_csv(os.getenv("ALLOWED_ORIGINS"), default=["*"])

    # Public server URL (used in API responses, token issuer, etc.)
    AUTH_SERVER_URL: str = os.getenv("AUTH_SERVER_URL", "http://localhost:8000")

    # URL shown in the docs page & SDK examples.
    DOCS_AUTH_SERVER_URL: str = os.getenv("DOCS_AUTH_SERVER_URL", "")

    # Public platform link used in hosted auth footers.
    # Supports both AUTH_PLATFORM_URL and legacy Auth_platform_URL keys.
    AUTH_PLATFORM_URL: str = os.getenv(
        "AUTH_PLATFORM_URL",
        os.getenv("Auth_platform_URL", os.getenv("AUTH_PLATFORM_URL", ""))
    )

    # Rate Limiting (requests per minute)
    RATE_LIMIT_LOGIN: int = int(os.getenv("RATE_LIMIT_LOGIN", "5"))
    RATE_LIMIT_OTP: int = int(os.getenv("RATE_LIMIT_OTP", "3"))
    RATE_LIMIT_SIGNUP: int = int(os.getenv("RATE_LIMIT_SIGNUP", "10"))
    RATE_LIMIT_GENERAL: int = int(os.getenv("RATE_LIMIT_GENERAL", "60"))

    # Security-related runtime toggles
    CSRF_COOKIE_SECURE: bool = _as_bool(
        os.getenv("CSRF_COOKIE_SECURE"),
        default=IS_PRODUCTION,
    )
    CSRF_SKIP_JSON: bool = _as_bool(
        os.getenv("CSRF_SKIP_JSON"),
        default=True,
    )

    # Boot-time migration runner toggle.
    # In multi-worker production mode, run migrations once externally and keep this false.
    RUN_DB_MIGRATIONS_ON_STARTUP: bool = _as_bool(
        os.getenv("RUN_DB_MIGRATIONS_ON_STARTUP"),
        default=False,
    )

    def validate(self) -> None:
        if not self.DATABASE_URL:
            raise RuntimeError("DATABASE_URL must be configured.")

        if bool(self.JWT_PRIVATE_KEY_PEM) != bool(self.JWT_PUBLIC_KEY_PEM):
            raise RuntimeError(
                "JWT_PRIVATE_KEY_PEM and JWT_PUBLIC_KEY_PEM must be provided together."
            )

        if not self.IS_PRODUCTION:
            return

        if "*" in self.ALLOWED_ORIGINS:
            raise RuntimeError("ALLOWED_ORIGINS cannot contain '*' in production.")

        if self.AUTH_SERVER_URL and not _is_https_url(self.AUTH_SERVER_URL):
            raise RuntimeError("AUTH_SERVER_URL must use https in production.")

        if self.AUTH_PLATFORM_URL and not _is_https_url(self.AUTH_PLATFORM_URL):
            raise RuntimeError("AUTH_PLATFORM_URL must use https in production.")


settings = Settings()
settings.validate()
