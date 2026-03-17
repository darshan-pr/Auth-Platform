import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env from project root - try multiple paths
env_paths = [
    Path(__file__).resolve().parent.parent.parent.parent / ".env",  # auth-platform/.env
    Path(__file__).resolve().parent.parent.parent / ".env",  # backend/.env
    Path.cwd() / ".env",
    Path.cwd().parent / ".env",
]

for env_path in env_paths:
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
        break
else:
    load_dotenv()  # Try default .env loading

class Settings:
    # Environment detection
    ENVIRONMENT: str = os.getenv("RAILWAY_ENVIRONMENT", os.getenv("ENVIRONMENT", "development"))
    IS_PRODUCTION: bool = os.getenv("RAILWAY_ENVIRONMENT") == "production"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    # JWT Configuration
    JWT_SECRET: str = os.getenv("JWT_SECRET", "your-secret-key-here")
    JWT_ISSUER: str = "auth-platform"
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # SMTP Configuration
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_EMAIL: str = os.getenv("SMTP_USER")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD")
    
    # CORS Configuration
    ALLOWED_ORIGINS: list = os.getenv("ALLOWED_ORIGINS", "*").split(",") if os.getenv("ALLOWED_ORIGINS") else ["*"]

    # Public server URL (used in API responses, token issuer, etc.)
    AUTH_SERVER_URL: str = os.getenv("AUTH_SERVER_URL", "http://localhost:8000")

    # URL shown in the docs page & SDK examples.
    # Set DOCS_AUTH_SERVER_URL in your .env to override (e.g. your Railway/production URL).
    # Falls back to AUTH_SERVER_URL if not set.
    DOCS_AUTH_SERVER_URL: str = os.getenv("DOCS_AUTH_SERVER_URL", "")

    # Rate Limiting (requests per minute)
    RATE_LIMIT_LOGIN: int = int(os.getenv("RATE_LIMIT_LOGIN", "5"))
    RATE_LIMIT_OTP: int = int(os.getenv("RATE_LIMIT_OTP", "3"))
    RATE_LIMIT_SIGNUP: int = int(os.getenv("RATE_LIMIT_SIGNUP", "10"))
    RATE_LIMIT_GENERAL: int = int(os.getenv("RATE_LIMIT_GENERAL", "60"))

settings = Settings()
