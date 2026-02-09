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
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    JWT_SECRET: str = os.getenv("JWT_SECRET", "your-secret-key-here")
    JWT_ISSUER: str = "auth-platform"
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_EMAIL: str = os.getenv("SMTP_USER")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD")

settings = Settings()
