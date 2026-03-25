import logging
import os
import sys

from app.config import settings
from app.db import Base, engine
from app.migration_runner import run_migrations

# Ensure models are registered before metadata bootstrap (SQLite path).
from app.models.admin import Admin
from app.models.admin_activity_event import AdminActivityEvent
from app.models.admin_passkey import AdminPasskeyCredential
from app.models.admin_session import AdminSession
from app.models.app import App
from app.models.login_event import LoginEvent
from app.models.oauth_consent import OAuthConsent
from app.models.passkey import PasskeyCredential
from app.models.refresh_token import RefreshToken
from app.models.tenant import Tenant
from app.models.user import User

logger = logging.getLogger(__name__)

_REGISTERED_MODELS = (
    App,
    User,
    Admin,
    RefreshToken,
    PasskeyCredential,
    AdminPasskeyCredential,
    Tenant,
    LoginEvent,
    OAuthConsent,
    AdminSession,
    AdminActivityEvent,
)


def bootstrap_database() -> None:
    """Initialize database schema in a deterministic way."""
    _ = _REGISTERED_MODELS

    if "pytest" in sys.modules:
        logger.info("Pytest runtime detected; skipping startup DB bootstrap.")
        return

    if os.getenv("SKIP_DB_BOOTSTRAP_ON_STARTUP", "").strip().lower() in {"1", "true", "yes", "on"}:
        logger.info("Skipping startup DB bootstrap (SKIP_DB_BOOTSTRAP_ON_STARTUP=true).")
        return

    dialect = (engine.dialect.name or "").lower()

    # SQLite is used for local/testing flows where SQL migration files are not portable.
    # In that case, metadata bootstrap keeps behavior stable.
    if dialect == "sqlite":
        logger.info("SQLite detected; using SQLAlchemy metadata bootstrap.")
        Base.metadata.create_all(bind=engine)
        return

    if not settings.RUN_DB_MIGRATIONS_ON_STARTUP:
        logger.info("Skipping startup migrations (RUN_DB_MIGRATIONS_ON_STARTUP=false).")
        return

    logger.info("Applying startup migrations...")
    run_migrations()
