from fastapi import APIRouter

from app.api import (
    admin_activity,
    admin_apps,
    admin_security,
    admin_sessions,
    admin_users,
)
from app.api.admin_core import redis_client

router = APIRouter()

router.include_router(admin_security.router)
router.include_router(admin_apps.router)
router.include_router(admin_users.router)
router.include_router(admin_sessions.router)
router.include_router(admin_activity.router)
