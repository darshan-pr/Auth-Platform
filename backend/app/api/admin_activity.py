from fastapi import APIRouter
from fastapi.routing import APIRoute

from app.api import admin_core

router = APIRouter()


for route in admin_core.router.routes:
    if not isinstance(route, APIRoute):
        continue

    if (
        route.path.startswith("/admin/my-auth-activity/history")
        or route.path.startswith("/admin/my-auth-activity/connected-apps")
        or route.path == "/admin/stats"
        or route.path == "/admin/login-events"
    ):
        router.routes.append(route)
