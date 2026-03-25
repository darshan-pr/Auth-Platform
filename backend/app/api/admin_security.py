from fastapi import APIRouter
from fastapi.routing import APIRoute

from app.api import admin_core

router = APIRouter()


for route in admin_core.router.routes:
    if not isinstance(route, APIRoute):
        continue

    if (
        route.path in {"/admin/register", "/admin/login"}
        or route.path.startswith("/admin/register/")
        or route.path.startswith("/admin/login/")
        or route.path.startswith("/admin/passkeys")
        or route.path == "/admin/logout"
        or route.path == "/admin/forgot-password"
        or route.path.startswith("/admin/forgot-password/")
        or route.path == "/admin/reset-password"
        or route.path.startswith("/admin/settings")
        or route.path == "/admin/tenant"
    ):
        router.routes.append(route)
