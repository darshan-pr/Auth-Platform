from fastapi import APIRouter
from fastapi.routing import APIRoute

from app.api import admin_core

router = APIRouter()


for route in admin_core.router.routes:
    if not isinstance(route, APIRoute):
        continue
    if route.path.startswith("/admin/my-auth-activity/sessions"):
        router.routes.append(route)
