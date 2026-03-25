from fastapi import APIRouter
from fastapi.routing import APIRoute

from app.api import oauth_core

router = APIRouter()


for route in oauth_core.router.routes:
    if not isinstance(route, APIRoute):
        continue
    if route.path == "/oauth/token":
        router.routes.append(route)
