from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.jwt_service import verify_token


class ConsoleAuthMiddleware(BaseHTTPMiddleware):
    """Protects dashboard entry routes and redirects to login when unauthenticated."""

    PROTECTED_PATHS = ("/dashboard", "/dashboard/", "/dashboard/index.html")

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.PROTECTED_PATHS:
            token = request.cookies.get("admin_token")
            if not token:
                return RedirectResponse(url="/login", status_code=302)
            try:
                payload = verify_token(token)
                if not payload or payload.get("type") != "admin_access":
                    resp = RedirectResponse(url="/login", status_code=302)
                    resp.delete_cookie("admin_token", path="/")
                    return resp
            except Exception:
                resp = RedirectResponse(url="/login", status_code=302)
                resp.delete_cookie("admin_token", path="/")
                return resp
        return await call_next(request)
