from pathlib import Path
from typing import Optional
import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models.app import App
from app.services.jwt_service import verify_token
from app.services.redirect_url_service import (
    append_query_params,
    build_server_signin_url,
    infer_app_signin_url,
)

logger = logging.getLogger(__name__)

_APP_DIR = Path(__file__).resolve().parent.parent
_ASSETS_DIR = _APP_DIR / "assets"
_STATIC_DIR = _APP_DIR / "static"
_TEMPLATES_DIR = _APP_DIR / "templates"

_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
router = APIRouter(include_in_schema=False)


def _with_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def _resolve_admin_login_warning(oauth_warning: Optional[str]) -> Optional[str]:
    warning_code = (oauth_warning or "").strip().lower()
    if warning_code == "retry_oauth":
        return "Sign in to Auth Platform first, then return to your app and try OAuth again."
    return None


@router.get("/", response_class=HTMLResponse)
async def public_landing_page():
    """Serve the public landing page."""
    landing_file = _STATIC_DIR / "landing.html"
    if landing_file.exists():
        return HTMLResponse(content=landing_file.read_text(encoding="utf-8"))
    return RedirectResponse(url="/login")


@router.get("/api/docs", response_class=HTMLResponse)
async def api_documentation():
    """Serve the custom API documentation page."""
    docs_file = _STATIC_DIR / "docs.html"
    if docs_file.exists():
        return HTMLResponse(content=docs_file.read_text(encoding="utf-8"))
    return RedirectResponse(url="/docs")


@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request, oauth_warning: Optional[str] = None):
    """Serve the admin login/register page."""
    return _with_no_cache_headers(
        _templates.TemplateResponse(
            "admin_auth.html",
            {
                "request": request,
                "redirect_url": "/dashboard",
                "initial_warning": _resolve_admin_login_warning(oauth_warning),
            },
        )
    )


@router.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings_page(request: Request):
    """Serve the admin settings page for authenticated admin sessions."""
    token = request.cookies.get("admin_token")
    if not token:
        return RedirectResponse(url="/login", status_code=302)

    try:
        payload = verify_token(token)
    except Exception:
        payload = None

    if not payload or payload.get("type") != "admin_access":
        resp = RedirectResponse(url="/login", status_code=302)
        resp.delete_cookie("admin_token", path="/")
        return resp

    return _with_no_cache_headers(_templates.TemplateResponse("admin_settings.html", {"request": request}))


@router.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(
    request: Request,
    token: str = None,
    email: str = None,
    app_id: str = None,
    db: Session = Depends(get_db),
):
    """Global reset/set password page linked from invitation emails."""
    error_ctx = {
        "request": request,
        "error": None,
        "error_title": "Invalid Link",
        "auth_platform_url": settings.AUTH_PLATFORM_URL,
        "app_logo_url": "/assets/logo.png",
        "app_signin_url": None,
        "server_signin_url": None,
    }

    if not token or not email or not app_id:
        error_ctx["error"] = "This link is invalid or incomplete. Please check the link in your email."
        return _with_no_cache_headers(_templates.TemplateResponse("reset_password.html", error_ctx))

    app_obj = db.query(App).filter(App.app_id == app_id).first()
    if not app_obj:
        error_ctx["error"] = "The application associated with this link is no longer available."
        return _with_no_cache_headers(_templates.TemplateResponse("reset_password.html", error_ctx))

    app_name = app_obj.name or "Application"
    app_signin_url = infer_app_signin_url(app_obj.redirect_uris)
    server_signin_url = build_server_signin_url(app_id)

    return _with_no_cache_headers(
        _templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "token": token,
                "email": email,
                "app_id": app_id,
                "app_name": app_name,
                "app_logo_url": app_obj.logo_url or "/assets/logo.png",
                "app_signin_url": app_signin_url,
                "server_signin_url": server_signin_url,
                "auth_platform_url": settings.AUTH_PLATFORM_URL,
                "error": None,
            },
        )
    )


@router.get("/signin")
async def app_signin_redirect(
    client_id: str = None,
    from_source: str = Query(default="signin", alias="from"),
    db: Session = Depends(get_db),
):
    """Server-side sign-in redirect target for post-reset flows."""
    if not client_id:
        return RedirectResponse(url="/login", status_code=302)

    app_obj = db.query(App).filter(App.app_id == client_id).first()
    if not app_obj:
        return RedirectResponse(url="/login", status_code=302)

    app_signin_url = infer_app_signin_url(app_obj.redirect_uris)
    if not app_signin_url:
        logger.warning(
            "No public redirect URI configured for client_id=%s. redirect_uris=%s",
            client_id,
            app_obj.redirect_uris,
        )
        return RedirectResponse(url="/login", status_code=302)

    safe_from = (from_source or "signin").strip()[:64]
    target = append_query_params(app_signin_url, {"client_id": client_id, "from": safe_from})
    logger.info("Post-reset sign-in redirect for client_id=%s -> %s", client_id, target)
    return RedirectResponse(url=target, status_code=302)


@router.get("/dashboard")
async def admin_dashboard_redirect():
    if not _STATIC_DIR.exists():
        return RedirectResponse(url="/login", status_code=302)
    return RedirectResponse(url="/dashboard/")


@router.get("/api/config")
async def public_config():
    """Return public client-side config for docs and SDK examples."""
    docs_url = settings.DOCS_AUTH_SERVER_URL or settings.AUTH_SERVER_URL
    return JSONResponse({"AUTH_SERVER_URL": docs_url})


def register_web_routes(app) -> None:
    app.include_router(router)
    app.mount("/assets", StaticFiles(directory=str(_ASSETS_DIR)), name="assets")

    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
        app.mount("/dashboard", StaticFiles(directory=str(_STATIC_DIR), html=True), name="admin-dashboard")
