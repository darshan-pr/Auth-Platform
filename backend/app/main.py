from fastapi import FastAPI, Request, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from pathlib import Path
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from typing import Optional
import logging
from app.api import admin, auth, health, token, oauth
from app.db import engine, Base, get_db
from app.config import settings
from app.migration_runner import run_migrations
from app.services.jwt_service import verify_token

logger = logging.getLogger(__name__)

# Import all models to ensure they're registered with Base
from app.models.app import App
from app.models.user import User
from app.models.admin import Admin
from app.models.refresh_token import RefreshToken
from app.models.passkey import PasskeyCredential
from app.models.tenant import Tenant
from app.models.login_event import LoginEvent

# Create all tables
Base.metadata.create_all(bind=engine)


# Run migrations on startup unless explicitly disabled.
if settings.RUN_DB_MIGRATIONS_ON_STARTUP:
    try:
        run_migrations()
    except Exception as e:
        logger.error(f"Migration runner failed: {e}")
else:
    logger.info("Skipping startup migrations (RUN_DB_MIGRATIONS_ON_STARTUP=false).")


# ============== Dashboard Auth Middleware ==============
class ConsoleAuthMiddleware(BaseHTTPMiddleware):
    """Protects the /dashboard page — redirects to /login if no valid admin JWT cookie.
    Only guards the HTML entry-point; static assets (CSS/JS) are served freely."""

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


app = FastAPI(
    title="Auth Platform API",
    description="Authentication microservice with OTP-based authentication",
    version="1.0.0",
    docs_url="/docs",  # Keep OpenAPI Swagger UI at /docs
    redoc_url="/redoc",
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,  # Configure via ALLOWED_ORIGINS env variable
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dashboard auth middleware — server-side gate for /dashboard routes
app.add_middleware(ConsoleAuthMiddleware)

# CSRF middleware — double-submit cookie pattern for state-changing requests
from app.services.csrf import CSRFMiddleware
app.add_middleware(CSRFMiddleware)

# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(admin.router, tags=["Admin"])
app.include_router(auth.router, tags=["Auth"])
app.include_router(token.router, prefix="/token", tags=["Token"])
app.include_router(oauth.router, tags=["OAuth"])


@app.get("/", include_in_schema=False, response_class=HTMLResponse)
async def public_landing_page():
    """Serve the public landing page."""
    landing_file = Path(__file__).resolve().parent / "static" / "landing.html"
    if landing_file.exists():
        with open(landing_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return RedirectResponse(url="/login")


@app.get("/api/docs", include_in_schema=False, response_class=HTMLResponse)
async def api_documentation():
    """Serve the custom API documentation page"""
    docs_file = Path(__file__).resolve().parent / "static" / "docs.html"
    if docs_file.exists():
        with open(docs_file, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    return RedirectResponse(url="/docs")


@app.get("/login", include_in_schema=False, response_class=HTMLResponse)
async def admin_login_page():
    """Serve the admin login / register page"""
    auth_file = Path(__file__).resolve().parent / "static" / "admin-auth.html"
    if auth_file.exists():
        with open(auth_file, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    return RedirectResponse(url="/docs")




# Jinja2 templates for the reset password page
_templates_dir = Path(__file__).resolve().parent / "templates"
_reset_templates = Jinja2Templates(directory=str(_templates_dir))


def _with_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

def _normalize_redirect_uri(raw: str):
    candidate = (raw or "").strip().strip("\"'")
    if not candidate:
        return None

    parsed = urlparse(candidate)

    # Accept scheme-less entries like "myapp.example.com/callback".
    if not parsed.scheme and "://" not in candidate:
        candidate = f"https://{candidate.lstrip('/')}"
        parsed = urlparse(candidate)

    if parsed.scheme in ("http", "https") and parsed.netloc:
        return candidate, parsed
    return None


def _is_localhost_target(parsed) -> bool:
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"} or host.endswith(".localhost")


def _infer_app_signin_url(
    redirect_uris: Optional[str],
    allow_localhost_fallback: bool = False,
) -> Optional[str]:
    if not redirect_uris:
        return None

    valid = []
    for raw in redirect_uris.split(","):
        normalized = _normalize_redirect_uri(raw)
        if normalized:
            valid.append(normalized)

    if not valid:
        return None

    public = [(candidate, parsed) for candidate, parsed in valid if not _is_localhost_target(parsed)]
    pool = public if public else (valid if allow_localhost_fallback else [])
    if not pool:
        return None

    for candidate, parsed in pool:
        path = (parsed.path or "").lower()
        if "signin" in path or "sign-in" in path or "login" in path:
            return candidate

    candidate, parsed = pool[0]
    first_path = (parsed.path or "").lower()
    if "callback" in first_path or "oauth" in first_path:
        return f"{parsed.scheme}://{parsed.netloc}/login"
    return candidate


def _append_query_params(url: str, params: dict) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in params.items():
        if value is not None and value != "":
            query[key] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


@app.get("/reset-password", include_in_schema=False, response_class=HTMLResponse)
async def reset_password_page(
    request: Request,
    token: str = None,
    email: str = None,
    app_id: str = None,
    db: Session = Depends(get_db),
):
    """Global reset/set password page — linked from invitation emails."""
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
        return _with_no_cache_headers(_reset_templates.TemplateResponse("reset_password.html", error_ctx))

    # Validate the app exists
    from app.models.app import App as AppModel
    app_obj = db.query(AppModel).filter(AppModel.app_id == app_id).first()
    if not app_obj:
        error_ctx["error"] = "The application associated with this link is no longer available."
        return _with_no_cache_headers(_reset_templates.TemplateResponse("reset_password.html", error_ctx))

    app_name = app_obj.name or "Application"
    app_signin_url = _infer_app_signin_url(app_obj.redirect_uris)
    server_signin_url = f"/signin?{urlencode({'client_id': app_id, 'from': 'password_reset'})}"

    return _with_no_cache_headers(_reset_templates.TemplateResponse("reset_password.html", {
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
    }))


@app.get("/signin", include_in_schema=False)
async def app_signin_redirect(
    client_id: str = None,
    from_source: str = Query(default="signin", alias="from"),
    db: Session = Depends(get_db),
):
    """Server-side sign-in redirect target for post-reset flows."""
    if not client_id:
        return RedirectResponse(url="/login", status_code=302)

    from app.models.app import App as AppModel
    app_obj = db.query(AppModel).filter(AppModel.app_id == client_id).first()
    if not app_obj:
        return RedirectResponse(url="/login", status_code=302)

    app_signin_url = _infer_app_signin_url(app_obj.redirect_uris)
    if not app_signin_url:
        logger.warning(
            "No public redirect URI configured for client_id=%s. redirect_uris=%s",
            client_id,
            app_obj.redirect_uris,
        )
        return RedirectResponse(url="/login", status_code=302)

    safe_from = (from_source or "signin").strip()[:64]
    target = _append_query_params(
        app_signin_url,
        {"client_id": client_id, "from": safe_from}
    )
    logger.info("Post-reset sign-in redirect for client_id=%s -> %s", client_id, target)
    return RedirectResponse(url=target, status_code=302)


# Serve static assets (illustrations etc.)
assets_dir = Path(__file__).resolve().parent / "assets"
app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

# Serve static files (CSS, JS, SDK downloads)
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    @app.get("/dashboard", include_in_schema=False)
    async def admin_dashboard_redirect():
        return RedirectResponse(url="/dashboard/")

    @app.get("/api/config", include_in_schema=False)
    async def public_config():
        """Return public client-side config (auth server URL) sourced from env.
        DOCS_AUTH_SERVER_URL overrides AUTH_SERVER_URL for use in docs & SDK examples.
        """
        from fastapi.responses import JSONResponse
        docs_url = settings.DOCS_AUTH_SERVER_URL or settings.AUTH_SERVER_URL
        return JSONResponse({"AUTH_SERVER_URL": docs_url})
    
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    app.mount("/dashboard", StaticFiles(directory=str(static_dir), html=True), name="admin-dashboard")
