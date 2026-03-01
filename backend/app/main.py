from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from pathlib import Path
from app.api import admin, auth, health, token, oauth
from app.db import engine, Base, get_db
from app.config import settings
from app.services.jwt_service import verify_token

# Import all models to ensure they're registered with Base
from app.models.app import App
from app.models.user import User
from app.models.admin import Admin
from app.models.refresh_token import RefreshToken
from app.models.passkey import PasskeyCredential
from app.models.tenant import Tenant

# Create all tables
Base.metadata.create_all(bind=engine)


# ============== Console Auth Middleware ==============
class ConsoleAuthMiddleware(BaseHTTPMiddleware):
    """Protects the /console page — redirects to /login if no valid admin JWT cookie.
    Only guards the HTML entry-point; static assets (CSS/JS) are served freely."""

    PROTECTED_PATHS = ("/console", "/console/", "/console/index.html")

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

# Console auth middleware — server-side gate for /console routes
app.add_middleware(ConsoleAuthMiddleware)

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


@app.get("/reset-password", include_in_schema=False, response_class=HTMLResponse)
async def reset_password_page(
    request: Request,
    token: str = None,
    email: str = None,
    app_id: str = None,
    db: Session = Depends(get_db),
):
    """Global reset/set password page — linked from invitation emails."""
    error_ctx = {"request": request, "error": None, "error_title": "Invalid Link"}

    if not token or not email or not app_id:
        error_ctx["error"] = "This link is invalid or incomplete. Please check the link in your email."
        return _reset_templates.TemplateResponse("reset_password.html", error_ctx)

    # Validate the app exists
    from app.models.app import App as AppModel
    app_obj = db.query(AppModel).filter(AppModel.app_id == app_id).first()
    if not app_obj:
        error_ctx["error"] = "The application associated with this link is no longer available."
        return _reset_templates.TemplateResponse("reset_password.html", error_ctx)

    app_name = app_obj.name or "Application"

    return _reset_templates.TemplateResponse("reset_password.html", {
        "request": request,
        "token": token,
        "email": email,
        "app_id": app_id,
        "app_name": app_name,
        "error": None,
    })


# Serve static assets (illustrations etc.)
assets_dir = Path(__file__).resolve().parent / "assets"
app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

# Serve static files (CSS, JS, SDK downloads)
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    @app.get("/console", include_in_schema=False)
    async def admin_console_redirect():
        return RedirectResponse(url="/console/")
    
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    app.mount("/console", StaticFiles(directory=str(static_dir), html=True), name="admin-console")
