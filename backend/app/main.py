from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from app.api import admin, auth, health, token, oauth
from app.db import engine, Base
from app.config import settings

# Import all models to ensure they're registered with Base
from app.models.app import App
from app.models.user import User
from app.models.admin import Admin
from app.models.refresh_token import RefreshToken
from app.models.passkey import PasskeyCredential

# Create all tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Auth Platform API",
    description="Authentication microservice with OTP-based authentication",
    version="1.0.0",
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,  # Configure via ALLOWED_ORIGINS env variable
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(admin.router, tags=["Admin"])
app.include_router(auth.router, tags=["Auth"])
app.include_router(token.router, prefix="/token", tags=["Token"])
app.include_router(oauth.router, tags=["OAuth"])

# Serve static assets (illustrations etc.)
assets_dir = Path(__file__).resolve().parent / "assets"
app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")
