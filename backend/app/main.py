from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import admin, auth, health, oauth, token
from app.bootstrap import bootstrap_database
from app.config import settings
from app.middleware.console_auth import ConsoleAuthMiddleware
from app.services.csrf import CSRFMiddleware
from app.web.routes import register_web_routes


app = FastAPI(
    title="Auth Platform API",
    description="Authentication microservice with OTP-based authentication",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


@app.on_event("startup")
def _on_startup() -> None:
    bootstrap_database()


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(ConsoleAuthMiddleware)
app.add_middleware(CSRFMiddleware)

app.include_router(health.router, tags=["Health"])
app.include_router(admin.router, tags=["Admin"])
app.include_router(auth.router, tags=["Auth"])
app.include_router(token.router, prefix="/token", tags=["Token"])
app.include_router(oauth.router, tags=["OAuth"])

register_web_routes(app)
