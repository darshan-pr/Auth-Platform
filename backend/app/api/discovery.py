from fastapi import APIRouter

from app.config import settings
from app.services.jwt_service import get_jwks

router = APIRouter()


def _issuer() -> str:
    return settings.JWT_ISSUER.rstrip("/")


@router.get("/.well-known/jwks.json")
def jwks():
    return get_jwks()


@router.get("/.well-known/openid-configuration")
def openid_configuration():
    issuer = _issuer()
    return {
        "issuer": issuer,
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
    }
