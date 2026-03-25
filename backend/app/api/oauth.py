from fastapi import APIRouter

from app.api import oauth_authorize, oauth_client_mgmt, oauth_consent, oauth_token

router = APIRouter()

router.include_router(oauth_authorize.router)
router.include_router(oauth_consent.router)
router.include_router(oauth_client_mgmt.router)
router.include_router(oauth_token.router)
