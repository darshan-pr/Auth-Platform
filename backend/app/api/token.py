from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db import get_db
from app.services import jwt_service

from app.services.jwt_service import verify_token as _verify_token, mark_user_online, is_user_blacklisted

router = APIRouter()

class TokenRefreshRequest(BaseModel):
    refresh_token: str

class TokenRevokeRequest(BaseModel):
    token: str

@router.post("/refresh")
def refresh_token(request: TokenRefreshRequest, db: Session = Depends(get_db)):
    """Refresh an access token using a refresh token"""
    try:
        result = jwt_service.refresh_token(db, request.refresh_token)
        # Extend online presence on refresh
        payload = _verify_token(request.refresh_token)
        if payload and payload.get("user_id") and payload.get("tenant_id"):
            mark_user_online(payload["user_id"], payload["tenant_id"])
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

@router.post("/revoke")
def revoke_token(request: TokenRevokeRequest, db: Session = Depends(get_db)):
    """Revoke a token"""
    return jwt_service.revoke_token(db, request.token)

@router.post("/verify")
def verify_token(request: TokenRevokeRequest):
    """Verify if a token is valid"""
    payload = jwt_service.verify_token(request.token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    # Check if user has been force-logged-out
    user_id = payload.get("user_id")
    tenant_id = payload.get("tenant_id")
    if user_id and tenant_id and is_user_blacklisted(user_id, tenant_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked by administrator"
        )
    return {"valid": True, "payload": payload}
