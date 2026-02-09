from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db import get_db
from app.services import jwt_service

router = APIRouter()

class TokenRefreshRequest(BaseModel):
    refresh_token: str

class TokenRevokeRequest(BaseModel):
    token: str

@router.post("/refresh")
def refresh_token(request: TokenRefreshRequest, db: Session = Depends(get_db)):
    """Refresh an access token using a refresh token"""
    try:
        return jwt_service.refresh_token(db, request.refresh_token)
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
    return {"valid": True, "payload": payload}
