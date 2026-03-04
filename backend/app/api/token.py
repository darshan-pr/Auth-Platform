from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db import get_db
from app.services import jwt_service
import asyncio

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

class SessionCheckRequest(BaseModel):
    access_token: str

@router.post("/session-check")
def session_check(request: SessionCheckRequest):
    """
    Lightweight session check endpoint — manual/fallback check.
    Returns { active: true } if session is valid, or 401 if revoked/expired.
    For real-time revocation detection, use the SSE endpoint /token/session-stream instead.
    """
    payload = jwt_service.verify_token(request.access_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalid or expired"
        )
    user_id = payload.get("user_id")
    tenant_id = payload.get("tenant_id")
    if user_id and tenant_id and is_user_blacklisted(user_id, tenant_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked by administrator"
        )
    return {"active": True}


@router.get("/session-stream")
async def session_stream(token: str):
    """
    SSE (Server-Sent Events) endpoint for real-time session revocation.
    
    Instead of the frontend polling every N seconds, it opens ONE persistent
    HTTP connection here. The server pushes a 'revoked' event the moment
    the admin force-logouts the user.
    
    How it works:
      - Frontend opens: new EventSource('/token/session-stream?token=xxx')
      - Server checks Redis every 3s (sub-millisecond Redis EXISTS command)
      - When admin revokes → server pushes SSE event → frontend logs out instantly
    
    Cost comparison vs polling:
      Polling (10s):  6 HTTP requests/min per user  = 6,000 req/min for 1,000 users
      SSE:            1 persistent connection/user   = 0 extra requests
    """
    # Validate token on connection
    payload = jwt_service.verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    user_id = payload.get("user_id")
    tenant_id = payload.get("tenant_id")
    
    if not user_id or not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token missing user/tenant context"
        )

    async def event_generator():
        # Immediate check — if already blacklisted, push and close
        if is_user_blacklisted(user_id, tenant_id):
            yield "event: revoked\ndata: {\"reason\": \"revoked_by_admin\"}\n\n"
            return

        # Connection established
        yield "event: connected\ndata: {\"status\": \"ok\"}\n\n"

        # Server-side loop: check Redis blacklist key every 3 seconds.
        # Redis EXISTS is O(1), takes < 1ms. This is NOT expensive.
        heartbeat_counter = 0
        try:
            while True:
                await asyncio.sleep(3)
                try:
                    blacklisted = await asyncio.to_thread(
                        is_user_blacklisted, user_id, tenant_id
                    )
                    if blacklisted:
                        yield "event: revoked\ndata: {\"reason\": \"revoked_by_admin\"}\n\n"
                        return
                except Exception:
                    pass  # Redis hiccup — keep connection alive, retry next cycle

                # Send a heartbeat comment every ~15s to keep proxies/LBs happy
                # (Railway, Render, Nginx all have proxy read timeouts; 15s is safe)
                heartbeat_counter += 1
                if heartbeat_counter >= 5:
                    yield ": heartbeat\n\n"
                    heartbeat_counter = 0
        except asyncio.CancelledError:
            # Client disconnected — clean up gracefully
            return

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",       # Disable Nginx proxy buffering
            "X-Content-Type-Options": "nosniff",
            "Transfer-Encoding": "chunked",   # Force chunked encoding for proxies
        },
    )
