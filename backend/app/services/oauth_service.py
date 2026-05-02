"""
OAuth 2.0 Authorization Code Flow with PKCE

Security Flow:
1. Client generates code_verifier (random string) and code_challenge (SHA256 hash)
2. Client redirects to /oauth/authorize with code_challenge
3. Auth platform authenticates user and issues authorization code
4. Client exchanges code + code_verifier for tokens at /oauth/token
5. PKCE ensures only the original client can exchange the code — no app_secret needed on frontend
"""
from __future__ import annotations

import secrets
import hashlib
import base64
import json
import logging
from app.redis import redis_client

logger = logging.getLogger(__name__)

AUTH_CODE_EXPIRY = 300       # 5 minutes — authorization codes are short-lived
OAUTH_SESSION_EXPIRY = 600   # 10 minutes — login session timeout


# ==================== OAuth Session Management ====================

def create_oauth_session(
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: str = "openid profile email",
) -> str:
    """
    Create an OAuth session when user lands on the authorize page.
    Stores all OAuth parameters in Redis so the login page can reference them.
    """
    session_id = secrets.token_urlsafe(32)
    session_data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
    }
    redis_client.setex(
        f"oauth:session:{session_id}",
        OAUTH_SESSION_EXPIRY,
        json.dumps(session_data)
    )
    logger.info(f"OAuth session created for client_id={client_id}, scope={scope}")
    return session_id


def get_oauth_session(session_id: str) -> dict | None:
    """Retrieve OAuth session data from Redis"""
    data = redis_client.get(f"oauth:session:{session_id}")
    if data:
        return json.loads(data)
    return None


def delete_oauth_session(session_id: str):
    """Clean up OAuth session after use"""
    redis_client.delete(f"oauth:session:{session_id}")


def update_oauth_session(session_id: str, updates: dict) -> dict | None:
    """Patch an OAuth session payload while preserving its expiration."""
    key = f"oauth:session:{session_id}"
    data = redis_client.get(key)
    if not data:
        return None

    session = json.loads(data)
    session.update(updates or {})
    ttl = redis_client.ttl(key)
    ttl_to_use = ttl if ttl and ttl > 0 else OAUTH_SESSION_EXPIRY
    redis_client.setex(key, ttl_to_use, json.dumps(session))
    return session


# ==================== Authorization Code Management ====================

def generate_authorization_code(
    client_id: str,
    redirect_uri: str,
    user_email: str,
    user_id: int,
    code_challenge: str,
    code_challenge_method: str,
    scope: str = "openid profile email",
) -> str:
    """
    Generate a one-time authorization code after successful authentication.
    Stored in Redis with short TTL. Includes PKCE data for validation during token exchange.
    """
    code = secrets.token_urlsafe(32)
    code_data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "user_email": user_email,
        "user_id": user_id,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
    }
    redis_client.setex(
        f"oauth:code:{code}",
        AUTH_CODE_EXPIRY,
        json.dumps(code_data)
    )
    logger.info(f"Authorization code generated for user={user_email}, client={client_id}, scope={scope}")
    return code


def validate_authorization_code(
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str
) -> dict | None:
    """
    Validate and consume an authorization code during token exchange.
    
    Validates:
    1. Code exists and hasn't expired
    2. client_id matches
    3. redirect_uri matches
    4. PKCE code_verifier proves the caller is the original requester
    
    Returns user data if valid, None otherwise.
    Code is deleted immediately (one-time use).
    """
    key = f"oauth:code:{code}"
    data = redis_client.get(key)
    if not data:
        logger.warning("Authorization code not found or expired")
        return None
    
    # Delete immediately — authorization codes are single-use
    redis_client.delete(key)
    
    code_data = json.loads(data)
    
    # Validate client_id
    if code_data["client_id"] != client_id:
        logger.warning(f"client_id mismatch: expected={code_data['client_id']}, got={client_id}")
        return None
    
    # Validate redirect_uri (must match exactly)
    if code_data["redirect_uri"] != redirect_uri:
        logger.warning(f"redirect_uri mismatch")
        return None
    
    # Validate PKCE
    if not verify_code_challenge(
        code_verifier,
        code_data["code_challenge"],
        code_data["code_challenge_method"]
    ):
        logger.warning("PKCE verification failed")
        return None
    
    logger.info(f"Authorization code validated for user={code_data['user_email']}")
    return code_data


# ==================== PKCE Helpers ====================

def verify_code_challenge(code_verifier: str, code_challenge: str, method: str) -> bool:
    """
    Verify PKCE code_challenge against code_verifier.

    Only S256 is accepted — plain PKCE is insecure and MUST NOT be used.
    S256: code_challenge == base64url(SHA256(code_verifier))
    """
    if method != "S256":
        logger.warning(f"Rejected PKCE method '{method}' — only S256 is allowed")
        return False

    computed = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return computed == code_challenge
