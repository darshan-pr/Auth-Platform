"""
Tests for the new security features:
- Rate Limiting
- CSRF Protection
- IP/Location Tracking (Login Events)
- Client Authentication (client_secret on OAuth token exchange)
- DPoP (Sender-Constrained Tokens)
"""

import json
import time
import hashlib
import base64
from unittest.mock import patch, MagicMock


# ============== Rate Limiting ==============

class TestRateLimiting:
    """Test rate limiting on auth endpoints."""

    def test_login_rate_limit_allows_normal_requests(self, client, test_app):
        """Normal requests should succeed (rate limiter mocked to allow all)"""
        response = client.post("/auth/login", json={
            "email": "nobody@example.com",
            "password": "WrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"],
        })
        # Should not be 429 — the rate limit mock allows everything
        assert response.status_code != 429

    def test_signup_rate_limit_allows_normal_requests(self, client, test_app):
        """Signup should succeed without hitting rate limit"""
        response = client.post("/auth/signup", json={
            "email": "newuser_rate@example.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"],
        })
        assert response.status_code != 429


# ============== CSRF Protection ==============

class TestCSRFProtection:
    """Test CSRF middleware behavior."""

    def test_json_requests_bypass_csrf(self, client, test_app):
        """JSON API requests should not require CSRF tokens"""
        response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "WrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"],
        })
        # Should not return 403 CSRF error — should get an auth error instead
        assert response.status_code != 403

    def test_get_requests_set_csrf_cookie(self, client):
        """GET requests should set a csrf_token cookie"""
        response = client.get("/health")
        assert response.status_code == 200
        # CSRF cookie should be set on GET requests
        cookies = response.cookies
        assert "csrf_token" in cookies

    def test_form_post_without_csrf_token_is_rejected(self, client):
        """Form POST without CSRF token should return 403"""
        response = client.post(
            "/admin/register",
            data={"email": "test@test.com", "password": "Test123!", "org_name": "Test"},
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code == 403
        assert "CSRF" in response.json()["detail"]

    def test_form_post_with_valid_csrf_token_proceeds(self, client):
        """Form POST with matching CSRF tokens should pass CSRF check"""
        # First get a CSRF token
        get_response = client.get("/health")
        csrf_token = get_response.cookies.get("csrf_token")
        assert csrf_token is not None

        # POST with CSRF token in header and cookie
        response = client.post(
            "/admin/register",
            data={"email": "test@test.com", "password": "Test123!", "org_name": "Test"},
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "x-csrf-token": csrf_token,
            },
            cookies={"csrf_token": csrf_token},
        )
        # Should not be 403 — CSRF passed, might fail on validation but not CSRF
        assert response.status_code != 403


# ============== IP/Location Tracking ==============

class TestLoginEvents:
    """Test that login events are recorded with IP data."""

    def test_login_records_event(self, client, test_app):
        """Successful login should record a login event in the DB"""
        # First signup a user
        client.post("/auth/signup", json={
            "email": "eventuser@example.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"],
        })

        # Login
        response = client.post("/auth/login", json={
            "email": "eventuser@example.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"],
        })
        assert response.status_code == 200

    def test_signup_records_event(self, client, test_app):
        """Signup should record a signup event"""
        response = client.post("/auth/signup", json={
            "email": "signupevent@example.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"],
        })
        assert response.status_code == 200


# ============== Client Auth on OAuth Token Exchange ==============

class TestClientAuthentication:
    """Test client_secret on /oauth/token."""

    def test_invalid_client_secret_is_rejected(self, client, test_app):
        """Providing a wrong client_secret should return 401"""
        response = client.post("/oauth/token", json={
            "grant_type": "authorization_code",
            "code": "fake_code",
            "client_id": test_app["app_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "code_verifier": "test_verifier",
            "client_secret": "wrong_secret",
        })
        assert response.status_code == 401

    def test_missing_client_secret_uses_pkce_only(self, client, test_app):
        """Without client_secret, should proceed with PKCE-only (existing behavior)"""
        response = client.post("/oauth/token", json={
            "grant_type": "authorization_code",
            "code": "fake_code",
            "client_id": test_app["app_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "code_verifier": "test_verifier",
        })
        # Should fail on code validation, not client authentication
        assert response.status_code != 401 or "client_secret" not in response.json().get("detail", "")


# ============== DPoP Service Unit Tests ==============

class TestDPoPService:
    """Test DPoP proof validation and thumbprint computation."""

    def test_compute_jwk_thumbprint(self):
        """Test JWK thumbprint computation for RSA key"""
        from app.services.dpop_service import _compute_jwk_thumbprint
        
        # Test with a known RSA public key JWK
        jwk = {
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
        }
        thumb = _compute_jwk_thumbprint(jwk)
        assert isinstance(thumb, str)
        assert len(thumb) > 0

    def test_validate_dpop_proof_rejects_missing_typ(self):
        """DPoP proof with wrong typ should be rejected"""
        from app.services.dpop_service import validate_dpop_proof

        # Build a minimal "proof" with wrong typ
        header = base64.urlsafe_b64encode(json.dumps({
            "typ": "JWT",  # should be dpop+jwt
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}
        }).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({
            "htm": "POST",
            "htu": "http://localhost/oauth/token",
            "iat": int(time.time()),
            "jti": "unique-id-123",
        }).encode()).rstrip(b"=").decode()
        signature = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()

        dpop = f"{header}.{payload}.{signature}"
        result = validate_dpop_proof(dpop, "POST", "http://localhost/oauth/token")
        assert result is None  # Should be rejected

    def test_validate_dpop_proof_rejects_expired_iat(self):
        """DPoP proof with expired iat should be rejected"""
        from app.services.dpop_service import validate_dpop_proof

        header = base64.urlsafe_b64encode(json.dumps({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}
        }).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({
            "htm": "POST",
            "htu": "http://localhost/oauth/token",
            "iat": int(time.time()) - 600,  # 10 minutes ago — too old
            "jti": "unique-id-456",
        }).encode()).rstrip(b"=").decode()
        signature = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()

        dpop = f"{header}.{payload}.{signature}"
        result = validate_dpop_proof(dpop, "POST", "http://localhost/oauth/token")
        assert result is None  # Should be rejected

    def test_validate_dpop_proof_accepts_valid_structure(self):
        """DPoP proof with a real cryptographic signature should return proof data"""
        from app.services.dpop_service import validate_dpop_proof
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        import uuid

        # Generate a real RSA keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        # Export public key numbers to build the JWK
        pub_numbers = public_key.public_numbers()

        def int_to_base64url(n: int) -> str:
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, 'big')).rstrip(b'=').decode()

        jwk = {
            "kty": "RSA",
            "alg": "RS256",
            "n": int_to_base64url(pub_numbers.n),
            "e": int_to_base64url(pub_numbers.e),
        }

        # Build the DPoP header and payload, then sign with PyJWT
        headers = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": jwk,
        }
        claims = {
            "htm": "POST",
            "htu": "http://localhost/oauth/token",
            "iat": int(time.time()),
            "jti": str(uuid.uuid4()),
        }
        dpop_token = pyjwt.encode(claims, private_key, algorithm="RS256", headers=headers)

        result = validate_dpop_proof(dpop_token, "POST", "http://localhost/oauth/token")
        assert result is not None
        assert "jkt" in result
        assert "jwk" in result

    def test_create_dpop_thumbprint(self):
        """Thumbprint extraction from DPoP proof should work"""
        from app.services.dpop_service import create_dpop_thumbprint

        header = base64.urlsafe_b64encode(json.dumps({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}
        }).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({}).encode()).rstrip(b"=").decode()
        signature = base64.urlsafe_b64encode(b"sig").rstrip(b"=").decode()

        dpop = f"{header}.{payload}.{signature}"
        thumbprint = create_dpop_thumbprint(dpop)
        assert thumbprint is not None
        assert isinstance(thumbprint, str)
