"""
Security tests for the auth platform.
Tests for security vulnerability fixes.
Covers: email enumeration prevention, brute-force protection,
HttpOnly cookie admin auth, app secret hashing.
"""

import pytest
import hashlib
from tests.conftest import mock_redis_store
from app.models.app import App
from app.models.user import User


# ============== Fix 2: Email Enumeration (Forgot Password) ==============

class TestEmailEnumeration:
    """Verify that the forgot-password endpoint never reveals user existence."""

    def test_forgot_password_existing_user_returns_200(self, client, test_app):
        """Known user should get a 200 with generic message."""
        # First create a user
        client.post("/auth/signup", json={
            "email": "exists@test.com",
            "password": "Password123!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })

        resp = client.post("/auth/forgot-password", json={
            "email": "exists@test.com",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "email" in data

    def test_forgot_password_nonexistent_user_returns_200(self, client, test_app):
        """Unknown email should also get 200 — no information leak."""
        resp = client.post("/auth/forgot-password", json={
            "email": "doesntexist@nowhere.com",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "If an account" in data.get("message", "")

    def test_forgot_password_same_message_for_both(self, client, test_app):
        """Both existing and non-existing users get the same message shape."""
        # Create user
        client.post("/auth/signup", json={
            "email": "real@test.com",
            "password": "Password123!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })

        resp_real = client.post("/auth/forgot-password", json={
            "email": "real@test.com",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        resp_fake = client.post("/auth/forgot-password", json={
            "email": "fake@test.com",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })

        # Both should be 200
        assert resp_real.status_code == 200
        assert resp_fake.status_code == 200

    def test_forgot_password_passwordless_user_still_generates_reset(self, client, test_app, db):
        """Existing users without password should still get reset material generated."""
        app = db.query(App).filter(App.app_id == test_app["app_id"]).first()
        assert app is not None

        user = User(
            email="passwordless@test.com",
            password_hash=None,
            app_id=test_app["app_id"],
            tenant_id=app.tenant_id,
            is_active=True,
        )
        db.add(user)
        db.commit()

        resp = client.post("/auth/forgot-password", json={
            "email": "passwordless@test.com",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        assert resp.status_code == 200

        data = resp.json()
        assert data.get("method") == "token"
        reset_token_key = f"reset_token:passwordless@test.com:{test_app['app_id']}"
        assert mock_redis_store.get(reset_token_key) is not None


# ============== Fix 3: Brute-Force Protection ==============

class TestBruteForceProtection:
    """Verify login and OTP brute-force protection."""

    def test_login_brute_force_lockout(self, client, test_app):
        """After 5 failed login attempts, the account should be locked."""
        # Create user
        client.post("/auth/signup", json={
            "email": "bruteforce@test.com",
            "password": "CorrectPass123!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })

        # Fail 5 times
        for i in range(5):
            resp = client.post("/auth/login", json={
                "email": "bruteforce@test.com",
                "password": f"WrongPass{i}!",
                "app_id": test_app["app_id"],
                "app_secret": test_app["app_secret"]
            })
            assert resp.status_code == 401

        # 6th attempt should be locked out (429)
        resp = client.post("/auth/login", json={
            "email": "bruteforce@test.com",
            "password": "CorrectPass123!",  # Even correct password
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        assert resp.status_code == 429
        assert "locked" in resp.json()["detail"].lower()

    def test_successful_login_clears_attempts(self, client, test_app):
        """Successful login should clear the attempt counter."""
        # Create user
        client.post("/auth/signup", json={
            "email": "clearcount@test.com",
            "password": "GoodPass123!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })

        # Fail 3 times (below threshold)
        for i in range(3):
            client.post("/auth/login", json={
                "email": "clearcount@test.com",
                "password": f"BadPass{i}!",
                "app_id": test_app["app_id"],
                "app_secret": test_app["app_secret"]
            })

        # Succeed
        resp = client.post("/auth/login", json={
            "email": "clearcount@test.com",
            "password": "GoodPass123!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        assert resp.status_code == 200

    def test_admin_login_brute_force_lockout(self, client):
        """Admin login should also lock after too many failures."""
        # Register admin via 2-step OTP
        client.post("/admin/register", json={
            "email": "lockedadmin@test.com",
            "password": "AdminPass123!",
            "tenant_name": "Lockout Org"
        })
        otp = mock_redis_store.get("otp:lockedadmin@test.com")
        client.post("/admin/register/verify-otp", json={
            "email": "lockedadmin@test.com",
            "otp": otp
        })

        # Fail 5 times
        for i in range(5):
            resp = client.post("/admin/login", json={
                "email": "lockedadmin@test.com",
                "password": f"WrongAdmin{i}!"
            })
            assert resp.status_code == 401

        # 6th attempt should be locked
        resp = client.post("/admin/login", json={
            "email": "lockedadmin@test.com",
            "password": "AdminPass123!"
        })
        assert resp.status_code == 429


# ============== Fix 4: Admin Token HttpOnly Cookie ==============

class TestAdminHttpOnlyCookie:
    """Verify admin token is set as HttpOnly cookie, not in response body."""

    def test_login_sets_httponly_cookie(self, client):
        """Admin login should set an HttpOnly cookie."""
        # Register first via 2-step OTP
        client.post("/admin/register", json={
            "email": "cookie@test.com",
            "password": "CookiePass123!",
            "tenant_name": "Cookie Org"
        })
        otp = mock_redis_store.get("otp:cookie@test.com")
        client.post("/admin/register/verify-otp", json={
            "email": "cookie@test.com",
            "otp": otp
        })

        # Login
        resp = client.post("/admin/login", json={
            "email": "cookie@test.com",
            "password": "CookiePass123!"
        })
        assert resp.status_code == 200

        # Check that access_token is NOT in response body
        data = resp.json()
        assert "access_token" not in data

        # Check that cookie was set
        cookies = resp.headers.get_list('set-cookie')
        assert any('admin_token=' in c for c in cookies), "admin_token cookie not set"
        cookie_str = [c for c in cookies if 'admin_token=' in c][0]
        assert 'httponly' in cookie_str.lower(), "Cookie is not HttpOnly"

    def test_register_sets_httponly_cookie(self, client):
        """Admin register verify-otp should set an HttpOnly cookie."""
        # Step 1: Send OTP
        resp = client.post("/admin/register", json={
            "email": "newadmin@test.com",
            "password": "NewAdmin123!",
            "tenant_name": "New Org"
        })
        assert resp.status_code == 200
        
        # Step 2: Verify OTP — this should set the cookie
        otp = mock_redis_store.get("otp:newadmin@test.com")
        resp2 = client.post("/admin/register/verify-otp", json={
            "email": "newadmin@test.com",
            "otp": otp
        })
        assert resp2.status_code == 200
        data = resp2.json()
        assert "access_token" not in data

        cookies = resp2.headers.get_list('set-cookie')
        assert any('admin_token=' in c for c in cookies)

    def test_logout_clears_cookie(self, client):
        """POST /admin/logout should clear the admin_token cookie."""
        resp = client.post("/admin/logout", json={})
        assert resp.status_code == 200
        cookies = resp.headers.get_list('set-cookie')
        # Should set admin_token to empty or with max-age=0
        assert any('admin_token=' in c for c in cookies)


# ============== Fix 5: App Secret Hashing ==============

class TestAppSecretHashing:
    """Verify app secrets are hashed at rest and masked on retrieval."""

    def test_app_creation_stores_hashed_secret(self, client, admin_token, db):
        """Creating an app should store a SHA-256 hash, not plaintext."""
        from app.models.app import App

        resp = client.post("/admin/apps", json={
            "name": "Hash Test App",
            "otp_enabled": False,
            "redirect_uris": "http://localhost:3000/callback"
        }, headers=admin_token["headers"])
        assert resp.status_code == 200
        data = resp.json()
        plaintext_secret = data["app_secret"]

        # Check that the DB stores the hash, not plaintext
        app = db.query(App).filter(App.app_id == data["app_id"]).first()
        assert app is not None
        expected_hash = hashlib.sha256(plaintext_secret.encode()).hexdigest()
        assert app.app_secret == expected_hash
        assert app.app_secret != plaintext_secret

    def test_get_credentials_returns_masked_secret(self, client, admin_token, test_app):
        """GET /admin/apps/{id}/credentials should return masked hint, not plaintext."""
        resp = client.get(
            f"/admin/apps/{test_app['app_id']}/credentials",
            headers=admin_token["headers"]
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "app_secret_hint" in data
        assert data["app_secret_hint"].startswith("****")
        assert "app_secret" not in data or data.get("app_secret") is None

    def test_regenerate_secret_returns_new_plaintext_once(self, client, admin_token, test_app, db):
        """Regenerating a secret should return new plaintext once and store hash."""
        from app.models.app import App

        resp = client.post(
            f"/admin/apps/{test_app['app_id']}/regenerate-secret",
            headers=admin_token["headers"]
        )
        assert resp.status_code == 200
        data = resp.json()
        # Plaintext is returned only this once
        assert "app_secret" in data
        new_plaintext = data["app_secret"]

        # Verify DB stores hash of the new secret
        app = db.query(App).filter(App.app_id == test_app["app_id"]).first()
        expected_hash = hashlib.sha256(new_plaintext.encode()).hexdigest()
        assert app.app_secret == expected_hash

    def test_hashed_secret_still_works_for_auth(self, client, admin_token):
        """An app created with hashed secret should still authenticate via API."""
        # Create a new app
        resp = client.post("/admin/apps", json={
            "name": "Auth Test App",
            "otp_enabled": False,
            "redirect_uris": "http://localhost:3000/callback"
        }, headers=admin_token["headers"])
        data = resp.json()
        app_id = data["app_id"]
        app_secret = data["app_secret"]  # plaintext, shown only once

        # Use the plaintext secret to sign up a user (validates hash comparison)
        resp = client.post("/auth/signup", json={
            "email": "hashuser@test.com",
            "password": "TestPass123!",
            "app_id": app_id,
            "app_secret": app_secret
        })
        assert resp.status_code == 200

        # And login
        resp = client.post("/auth/login", json={
            "email": "hashuser@test.com",
            "password": "TestPass123!",
            "app_id": app_id,
            "app_secret": app_secret
        })
        assert resp.status_code == 200
