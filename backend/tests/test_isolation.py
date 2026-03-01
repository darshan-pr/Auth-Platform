"""
Tests for multi-tenant data isolation.
Covers: app isolation, user isolation, cross-tenant prevention, JWT tenant claims.
"""
import pytest


class TestAppIsolation:
    """Test that apps are isolated by tenant"""

    def test_create_app_has_tenant_id(self, client, admin_token):
        response = client.post("/admin/apps", json={
            "name": "My App",
            "otp_enabled": False
        }, headers=admin_token["headers"])
        assert response.status_code == 200
        data = response.json()
        assert data["tenant_id"] == admin_token["tenant_id"]

    def test_list_apps_only_shows_own_tenant(self, client, admin_token, second_admin_token, test_app, second_tenant_app):
        """Each admin should only see their own tenant's apps"""
        # Admin 1 sees only their app
        r1 = client.get("/admin/apps", headers=admin_token["headers"])
        apps1 = r1.json()
        assert len(apps1) == 1
        assert apps1[0]["name"] == "Test App"

        # Admin 2 sees only their app
        r2 = client.get("/admin/apps", headers=second_admin_token["headers"])
        apps2 = r2.json()
        assert len(apps2) == 1
        assert apps2[0]["name"] == "Other App"

    def test_cannot_access_other_tenants_app(self, client, admin_token, second_tenant_app):
        """Admin cannot access an app from another tenant"""
        other_app_id = second_tenant_app["app_id"]
        response = client.get(f"/admin/apps/{other_app_id}", headers=admin_token["headers"])
        assert response.status_code == 404

    def test_cannot_update_other_tenants_app(self, client, admin_token, second_tenant_app):
        other_app_id = second_tenant_app["app_id"]
        response = client.put(f"/admin/apps/{other_app_id}", json={
            "name": "Hacked Name"
        }, headers=admin_token["headers"])
        assert response.status_code == 404

    def test_cannot_delete_other_tenants_app(self, client, admin_token, second_tenant_app):
        other_app_id = second_tenant_app["app_id"]
        response = client.delete(f"/admin/apps/{other_app_id}", headers=admin_token["headers"])
        assert response.status_code == 404

    def test_cannot_get_other_tenants_credentials(self, client, admin_token, second_tenant_app):
        other_app_id = second_tenant_app["app_id"]
        response = client.get(
            f"/admin/apps/{other_app_id}/credentials",
            headers=admin_token["headers"]
        )
        assert response.status_code == 404


class TestUserIsolation:
    """Test that users are isolated by tenant"""

    def test_create_user_in_tenant(self, client, admin_token, test_app):
        response = client.post("/admin/users", json={
            "email": "user@test.com",
            "app_id": test_app["app_id"]
        }, headers=admin_token["headers"])
        assert response.status_code == 200
        data = response.json()
        assert data["tenant_id"] == admin_token["tenant_id"]

    def test_cannot_create_user_with_other_tenants_app(self, client, admin_token, second_tenant_app):
        """Admin cannot create users under another tenant's app"""
        response = client.post("/admin/users", json={
            "email": "user@test.com",
            "app_id": second_tenant_app["app_id"]
        }, headers=admin_token["headers"])
        assert response.status_code == 400
        assert "not found in your tenant" in response.json()["detail"]

    def test_list_users_only_shows_own_tenant(self, client, admin_token, second_admin_token, test_app, second_tenant_app):
        # Create user in tenant 1
        client.post("/admin/users", json={
            "email": "t1user@test.com", "app_id": test_app["app_id"]
        }, headers=admin_token["headers"])

        # Create user in tenant 2
        client.post("/admin/users", json={
            "email": "t2user@test.com", "app_id": second_tenant_app["app_id"]
        }, headers=second_admin_token["headers"])

        # Each admin only sees their user
        r1 = client.get("/admin/users", headers=admin_token["headers"])
        assert r1.json()["total"] == 1
        assert r1.json()["users"][0]["email"] == "t1user@test.com"

        r2 = client.get("/admin/users", headers=second_admin_token["headers"])
        assert r2.json()["total"] == 1
        assert r2.json()["users"][0]["email"] == "t2user@test.com"

    def test_same_email_different_tenants(self, client, admin_token, second_admin_token, test_app, second_tenant_app):
        """Same email can exist in different tenants"""
        r1 = client.post("/admin/users", json={
            "email": "shared@test.com", "app_id": test_app["app_id"]
        }, headers=admin_token["headers"])
        assert r1.status_code == 200

        r2 = client.post("/admin/users", json={
            "email": "shared@test.com", "app_id": second_tenant_app["app_id"]
        }, headers=second_admin_token["headers"])
        assert r2.status_code == 200

    def test_cannot_access_other_tenants_user(self, client, admin_token, second_admin_token, second_tenant_app):
        # Create user in tenant 2
        r = client.post("/admin/users", json={
            "email": "private@test.com", "app_id": second_tenant_app["app_id"]
        }, headers=second_admin_token["headers"])
        user_id = r.json()["id"]

        # Admin 1 cannot see it
        response = client.get(f"/admin/users/{user_id}", headers=admin_token["headers"])
        assert response.status_code == 404


class TestDashboardStatsIsolation:
    """Test that dashboard stats are tenant-scoped"""

    def test_stats_only_count_own_tenant(self, client, admin_token, second_admin_token, test_app, second_tenant_app):
        # Create users in each tenant
        client.post("/admin/users", json={
            "email": "u1@test.com", "app_id": test_app["app_id"]
        }, headers=admin_token["headers"])
        client.post("/admin/users", json={
            "email": "u2@test.com", "app_id": test_app["app_id"]
        }, headers=admin_token["headers"])
        client.post("/admin/users", json={
            "email": "u3@test.com", "app_id": second_tenant_app["app_id"]
        }, headers=second_admin_token["headers"])

        # Admin 1 stats
        s1 = client.get("/admin/stats", headers=admin_token["headers"]).json()
        assert s1["total_apps"] == 1
        assert s1["total_users"] == 2

        # Admin 2 stats
        s2 = client.get("/admin/stats", headers=second_admin_token["headers"]).json()
        assert s2["total_apps"] == 1
        assert s2["total_users"] == 1


class TestAuthTenantIsolation:
    """Test that auth flows (signup/login) respect tenant boundaries"""

    def test_signup_adds_tenant_id(self, client, test_app):
        """Signing up through an app should assign the app's tenant"""
        response = client.post("/auth/signup", json={
            "email": "newuser@test.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        assert response.status_code == 200

    def test_login_returns_token_with_tenant(self, client, test_app):
        """Login tokens should contain tenant_id"""
        # First signup
        client.post("/auth/signup", json={
            "email": "loginuser@test.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })

        # Then login (OTP disabled for this app)
        response = client.post("/auth/login", json={
            "email": "loginuser@test.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] is not None

        # Verify the token contains tenant_id
        verify_response = client.post("/token/verify", json={
            "token": data["access_token"]
        })
        assert verify_response.status_code == 200
        payload = verify_response.json()["payload"]
        assert "tenant_id" in payload
        assert payload["tenant_id"] is not None
        assert "app_id" in payload
        assert "user_id" in payload

    def test_user_can_login_from_different_app_same_tenant(self, client, admin_token, test_app):
        """A user registered through one app should be accessible from another app in the same tenant"""
        # Create a second app in the same tenant
        r = client.post("/admin/apps", json={
            "name": "Second App",
            "otp_enabled": False,
        }, headers=admin_token["headers"])
        second_app = r.json()

        # Signup through first app
        client.post("/auth/signup", json={
            "email": "multiapp@test.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })

        # Login through second app (same tenant → should find the user)
        response = client.post("/auth/login", json={
            "email": "multiapp@test.com",
            "password": "StrongPass1!",
            "app_id": second_app["app_id"],
            "app_secret": second_app["app_secret"]
        })
        assert response.status_code == 200
        assert response.json()["access_token"] is not None

    def test_user_cannot_login_from_different_tenant(self, client, test_app, second_tenant_app):
        """A user from tenant 1 should not be found when logging in through tenant 2's app"""
        # Signup through tenant 1's app
        client.post("/auth/signup", json={
            "email": "tenant1user@test.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })

        # Try login through tenant 2's app
        response = client.post("/auth/login", json={
            "email": "tenant1user@test.com",
            "password": "StrongPass1!",
            "app_id": second_tenant_app["app_id"],
            "app_secret": second_tenant_app["app_secret"]
        })
        assert response.status_code == 401  # User not found in tenant 2


class TestJWTTenantClaims:
    """Test that JWT tokens contain the required tenant context"""

    def test_access_token_contains_tenant_id(self, client, test_app):
        """Access token should contain user_id, tenant_id, and app_id (client_id)"""
        # Signup + login
        client.post("/auth/signup", json={
            "email": "jwt@test.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        login_r = client.post("/auth/login", json={
            "email": "jwt@test.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        token = login_r.json()["access_token"]

        # Verify claims
        verify_r = client.post("/token/verify", json={"token": token})
        payload = verify_r.json()["payload"]
        assert payload["sub"] == "jwt@test.com"
        assert "user_id" in payload
        assert "tenant_id" in payload
        assert payload["app_id"] == test_app["app_id"]
        assert payload["type"] == "access"

    def test_refresh_preserves_tenant_id(self, client, test_app):
        """Refreshing a token should preserve tenant_id in the new access token"""
        # Signup + login
        client.post("/auth/signup", json={
            "email": "refresh@test.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        login_r = client.post("/auth/login", json={
            "email": "refresh@test.com",
            "password": "StrongPass1!",
            "app_id": test_app["app_id"],
            "app_secret": test_app["app_secret"]
        })
        refresh_token = login_r.json()["refresh_token"]

        # Refresh
        refresh_r = client.post("/token/refresh", json={
            "refresh_token": refresh_token
        })
        assert refresh_r.status_code == 200
        new_token = refresh_r.json()["access_token"]

        # Verify new token has tenant_id
        verify_r = client.post("/token/verify", json={"token": new_token})
        payload = verify_r.json()["payload"]
        assert "tenant_id" in payload
        assert payload["tenant_id"] is not None

    def test_admin_token_type_is_admin_access(self, client, admin_token):
        """Admin JWT should have type=admin_access"""
        verify_r = client.post("/token/verify", json={
            "token": admin_token["token"]
        })
        payload = verify_r.json()["payload"]
        assert payload["type"] == "admin_access"
        assert payload["admin_id"] == admin_token["admin_id"]
        assert payload["tenant_id"] == admin_token["tenant_id"]
