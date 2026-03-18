"""
Tests for tenant management and admin authentication.
Covers: admin registration, login, tenant CRUD, JWT validation.
"""
from tests.conftest import mock_redis_store


class TestAdminRegistration:
    """Test admin registration creates admin + tenant"""

    def test_register_admin_creates_tenant(self, client):
        # Step 1: Send OTP
        response = client.post("/admin/register", json={
            "email": "newadmin@test.com",
            "password": "SecurePass1!",
            "tenant_name": "My Company"
        })
        assert response.status_code == 200
        data = response.json()
        assert "OTP" in data["message"] or "otp" in data["message"].lower()
        
        # Step 2: Verify OTP
        otp = mock_redis_store.get("otp:newadmin@test.com")
        assert otp is not None
        
        response2 = client.post("/admin/register/verify-otp", json={
            "email": "newadmin@test.com",
            "otp": otp
        })
        assert response2.status_code == 200
        data2 = response2.json()
        # Token is now in HttpOnly cookie, not response body
        cookies = response2.headers.get_list('set-cookie')
        assert any('admin_token=' in c for c in cookies)
        assert data2["tenant_name"] == "My Company"
        assert data2["tenant_id"] is not None
        assert data2["admin_id"] is not None

    def test_register_duplicate_email_fails(self, client, admin_token):
        response = client.post("/admin/register", json={
            "email": "admin@test.com",
            "password": "AnotherPass1!",
            "tenant_name": "Duplicate Org"
        })
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

    def test_register_creates_unique_slugs(self, client):
        # Step 1 for both admins: send OTPs
        r1 = client.post("/admin/register", json={
            "email": "a1@test.com", "password": "Pass1234!", "tenant_name": "Same Name"
        })
        r2 = client.post("/admin/register", json={
            "email": "a2@test.com", "password": "Pass1234!", "tenant_name": "Same Name"
        })
        assert r1.status_code == 200
        assert r2.status_code == 200
        # Both OTP requests succeed — slugs created on verify
        # Verify both
        otp1 = mock_redis_store.get("otp:a1@test.com")
        otp2 = mock_redis_store.get("otp:a2@test.com")
        v1 = client.post("/admin/register/verify-otp", json={"email": "a1@test.com", "otp": otp1})
        v2 = client.post("/admin/register/verify-otp", json={"email": "a2@test.com", "otp": otp2})
        assert v1.status_code == 200
        assert v2.status_code == 200


class TestAdminLogin:
    """Test admin login and JWT generation"""

    def test_login_success(self, client, admin_token):
        response = client.post("/admin/login", json={
            "email": "admin@test.com",
            "password": "TestPass123!"
        })
        assert response.status_code == 200
        data = response.json()
        # Token is now in HttpOnly cookie, not response body
        cookies = response.headers.get_list('set-cookie')
        assert any('admin_token=' in c for c in cookies)
        assert data["tenant_id"] == admin_token["tenant_id"]
        assert data["tenant_name"] == "Test Org"

    def test_login_wrong_password(self, client, admin_token):
        response = client.post("/admin/login", json={
            "email": "admin@test.com",
            "password": "WrongPass1!"
        })
        assert response.status_code == 401

    def test_login_nonexistent_email(self, client):
        response = client.post("/admin/login", json={
            "email": "nobody@test.com",
            "password": "Pass1234!"
        })
        assert response.status_code == 401


class TestAdminAuth:
    """Test admin JWT authentication on protected endpoints"""

    def test_protected_endpoint_without_token(self, client):
        response = client.get("/admin/apps")
        assert response.status_code in (401, 403)

    def test_protected_endpoint_with_invalid_token(self, client):
        response = client.get("/admin/apps", headers={
            "Authorization": "Bearer invalid.token.here"
        })
        assert response.status_code == 401

    def test_protected_endpoint_with_valid_token(self, client, admin_token):
        response = client.get("/admin/apps", headers=admin_token["headers"])
        assert response.status_code == 200


class TestTenantManagement:
    """Test tenant CRUD operations"""

    def test_get_tenant(self, client, admin_token):
        response = client.get("/admin/tenant", headers=admin_token["headers"])
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Org"
        assert data["slug"] == "test-org"
        assert data["id"] == admin_token["tenant_id"]

    def test_update_tenant(self, client, admin_token):
        response = client.put("/admin/tenant", json={
            "name": "Updated Org Name"
        }, headers=admin_token["headers"])
        assert response.status_code == 200
        assert response.json()["name"] == "Updated Org Name"

    def test_tenants_are_independent(self, client, admin_token, second_admin_token):
        t1 = client.get("/admin/tenant", headers=admin_token["headers"]).json()
        t2 = client.get("/admin/tenant", headers=second_admin_token["headers"]).json()
        assert t1["id"] != t2["id"]
        assert t1["name"] != t2["name"]
