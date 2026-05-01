"""
Test fixtures for multi-tenant auth platform tests.

Uses SQLite in-memory database for isolation and speed.
Mocks Redis for OTP/session operations.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


def _ensure_test_jwt_keys() -> None:
    """Create a temporary RS256 keypair for tests if none is configured."""
    if os.getenv("JWT_PRIVATE_KEY_PEM") or os.getenv("JWT_PUBLIC_KEY_PEM"):
        return

    configured_dir = os.getenv("JWT_KEYS_DIR")
    if configured_dir:
        keys_dir = Path(configured_dir)
        if (keys_dir / "private_key.pem").exists() and (keys_dir / "public_key.pem").exists():
            return
    else:
        keys_dir = Path(tempfile.mkdtemp(prefix="jwt-keys-"))
        os.environ["JWT_KEYS_DIR"] = str(keys_dir)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    (keys_dir / "private_key.pem").write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (keys_dir / "public_key.pem").write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


_ensure_test_jwt_keys()

from app.db import Base, get_db
from app.main import app

# SQLite in-memory database for testing
SQLALCHEMY_DATABASE_URL = "sqlite://"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key support in SQLite"""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Mock Redis client
mock_redis = MagicMock()
mock_redis_store = {}
mock_redis_sorted_sets = {}  # For rate limiter


def mock_redis_setex(key, ttl, value):
    mock_redis_store[key] = value


def mock_redis_get(key):
    return mock_redis_store.get(key)


def mock_redis_delete(key):
    mock_redis_store.pop(key, None)
    mock_redis_sorted_sets.pop(key, None)


def mock_redis_exists(key):
    return key in mock_redis_store


def mock_redis_incr(key):
    val = int(mock_redis_store.get(key, 0)) + 1
    mock_redis_store[key] = str(val)
    return val


def mock_redis_expire(key, ttl):
    pass  # no-op for tests


def mock_redis_ttl(key):
    if key in mock_redis_store:
        return 900  # Simulate active lockout
    return -2  # Key doesn't exist


# Rate limiter sorted set mocks
def mock_redis_zadd(key, mapping):
    if key not in mock_redis_sorted_sets:
        mock_redis_sorted_sets[key] = {}
    mock_redis_sorted_sets[key].update(mapping)
    return len(mapping)


def mock_redis_zcard(key):
    return len(mock_redis_sorted_sets.get(key, {}))


def mock_redis_zremrangebyscore(key, min_score, max_score):
    if key in mock_redis_sorted_sets:
        mock_redis_sorted_sets[key] = {
            k: v for k, v in mock_redis_sorted_sets[key].items()
            if not (float(min_score) <= float(v) <= float(max_score))
        }
    return 0


def mock_redis_zrange(key, start, stop, withscores=False):
    items = list(mock_redis_sorted_sets.get(key, {}).items())
    if withscores:
        return [(k, float(v)) for k, v in items[start:stop+1 if stop >= 0 else None]]
    return [k for k, _ in items[start:stop+1 if stop >= 0 else None]]


mock_redis.setex = mock_redis_setex
mock_redis.get = mock_redis_get
mock_redis.delete = mock_redis_delete
mock_redis.incr = mock_redis_incr
mock_redis.expire = mock_redis_expire
mock_redis.ttl = mock_redis_ttl


@pytest.fixture(autouse=True)
def mock_redis_client():
    """Mock Redis for all tests"""
    mock_redis_store.clear()
    mock_redis_sorted_sets.clear()

    # Pipeline mock for rate limiter — always allows requests in tests
    mock_pipeline = MagicMock()
    mock_pipeline.zremrangebyscore.return_value = mock_pipeline
    mock_pipeline.zcard.return_value = mock_pipeline
    mock_pipeline.zadd.return_value = mock_pipeline
    mock_pipeline.expire.return_value = mock_pipeline
    mock_pipeline.execute.return_value = [0, 0, 1, True]
    mock_redis.pipeline.return_value = mock_pipeline
    mock_redis.exists.side_effect = mock_redis_exists

    with patch("app.services.otp_service.redis_client", mock_redis), \
         patch("app.services.password_service.redis_client", mock_redis), \
         patch("app.services.oauth_service.redis_client", mock_redis), \
         patch("app.services.passkey_service.redis_client", mock_redis), \
         patch("app.api.auth.redis_client", mock_redis), \
         patch("app.api.admin.redis_client", mock_redis), \
         patch("app.redis.redis_client", mock_redis), \
         patch("app.services.geo_service.get_location", return_value={}):
        yield mock_redis


@pytest.fixture(autouse=True)
def mock_email():
    """Mock email sending for all tests"""
    with patch("app.services.mail_service._send_email"):
        yield


@pytest.fixture(scope="function")
def db():
    """Create a fresh database for each test"""
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    """Create a test client with DB override"""
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def admin_token(client):
    """Register an admin via 2-step OTP flow and return their auth token + metadata"""
    # Step 1: Send OTP
    reg_response = client.post("/admin/register", json={
        "email": "admin@test.com",
        "password": "TestPass123!",
        "tenant_name": "Test Org"
    })
    assert reg_response.status_code == 200
    
    # Step 2: Retrieve OTP from mock Redis and verify
    otp = mock_redis_store.get("otp:admin@test.com")
    assert otp is not None, "OTP was not generated in mock Redis"
    
    response = client.post("/admin/register/verify-otp", json={
        "email": "admin@test.com",
        "otp": otp
    })
    assert response.status_code == 200
    data = response.json()
    
    # Extract token from HttpOnly cookie set by the server
    token = None
    for cookie_header in response.headers.get_list('set-cookie'):
        if 'admin_token=' in cookie_header:
            token = cookie_header.split('admin_token=')[1].split(';')[0]
            break
    
    return {
        "token": token,
        "tenant_id": data["tenant_id"],
        "admin_id": data["admin_id"],
        "headers": {"Authorization": f"Bearer {token}"} if token else {}
    }


@pytest.fixture
def second_admin_token(client):
    """Register a second admin via 2-step OTP flow with separate tenant"""
    # Step 1: Send OTP
    reg_response = client.post("/admin/register", json={
        "email": "admin2@other.com",
        "password": "TestPass456!",
        "tenant_name": "Other Org"
    })
    assert reg_response.status_code == 200
    
    # Step 2: Retrieve OTP from mock Redis and verify
    otp = mock_redis_store.get("otp:admin2@other.com")
    assert otp is not None, "OTP was not generated in mock Redis"
    
    response = client.post("/admin/register/verify-otp", json={
        "email": "admin2@other.com",
        "otp": otp
    })
    assert response.status_code == 200
    data = response.json()
    
    token = None
    for cookie_header in response.headers.get_list('set-cookie'):
        if 'admin_token=' in cookie_header:
            token = cookie_header.split('admin_token=')[1].split(';')[0]
            break
    
    return {
        "token": token,
        "tenant_id": data["tenant_id"],
        "admin_id": data["admin_id"],
        "headers": {"Authorization": f"Bearer {token}"} if token else {}
    }


@pytest.fixture
def test_app(client, admin_token):
    """Create a test app under the first admin's tenant"""
    response = client.post("/admin/apps", json={
        "name": "Test App",
        "description": "Test application",
        "otp_enabled": False,
        "redirect_uris": "http://localhost:3000/callback"
    }, headers=admin_token["headers"])
    assert response.status_code == 200
    return response.json()


@pytest.fixture
def second_tenant_app(client, second_admin_token):
    """Create a test app under the second admin's tenant"""
    response = client.post("/admin/apps", json={
        "name": "Other App",
        "description": "Other tenant's app",
        "otp_enabled": False,
        "redirect_uris": "http://localhost:4000/callback"
    }, headers=second_admin_token["headers"])
    assert response.status_code == 200
    return response.json()
