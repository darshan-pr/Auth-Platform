"""
Test fixtures for multi-tenant auth platform tests.

Uses SQLite in-memory database for isolation and speed.
Mocks Redis for OTP/session operations.
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

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
    mock_redis.exists.return_value = False

    with patch("app.services.otp_service.redis_client", mock_redis), \
         patch("app.services.password_service.redis_client", mock_redis), \
         patch("app.services.oauth_service.redis_client", mock_redis), \
         patch("app.services.passkey_service.redis_client", mock_redis), \
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
    """Register an admin and return their auth token + metadata"""
    response = client.post("/admin/register", json={
        "email": "admin@test.com",
        "password": "TestPass123!",
        "tenant_name": "Test Org"
    })
    assert response.status_code == 200
    data = response.json()
    return {
        "token": data["access_token"],
        "tenant_id": data["tenant_id"],
        "admin_id": data["admin_id"],
        "headers": {"Authorization": f"Bearer {data['access_token']}"}
    }


@pytest.fixture
def second_admin_token(client):
    """Register a second admin with separate tenant"""
    response = client.post("/admin/register", json={
        "email": "admin2@other.com",
        "password": "TestPass456!",
        "tenant_name": "Other Org"
    })
    assert response.status_code == 200
    data = response.json()
    return {
        "token": data["access_token"],
        "tenant_id": data["tenant_id"],
        "admin_id": data["admin_id"],
        "headers": {"Authorization": f"Bearer {data['access_token']}"}
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
