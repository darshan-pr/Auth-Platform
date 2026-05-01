import importlib

from app.config import settings
import app.services.jwt_service as jwt_service_module


def test_hs256_uses_jwt_secret_for_sign_and_verify():
    original_algorithm = settings.JWT_ALGORITHM
    original_secret = settings.JWT_SECRET

    try:
        settings.JWT_ALGORITHM = "HS256"
        settings.JWT_SECRET = "secret-one"
        jwt_service = importlib.reload(jwt_service_module)

        token = jwt_service.create_access_token({"sub": "user-1", "user_id": 1})
        payload = jwt_service.verify_token(token)

        assert payload is not None
        assert payload["sub"] == "user-1"

        settings.JWT_SECRET = "secret-two"
        jwt_service = importlib.reload(jwt_service_module)

        assert jwt_service.verify_token(token) is None
    finally:
        settings.JWT_ALGORITHM = original_algorithm
        settings.JWT_SECRET = original_secret
        importlib.reload(jwt_service_module)
