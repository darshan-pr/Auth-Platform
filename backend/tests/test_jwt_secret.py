import importlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from app.config import settings
import app.services.jwt_service as jwt_service_module


def _write_keypair(target_dir: Path) -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    (target_dir / "private_key.pem").write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (target_dir / "public_key.pem").write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_rs256_rejects_tokens_from_different_keypair(tmp_path):
    original_algorithm = settings.JWT_ALGORITHM
    original_keys_dir = settings.JWT_KEYS_DIR
    original_private = settings.JWT_PRIVATE_KEY_PEM
    original_public = settings.JWT_PUBLIC_KEY_PEM

    keys_dir_one = tmp_path / "keys-one"
    keys_dir_two = tmp_path / "keys-two"
    keys_dir_one.mkdir()
    keys_dir_two.mkdir()
    _write_keypair(keys_dir_one)
    _write_keypair(keys_dir_two)

    try:
        settings.JWT_ALGORITHM = "RS256"
        settings.JWT_PRIVATE_KEY_PEM = ""
        settings.JWT_PUBLIC_KEY_PEM = ""

        settings.JWT_KEYS_DIR = str(keys_dir_one)
        jwt_service = importlib.reload(jwt_service_module)

        token = jwt_service.create_access_token({"sub": "user-1", "user_id": 1})
        payload = jwt_service.verify_token(token)
        assert payload is not None
        assert payload["sub"] == "user-1"

        settings.JWT_KEYS_DIR = str(keys_dir_two)
        jwt_service = importlib.reload(jwt_service_module)
        assert jwt_service.verify_token(token) is None
    finally:
        settings.JWT_ALGORITHM = original_algorithm
        settings.JWT_KEYS_DIR = original_keys_dir
        settings.JWT_PRIVATE_KEY_PEM = original_private
        settings.JWT_PUBLIC_KEY_PEM = original_public
        importlib.reload(jwt_service_module)
