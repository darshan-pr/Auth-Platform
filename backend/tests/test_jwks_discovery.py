import json
from datetime import timedelta

import jwt

from app.config import settings
from app.services.jwt_service import create_access_token, get_public_jwk


def _public_key_from_jwk(jwk: dict):
    return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))


def _decode_with_jwks(token: str, jwks: dict, audience: str) -> dict:
    header = jwt.get_unverified_header(token)
    jwk = next(key for key in jwks["keys"] if key["kid"] == header["kid"])
    return jwt.decode(
        token,
        _public_key_from_jwk(jwk),
        algorithms=[jwk["alg"]],
        issuer=settings.JWT_ISSUER,
        audience=audience,
    )


def test_jwks_endpoint_is_public_and_contains_active_signing_key(client):
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    jwks = response.json()
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1

    active_key = get_public_jwk()
    published_key = jwks["keys"][0]
    assert published_key["kid"] == active_key["kid"]
    assert published_key["kty"] == "RSA"
    assert published_key["use"] == "sig"
    assert published_key["alg"] == settings.JWT_ALGORITHM
    assert published_key["n"] == active_key["n"]
    assert published_key["e"] == active_key["e"]


def test_openid_configuration_is_public(client):
    response = client.get("/.well-known/openid-configuration")

    assert response.status_code == 200
    payload = response.json()
    issuer = settings.JWT_ISSUER.rstrip("/")
    assert payload["issuer"] == issuer
    assert payload["jwks_uri"] == f"{issuer}/.well-known/jwks.json"
    assert payload["authorization_endpoint"] == f"{issuer}/oauth/authorize"
    assert payload["token_endpoint"] == f"{issuer}/oauth/token"


def test_access_token_has_kid_and_verifies_locally_with_jwks(client):
    audience = "3a856345003e9d2b"
    token = create_access_token(
        {
            "sub": "usr_123",
            "user_id": 123,
            "email": "user@example.com",
            "aud": audience,
        }
    )

    jwks = client.get("/.well-known/jwks.json").json()
    header = jwt.get_unverified_header(token)
    assert header["kid"] == jwks["keys"][0]["kid"]

    payload = _decode_with_jwks(token, jwks, audience)
    assert payload["iss"] == settings.JWT_ISSUER
    assert payload["sub"] == "usr_123"
    assert payload["aud"] == audience
    assert payload["email"] == "user@example.com"
    assert isinstance(payload["iat"], int)
    assert isinstance(payload["exp"], int)


def test_expired_or_wrong_audience_tokens_fail_local_verification(client):
    audience = "3a856345003e9d2b"
    jwks = client.get("/.well-known/jwks.json").json()

    expired_token = create_access_token(
        {"sub": "usr_123", "user_id": 123, "aud": audience},
        expires_delta=timedelta(seconds=-1),
    )
    wrong_audience_token = create_access_token(
        {"sub": "usr_123", "user_id": 123, "aud": "other-api"},
    )

    try:
        _decode_with_jwks(expired_token, jwks, audience)
        assert False, "expired token should fail local verification"
    except jwt.ExpiredSignatureError:
        pass

    try:
        _decode_with_jwks(wrong_audience_token, jwks, audience)
        assert False, "wrong-audience token should fail local verification"
    except jwt.InvalidAudienceError:
        pass
