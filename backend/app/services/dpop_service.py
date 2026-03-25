"""
DPoP (Demonstrating Proof-of-Possession) — RFC 9449

Sender-constrained tokens: the access token is bound to a specific
client key-pair so that stolen tokens are useless without the private key.

Flow:
  1. Client generates an ephemeral key-pair, signs a DPoP proof JWT
  2. Client sends the DPoP proof in the `DPoP` header during token exchange
  3. Server validates the proof and binds the access token via a `cnf.jkt` claim
  4. On subsequent API calls, the client presents a new DPoP proof JWT
  5. Server verifies the proof's JWK thumbprint matches the `cnf.jkt` in the token
"""

import json
import time
import hashlib
import base64
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _base64url_decode(s: str) -> bytes:
    """Decode base64url-encoded string (no padding)."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _base64url_encode(b: bytes) -> str:
    """Encode bytes to base64url string (no padding)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _compute_jwk_thumbprint(jwk: dict) -> str:
    """
    Compute the JWK Thumbprint (RFC 7638) for the given JWK.
    Uses the required members in lexicographic order.
    """
    kty = jwk.get("kty", "")

    if kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        members = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise ValueError(f"Unsupported key type: {kty}")

    # Canonical JSON: sorted keys, no whitespace
    canonical = json.dumps(members, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("ascii")).digest()
    return _base64url_encode(digest)


def _public_key_from_jwk(jwk: dict):
    """
    Reconstruct a cryptography public key object from a JWK dict.
    Supports RSA and EC keys (the most common for DPoP).
    Returns a key object usable by PyJWT for signature verification.
    """
    kty = jwk.get("kty", "")

    if kty == "RSA":
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            RSAPublicNumbers,
        )
        from cryptography.hazmat.backends import default_backend

        def _b64_to_int(b64: str) -> int:
            data = _base64url_decode(b64)
            return int.from_bytes(data, "big")

        n = _b64_to_int(jwk["n"])
        e = _b64_to_int(jwk["e"])
        pub_numbers = RSAPublicNumbers(e, n)
        return pub_numbers.public_key(default_backend())

    elif kty == "EC":
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers,
            SECP256R1,
            SECP384R1,
            SECP521R1,
        )
        from cryptography.hazmat.backends import default_backend

        crv_map = {
            "P-256": SECP256R1(),
            "P-384": SECP384R1(),
            "P-521": SECP521R1(),
        }
        crv_name = jwk.get("crv", "P-256")
        curve = crv_map.get(crv_name)
        if not curve:
            raise ValueError(f"Unsupported EC curve: {crv_name}")

        def _b64_to_int(b64: str) -> int:
            data = _base64url_decode(b64)
            return int.from_bytes(data, "big")

        x = _b64_to_int(jwk["x"])
        y = _b64_to_int(jwk["y"])
        pub_numbers = EllipticCurvePublicNumbers(x, y, curve)
        return pub_numbers.public_key(default_backend())

    elif kty == "OKP":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        x_bytes = _base64url_decode(jwk["x"])
        return Ed25519PublicKey.from_public_bytes(x_bytes)

    else:
        raise ValueError(f"Unsupported key type for DPoP: {kty}")


def validate_dpop_proof(
    dpop_header: str,
    http_method: str,
    http_uri: str,
    access_token: Optional[str] = None,
) -> Optional[dict]:
    """
    Validate a DPoP proof JWT (RFC 9449).

    Returns the proof payload containing the JWK and thumbprint, or None on failure.

    Checks:
    - JWS has exactly 3 parts (header.payload.signature)
    - Header typ == "dpop+jwt"
    - Header alg is asymmetric and supported (no 'none', no symmetric)
    - Header jwk is present and contains no private key material
    - **Cryptographic signature verification** using the public key in `jwk`
    - Payload htm matches http_method
    - Payload htu matches http_uri
    - Payload iat is recent (within 5 minutes)
    - Payload jti is present (unique nonce, replay-protected via Redis)
    - If access_token provided, payload ath matches SHA-256 of the token
    """
    try:
        parts = dpop_header.split(".")
        if len(parts) != 3:
            logger.warning("DPoP proof: invalid JWS format")
            return None

        # Decode header (without signature verification first — to extract alg/jwk)
        header = json.loads(_base64url_decode(parts[0]))
        payload_dict = json.loads(_base64url_decode(parts[1]))

        # --- Header checks ---
        if header.get("typ") != "dpop+jwt":
            logger.warning("DPoP proof: invalid typ")
            return None

        alg = header.get("alg", "")
        # Reject symmetric algorithms and 'none' — DPoP must use asymmetric keys
        _DISALLOWED_ALGS = {"none", "", "HS256", "HS384", "HS512"}
        if alg in _DISALLOWED_ALGS:
            logger.warning(f"DPoP proof: disallowed alg={alg!r}")
            return None

        jwk = header.get("jwk")
        if not jwk:
            logger.warning("DPoP proof: missing jwk")
            return None

        # Reject private key material in the JWK
        if "d" in jwk:
            logger.warning("DPoP proof: private key material in jwk")
            return None

        # --- Cryptographic signature verification (THE CRITICAL STEP) ---
        # Reconstruct the public key from the JWK and verify the JWT signature.
        # Without this, the proof is not authenticated at all.
        try:
            import jwt as pyjwt

            public_key = _public_key_from_jwk(jwk)
            # Verify signature and decode — options disable exp/iat enforcement
            # (we do those checks manually below with stricter logic)
            pyjwt.decode(
                dpop_header,
                public_key,
                algorithms=[alg],
                options={
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except Exception as sig_err:
            logger.warning(f"DPoP proof: signature verification failed: {sig_err}")
            return None

        # --- Payload claim checks ---
        htm = payload_dict.get("htm", "")
        if htm.upper() != http_method.upper():
            logger.warning(f"DPoP proof: htm mismatch, expected={http_method}, got={htm}")
            return None

        htu = payload_dict.get("htu", "")
        if htu != http_uri:
            logger.warning(f"DPoP proof: htu mismatch, expected={http_uri}, got={htu}")
            return None

        # Check iat (issued at) — must be within 5 minutes
        iat = payload_dict.get("iat", 0)
        now = time.time()
        if abs(now - iat) > 300:
            logger.warning("DPoP proof: iat too old or in the future")
            return None

        # Check jti (nonce) presence and replay protection via Redis
        jti = payload_dict.get("jti")
        if not jti:
            logger.warning("DPoP proof: missing jti")
            return None

        try:
            from app.redis import redis_client
            jti_key = f"dpop:jti:{jti}"
            if redis_client.exists(jti_key):
                logger.warning("DPoP proof: jti replay detected")
                return None
            redis_client.setex(jti_key, 300, "1")  # 5 min TTL matches iat window
        except Exception:
            pass  # If Redis is down, skip replay check (fail open for availability)

        # If access_token provided, verify ath claim (token binding)
        if access_token:
            expected_ath = _base64url_encode(
                hashlib.sha256(access_token.encode("ascii")).digest()
            )
            if payload_dict.get("ath") != expected_ath:
                logger.warning("DPoP proof: ath mismatch")
                return None

        # Compute JWK thumbprint for cnf binding
        thumbprint = _compute_jwk_thumbprint(jwk)

        return {
            "jwk": jwk,
            "jkt": thumbprint,
            "alg": alg,
            "jti": jti,
        }

    except Exception as e:
        logger.warning(f"DPoP proof validation error: {e}")
        return None


def create_dpop_thumbprint(dpop_header: str) -> Optional[str]:
    """
    Extract the JWK thumbprint from a DPoP proof header.
    Used during token issuance to bind the token to the client's key.
    """
    try:
        parts = dpop_header.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(_base64url_decode(parts[0]))
        jwk = header.get("jwk")
        if not jwk:
            return None
        return _compute_jwk_thumbprint(jwk)
    except Exception as e:
        logger.warning(f"DPoP thumbprint extraction error: {e}")
        return None
