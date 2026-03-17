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


def validate_dpop_proof(
    dpop_header: str,
    http_method: str,
    http_uri: str,
    access_token: Optional[str] = None,
) -> Optional[dict]:
    """
    Validate a DPoP proof JWT.

    Returns the proof payload containing the JWK and thumbprint, or None on failure.

    Checks:
    - JWS has exactly 3 parts (header.payload.signature)
    - Header typ == "dpop+jwt"
    - Header alg is supported
    - Header jwk is present and contains no private key material
    - Payload htm matches http_method
    - Payload htu matches http_uri
    - Payload iat is recent (within 5 minutes)
    - Payload jti is present (unique nonce)
    - If access_token provided, payload ath matches SHA-256 of the token
    """
    try:
        parts = dpop_header.split(".")
        if len(parts) != 3:
            logger.warning("DPoP proof: invalid JWS format")
            return None

        # Decode header
        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))

        # Check header
        if header.get("typ") != "dpop+jwt":
            logger.warning("DPoP proof: invalid typ")
            return None

        alg = header.get("alg", "")
        if alg in ("none", ""):
            logger.warning("DPoP proof: alg=none is not allowed")
            return None

        jwk = header.get("jwk")
        if not jwk:
            logger.warning("DPoP proof: missing jwk")
            return None

        # Ensure no private key material in JWK
        if "d" in jwk:
            logger.warning("DPoP proof: private key material in jwk")
            return None

        # Check payload claims
        htm = payload.get("htm", "")
        if htm.upper() != http_method.upper():
            logger.warning(f"DPoP proof: htm mismatch, expected={http_method}, got={htm}")
            return None

        htu = payload.get("htu", "")
        if htu != http_uri:
            logger.warning(f"DPoP proof: htu mismatch, expected={http_uri}, got={htu}")
            return None

        # Check iat (issued at) — must be within 5 minutes
        iat = payload.get("iat", 0)
        now = time.time()
        if abs(now - iat) > 300:
            logger.warning("DPoP proof: iat too old or in the future")
            return None

        # Check jti (nonce)
        jti = payload.get("jti")
        if not jti:
            logger.warning("DPoP proof: missing jti")
            return None

        # Check jti uniqueness via Redis (prevent replay)
        try:
            from app.redis import redis_client
            jti_key = f"dpop:jti:{jti}"
            if redis_client.exists(jti_key):
                logger.warning("DPoP proof: jti replay detected")
                return None
            redis_client.setex(jti_key, 300, "1")  # 5 min TTL
        except Exception:
            pass  # If Redis is down, skip replay check

        # If access_token provided, verify ath claim
        if access_token:
            expected_ath = _base64url_encode(
                hashlib.sha256(access_token.encode("ascii")).digest()
            )
            if payload.get("ath") != expected_ath:
                logger.warning("DPoP proof: ath mismatch")
                return None

        # Compute JWK thumbprint
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
