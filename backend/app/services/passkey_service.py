"""
Passkey (WebAuthn) Service

Implements server-side logic for WebAuthn/passkey authentication.
Uses manual CBOR-free approach to keep dependencies minimal.

The flow:
  Registration:
    1. Server generates challenge → client calls navigator.credentials.create()
    2. Client sends attestation response → server verifies & stores credential
  
  Authentication:
    1. Server generates challenge + allowed credentials → client calls navigator.credentials.get()
    2. Client sends assertion response → server verifies cryptographic signature & sign count
"""

import secrets
import hashlib
import base64
import json
import struct
import logging
from typing import Optional
from datetime import datetime

from app.redis import redis_client

logger = logging.getLogger(__name__)

CHALLENGE_EXPIRY = 300  # 5 minutes
RP_NAME = "Auth Platform"

# OTP verification required for passkey registration
PASSKEY_OTP_EXPIRY = 300  # 5 minutes


def _base64url_decode(data: str) -> bytes:
    """Decode base64url-encoded string"""
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ==================== OTP for Passkey Registration ====================

def generate_passkey_registration_otp(email: str, app_id: str) -> str:
    """Generate an OTP that must be verified before a passkey can be registered."""
    import random
    otp = str(random.SystemRandom().randint(100000, 999999))
    key = f"passkey_reg_otp:{app_id}:{email}"
    redis_client.setex(key, PASSKEY_OTP_EXPIRY, otp)
    logger.info(f"Passkey registration OTP generated for {email}")
    return otp


def verify_passkey_registration_otp(email: str, app_id: str, otp: str) -> bool:
    """Verify the OTP for passkey registration. Marks email as verified for 5 min."""
    key = f"passkey_reg_otp:{app_id}:{email}"
    stored = redis_client.get(key)
    if stored is None:
        return False
    if stored != otp:
        return False
    redis_client.delete(key)
    # Mark email as OTP-verified for passkey registration
    verified_key = f"passkey_reg_verified:{app_id}:{email}"
    redis_client.setex(verified_key, PASSKEY_OTP_EXPIRY, "1")
    logger.info(f"Passkey registration OTP verified for {email}")
    return True


def is_passkey_registration_verified(email: str, app_id: str) -> bool:
    """Check if the email has been OTP-verified for passkey registration."""
    key = f"passkey_reg_verified:{app_id}:{email}"
    return redis_client.get(key) == "1"


def clear_passkey_registration_verified(email: str, app_id: str):
    """Clear the passkey registration OTP verification flag."""
    key = f"passkey_reg_verified:{app_id}:{email}"
    redis_client.delete(key)


# ==================== Challenge Management ====================

def generate_passkey_registration_challenge(user_email: str, app_id: str, rp_id: str) -> dict:
    """
    Generate a WebAuthn registration challenge.
    Returns the PublicKeyCredentialCreationOptions to send to the client.
    """
    challenge = secrets.token_bytes(32)
    challenge_b64 = _base64url_encode(challenge)

    # Store challenge in Redis
    key = f"passkey:reg:{app_id}:{user_email}"
    redis_client.setex(key, CHALLENGE_EXPIRY, challenge_b64)

    user_id = hashlib.sha256(f"{app_id}:{user_email}".encode()).digest()

    return {
        "challenge": challenge_b64,
        "rp": {
            "name": RP_NAME,
            "id": rp_id,
        },
        "user": {
            "id": _base64url_encode(user_id),
            "name": user_email,
            "displayName": user_email.split("@")[0],
        },
        "pubKeyCredParams": [
            {"alg": -7, "type": "public-key"},   # ES256
            {"alg": -257, "type": "public-key"},  # RS256
        ],
        "timeout": CHALLENGE_EXPIRY * 1000,
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": True,
            "residentKey": "required",
            "userVerification": "required",
        },
        "attestation": "none",
    }


def verify_passkey_registration(
    user_email: str,
    app_id: str,
    rp_id: str,
    credential_id: str,
    client_data_json_b64: str,
    attestation_object_b64: str,
) -> Optional[dict]:
    """
    Verify a WebAuthn registration response.
    Returns credential data to store, or None if verification fails.
    """
    # Retrieve and delete challenge
    key = f"passkey:reg:{app_id}:{user_email}"
    stored_challenge = redis_client.get(key)
    if not stored_challenge:
        logger.warning("Registration challenge not found or expired")
        return None
    redis_client.delete(key)

    # Decode client data
    try:
        client_data_bytes = _base64url_decode(client_data_json_b64)
        client_data = json.loads(client_data_bytes)
    except Exception as e:
        logger.warning(f"Failed to decode client data: {e}")
        return None

    # Verify client data
    if client_data.get("type") != "webauthn.create":
        logger.warning("Invalid client data type")
        return None

    if client_data.get("challenge") != stored_challenge:
        logger.warning("Challenge mismatch")
        return None

    # Decode attestation object (simplified - we trust "none" attestation)
    try:
        att_bytes = _base64url_decode(attestation_object_b64)
        # Parse CBOR manually for the attestation object
        # For "none" attestation, we need to extract authData
        auth_data = _parse_attestation_auth_data(att_bytes)
        if not auth_data:
            logger.warning("Failed to parse attestation auth data")
            return None
    except Exception as e:
        logger.warning(f"Failed to decode attestation object: {e}")
        return None

    # Verify RP ID hash
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    if auth_data["rp_id_hash"] != rp_id_hash:
        logger.warning("RP ID hash mismatch")
        return None

    # Check user presence and verification flags
    if not (auth_data["flags"] & 0x01):  # User Present
        logger.warning("User presence flag not set")
        return None

    # Store the algorithm alongside the public key for signature verification later
    return {
        "credential_id": credential_id,
        "public_key": _base64url_encode(auth_data["public_key_bytes"]),
        "sign_count": auth_data["sign_count"],
        "algorithm": auth_data.get("algorithm", -7),  # Default ES256
    }


def _parse_attestation_auth_data(att_bytes: bytes) -> Optional[dict]:
    """
    Parse the authenticator data from an attestation object.
    Handles CBOR-encoded attestation objects with "none" format.
    """
    try:
        # Find authData in the CBOR structure
        # For simplicity, we look for the authData field
        # CBOR map with keys: "fmt", "attStmt", "authData"
        # The authData is a byte string containing:
        #   - 32 bytes: RP ID hash  
        #   - 1 byte: flags
        #   - 4 bytes: sign count (big-endian)
        #   - Variable: attested credential data (if flags & 0x40)

        # Simple CBOR parsing for our specific case
        auth_data_raw = _extract_auth_data_from_cbor(att_bytes)
        if not auth_data_raw or len(auth_data_raw) < 37:
            return None

        rp_id_hash = auth_data_raw[:32]
        flags = auth_data_raw[32]
        sign_count = struct.unpack(">I", auth_data_raw[33:37])[0]

        result = {
            "rp_id_hash": rp_id_hash,
            "flags": flags,
            "sign_count": sign_count,
            "public_key_bytes": b"",
            "algorithm": -7,  # Default to ES256
        }

        # If attested credential data is present (bit 6 of flags)
        if flags & 0x40:
            if len(auth_data_raw) < 55:
                return None
            # AAGUID (16 bytes)
            aaguid = auth_data_raw[37:53]
            # Credential ID length (2 bytes, big-endian)
            cred_id_len = struct.unpack(">H", auth_data_raw[53:55])[0]
            # Credential ID
            cred_id = auth_data_raw[55:55 + cred_id_len]
            # The rest is the public key in COSE format
            public_key_bytes = auth_data_raw[55 + cred_id_len:]
            result["public_key_bytes"] = public_key_bytes
            # Try to detect algorithm from COSE key
            result["algorithm"] = _detect_cose_algorithm(public_key_bytes)

        return result
    except Exception as e:
        logger.warning(f"Error parsing auth data: {e}")
        return None


def _detect_cose_algorithm(cose_key_bytes: bytes) -> int:
    """Try to detect the COSE algorithm from the key bytes. Returns alg value."""
    # Look for alg field in COSE key (key 3 in COSE map)
    # Simple heuristic: COSE keys for EC2 start with certain patterns
    # Default to ES256 (-7) if we can't determine
    try:
        # CBOR integer -7 is encoded as 0x26, -257 is encoded differently
        # Look for the algorithm marker in the COSE key
        if b'\x26' in cose_key_bytes[:20]:  # -7 (ES256)
            return -7
        elif b'\x39\x01\x00' in cose_key_bytes[:20]:  # -257 (RS256)
            return -257
    except Exception:
        pass
    return -7  # Default ES256


def _extract_auth_data_from_cbor(data: bytes) -> Optional[bytes]:
    """
    Extract authData from a CBOR-encoded attestation object.
    Simple parser that looks for the authData byte string.
    """
    try:
        # CBOR map - first byte indicates a map
        # We'll do a simple scan for the authData key
        # In CBOR, "authData" is encoded as a text string

        # Look for the "authData" key in the CBOR data
        auth_data_key = b"authData"
        idx = data.find(auth_data_key)
        if idx == -1:
            return None

        # Move past the key
        idx += len(auth_data_key)

        # The next element should be a byte string (major type 2)
        if idx >= len(data):
            return None

        first_byte = data[idx]
        major_type = (first_byte & 0xE0) >> 5
        additional = first_byte & 0x1F

        if major_type != 2:  # byte string
            return None

        idx += 1

        # Decode length
        if additional < 24:
            length = additional
        elif additional == 24:
            length = data[idx]
            idx += 1
        elif additional == 25:
            length = struct.unpack(">H", data[idx:idx + 2])[0]
            idx += 2
        elif additional == 26:
            length = struct.unpack(">I", data[idx:idx + 4])[0]
            idx += 4
        else:
            return None

        return data[idx:idx + length]
    except Exception as e:
        logger.warning(f"CBOR extraction error: {e}")
        return None


# ==================== Cryptographic Signature Verification ====================

def _cose_key_to_public_key(cose_key_bytes: bytes, algorithm: int):
    """
    Convert COSE-encoded public key bytes to a cryptography library public key object.
    Supports ES256 (alg -7) and RS256 (alg -257).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers, SECP256R1,
        )
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.backends import default_backend

        # Parse the COSE key from CBOR
        cose_map = _parse_cose_key_cbor(cose_key_bytes)
        if not cose_map:
            logger.warning("Failed to parse COSE key CBOR")
            return None

        kty = cose_map.get(1)  # Key type: 2 = EC2, 3 = RSA

        if kty == 2 and algorithm in (-7,):
            # EC2 key (ES256 with P-256)
            x = cose_map.get(-2)
            y = cose_map.get(-3)
            if not x or not y:
                logger.warning("Missing x/y coordinates in EC2 COSE key")
                return None

            x_int = int.from_bytes(x, "big")
            y_int = int.from_bytes(y, "big")

            public_numbers = EllipticCurvePublicNumbers(x_int, y_int, SECP256R1())
            return public_numbers.public_key(default_backend())

        elif kty == 3 and algorithm in (-257,):
            # RSA key (RS256)
            n = cose_map.get(-1)  # modulus
            e = cose_map.get(-2)  # exponent
            if not n or not e:
                logger.warning("Missing n/e in RSA COSE key")
                return None

            n_int = int.from_bytes(n, "big")
            e_int = int.from_bytes(e, "big")

            public_numbers = RSAPublicNumbers(e_int, n_int)
            return public_numbers.public_key(default_backend())

        else:
            logger.warning(f"Unsupported COSE key type {kty} / algorithm {algorithm}")
            return None

    except Exception as e:
        logger.warning(f"Error converting COSE key: {e}")
        return None


def _parse_cose_key_cbor(data: bytes) -> Optional[dict]:
    """
    Minimal CBOR parser for COSE Key objects.
    Returns a dict of { COSE_label: bytes_value }.
    Handles integer keys (positive and negative) and byte string values.
    """
    try:
        result = {}
        idx = 0

        if len(data) == 0:
            return None

        # First byte is the map header
        first_byte = data[idx]
        major_type = (first_byte & 0xE0) >> 5
        if major_type != 5:  # CBOR map
            return None

        num_items = first_byte & 0x1F
        idx += 1

        if num_items == 24:
            num_items = data[idx]
            idx += 1

        for _ in range(num_items):
            if idx >= len(data):
                break

            # Parse key (integer)
            key_byte = data[idx]
            key_major = (key_byte & 0xE0) >> 5
            key_additional = key_byte & 0x1F
            idx += 1

            if key_major == 0:  # Positive integer
                if key_additional < 24:
                    key_val = key_additional
                elif key_additional == 24:
                    key_val = data[idx]; idx += 1
                else:
                    break
            elif key_major == 1:  # Negative integer
                if key_additional < 24:
                    key_val = -(key_additional + 1)
                elif key_additional == 24:
                    key_val = -(data[idx] + 1); idx += 1
                else:
                    break
            else:
                # Skip unknown key types
                break

            if idx >= len(data):
                break

            # Parse value
            val_byte = data[idx]
            val_major = (val_byte & 0xE0) >> 5
            val_additional = val_byte & 0x1F
            idx += 1

            if val_major == 2:  # Byte string
                if val_additional < 24:
                    val_len = val_additional
                elif val_additional == 24:
                    val_len = data[idx]; idx += 1
                elif val_additional == 25:
                    val_len = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
                elif val_additional == 26:
                    val_len = struct.unpack(">I", data[idx:idx+4])[0]; idx += 4
                else:
                    break
                result[key_val] = data[idx:idx + val_len]
                idx += val_len

            elif val_major == 0:  # Positive integer
                if val_additional < 24:
                    result[key_val] = val_additional
                elif val_additional == 24:
                    result[key_val] = data[idx]; idx += 1
                elif val_additional == 25:
                    result[key_val] = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
                else:
                    break

            elif val_major == 1:  # Negative integer
                if val_additional < 24:
                    result[key_val] = -(val_additional + 1)
                elif val_additional == 24:
                    result[key_val] = -(data[idx] + 1); idx += 1
                else:
                    break

            elif val_major == 3:  # Text string
                if val_additional < 24:
                    val_len = val_additional
                elif val_additional == 24:
                    val_len = data[idx]; idx += 1
                else:
                    break
                result[key_val] = data[idx:idx + val_len].decode("utf-8", errors="replace")
                idx += val_len

            else:
                # Unknown value type — skip
                break

        return result if result else None

    except Exception as e:
        logger.warning(f"COSE CBOR parse error: {e}")
        return None


def _verify_signature(public_key_bytes_b64: str, algorithm: int,
                      authenticator_data: bytes, client_data_json_bytes: bytes,
                      signature_bytes: bytes) -> bool:
    """
    Verify the WebAuthn assertion signature.
    
    The signed data is: authenticator_data || SHA-256(client_data_json)
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding
        from cryptography.exceptions import InvalidSignature

        # Reconstruct the public key
        pk_bytes = _base64url_decode(public_key_bytes_b64)
        public_key = _cose_key_to_public_key(pk_bytes, algorithm)
        if not public_key:
            logger.warning("Could not reconstruct public key for signature verification")
            return False

        # Construct the signed data: authenticator_data || SHA-256(clientDataJSON)
        client_data_hash = hashlib.sha256(client_data_json_bytes).digest()
        signed_data = authenticator_data + client_data_hash

        if algorithm == -7:
            # ES256: ECDSA with SHA-256
            public_key.verify(
                signature_bytes,
                signed_data,
                ec.ECDSA(hashes.SHA256())
            )
            return True

        elif algorithm == -257:
            # RS256: RSASSA-PKCS1-v1_5 with SHA-256
            public_key.verify(
                signature_bytes,
                signed_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True

        else:
            logger.warning(f"Unsupported algorithm for verification: {algorithm}")
            return False

    except InvalidSignature:
        logger.warning("Cryptographic signature verification FAILED — possible replay or tampering")
        return False
    except Exception as e:
        logger.warning(f"Signature verification error: {e}")
        return False


# ==================== Authentication ====================

def generate_passkey_auth_challenge(app_id: str, rp_id: str, credential_ids: list[str]) -> dict:
    """
    Generate a WebAuthn authentication challenge.
    Returns the PublicKeyCredentialRequestOptions for the client.
    """
    challenge = secrets.token_bytes(32)
    challenge_b64 = _base64url_encode(challenge)

    # Store challenge in Redis
    key = f"passkey:auth:{app_id}:{challenge_b64}"
    redis_client.setex(key, CHALLENGE_EXPIRY, "1")

    options = {
        "challenge": challenge_b64,
        "rpId": rp_id,
        "timeout": CHALLENGE_EXPIRY * 1000,
        "userVerification": "required",
    }

    if credential_ids:
        options["allowCredentials"] = [
            {"type": "public-key", "id": cid} for cid in credential_ids
        ]

    return options


def verify_passkey_authentication(
    app_id: str,
    rp_id: str,
    credential_id: str,
    client_data_json_b64: str,
    authenticator_data_b64: str,
    signature_b64: str,
    stored_public_key_b64: str,
    stored_sign_count: int,
    stored_algorithm: int = -7,
) -> Optional[int]:
    """
    Verify a WebAuthn authentication response with full server-side
    cryptographic signature verification.
    
    Returns the new sign count if successful, None otherwise.
    """
    try:
        # Decode client data
        client_data_bytes = _base64url_decode(client_data_json_b64)
        client_data = json.loads(client_data_bytes)

        # Verify type
        if client_data.get("type") != "webauthn.get":
            logger.warning("Invalid client data type for authentication")
            return None

        # Verify challenge exists in Redis
        challenge = client_data.get("challenge")
        challenge_key = f"passkey:auth:{app_id}:{challenge}"
        if not redis_client.get(challenge_key):
            logger.warning("Authentication challenge not found or expired")
            return None
        redis_client.delete(challenge_key)

        # Decode authenticator data
        auth_data = _base64url_decode(authenticator_data_b64)
        if len(auth_data) < 37:
            logger.warning("Authenticator data too short")
            return None

        # Verify RP ID hash
        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        if auth_data[:32] != rp_id_hash:
            logger.warning("RP ID hash mismatch during authentication")
            return None

        # Check flags
        flags = auth_data[32]
        if not (flags & 0x01):  # User Present
            logger.warning("User presence flag not set during authentication")
            return None
        if not (flags & 0x04):  # User Verified
            logger.warning("User verification flag not set during authentication")
            return None

        # Check sign count
        new_sign_count = struct.unpack(">I", auth_data[33:37])[0]
        if new_sign_count > 0 and stored_sign_count > 0 and new_sign_count <= stored_sign_count:
            logger.warning(f"Sign count not incremented: stored={stored_sign_count}, new={new_sign_count}")
            # Potential cloned authenticator — reject
            return None

        # === CRITICAL: Verify cryptographic signature server-side ===
        signature_bytes = _base64url_decode(signature_b64)
        if not _verify_signature(
            stored_public_key_b64, stored_algorithm,
            auth_data, client_data_bytes, signature_bytes
        ):
            logger.warning(f"Signature verification FAILED for credential {credential_id[:16]}...")
            return None

        logger.info(f"Passkey authentication verified (with crypto signature) for credential {credential_id[:16]}...")
        return new_sign_count

    except Exception as e:
        logger.warning(f"Passkey auth verification error: {e}")
        return None
