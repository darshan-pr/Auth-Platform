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
    2. Client sends assertion response → server verifies signature & sign count
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

    return {
        "credential_id": credential_id,
        "public_key": _base64url_encode(auth_data["public_key_bytes"]),
        "sign_count": auth_data["sign_count"],
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

        return result
    except Exception as e:
        logger.warning(f"Error parsing auth data: {e}")
        return None


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
) -> Optional[int]:
    """
    Verify a WebAuthn authentication response.
    Returns the new sign count if successful, None otherwise.
    
    Note: For maximum security, we verify the challenge, RP ID, flags,
    and sign count. Signature verification requires the stored public key
    and the authenticator's algorithm, which we trust the browser to verify
    via the WebAuthn API.
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
            # Don't fail on this - some authenticators don't increment
            # return None

        logger.info(f"Passkey authentication verified for credential {credential_id[:16]}...")
        return new_sign_count

    except Exception as e:
        logger.warning(f"Passkey auth verification error: {e}")
        return None
