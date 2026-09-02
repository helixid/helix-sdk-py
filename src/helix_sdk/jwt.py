# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
EdDSA (Ed25519) JWT issue/decode/verify, ported from helix-sdk-js's
src/core/jwt.ts. Used for session tokens returned by /v1/vp/verify
(session: true) and validated locally against /v1/sessions/public-key,
per the "session bridge" pattern in helix-server's examples.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, Tuple

from . import keys
from .errors import InvalidJWTError, JWTExpiredError

_JWT_HEADER = {"alg": "EdDSA", "typ": "JWT", "crv": "Ed25519"}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:  # noqa: BLE001
        raise InvalidJWTError("JWT contains invalid base64url encoding") from exc


def _parse_json_part(part: str, label: str) -> Any:
    try:
        return json.loads(_b64url_decode(part).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise InvalidJWTError(f"JWT {label} is invalid JSON") from exc


def _split_token(token: str) -> Tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3 or any(len(p) == 0 for p in parts):
        raise InvalidJWTError("JWT must contain header, payload, and signature")
    return parts[0], parts[1], parts[2]


def issue_jwt(payload: Dict[str, Any], private_key_hex: str) -> str:
    header_b64 = _b64url_encode(json.dumps(_JWT_HEADER, separators=(",", ":")).encode("utf-8"))
    body_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{body_b64}"
    signature_hex = keys.sign_data(signing_input, private_key_hex)
    signature_b64 = _b64url_encode(bytes.fromhex(signature_hex))
    return f"{signing_input}.{signature_b64}"


def decode_jwt_unsafe(token: str) -> Dict[str, Any]:
    """Decodes the payload without verifying the signature. Never use this
    to make authorization decisions -- see verify_jwt()."""
    _, payload_part, _ = _split_token(token)
    return _parse_json_part(payload_part, "payload")


def verify_jwt(token: str, public_key_hex: str) -> Dict[str, Any]:
    header_part, payload_part, signature_part = _split_token(token)
    header = _parse_json_part(header_part, "header")
    if header.get("alg") != "EdDSA" or header.get("typ") != "JWT" or header.get("crv") != "Ed25519":
        raise InvalidJWTError("JWT header is not supported")

    signing_input = f"{header_part}.{payload_part}"
    signature_hex = _b64url_decode(signature_part).hex()
    if not keys.verify_signature(signing_input.encode("utf-8"), signature_hex, public_key_hex):
        raise InvalidJWTError("JWT signature is invalid")

    payload = decode_jwt_unsafe(token)
    if payload.get("exp", 0) <= int(time.time()):
        raise JWTExpiredError()
    return payload
