# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
SessionManager, ported from helix-sdk-js's src/session/SessionManager.ts.

A verifier-owned, HMAC-SHA256-signed session token -- distinct from the
EdDSA JWT in jwt.py (which is issued by helix-api itself for the
"session bridge" pattern). SessionManager lets a verifier mint its own
short-lived tokens after a successful /v1/vp/verify call, so subsequent
calls from the same agent can skip re-verification until the token
expires. The verifier owns the secret; nothing here talks to the API.
"""

from __future__ import annotations

import base64
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Dict, List, Optional

_HEADER = {"alg": "HS256", "typ": "JWT"}


@dataclass
class DelegationLink:
    issuer: str
    subject: str
    vc_id: str
    scopes: List[str]
    delegation_depth: int


@dataclass
class SessionClaims:
    agent_did: str
    scopes: List[str]
    delegation_chain: List[Dict[str, Any]]
    iat: int
    exp: int
    jti: str


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode_str(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding).decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        raise ValueError("JWT contains invalid base64url encoding") from exc


def _parse_token(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3 or any(len(p) == 0 for p in parts):
        raise ValueError("JWT must contain header, payload, and signature")
    return parts[0], parts[1], parts[2]


def _sign_signing_input(signing_input: str, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), signing_input.encode("utf-8"), sha256).digest()
    return _b64url_encode(digest)


def _assert_claims(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("JWT payload is invalid")
    if not isinstance(value.get("agentDid"), str) or not value["agentDid"]:
        raise ValueError("JWT payload is missing agentDid")
    if not isinstance(value.get("scopes"), list) or not all(isinstance(s, str) for s in value["scopes"]):
        raise ValueError("JWT payload has invalid scopes")
    chain = value.get("delegationChain")
    if not isinstance(chain, list) or not all(
        isinstance(link, dict)
        and isinstance(link.get("issuer"), str)
        and isinstance(link.get("subject"), str)
        and isinstance(link.get("vcId"), str)
        and isinstance(link.get("scopes"), list)
        and all(isinstance(s, str) for s in link["scopes"])
        and isinstance(link.get("delegationDepth"), int)
        for link in chain
    ):
        raise ValueError("JWT payload has invalid delegationChain")
    if not isinstance(value.get("jti"), str) or not value["jti"]:
        raise ValueError("JWT payload is missing jti")
    if not isinstance(value.get("iat"), int) or not isinstance(value.get("exp"), int):
        raise ValueError("JWT payload has invalid iat/exp")
    return value


@dataclass
class SessionManager:
    secret: str
    ttl: int

    def __post_init__(self) -> None:
        if not self.secret or len(self.secret) < 16:
            raise ValueError("SessionManager secret must be at least 16 characters")
        if not isinstance(self.ttl, int) or self.ttl <= 0:
            raise ValueError("SessionManager ttl must be a positive integer (seconds)")

    def issue(
        self, agent_did: str, scopes: List[str], delegation_chain: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        if not agent_did:
            raise ValueError("issue() requires agentDid")
        if not isinstance(scopes, list):
            raise ValueError("issue() requires scopes array")

        now = int(time.time())
        claims = {
            "agentDid": agent_did,
            "scopes": scopes,
            "delegationChain": delegation_chain or [],
            "iat": now,
            "exp": now + self.ttl,
            "jti": str(uuid.uuid4()),
        }

        header_part = _b64url_encode(json.dumps(_HEADER, separators=(",", ":")).encode("utf-8"))
        payload_part = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_part}.{payload_part}"
        signature_part = _sign_signing_input(signing_input, self.secret)

        return f"{signing_input}.{signature_part}"

    def verify(self, token: str) -> Dict[str, Any]:
        header_part, payload_part, signature_part = _parse_token(token)

        try:
            header = json.loads(_b64url_decode_str(header_part))
        except Exception as exc:  # noqa: BLE001
            raise ValueError("JWT header is invalid") from exc

        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise ValueError("JWT header is not supported")

        expected_signature = _sign_signing_input(f"{header_part}.{payload_part}", self.secret)
        if not hmac.compare_digest(signature_part, expected_signature):
            raise ValueError("JWT signature is invalid")

        try:
            payload = json.loads(_b64url_decode_str(payload_part))
        except Exception as exc:  # noqa: BLE001
            raise ValueError("JWT payload is invalid") from exc

        claims = _assert_claims(payload)

        if claims["exp"] <= int(time.time()):
            raise ValueError("JWT has expired")

        return claims
