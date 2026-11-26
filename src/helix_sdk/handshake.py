# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The KYA-OS session handshake, client side and the format rules both sides
share (story L2-A; conformance L2.1, L2.2, L2.6, L2.7, L2.9, L2.14, L2.15;
schemas ``handshake-request.json`` and ``handshake-response.json``),
mirroring helix-sdk-js's core/kyaos/handshake.ts.

A client calls the server's ``_kyaos_handshake`` tool with
``create_handshake_request()``: a fresh 16-byte nonce written as 22 base64url
characters, the server's DID (or public origin) as audience and the current
Unix time. The server answers with a ``kyaos_<uuid-v4>`` session id that
later calls carry as the ``_kyaos_session`` control argument.

Wire members stay camelCase (``agentDid``, ``clientInfo``, ...): they are
the JSON the protocol defines, not Python names.
"""

from __future__ import annotations

import base64
import os
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

HANDSHAKE_TOOL_NAME = "_kyaos_handshake"
"""Name of the tool the middleware registers for the handshake; the ``_kyaos_`` prefix keeps it off the service's own tools."""
SESSION_CONTROL_ARGUMENT = "_kyaos_session"
"""The control argument a tool call carries its session id in (stripped before the handler, never hashed)."""
SESSION_ID_PREFIX = "kyaos_"
PROTOCOL_VERSION = "1.0"

NONCE_BYTES = 16
NONCE_MIN_LENGTH = 22
"""16 bytes of base64url without padding."""
DEFAULT_CLOCK_SKEW_SECONDS = 120
MIN_CLOCK_SKEW_SECONDS = 30
MAX_CLOCK_SKEW_SECONDS = 600
DEFAULT_SESSION_TTL_MINUTES = 30
"""Idle time after which a session is gone (the schema's ``sessionTtl`` is seconds; the config is minutes)."""

_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")
_DID = re.compile(r"did:[a-z0-9]+:.+")
_UUID_V4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_PROTOCOL = re.compile(r"\d+\.\d+")
_REQUEST_MEMBERS = {"nonce", "audience", "timestamp", "agentDid", "clientInfo", "clientProtocolVersion", "clientCapabilities"}
_CLIENT_INFO_MEMBERS = {"name", "title", "version", "platform", "vendor", "persistentId", "clientId"}


def generate_nonce(random: Callable[[int], bytes] = os.urandom) -> str:
    """A fresh nonce: NONCE_BYTES random bytes as base64url without padding (L2.2, L2.6)."""
    return base64.urlsafe_b64encode(random(NONCE_BYTES)).rstrip(b"=").decode("ascii")


def is_valid_nonce(value: Any) -> bool:
    """Strict base64url of at least 16 bytes: alphabet only, no padding, no white space, a decodable length."""
    return (
        isinstance(value, str)
        and len(value) >= NONCE_MIN_LENGTH
        and len(value) % 4 != 1
        and _BASE64URL.fullmatch(value) is not None
    )


def is_did(value: Any) -> bool:
    return isinstance(value, str) and _DID.fullmatch(value) is not None


def generate_session_id(make_uuid: Callable[[], str] = lambda: str(uuid.uuid4())) -> str:
    """``kyaos_<uuid-v4>`` (L2.7)."""
    return f"{SESSION_ID_PREFIX}{make_uuid()}"


def is_session_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(SESSION_ID_PREFIX)
        and _UUID_V4.fullmatch(value[len(SESSION_ID_PREFIX):]) is not None
    )


def clock_skew_seconds(value: Optional[int] = None) -> int:
    """A skew the config may set: an integer number of seconds from 30 to 600, default 120 (L2.9)."""
    if value is None:
        return DEFAULT_CLOCK_SKEW_SECONDS
    if isinstance(value, bool) or not isinstance(value, int) or not MIN_CLOCK_SKEW_SECONDS <= value <= MAX_CLOCK_SKEW_SECONDS:
        raise ValueError(f"clock_skew_seconds must be an integer from {MIN_CLOCK_SKEW_SECONDS} to {MAX_CLOCK_SKEW_SECONDS}")
    return value


def within_skew(timestamp: float, now_seconds: float, skew_seconds: float) -> bool:
    """Whether ``timestamp`` (Unix seconds) is within ``skew_seconds`` of ``now_seconds``, either side (L2.3, L2.4)."""
    return abs(now_seconds - timestamp) <= skew_seconds


def create_handshake_request(
    audience: str,
    agent_did: Optional[str] = None,
    client_info: Optional[Mapping[str, Any]] = None,
    client_capabilities: Optional[Mapping[str, Any]] = None,
    now: Optional[float] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """A handshake request with a fresh nonce and the current timestamp
    (L2.15). ``audience`` is the server's DID or its public origin; ``now``
    is Unix seconds (default ``time.time()``)."""
    request: Dict[str, Any] = {
        "nonce": nonce if nonce is not None else generate_nonce(),
        "audience": audience,
        "timestamp": int(time.time() if now is None else now),
    }
    if agent_did is not None:
        request["agentDid"] = agent_did
    if client_info is not None:
        request["clientInfo"] = dict(client_info)
    request["clientProtocolVersion"] = PROTOCOL_VERSION
    if client_capabilities is not None:
        request["clientCapabilities"] = dict(client_capabilities)
    return request


class HandshakeFormatProblems:
    """``problem`` values of a refused handshake request, the same strings as helix-sdk-js."""

    REQUEST_NOT_OBJECT = "request_not_object"
    UNKNOWN_MEMBER = "unknown_member"
    NONCE_INVALID = "nonce_invalid"
    AUDIENCE_INVALID = "audience_invalid"
    TIMESTAMP_INVALID = "timestamp_invalid"
    AGENT_DID_INVALID = "agent_did_invalid"
    CLIENT_INFO_INVALID = "client_info_invalid"
    CLIENT_PROTOCOL_VERSION_INVALID = "client_protocol_version_invalid"
    CLIENT_CAPABILITIES_INVALID = "client_capabilities_invalid"


@dataclass(frozen=True)
class HandshakeFormatResult:
    ok: bool
    request: Optional[Dict[str, Any]] = None
    problem: Optional[str] = None
    message: Optional[str] = None


def _refused(problem: str, message: str) -> HandshakeFormatResult:
    return HandshakeFormatResult(ok=False, problem=problem, message=message)


def _client_info_problem(value: Any) -> Optional[str]:
    if not isinstance(value, Mapping):
        return "clientInfo must be an object"
    name = value.get("name")
    if not isinstance(name, str) or not name:
        return "clientInfo.name must be a non-empty string"
    for member, item in value.items():
        if member not in _CLIENT_INFO_MEMBERS:
            return f"clientInfo has an unknown member {member}"
        if not isinstance(item, str):
            return f"clientInfo.{member} must be a string"
    return None


def validate_handshake_format(value: Any) -> HandshakeFormatResult:
    """Checks a handshake request's shape against ``handshake-request.json``
    (L2.14): the three required members, their types, the nonce's base64url
    form and length, the DID form of ``agentDid``, and no unknown members.
    Time and audience are the server's to judge; see the middleware."""
    P = HandshakeFormatProblems
    if not isinstance(value, Mapping):
        return _refused(P.REQUEST_NOT_OBJECT, "handshake request must be an object")
    for member in value:
        if member not in _REQUEST_MEMBERS:
            return _refused(P.UNKNOWN_MEMBER, f"handshake request has an unknown member {member}")
    if not is_valid_nonce(value.get("nonce")):
        return _refused(P.NONCE_INVALID, f"nonce must be base64url of at least {NONCE_MIN_LENGTH} characters")
    audience = value.get("audience")
    if not isinstance(audience, str) or not audience:
        return _refused(P.AUDIENCE_INVALID, "audience must be a non-empty string")
    timestamp = value.get("timestamp")
    # A whole number, as JSON carries it: 1710268800 and 1710268800.0 are the same value (Number.isInteger in JS).
    if isinstance(timestamp, float) and timestamp.is_integer():
        timestamp = int(timestamp)
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        return _refused(P.TIMESTAMP_INVALID, "timestamp must be a non-negative integer (Unix seconds)")
    # A member that is present must be valid; JSON null is not "absent" (as in helix-sdk-js).
    if "agentDid" in value and not is_did(value["agentDid"]):
        return _refused(P.AGENT_DID_INVALID, "agentDid must be a DID")
    if "clientInfo" in value:
        problem = _client_info_problem(value["clientInfo"])
        if problem is not None:
            return _refused(P.CLIENT_INFO_INVALID, problem)
    if "clientProtocolVersion" in value:
        version = value["clientProtocolVersion"]
        if not isinstance(version, str) or _PROTOCOL.fullmatch(version) is None:
            return _refused(P.CLIENT_PROTOCOL_VERSION_INVALID, "clientProtocolVersion must look like 1.0")
    if "clientCapabilities" in value and not isinstance(value["clientCapabilities"], Mapping):
        return _refused(P.CLIENT_CAPABILITIES_INVALID, "clientCapabilities must be an object")
    request = dict(value)
    request["timestamp"] = timestamp
    return HandshakeFormatResult(ok=True, request=request)
