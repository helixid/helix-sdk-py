# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""Which JSON-RPC methods need a caller, and what an unidentified refusal
records (parity with helix-sdk-js's ``gate.ts``)."""

from __future__ import annotations

import base64
import json
from typing import Any, Callable, Mapping, Optional

from .credentials import _header_values

DEFAULT_OPEN_METHODS = ("initialize", "notifications/initialized", "tools/list")
"""The JSON-RPC methods the gate lets through without a caller, unless the
operator sets ``open_methods``. Left open on purpose, so any client can see
what this server offers before it presents a credential: ``initialize`` (the
MCP handshake), ``notifications/initialized`` (the notification a client sends
right after it; it carries nothing and gets no answer) and ``tools/list`` (the
tool catalog). Every other method (``tools/call``, ``resources/*``,
``prompts/*``, ``ping``, ...) needs a verified caller."""

RESOURCE_METHODS = frozenset({"resources/read", "resources/subscribe", "resources/unsubscribe"})
"""Methods whose target is a resource URI, checked against ``resource_scopes``."""
PROMPT_METHODS = frozenset({"prompts/get"})
"""Methods whose target is a prompt name, checked against ``prompt_scopes``."""

_CALLER_REFUSALS = frozenset({"PROOF_MISSING", "PROOF_INVALID", "OAUTH_TOKEN_INVALID", "CREDENTIAL_CONFLICT"})


def method_of(call: Mapping[str, Any]) -> str:
    """The JSON-RPC method of a call: 'method', else the received request's, else ``tools/call`` (the gate's original shape)."""
    method = call.get("method")
    if isinstance(method, str) and method:
        return method
    request = call.get("request")
    received = request.get("method") if isinstance(request, Mapping) else None
    return received if isinstance(received, str) and received else "tools/call"


def target_of(method: str, call: Mapping[str, Any]) -> Optional[str]:
    """What a call acts on: the tool, resource URI or prompt name ('name', else the request's ``params.name`` / ``params.uri``)."""
    name = call.get("name")
    if isinstance(name, str):
        return name
    request = call.get("request")
    params = request.get("params") if isinstance(request, Mapping) else None
    if not isinstance(params, Mapping):
        return None
    value = params.get("uri" if method in RESOURCE_METHODS else "name")
    return value if isinstance(value, str) else None


def header_of(headers: Any, name: str) -> Optional[str]:
    """A header's first non-empty value, case-insensitively."""
    values = _header_values(headers, name)
    return values[0] if values else None


def claimed_issuer_of(headers: Any) -> Optional[str]:
    """The unverified ``iss`` of a bearer JWT (an opaque token names none). Only ever recorded as unverified."""
    value = header_of(headers, "authorization") or ""
    parts = value.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    segments = parts[1].strip().split(".")
    if len(segments) != 3:
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(segments[1] + "=" * (-len(segments[1]) % 4)))
    except Exception:  # noqa: BLE001 - not a JWT: no claim to record
        return None
    iss = claims.get("iss") if isinstance(claims, dict) else None
    return iss if isinstance(iss, str) else None


def claimed_did_of(meta: Any, read_proof: Callable[[Any], Any]) -> Optional[str]:
    """The DID a request proof says it is from, unverified (``did`` of the proof in ``_meta``)."""
    proof = read_proof(meta)
    did = proof.get("did") if isinstance(proof, Mapping) else None
    return did if isinstance(did, str) and did.startswith("did:") else None


def refusal_code_of(error: BaseException) -> Optional[str]:
    """The reason code of a refusal of a caller the gate could not identify; None for anything else (a server fault)."""
    code = getattr(error, "code", None)
    if not isinstance(code, str) or code not in _CALLER_REFUSALS:
        return None
    # A refused proof names the verifier's first reason (nonce_replayed, status_revoked, ...); anything else its code.
    reasons = getattr(error, "reasons", None)
    if isinstance(reasons, (list, tuple)) and reasons and isinstance(reasons[0], str):
        return reasons[0]
    return code.lower()


__all__ = [
    "DEFAULT_OPEN_METHODS",
    "RESOURCE_METHODS",
    "PROMPT_METHODS",
    "method_of",
    "target_of",
    "header_of",
    "claimed_issuer_of",
    "claimed_did_of",
    "refusal_code_of",
]
