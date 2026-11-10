# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Finds the caller's credential, ported from helix-sdk-js's
mcp-middleware/src/credentials.ts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Mapping, Optional

from helix_sdk.errors import VPInvalidStructureError
from helix_sdk.vp_transport import HELIX_VP_META_KEY

from .errors import CREDENTIAL_CONFLICT, MCPAuthError

_VP_HEADER = "x-helix-vp"
_AUTH = re.compile(r"^(\S+)\s+(\S+)$")


@dataclass(frozen=True)
class ExtractedCredential:
    kind: str
    """'vp' (value is the base64url-encoded VP) or 'oauth' (value is the bearer token)."""
    value: str


def _header_values(headers: Any, name: str) -> List[str]:
    """All values of a header, case-insensitively; empty values are dropped.
    Accepts a plain mapping (values may be lists), or a multi-value headers
    object with getlist() (Starlette, Werkzeug) or get_all() (http.client)."""
    if not headers:
        return []
    out: List[Any] = []
    getter = getattr(headers, "getlist", None) or getattr(headers, "get_all", None)
    if callable(getter):
        out.extend(getter(name) or [])
    elif isinstance(headers, Mapping):
        for key, value in headers.items():
            if not isinstance(key, str) or key.lower() != name or value is None:
                continue
            out.extend(value if isinstance(value, (list, tuple)) else [value])
    return [v.strip() for v in out if isinstance(v, str) and v.strip()]


def extract_credential(headers: Any = None, meta: Optional[Mapping[str, Any]] = None) -> Optional[ExtractedCredential]:
    """`Authorization: HelixVP <vp>`, the legacy `X-Helix-VP` header, or MCP
    `_meta["x-helix-vp"]` (stdio) for a HelixID VP, or
    `Authorization: Bearer <token>` for OAuth. Tool arguments are never read.

    Ambiguity is rejected, never resolved by picking one: two different VPs,
    two Authorization headers, or a VP together with a bearer token all raise
    CREDENTIAL_CONFLICT. The same VP repeated in several places is accepted."""
    vps: List[str] = []
    bearer: Optional[str] = None

    def add(vp: str) -> None:
        if vp not in vps:
            vps.append(vp)

    authorization = _header_values(headers, "authorization")
    if len(authorization) > 1:
        raise MCPAuthError(CREDENTIAL_CONFLICT, "Multiple Authorization headers were provided")
    if authorization:
        match = _AUTH.match(authorization[0])
        if not match:
            raise MCPAuthError(CREDENTIAL_CONFLICT, "Malformed Authorization header")
        scheme, credential = match.group(1).lower(), match.group(2)
        if scheme == "helixvp":
            add(credential)
        elif scheme == "bearer":
            bearer = credential
        # Any other scheme is not ours; treated as no credential.

    for value in _header_values(headers, _VP_HEADER):
        add(value)

    raw = (meta or {}).get(HELIX_VP_META_KEY)
    if raw is not None and raw != "":
        if not isinstance(raw, str):
            raise VPInvalidStructureError(f'_meta["{HELIX_VP_META_KEY}"] must be a base64url-encoded string')
        add(raw.strip())

    if len(vps) > 1:
        raise MCPAuthError(CREDENTIAL_CONFLICT, "Conflicting VPs were provided in more than one location")
    if vps and bearer is not None:
        raise MCPAuthError(
            CREDENTIAL_CONFLICT, "Both a HelixID VP and an OAuth bearer token were provided; send exactly one"
        )
    if vps:
        return ExtractedCredential("vp", vps[0])
    if bearer is not None:
        return ExtractedCredential("oauth", bearer)
    return None
