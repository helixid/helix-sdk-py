# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Where a signed VP travels with a request, mirroring helix-sdk-js's
vp-transport.ts. There is exactly one place per transport, and never inside
tool arguments or a request body:

- HTTP: the X-Helix-VP header.
- MCP (any transport, including stdio): params._meta["x-helix-vp"].

Both carry the same value: the signed VP as base64url-encoded JSON.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Mapping, Optional

from .errors import VPInvalidStructureError

HELIX_VP_HEADER = "X-Helix-VP"
HELIX_VP_META_KEY = "x-helix-vp"


def encode_helix_vp(vp: Dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(vp).encode("utf-8")).rstrip(b"=").decode("ascii")


def decode_helix_vp(value: str) -> Dict[str, Any]:
    raw = value.strip()
    try:
        decoded = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, TypeError) as exc:
        raise VPInvalidStructureError(f"{HELIX_VP_HEADER} is not base64url-encoded JSON") from exc
    if not isinstance(decoded, dict):
        raise VPInvalidStructureError(f"{HELIX_VP_HEADER} is not a JSON object")
    return decoded


def helix_vp_headers(vp: Dict[str, Any]) -> Dict[str, str]:
    """Headers to send with an HTTP request: `httpx.get(url, headers=helix_vp_headers(vp))`."""
    return {HELIX_VP_HEADER: encode_helix_vp(vp)}


def read_helix_vp_header(headers: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """Reads the VP from the X-Helix-VP header (case-insensitive); None when absent."""
    if not headers:
        return None
    raw = next((v for k, v in headers.items() if k.lower() == HELIX_VP_META_KEY), None)
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else None
    return decode_helix_vp(raw) if raw else None


def read_helix_vp_meta(meta: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """Reads the VP from an MCP request's `_meta`; None when absent."""
    raw = (meta or {}).get(HELIX_VP_META_KEY)
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise VPInvalidStructureError(f'_meta["{HELIX_VP_META_KEY}"] must be a base64url-encoded string')
    return decode_helix_vp(raw)
