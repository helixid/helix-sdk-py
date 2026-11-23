"""The downstream delegation headers (KYA-OS story L3-D, SPEC.md §8.1) and
how the credential travels in them. Ported from helix-sdk-js's
mcp-middleware/src/delegation/headers.ts.

Authoritative: ``KYA-OS-Delegation-Credential`` (the chain the agent
presented, or with the service's own hop appended when it re-delegates),
``KYA-OS-Delegation-Proof`` (the forwarding service's JWT, §8.2) and
``KYA-OS-Agent-DID``. Anchor: ``KYA-OS-Session-Id``. Advisory, never read for
a decision: ``KYA-OS-Delegation-Chain`` and ``KYA-OS-Granted-Scopes``.

Helix's delegations are VC 2.0 hops with an embedded ``eddsa-jcs-2022``
proof (SPEC.md §6.10), not VC-JWTs, so the credential header carries the
whole chain, root to leaf, as base64url (no padding) of its UTF-8 JSON
array: the downstream service verifies every hop itself.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, List, Mapping, Optional, Sequence

DELEGATION_HEADERS = {
    "credential": "KYA-OS-Delegation-Credential",
    "proof": "KYA-OS-Delegation-Proof",
    "agent_did": "KYA-OS-Agent-DID",
    "session_id": "KYA-OS-Session-Id",
    "chain": "KYA-OS-Delegation-Chain",
    "granted_scopes": "KYA-OS-Granted-Scopes",
}

MAX_CREDENTIAL_HEADER_LENGTH = 64 * 1024
"""The largest credential header read, in characters; a chain of ten hops fits well inside."""

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")


def encode_delegation_credential(chain: Sequence[Any]) -> str:
    """The chain as the credential header carries it: base64url of the JSON array, root first."""
    text = json.dumps(list(chain), separators=(",", ":"), ensure_ascii=False)
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def decode_delegation_credential(value: str) -> Optional[List[Any]]:
    """The chain a credential header carries, or None when it is not strict
    base64url of a non-empty JSON array (a single credential object is read
    as a chain of one)."""
    if not isinstance(value, str) or not value or len(value) > MAX_CREDENTIAL_HEADER_LENGTH or not _BASE64URL.match(value):
        return None
    try:
        parsed = json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8"))
    except (ValueError, binascii.Error, RecursionError):
        return None
    if isinstance(parsed, list):
        return parsed or None
    return [parsed] if isinstance(parsed, dict) else None


def header_values(headers: Any, name: str) -> List[str]:
    """Every value of a header, case-insensitively, trimmed; empty values
    dropped. Takes a Starlette ``Headers`` (``getlist``), a mapping (values a
    string or a list) or a list of ``(name, value)`` pairs."""
    if headers is None:
        return []
    lower = name.lower()
    values: List[str] = []
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        values = [str(value) for value in getlist(name)]
    else:
        items = headers.items() if isinstance(headers, Mapping) else headers
        for key, value in items:
            key = key.decode("latin-1") if isinstance(key, bytes) else str(key)
            if key.lower() != lower or value is None:
                continue
            if isinstance(value, (list, tuple)):
                values.extend(v.decode("latin-1") if isinstance(v, bytes) else str(v) for v in value)
            else:
                values.append(value.decode("latin-1") if isinstance(value, bytes) else str(value))
    return [value.strip() for value in values if value.strip()]


def has_delegation_headers(headers: Any) -> bool:
    """Whether a request carries downstream delegation headers (the credential or the proof)."""
    return bool(header_values(headers, DELEGATION_HEADERS["credential"]) or header_values(headers, DELEGATION_HEADERS["proof"]))
