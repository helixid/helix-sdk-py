# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""A verification method's validity (KYA-OS story C-E point 3): which proofs
a superseded or revoked key may still vouch for. A superseded key stays in its
DID document with ``validUntil``; a compromised one also carries ``revoked``,
and nothing it signed is accepted, whatever ``created`` a proof claims.

A leaf module, so the JWS and Data Integrity verifiers can import it without a
cycle. Mirrors helix-core ``core/did/key-validity.ts`` and helix-sdk-js
``kyaos/key-validity.ts``.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Mapping, Optional


class KeyValidityReasons:
    """Why a key was refused for a proof; the same strings as JS."""

    KEY_REVOKED = "key_revoked"
    KEY_SUPERSEDED = "key_superseded"
    KEY_VALIDITY_MALFORMED = "key_validity_malformed"


class KeyValidityProblem:
    """A refusal: ``reason`` (a KeyValidityReasons value) and ``message``."""

    __slots__ = ("reason", "message")

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        self.message = message

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"KeyValidityProblem({self.reason!r}, {self.message!r})"


_RFC3339 = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$", re.IGNORECASE)


def rfc3339_instant(value: Any) -> Optional[int]:
    """An RFC 3339 instant with an offset, as epoch ms; None for anything else."""
    if not isinstance(value, str):
        return None
    match = _RFC3339.match(value)
    if not match:
        return None
    base, fraction, offset = match.group(1), match.group(2) or "", match.group(3)
    micro = (fraction[1:] + "000000")[:6] if fraction else "000000"
    zone = "+00:00" if offset.upper() == "Z" else offset
    try:
        parsed = datetime.fromisoformat(f"{base.upper()}.{micro}{zone}")
    except ValueError:
        return None
    return int(parsed.timestamp() * 1000)


def proof_time(value: Any) -> Optional[int]:
    """A proof time as epoch ms: an RFC 3339 string (``created``) or epoch seconds (``created``, ``iat``)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and value >= 0:
        return int(value * 1000)
    return rfc3339_instant(value)


def key_validity_problem(method: Mapping[str, Any], at: Optional[int], now: Optional[int] = None) -> Optional[KeyValidityProblem]:
    """Whether the key ``method`` describes may vouch for a proof created at ``at``
    (epoch ms; with none, at ``now``). None when the key is usable."""
    kid = str(method.get("id", "the key"))
    for member in ("validFrom", "validUntil", "revoked"):
        if member in method and rfc3339_instant(method[member]) is None:
            return KeyValidityProblem(KeyValidityReasons.KEY_VALIDITY_MALFORMED, f"{kid}: {member} is not an RFC 3339 instant")
    if "revoked" in method:
        return KeyValidityProblem(KeyValidityReasons.KEY_REVOKED, f"{kid} was revoked at {method['revoked']}")
    if at is not None:
        when = at
    elif now is not None:
        when = now
    else:
        when = int(datetime.now().timestamp() * 1000)
    until = rfc3339_instant(method.get("validUntil"))
    if until is not None and when > until:
        return KeyValidityProblem(KeyValidityReasons.KEY_SUPERSEDED, f"{kid} was valid until {method['validUntil']}; the proof is from {when} ms")
    start = rfc3339_instant(method.get("validFrom"))
    if start is not None and when < start:
        return KeyValidityProblem(KeyValidityReasons.KEY_SUPERSEDED, f"{kid} is valid from {method['validFrom']}; the proof is from {when} ms")
    return None
