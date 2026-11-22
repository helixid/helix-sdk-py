# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Status lists as the local verifier reads them (KYA-OS story F-2; SPEC.md
section 6.6, story L3-C for the signed per-issuer lists).

The verifier never fetches: the ``fetch_status_list`` seam hands it a
:class:`StatusListRead`, the list already decoded to its bits, with the
members of the list the verifier still holds the credential to (issuer,
purpose, id, validity window) and whether the read was live. The seam is
where L3-C verifies the list's own proof; what is here follows from the entry
and the bits alone, fail-closed. Mirrors helix-sdk-js ``verifier/status.ts``.
"""

from __future__ import annotations

import base64
import gzip
import io
import re
from dataclasses import dataclass
from typing import Any, Callable, List, Mapping, Optional, Union

from ..credentials import issuer_of, window_verdict
from .codes import ReasonCodes

MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024


@dataclass
class StatusListRead:
    bits: bytes
    issuer: Optional[str] = None
    status_purpose: Union[str, List[str], None] = None
    id: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    fresh: bool = True


FetchStatusList = Callable[[str], Optional[StatusListRead]]


@dataclass(frozen=True)
class StatusVerdict:
    ok: bool
    fresh: bool
    code: Optional[str] = None
    message: Optional[str] = None


_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


def _payload(encoded_list: str) -> bytes:
    payload = encoded_list[1:] if encoded_list.startswith("u") and _BASE64URL.fullmatch(encoded_list) else encoded_list
    return base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))


def decode_status_list_bits(encoded_list: str) -> bytes:
    """Inflates an ``encodedList`` to its bits, bounded; raises when it is not GZIP or exceeds the bound."""
    compressed = _payload(encoded_list)
    if compressed[:2] != b"\x1f\x8b":
        raise ValueError("status list encodedList is not GZIP")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        bits = stream.read(MAX_STATUS_LIST_BYTES + 1)
    if len(bits) > MAX_STATUS_LIST_BYTES:
        raise ValueError("status list exceeds the inflation bound")
    return bits


def read_status_bit(bits: bytes, index: int) -> Optional[int]:
    """The bit at ``index``, MSB first; None when the list has no such bit."""
    byte_index = index // 8
    if byte_index >= len(bits):
        return None
    return 1 if bits[byte_index] & (0x80 >> (index % 8)) else 0


def decode_status_list_credential(value: Any, fresh: bool = True) -> StatusListRead:
    """A fetched status-list credential decoded to a read; Bitstring v1.0 window first, VC 1.1 as the fallback."""
    if not isinstance(value, Mapping):
        raise ValueError("status list is not an object")
    subject = value.get("credentialSubject")
    encoded = subject.get("encodedList") if isinstance(subject, Mapping) else None
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("status list has no credentialSubject.encodedList")
    purpose = subject.get("statusPurpose")

    def bound(current: str, legacy: str) -> Optional[str]:
        stated = value.get(current) if value.get(current) is not None else value.get(legacy)
        if stated is None:
            return None
        return stated if isinstance(stated, str) else ""

    return StatusListRead(
        bits=decode_status_list_bits(encoded),
        issuer=issuer_of(value.get("issuer")),
        status_purpose=purpose if isinstance(purpose, (str, list)) else None,
        id=value.get("id") if isinstance(value.get("id"), str) else None,
        valid_from=bound("validFrom", "issuanceDate"),
        valid_until=bound("validUntil", "expirationDate"),
        fresh=fresh,
    )


def parse_status_list_index(raw: Any) -> Optional[int]:
    """The whole decimal index an entry names, or None for any other form (never coerced)."""
    if not isinstance(raw, str) or re.fullmatch(r"[0-9]+", raw) is None:
        return None
    digits = raw.lstrip("0") or "0"
    if len(digits) > 16:
        return None
    index = int(digits)
    return index if index <= 2**53 - 1 else None


def check_status_entry(
    entry: Mapping[str, Any],
    credential_issuer: str,
    read: Optional[StatusListRead],
    *,
    now_ms: int,
    max_clock_skew_ms: Any = None,
) -> StatusVerdict:
    """Holds ``entry`` of a credential ``credential_issuer`` issued to the list ``read`` at the entry's URL."""
    fresh = read is None or read.fresh is not False

    def refuse(code: str, message: str) -> StatusVerdict:
        return StatusVerdict(False, fresh, code, message)

    size = entry.get("statusSize")
    if size is not None and (isinstance(size, bool) or size != 1):
        return refuse(ReasonCodes.STATUS_ENTRY_MALFORMED, "statusSize must be 1 for a revocation entry")
    index = parse_status_list_index(entry.get("statusListIndex"))
    if index is None:
        return refuse(ReasonCodes.STATUS_ENTRY_MALFORMED, "statusListIndex is not a non-negative decimal string")
    if read is None:
        return refuse(ReasonCodes.STATUS_UNAVAILABLE, f"status list {entry.get('statusListCredential')} could not be read")
    if read.issuer is not None and read.issuer != credential_issuer:
        return refuse(ReasonCodes.STATUS_LIST_MISMATCH, f"status list is signed by {read.issuer}, not the credential issuer {credential_issuer}")
    purpose = entry.get("statusPurpose")
    if read.status_purpose is not None:
        purposes = read.status_purpose if isinstance(read.status_purpose, list) else [read.status_purpose]
        if purpose not in purposes:
            return refuse(ReasonCodes.STATUS_LIST_MISMATCH, f"status list purpose does not include {purpose}")
    if read.id is not None and read.id != entry.get("statusListCredential"):
        return refuse(ReasonCodes.STATUS_LIST_MISMATCH, f"status list id {read.id} is not the URL it was read from")
    window = window_verdict(read.valid_from, read.valid_until, now_ms, max_clock_skew_ms)
    if window != "inside":
        return refuse(ReasonCodes.STATUS_STALE, f"status list is outside the window it states ({window})")
    bit = read_status_bit(read.bits, index)
    if bit is None:
        return refuse(ReasonCodes.STATUS_ENTRY_MALFORMED, f"statusListIndex {index} is outside the list")
    if bit == 1:
        state = "suspended" if purpose == "suspension" else "revoked"
        return refuse(ReasonCodes.STATUS_REVOKED, f"the status list marks the credential {state}")
    return StatusVerdict(True, fresh)
