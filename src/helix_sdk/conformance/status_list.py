# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
#
# The keeper and acceptance rules follow the KYA-OS suite's independent reading
# (decentralized-identity/kya-os-mcp, conformance/status_list.py at a4d7f61,
# MIT licensed, Copyright (c) 2026 KYA-OS).
"""A status list held to SPEC.md section 6.6 for a section 6.2 credential (KYA-OS
story F-2, the ``status-list`` vector category). The Python twin of
helix-sdk-js ``kyaos/conformance/status-list.ts``.
"""

from __future__ import annotations

import base64
import gzip
import io
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .legacy import issuer_did, verify_legacy_proof

_ORIGIN = re.compile(r"https://[a-z0-9.-]+(:[0-9]{1,5})?")
_ORIGIN_IN_ANY_FORM = re.compile(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(/?)")
_DATE_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt]([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])"
)
MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024


def mistaken_binding(binding: str) -> Optional[str]:
    written = _ORIGIN_IN_ANY_FORM.fullmatch(binding)
    if written and written.group(1) == "/":
        return 'statusListIssuers binds an origin followed by "/"'
    if written and re.search(r"[A-Z]", binding):
        return "statusListIssuers binds an origin whose host is not in lower case"
    if binding.endswith("/"):
        return 'statusListIssuers binds a URL that ends in "/"'
    return None


def status_configuration(value: Mapping[str, Any]) -> Tuple[Optional[str], Optional[str], Dict[str, List[str]]]:
    """The (root, root list, services) an input states; raises ValueError for one that is not well formed."""
    for member in ("trustedRootIssuer", "trustedRootStatusList"):
        if member in value and not (isinstance(value[member], str) and value[member]):
            raise ValueError(member + " is not a non-empty string")
    services = value.get("statusListIssuers", {})
    if not isinstance(services, dict):
        raise ValueError("statusListIssuers does not map issuers to lists of URLs")
    bound: Dict[str, str] = {}
    for did, bindings in services.items():
        if not did or not isinstance(bindings, list):
            raise ValueError("statusListIssuers does not map issuers to lists of URLs")
        for binding in bindings:
            if not (isinstance(binding, str) and re.match(r"https?://", binding)):
                raise ValueError("statusListIssuers does not map issuers to lists of URLs")
            mistaken = mistaken_binding(binding)
            if mistaken:
                raise ValueError(mistaken)
            if bound.setdefault(binding, did) != did:
                raise ValueError("statusListIssuers binds one URL to two issuers")
    return value.get("trustedRootIssuer"), value.get("trustedRootStatusList"), services


def keeper(url: str, owner: str, root: Optional[str], root_list: Optional[str], services: Mapping[str, List[str]]) -> Tuple[str, bool]:
    """The one issuer whose list is read at ``url``, and whether no binding names it."""
    for did, bindings in services.items():
        if url in bindings:
            return did, False
    for did, bindings in services.items():
        for binding in bindings:
            if _ORIGIN.fullmatch(binding) and any(url.startswith(binding + mark) for mark in "/?#"):
                return did, False
    if root is not None and root_list == url:
        return root, True
    return owner, True


def accepts_list(document: Any, owner: str, url: str, purpose: str, root: Optional[str], root_list: Optional[str], services: Mapping[str, List[str]]) -> bool:
    if not isinstance(document, dict) or not owner:
        return False
    signer = issuer_did(document.get("issuer"))
    if signer is None:
        return False
    kept_by, unbound = keeper(url, owner, root, root_list, services)
    if signer != kept_by:
        return False
    if "id" in document:
        if document["id"] != url:
            return False
    elif not unbound or root not in (None, owner) or any(did != owner for did in services):
        return False
    subject = document.get("credentialSubject")
    if not isinstance(subject, dict):
        return False
    declared = subject.get("statusPurpose")
    if isinstance(declared, str):
        return declared == purpose
    types = document.get("type")
    return (
        isinstance(declared, list)
        and len(declared) > 0
        and all(isinstance(entry, str) for entry in declared)
        and purpose in declared
        and isinstance(types, list)
        and "BitstringStatusListCredential" in types
        and subject.get("type") == "BitstringStatusList"
    )


def _window_bound(document: Mapping[str, Any], current: str, legacy: str) -> Optional[float]:
    member = current if current in document else legacy if legacy in document else None
    if member is None:
        return None
    stated = document[member]
    if not isinstance(stated, str) or not _DATE_TIME.fullmatch(stated):
        raise ValueError(member + " is not a date")
    text = stated.upper().replace("Z", "+00:00")
    text = re.sub(r"\.([0-9]+)", lambda fraction: "." + fraction.group(1)[:6].ljust(6, "0"), text, count=1)
    return datetime.fromisoformat(text).timestamp() * 1000


def within_window(document: Mapping[str, Any], now_ms: float) -> bool:
    until = _window_bound(document, "validUntil", "expirationDate")
    start = _window_bound(document, "validFrom", "issuanceDate")
    return (until is None or now_ms <= until) and (start is None or start <= now_ms)


def status_index(raw: Any) -> Optional[int]:
    if not isinstance(raw, str) or re.fullmatch(r"[0-9]+", raw) is None:
        return None
    digits = raw.lstrip("0") or "0"
    if len(digits) > 16:
        return None
    index = int(digits)
    return index if index <= 2**53 - 1 else None


def list_bits(encoded: str) -> bytes:
    payload = encoded[1:] if encoded.startswith("u") else encoded
    if re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", payload) is None:
        raise ValueError("encodedList is not base64url")
    compressed = base64.urlsafe_b64decode(payload.rstrip("=") + "=" * (-len(payload.rstrip("=")) % 4))
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        bits = stream.read(MAX_STATUS_LIST_BYTES + 1)
    if len(bits) > MAX_STATUS_LIST_BYTES:
        raise ValueError("status list exceeds the inflation bound")
    return bits


def status_list_refusal(value: Mapping[str, Any], now_ms: Optional[float] = None) -> Optional[str]:
    """None when the credential is active, else why it is refused (fail-closed on anything unreadable)."""
    now = time.time() * 1000 if now_ms is None else now_ms
    try:
        credential = value["credential"]
        entry = credential.get("credentialStatus")
        if not isinstance(entry, dict):
            return "the credential has no credentialStatus"
        url = entry.get("statusListCredential")
        if not isinstance(url, str):
            return "the entry names no list"
        document = value["statusLists"].get(url)
        purpose = entry.get("statusPurpose")
        root, root_list, services = status_configuration(value)
        owner = issuer_did(credential.get("issuer"))
        if not isinstance(purpose, str) or owner is None or not accepts_list(document, owner, url, purpose, root, root_list, services):
            return "the list is not one section 6.6 reads for the credential"
        credential_proof = verify_legacy_proof(credential, value["didDocuments"])
        if credential_proof is not None:
            return "credential: " + credential_proof
        list_proof = verify_legacy_proof(document, value["didDocuments"])
        if list_proof is not None:
            return "list: " + list_proof
        if not within_window(document, now):
            return "the list is outside the window it states"
        size = entry.get("statusSize", 1)
        if isinstance(size, bool) or size != 1:
            return "the entry is not one bit"
        index = status_index(entry.get("statusListIndex"))
        if index is None:
            return "statusListIndex is not a whole decimal"
        bits = list_bits(document["credentialSubject"]["encodedList"])
        if index >= len(bits) * 8:
            return "statusListIndex is outside the list"
        return "revoked" if bits[index // 8] & (0x80 >> (index % 8)) else None
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OSError, EOFError) as exc:
        return f"unreadable: {exc}"
