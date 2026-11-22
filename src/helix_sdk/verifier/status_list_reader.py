# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Reading a fetched status-list credential (KYA-OS story L3-C, SPEC.md 6.6).

W3C Bitstring Status List v1.0 (what Helix issues) and StatusList2021 (read
for the Core L3.11 vectors; Helix never issues it). Order, fail-closed: the
list's shape, its proof by the list's own issuer (``DataIntegrityProof``
``eddsa-jcs-2022``, or the section 6.2 ``Ed25519Signature2020``), and only
then its bits. Mirrors helix-sdk-js ``verifier/status-list-reader.ts``.
"""

from __future__ import annotations

import re
from calendar import monthrange
from typing import Any, Callable, Mapping, Optional

from ..credentials import DidResolver, issuer_of, verify_data_integrity
from .codes import ReasonCodes
from .status import FetchStatusList, StatusListRead, decode_status_list_bits, parse_status_bound

BITSTRING_LIST_CREDENTIAL_TYPE = "BitstringStatusListCredential"
BITSTRING_LIST_SUBJECT_TYPE = "BitstringStatusList"
STATUS_LIST_2021_CREDENTIAL_TYPE = "StatusList2021Credential"
STATUS_LIST_2021_SUBJECT_TYPE = "StatusList2021"

_DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$")


class StatusListError(Exception):
    """Why a fetched list could not be read; the credential it covers then reads as revoked."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _malformed(message: str) -> StatusListError:
    return StatusListError(ReasonCodes.STATUS_LIST_MALFORMED, message)


def status_list_format(document: Any) -> Optional[str]:
    """``'bitstring'`` or ``'statuslist2021'`` by the types a list states, or None."""
    if not isinstance(document, Mapping):
        return None
    types = document.get("type")
    subject = document.get("credentialSubject")
    if not isinstance(types, list) or not isinstance(subject, Mapping):
        return None
    if BITSTRING_LIST_CREDENTIAL_TYPE in types and subject.get("type") == BITSTRING_LIST_SUBJECT_TYPE:
        return "bitstring"
    if STATUS_LIST_2021_CREDENTIAL_TYPE in types and subject.get("type") == STATUS_LIST_2021_SUBJECT_TYPE:
        return "statuslist2021"
    return None


def is_calendar_date_time(value: str) -> bool:
    """An RFC 3339 date-time with offset that a calendar has (no 30th of February, no 60th second)."""
    if not _DATE_TIME.match(value):
        return False
    year, month, day = (int(part) for part in value[:10].split("-"))
    if not 1 <= month <= 12 or not 1 <= day <= monthrange(year, month)[1]:
        return False
    return parse_status_bound(value) is not None


def verify_status_list_proof(document: Mapping[str, Any], resolve_did: DidResolver) -> Optional[str]:
    """None when the list's one proof verifies under its issuer's assertion key, else why not. An unsigned list never verifies."""
    proof = document.get("proof")
    if proof is None:
        return "the list is unsigned"
    if not isinstance(proof, Mapping):
        return "the list carries no single proof object"
    issuer = issuer_of(document.get("issuer"))
    if issuer is None:
        return "the list names no issuer DID"
    if proof.get("type") == "DataIntegrityProof":
        verdict = verify_data_integrity(document, resolve_did)
        return None if verdict.ok else f"{verdict.reason}: {verdict.message}"
    if proof.get("type") == "Ed25519Signature2020":
        try:
            resolved = resolve_did(issuer)
        except Exception as exc:  # noqa: BLE001 - a resolver that throws fails closed
            return f"could not resolve {issuer}: {exc}"
        if resolved is None:
            return f"{issuer} did not resolve"
        # Imported here: the conformance package imports this one.
        from ..conformance.legacy import verify_legacy_proof

        return verify_legacy_proof(dict(document), {issuer: resolved})
    return f"proof type {proof.get('type')} is not one a status list is read under"


def _window_bound(document: Mapping[str, Any], current: str, legacy: str) -> Optional[str]:
    member = current if current in document else legacy if legacy in document else None
    if member is None:
        return None
    value = document[member]
    if not isinstance(value, str) or not is_calendar_date_time(value):
        raise _malformed(f"{member} is not an RFC 3339 date-time with offset")
    return value


def _read_list(document: Any, kind: str, resolve_did: DidResolver, fresh: bool) -> StatusListRead:
    if not isinstance(document, Mapping):
        raise _malformed("the status list is not a JSON object")
    if status_list_format(document) != kind:
        if kind == "bitstring":
            raise _malformed(f"the list is not a {BITSTRING_LIST_CREDENTIAL_TYPE} with a {BITSTRING_LIST_SUBJECT_TYPE} subject")
        raise _malformed(f"the list is not a {STATUS_LIST_2021_CREDENTIAL_TYPE} with a {STATUS_LIST_2021_SUBJECT_TYPE} subject")
    subject = document["credentialSubject"]
    purpose = subject.get("statusPurpose")
    if kind == "bitstring":
        fine = (isinstance(purpose, str) and purpose != "") or (
            isinstance(purpose, list) and len(purpose) > 0 and all(isinstance(entry, str) and entry != "" for entry in purpose)
        )
        if not fine:
            raise _malformed("statusPurpose is not a purpose or a non-empty list of purposes")
    elif not isinstance(purpose, str) or purpose == "":
        raise _malformed("a StatusList2021 list states one statusPurpose string")
    encoded = subject.get("encodedList")
    if not isinstance(encoded, str) or encoded == "":
        raise _malformed("the list has no credentialSubject.encodedList")
    list_id = document.get("id")
    if list_id is not None and not isinstance(list_id, str):
        raise _malformed("the list id is not a string")
    valid_from = _window_bound(document, "validFrom", "issuanceDate")
    valid_until = _window_bound(document, "validUntil", "expirationDate")

    # The proof, before any bit is read (section 6.6).
    refusal = verify_status_list_proof(document, resolve_did)
    if refusal is not None:
        raise StatusListError(ReasonCodes.STATUS_LIST_PROOF_INVALID, refusal)
    try:
        bits = decode_status_list_bits(encoded)
    except Exception as exc:  # noqa: BLE001 - any decoding failure is one refusal
        raise _malformed(f"encodedList does not inflate: {exc}") from exc
    return StatusListRead(
        bits=bits,
        issuer=issuer_of(document.get("issuer")),
        status_purpose=purpose,
        id=list_id,
        valid_from=valid_from,
        valid_until=valid_until,
        fresh=fresh,
        proof_verified=True,
    )


def read_bitstring_status_list(document: Any, resolve_did: DidResolver, fresh: bool = True) -> StatusListRead:
    """Reads a W3C Bitstring Status List v1.0 credential: shape, proof, then bits."""
    return _read_list(document, "bitstring", resolve_did, fresh)


def read_status_list_2021(document: Any, resolve_did: DidResolver, fresh: bool = True) -> StatusListRead:
    """Reads a StatusList2021 credential (Core L3.11): same bit logic, its own type names and window members."""
    return _read_list(document, "statuslist2021", resolve_did, fresh)


def read_status_list_credential(document: Any, resolve_did: DidResolver, fresh: bool = True) -> StatusListRead:
    """Reads a list of either format, by the types it states; a list of neither is malformed."""
    kind = status_list_format(document)
    if kind is None:
        raise _malformed("the document is neither a Bitstring Status List nor a StatusList2021 credential")
    return _read_list(document, kind, resolve_did, fresh)


#: ``fetch(url)`` returning ``(status, body)``: the host's SafeFetch (https only, public unicast, bounds).
StatusListHttpFetch = Callable[[str], "tuple[int, Any]"]


def create_status_list_fetcher(fetch: StatusListHttpFetch, resolve_did: DidResolver) -> FetchStatusList:
    """A ``fetch_status_list`` seam over ``fetch``: unreachable or non-2xx is ``status_unavailable``; the rest keeps the reader's code."""

    def fetch_status_list(url: str) -> StatusListRead:
        try:
            status, body = fetch(url)
            if not 200 <= status < 300:
                raise ValueError(f"answered {status}")
        except Exception as exc:  # noqa: BLE001 - whatever stopped the read fails closed
            raise StatusListError(ReasonCodes.STATUS_UNAVAILABLE, f"status list {url} could not be read: {exc}") from exc
        return read_status_list_credential(body, resolve_did, fresh=True)

    return fetch_status_list
