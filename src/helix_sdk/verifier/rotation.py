# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Key rotation in a DID document (KYA-OS story C-E point 2), verifier side.

Every document version Helix publishes carries a monotonic
``rotationSequence`` and ``updated``. A resolver remembers the highest
sequence it has seen per DID and refuses a document with a lower one, so a
cached old document cannot be replayed as current; a document without a
sequence is refused once one was seen (dropping it is a downgrade). The
``jwks.json`` projection of the document carries the same sequence and is
read through the same guard. Mirrors helix-sdk-js ``verifier/rotation.ts``.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, TypeVar

DID_DOCUMENT_STALE = "did_document_stale"

T = TypeVar("T")


def rotation_sequence_of(document: Any) -> Optional[int]:
    """The document's ``rotationSequence``: a whole number from 1, else None."""
    value = document.get("rotationSequence") if isinstance(document, Mapping) else None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


class RotationSequenceStore(Protocol):
    """Where a guard keeps the highest sequence seen per DID; a shared store lets every instance refuse the same replay."""

    def get(self, did: str) -> Optional[int]: ...  # pragma: no cover - protocol

    def raise_to(self, did: str, sequence: int) -> None: ...  # pragma: no cover - protocol


class MemoryRotationSequenceStore:
    """The in-process store: bounded, oldest DID dropped first."""

    def __init__(self, max_entries: int = 10_000) -> None:
        self._seen: "OrderedDict[str, int]" = OrderedDict()
        self._max = max_entries

    def get(self, did: str) -> Optional[int]:
        return self._seen.get(did)

    def raise_to(self, did: str, sequence: int) -> None:
        kept = self._seen.get(did)
        if kept is not None and kept >= sequence:
            return
        self._seen.pop(did, None)
        self._seen[did] = sequence
        if len(self._seen) > self._max:
            self._seen.popitem(last=False)


class StaleDidDocumentError(Exception):
    """A document (or JWKS) older than one already seen for the same DID."""

    reason = DID_DOCUMENT_STALE

    def __init__(self, did: str, sequence: Optional[int], last_seen: int) -> None:
        self.did = did
        self.sequence = sequence
        self.last_seen = last_seen
        if sequence is None:
            message = f"DID document of {did} carries no rotationSequence, but sequence {last_seen} was already seen"
        else:
            message = f"DID document of {did} has rotationSequence {sequence}, lower than {last_seen} already seen"
        super().__init__(message)


class RotationSequenceGuard:
    """Refuses a document version older than one already seen for the same DID."""

    def __init__(self, store: Optional[RotationSequenceStore] = None) -> None:
        self.store: RotationSequenceStore = store if store is not None else MemoryRotationSequenceStore()

    def check(self, did: str, document: Any) -> Optional[StaleDidDocumentError]:
        """None when ``document`` is current, the error (not raised) otherwise; records a higher sequence."""
        sequence = rotation_sequence_of(document)
        last_seen = self.store.get(did)
        if last_seen is not None and (sequence is None or sequence < last_seen):
            return StaleDidDocumentError(did, sequence, last_seen)
        if sequence is not None:
            self.store.raise_to(did, sequence)
        return None

    def assert_current(self, did: str, document: Any) -> None:
        stale = self.check(did, document)
        if stale is not None:
            raise stale


def guarded_resolver(resolve: Callable[[str], Optional[T]], guard: Optional[RotationSequenceGuard] = None) -> Callable[[str], Optional[T]]:
    """A resolver whose documents pass ``guard`` first: a stale one raises StaleDidDocumentError."""
    the_guard = guard if guard is not None else RotationSequenceGuard()

    def resolved(did: str) -> Optional[T]:
        document = resolve(did)
        if document is not None:
            the_guard.assert_current(did, document)
        return document

    return resolved


def project_jwks(document: Mapping[str, Any]) -> Dict[str, Any]:
    """The ``jwks.json`` projection: every Ed25519 method as an OKP JWK, kid
    preserved (the full ``<did>#<fragment>`` id), with its validity and the
    document's sequence and ``updated``."""
    keys: List[Dict[str, Any]] = []
    methods = document.get("verificationMethod")
    did = document.get("id")
    for method in methods if isinstance(methods, list) else []:
        jwk = method.get("publicKeyJwk") if isinstance(method, Mapping) else None
        method_id = method.get("id") if isinstance(method, Mapping) else None
        if not isinstance(jwk, Mapping) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str) or not isinstance(method_id, str):
            continue
        key: Dict[str, Any] = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": jwk["x"],
            "kid": f"{did}{method_id}" if method_id.startswith("#") else method_id,
            "use": "sig",
            "alg": "EdDSA",
        }
        for member in ("validFrom", "validUntil", "revoked"):
            if isinstance(method.get(member), str):
                key[member] = method[member]
        keys.append(key)
    projected: Dict[str, Any] = {"keys": keys}
    sequence = rotation_sequence_of(document)
    if sequence is not None:
        projected["rotationSequence"] = sequence
    if isinstance(document.get("updated"), str):
        projected["updated"] = document["updated"]
    return projected


def read_jwks(did: str, value: Any, guard: RotationSequenceGuard) -> List[Dict[str, Any]]:
    """The keys of a fetched ``jwks.json`` for ``did``; raises StaleDidDocumentError for a lower sequence than seen."""
    if not isinstance(value, Mapping) or not isinstance(value.get("keys"), list):
        raise ValueError(f"jwks of {did} is not a JWK Set")
    guard.assert_current(did, value)
    return [
        dict(key)
        for key in value["keys"]
        if isinstance(key, Mapping)
        and key.get("kty") == "OKP"
        and key.get("crv") == "Ed25519"
        and isinstance(key.get("x"), str)
        and isinstance(key.get("kid"), str)
        and key["kid"].startswith(f"{did}#")
    ]
