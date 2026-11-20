# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The evidence vault (AUDITABILITY.md, Evidence, retention, and access),
ported from helix-core's ``src/core/audit/evidence.ts``.

An exact payload that must be kept (a request body, a rejected
presentation, an exception) never enters the event core. It is encrypted
with randomized AES-256-GCM under tenant-bound authenticated data, stored by
an opaque object id, and the event carries only the ``EvidenceRef``: object
id, ciphertext digest, size, suite, key id, nonce and AAD digest.
Decryption needs the same AAD, so an object cannot be read under another
tenant or purpose, and a reference that does not match its bytes is refused.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Protocol, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto.jcs import canonicalize
from ..errors import AuditEvidenceError
from .digest import digest_bytes
from .types import EvidenceRef, PartyRef

__all__ = [
    "AuditEvidenceError",
    "EncryptedEvidence",
    "EvidenceEncryptor",
    "EvidenceStore",
    "MemoryEvidenceStore",
    "assert_evidence_matches_ref",
    "evidence_aad",
]

_NONCE_BYTES = 12
_TAG_BYTES = 16
_KEY_BYTES = 32
_HEX_KEY = re.compile(r"[0-9a-fA-F]{64}")


@dataclass
class EncryptedEvidence:
    """An encrypted object as the vault stores it: the reference and the bytes it describes."""

    ref: EvidenceRef
    ciphertext: bytes


def evidence_aad(tenant: PartyRef, purpose: str) -> bytes:
    """Authenticated data that binds an evidence object to a tenant and a
    purpose: the UTF-8 bytes of ``JCS({purpose, tenant})``. Both sides derive
    it; it is never stored beside the ciphertext."""
    return canonicalize({"purpose": purpose, "tenant": tenant}).encode("utf-8")


def _to_bytes(value: Union[bytes, str]) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def _key_bytes(key: Union[bytes, str]) -> bytes:
    if isinstance(key, str):
        data = bytes.fromhex(key) if _HEX_KEY.fullmatch(key) else None
    else:
        data = bytes(key)
    if data is None or len(data) != _KEY_BYTES:
        raise TypeError("Evidence key must be 32 bytes (raw or 64 hex digits)")
    return data


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class EvidenceEncryptor:
    """Randomized AES-256-GCM evidence encryption with opaque object addressing."""

    def __init__(
        self,
        key: Union[bytes, str],
        key_id: str,
        random_bytes: Optional[Callable[[int], bytes]] = None,
    ) -> None:
        self._key = _key_bytes(key)
        if not key_id:
            raise TypeError("Evidence keyId must be non-empty")
        self.key_id = key_id
        self._random = random_bytes or os.urandom

    def encrypt(
        self,
        plaintext: Union[bytes, str],
        media_type: str,
        aad: bytes,
        commit_plaintext: bool = False,
    ) -> EncryptedEvidence:
        if len(aad) == 0:
            raise AuditEvidenceError("Evidence encryption requires tenant-scoped authenticated data")
        data = _to_bytes(plaintext)
        nonce = bytes(self._random(_NONCE_BYTES))
        object_random = bytes(self._random(16))
        # AESGCM writes WebCrypto's layout: ciphertext followed by the 16-byte tag.
        ciphertext = AESGCM(self._key).encrypt(nonce, data, bytes(aad))
        ref: Dict[str, Any] = {"objectId": f"evi_{_base64url(object_random)}", "ciphertextDigest": digest_bytes(ciphertext)}
        if commit_plaintext:
            ref["plaintextCommitment"] = digest_bytes(data)
        ref.update(
            {
                "mediaType": media_type,
                "size": str(len(ciphertext)),
                "encryption": {
                    "suite": "A256GCM",
                    "keyId": self.key_id,
                    "nonce": _base64url(nonce),
                    "aadDigest": digest_bytes(bytes(aad)),
                },
            }
        )
        return EncryptedEvidence(ref=ref, ciphertext=ciphertext)

    def decrypt(self, encrypted: EncryptedEvidence, aad: bytes) -> bytes:
        """The plaintext, only for the bytes the reference describes, under this key, with the AAD that was bound."""
        if len(aad) == 0:
            raise AuditEvidenceError("Evidence decryption requires tenant-scoped authenticated data")
        ref, ciphertext = encrypted.ref, bytes(encrypted.ciphertext)
        encryption = ref["encryption"]
        if encryption["suite"] != "A256GCM" or encryption["keyId"] != self.key_id:
            raise AuditEvidenceError("Evidence reference names another suite or key", {"keyId": encryption["keyId"]})
        if digest_bytes(ciphertext) != ref["ciphertextDigest"] or str(len(ciphertext)) != ref["size"]:
            raise AuditEvidenceError("Evidence ciphertext does not match its reference")
        if digest_bytes(bytes(aad)) != encryption["aadDigest"]:
            raise AuditEvidenceError("Evidence authenticated data does not match its reference")
        if len(ciphertext) < _TAG_BYTES:
            raise AuditEvidenceError("Evidence ciphertext is shorter than its authentication tag")
        try:
            nonce = _base64url_decode(encryption["nonce"])
            plaintext = AESGCM(self._key).decrypt(nonce, ciphertext, bytes(aad))
        except Exception:  # noqa: BLE001 - InvalidTag, a malformed nonce: never the reason, only the verdict
            raise AuditEvidenceError("Evidence AEAD verification failed") from None
        commitment = ref.get("plaintextCommitment")
        if commitment is not None and digest_bytes(plaintext) != commitment:
            raise AuditEvidenceError("Evidence plaintext does not match its commitment")
        return plaintext


class EvidenceStore(Protocol):
    """Where ciphertext lives, apart from the ledger: the sink implements it over the database, tests in memory."""

    def put_if_absent(self, encrypted: EncryptedEvidence) -> EvidenceRef:
        """Stores the object unless its id is taken; an id taken by different bytes is a collision and refused."""
        ...

    def get(self, object_id: str) -> Optional[EncryptedEvidence]:
        """The stored object, or None when there is none for that id."""
        ...


class MemoryEvidenceStore:
    def __init__(self) -> None:
        self._objects: Dict[str, EncryptedEvidence] = {}

    def put_if_absent(self, encrypted: EncryptedEvidence) -> EvidenceRef:
        assert_evidence_matches_ref(encrypted)
        existing = self._objects.get(encrypted.ref["objectId"])
        if existing is not None:
            if existing.ref["ciphertextDigest"] != encrypted.ref["ciphertextDigest"]:
                raise AuditEvidenceError("Opaque evidence object id collision", {"objectId": encrypted.ref["objectId"]})
            return existing.ref
        self._objects[encrypted.ref["objectId"]] = EncryptedEvidence(ref=encrypted.ref, ciphertext=bytes(encrypted.ciphertext))
        return encrypted.ref

    def get(self, object_id: str) -> Optional[EncryptedEvidence]:
        found = self._objects.get(object_id)
        return None if found is None else EncryptedEvidence(ref=found.ref, ciphertext=bytes(found.ciphertext))


def assert_evidence_matches_ref(encrypted: EncryptedEvidence) -> None:
    """Refuses an object whose bytes are not the ones its reference commits to."""
    ciphertext = bytes(encrypted.ciphertext)
    if digest_bytes(ciphertext) != encrypted.ref["ciphertextDigest"] or str(len(ciphertext)) != encrypted.ref["size"]:
        raise AuditEvidenceError(
            "Evidence bytes do not match their ciphertext digest or size", {"objectId": encrypted.ref["objectId"]}
        )
