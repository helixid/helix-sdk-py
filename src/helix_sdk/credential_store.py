# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story F-1 (credential split): what an agent's SDK holds and sends.

* the identity credential Helix issued (no scopes);
* one capability attestation per scope, owner-signed through
  :meth:`CredentialStore.sign_attestations` or Helix-signed at onboarding;
  they resolve from the Entity Card, so they are stored but not carried;
* delegation hops (SPEC.md section 6.10), of which :meth:`present_chain`
  returns the agent's chain root to leaf beside the identity: what a request
  carries.

Self-custody invariant (stories rule 7): nothing here talks to an API, and
signing goes through a Signer that keeps the key wherever it lives.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence, TypedDict, Union

from .credentials import (
    CAPABILITY_ATTESTATION_TYPE,
    DELEGATION_CREDENTIAL_TYPE,
    HELIX_CONTEXT,
    IDENTITY_CREDENTIAL_TYPE,
    VC_V2_CONTEXT,
    _iso_now,
    _require_capability,
    invoker_of,
    sign_data_integrity,
)
from .crypto.jws import Signer

Credential = Dict[str, Any]

CredentialSigner = Signer
"""Whoever holds an Ed25519 key and signs with it: ``did``, ``kid`` (the
verification-method fragment without ``#``) and ``sign(data) -> bytes``. The
same shape as helix-core's Signer (story L1-C); JS's ``CredentialSigner``
signs asynchronously, Python's synchronously."""


class _BitstringStatusEntryBase(TypedDict):
    type: str
    """Always ``"BitstringStatusListEntry"``."""
    statusPurpose: str
    """``"revocation"`` or ``"suspension"``."""
    statusListIndex: str
    statusListCredential: str


class BitstringStatusEntry(_BitstringStatusEntryBase, total=False):
    id: str


class DataIntegrityProof(TypedDict):
    type: str
    """Always ``"DataIntegrityProof"``."""
    cryptosuite: str
    """Always ``"eddsa-jcs-2022"``."""
    created: str
    verificationMethod: str
    proofPurpose: str
    """Always ``"assertionMethod"``."""
    proofValue: str


_StoredCredentialOptional = TypedDict(
    "_StoredCredentialOptional",
    {"@context": Any, "validUntil": str, "proof": Dict[str, Any]},
    total=False,
)


class StoredCredential(_StoredCredentialOptional):
    """A credential as the store reads it: the members it needs to route and
    order, the rest untouched (other members are allowed at runtime)."""

    id: str
    type: List[str]
    issuer: str
    credentialSubject: Dict[str, Any]


class CapabilityAttestation(StoredCredential):
    validFrom: str
    credentialStatus: BitstringStatusEntry


class DelegationHop(StoredCredential):
    """``credentialSubject`` carries ``id``, ``invoker`` or ``controller``,
    ``parentCapability``, ``invocationTarget``, ``allowedAction`` and
    optional ``caveats`` (SPEC.md section 6.10)."""


class CredentialStoreData(TypedDict):
    identity: Optional[StoredCredential]
    attestations: List[StoredCredential]
    hops: List[StoredCredential]


class PresentedChain(TypedDict):
    """What a request carries (story F-1 point 7): the identity, then the hops root to leaf."""

    identity: StoredCredential
    hops: List[StoredCredential]


class _SignAttestationsRequired(TypedDict):
    valid_until: str
    status_entries: Sequence[BitstringStatusEntry]
    """One per capability, in order: the owner's own status list, or entries Helix handed out."""


class SignAttestationsOptions(_SignAttestationsRequired, total=False):
    """The keyword arguments of :meth:`CredentialStore.sign_attestations`, as a
    mapping a caller can build once and pass with ``**options``."""

    subject_did: str
    """The agent the attestations are about; default the stored identity's subject."""
    valid_from: str
    ids: Sequence[str]
    """Each attestation's ``id``, in order; default ``urn:uuid:`` values."""
    created: str
    """The proof's ``created``; default now."""


def sign_attestation_document(document: Mapping[str, Any], signer: CredentialSigner, created: str) -> Dict[str, Any]:
    """``eddsa-jcs-2022`` as the KYA-OS reference and helix-core write it:
    SHA-256(canonical proof options with the document ``@context``) followed
    by SHA-256(canonical unsecured document), Ed25519 over the two, base58btc.
    ``signer`` must be the document's issuer and return a 64-byte signature;
    a document that already carries a proof is refused."""
    return sign_data_integrity(document, signer, created)


def _kind_of(credential: Mapping[str, Any]) -> Optional[str]:
    types = credential.get("type")
    if not isinstance(types, list):
        return None
    if IDENTITY_CREDENTIAL_TYPE in types:
        return "identity"
    if CAPABILITY_ATTESTATION_TYPE in types:
        return "attestation"
    if DELEGATION_CREDENTIAL_TYPE in types:
        return "hop"
    return None


class CredentialStore:
    """Identity, capability attestations and delegation hops, kept apart."""

    def __init__(
        self,
        identity: Optional[Mapping[str, Any]] = None,
        attestations: Optional[Sequence[Mapping[str, Any]]] = None,
        hops: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> None:
        self._identity: Optional[Credential] = dict(identity) if identity is not None else None
        self._attestations: List[Credential] = [dict(a) for a in attestations or []]
        self._hops: List[Credential] = [dict(h) for h in hops or []]

    # -- construction ----------------------------------------------------------

    @classmethod
    def from_onboarding(cls, response: Mapping[str, Any]) -> "CredentialStore":
        """The store ``POST /v1/agents`` leaves an agent with."""
        return cls(response["identity"], response.get("attestations") or [])

    @classmethod
    def from_json(cls, data: Union[str, Mapping[str, Any]]) -> "CredentialStore":
        parsed = json.loads(data) if isinstance(data, str) else data
        return cls(parsed.get("identity"), parsed.get("attestations") or [], parsed.get("hops") or [])

    def to_dict(self) -> CredentialStoreData:
        return {"identity": self._identity, "attestations": list(self._attestations), "hops": list(self._hops)}

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    # -- reading ---------------------------------------------------------------

    @property
    def identity(self) -> Optional[Credential]:
        return self._identity

    @property
    def attestations(self) -> List[Credential]:
        return list(self._attestations)

    @property
    def hops(self) -> List[Credential]:
        return list(self._hops)

    @property
    def agent_did(self) -> Optional[str]:
        if self._identity is None:
            return None
        subject = self._identity.get("credentialSubject") or {}
        value = subject.get("id")
        return value if isinstance(value, str) else None

    def attested_capabilities(self) -> List[str]:
        names: List[str] = []
        for attestation in self._attestations:
            name = (attestation.get("credentialSubject") or {}).get("capability")
            if isinstance(name, str) and name not in names:
                names.append(name)
        return names

    # -- writing ---------------------------------------------------------------

    def add(self, credential: Mapping[str, Any]) -> "CredentialStore":
        kind = _kind_of(credential)
        if kind == "identity":
            return self.set_identity(credential)
        if kind == "attestation":
            return self.add_attestation(credential)
        if kind == "hop":
            return self.add_hop(credential)
        raise ValueError("credential is not an identity, a capability attestation or a delegation hop")

    def set_identity(self, credential: Mapping[str, Any]) -> "CredentialStore":
        if _kind_of(credential) != "identity":
            raise ValueError("not an AgentIdentityCredential")
        self._identity = dict(credential)
        return self

    def add_attestation(self, credential: Mapping[str, Any]) -> "CredentialStore":
        if _kind_of(credential) != "attestation":
            raise ValueError("not a CapabilityAttestationCredential")
        self._replace(self._attestations, dict(credential))
        return self

    def add_hop(self, credential: Mapping[str, Any]) -> "CredentialStore":
        if _kind_of(credential) != "hop":
            raise ValueError("not a DelegationCredential")
        self._replace(self._hops, dict(credential))
        return self

    @staticmethod
    def _replace(items: List[Credential], credential: Credential) -> None:
        for index, item in enumerate(items):
            if item.get("id") == credential.get("id"):
                items[index] = credential
                return
        items.append(credential)

    def remove_attestation(self, capability: str) -> int:
        before = len(self._attestations)
        self._attestations = [a for a in self._attestations if (a.get("credentialSubject") or {}).get("capability") != capability]
        return before - len(self._attestations)

    def remove_hop(self, hop_id: str) -> bool:
        before = len(self._hops)
        self._hops = [h for h in self._hops if h.get("id") != hop_id]
        return len(self._hops) != before

    # -- presenting ------------------------------------------------------------

    def present_chain(self, invocation_target: Optional[str] = None) -> PresentedChain:
        """The identity plus the hops delegating to the agent, root to leaf."""
        if self._identity is None:
            raise ValueError("no identity credential stored")
        agent_did = self.agent_did
        leaves = [
            hop
            for hop in self._hops
            if invoker_of(hop) == agent_did
            and (invocation_target is None or hop["credentialSubject"].get("invocationTarget") == invocation_target)
        ]
        if not leaves:
            return {"identity": self._identity, "hops": []}
        leaf = leaves[-1]
        by_capability = {hop["credentialSubject"]["id"]: hop for hop in self._hops}
        chain: List[Credential] = [leaf]
        current = leaf
        while current["credentialSubject"]["parentCapability"] != current["credentialSubject"]["invocationTarget"]:
            parent = by_capability.get(current["credentialSubject"]["parentCapability"])
            if parent is None:
                raise ValueError(f"hop {current.get('id')} names a parent capability the store does not hold")
            if any(parent is hop for hop in chain) or len(chain) >= 10:
                raise ValueError("delegation chain does not terminate at a root")
            chain.insert(0, parent)
            current = parent
        return {"identity": self._identity, "hops": chain}

    # -- the owner path --------------------------------------------------------

    def sign_attestations(
        self,
        capabilities: Sequence[str],
        signer: CredentialSigner,
        *,
        valid_until: str,
        status_entries: Sequence[Mapping[str, Any]],
        subject_did: Optional[str] = None,
        valid_from: Optional[str] = None,
        ids: Optional[Sequence[str]] = None,
        created: Optional[str] = None,
    ) -> List[Credential]:
        """One owner-signed ``CapabilityAttestationCredential`` per capability, stored and returned. Nothing is sent."""
        subject = subject_did or self.agent_did
        if subject is None:
            raise ValueError("subject_did is required when no identity is stored")
        if len(status_entries) != len(capabilities):
            raise ValueError("one status entry per capability is required")
        signed: List[Credential] = []
        for index, capability in enumerate(capabilities):
            _require_capability(capability)
            document: Dict[str, Any] = {
                "@context": [VC_V2_CONTEXT, HELIX_CONTEXT],
                "id": ids[index] if ids is not None else f"urn:uuid:{uuid.uuid4()}",
                "type": ["VerifiableCredential", CAPABILITY_ATTESTATION_TYPE],
                "issuer": signer.did,
                "validFrom": valid_from or _iso_now(),
                "validUntil": valid_until,
                "credentialSubject": {"id": subject, "capability": capability},
                "credentialStatus": dict(status_entries[index]),
            }
            attestation = sign_attestation_document(document, signer, created or _iso_now())
            self.add_attestation(attestation)
            signed.append(attestation)
        return signed
