# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The legacy section 6.2 delegation credential as the SDK reads it, for the
``delegation-chain`` and ``status-list`` vector categories (KYA-OS story F-2).
The Python twin of helix-sdk-js ``kyaos/conformance/legacy.ts``: an Ed25519
signature over the RFC 8785 bytes of the credential without its ``proof``,
``proofValue`` base64url, the VC-JWT form, the CID section 3.3 key retrieval
and the section 6.2 / 6.4 chain rules.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Union

import nacl.exceptions
import nacl.signing

from ..crypto.jcs import CanonicalJsonError, canonicalize
from ..crypto.jws import base64url_decode_strict, verification_method_to_jwk
from .delegation_binding import read_signature_base64


def _relative(identifier: Any, did: str) -> Optional[str]:
    if not isinstance(identifier, str):
        return None
    if identifier.startswith("#"):
        return identifier
    if identifier == did:
        return ""
    if identifier.startswith(did + "#"):
        return identifier[len(did):]
    return None


def assertion_key(document: Any, did: str, name: Any, named: bool) -> Optional[bytes]:
    """The Ed25519 key ``name`` names among ``did``'s assertion methods (the first entry's when not ``named``)."""
    if not isinstance(document, dict) or document.get("id") != did or "#" in did:
        return None
    entries = document.get("assertionMethod")
    if not isinstance(entries, list):
        return None
    wanted: Any = name
    if not named:
        first = entries[0] if entries else None
        wanted = first.get("id") if isinstance(first, dict) else first
    elif not isinstance(wanted, str) or not wanted:
        return None
    elif not wanted.startswith(("did:", "#")):
        wanted = "#" + wanted
    target = _relative(wanted, did)
    if target is None:
        return None
    published = document.get("verificationMethod")
    published = published if isinstance(published, list) else []
    definitions = [entry for entry in published + entries if isinstance(entry, dict) and _relative(entry.get("id"), did) == target]
    listed = any(_relative(entry.get("id") if isinstance(entry, dict) else entry, did) == target for entry in entries)
    if not listed or len(definitions) != 1:
        return None
    method = definitions[0]
    if not all(isinstance(method.get(field), str) and method[field] for field in ("id", "type", "controller")):
        return None
    if method["controller"] != did:
        return None
    try:
        key = base64url_decode_strict(verification_method_to_jwk(method)["x"])
    except Exception:  # noqa: BLE001 - a method with no usable key gives none
        return None
    return key if key is not None and len(key) == 32 else None


def issuer_did(issuer: Any) -> Optional[str]:
    if isinstance(issuer, str) and issuer:
        return issuer
    if isinstance(issuer, dict) and isinstance(issuer.get("id"), str) and issuer["id"]:
        return issuer["id"]
    return None


def _verifies(signature: bytes, data: bytes, key: bytes) -> bool:
    if len(signature) != 64:
        return False
    try:
        nacl.signing.VerifyKey(key).verify(data, signature)
        return True
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError, ValueError):
        return False


def verify_legacy_proof(credential: Any, documents: Mapping[str, Any]) -> Optional[str]:
    """The embedded section 6.2 proof of a credential or status list: None when it holds, else why not."""
    if not isinstance(credential, dict):
        return "not a credential object"
    proof = credential.get("proof")
    if not isinstance(proof, dict):
        return "no proof"
    if proof.get("type") not in ("Ed25519Signature2020", "DataIntegrityProof"):
        return "unsupported proof type"
    if "proofPurpose" in proof and proof["proofPurpose"] != "assertionMethod":
        return "proof is not for assertionMethod"
    did = issuer_did(credential.get("issuer"))
    if did is None:
        return "no issuer"
    method = proof.get("verificationMethod")
    if "verificationMethod" in proof and (not isinstance(method, str) or not method):
        return "verificationMethod names no key"
    key = assertion_key(documents.get(did), did, method, "verificationMethod" in proof)
    if key is None:
        return "no assertionMethod key of the issuer"
    signature = read_signature_base64(proof.get("proofValue"), False) if isinstance(proof.get("proofValue"), str) else None
    if signature is None:
        return "proofValue is no signature"
    try:
        data = canonicalize({name: value for name, value in credential.items() if name != "proof"}).encode("utf-8")
    except CanonicalJsonError:
        return "credential has no canonical form"
    return None if _verifies(signature, data, key) else "signature does not verify"


def _read_segment(segment: str) -> Any:
    data = read_signature_base64(segment, True)
    if data is None:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def verify_vc_jwt(jwt: str, documents: Mapping[str, Any], now_ms: int) -> Dict[str, Any]:
    """A VC-JWT verified: ``{"credential": vc}`` or ``{"refusal": why}``."""
    segments = jwt.split(".")
    if len(segments) != 3:
        return {"refusal": "a VC-JWT is three segments"}
    header, payload = _read_segment(segments[0]), _read_segment(segments[1])
    if not isinstance(header, dict) or not isinstance(payload, dict) or header.get("alg") != "EdDSA":
        return {"refusal": "not an EdDSA VC-JWT"}
    if "kid" in header and (not isinstance(header["kid"], str) or not header["kid"]):
        return {"refusal": "kid names no key"}
    vc, iss = payload.get("vc"), payload.get("iss")
    if not isinstance(vc, dict) or not isinstance(iss, str) or issuer_did(vc.get("issuer")) != iss:
        return {"refusal": "the credential is not the iss claim's"}
    for claim in ("exp", "nbf"):
        value = payload.get(claim)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))):
            return {"refusal": f"{claim} is not a NumericDate"}
    if isinstance(payload.get("exp"), (int, float)) and now_ms / 1000 >= payload["exp"]:
        return {"refusal": "expired (exp)"}
    if isinstance(payload.get("nbf"), (int, float)) and now_ms / 1000 + 30 < payload["nbf"]:
        return {"refusal": "not yet valid (nbf)"}
    key = assertion_key(documents.get(iss), iss, header.get("kid"), "kid" in header)
    if key is None:
        return {"refusal": "no assertionMethod key of the issuer"}
    signature = read_signature_base64(segments[2], True)
    if signature is None:
        return {"refusal": "signature segment is not base64url"}
    data = f"{segments[0]}.{segments[1]}".encode("utf-8")
    return {"credential": vc} if _verifies(signature, data, key) else {"refusal": "signature does not verify"}


def _parse_date(value: str) -> Optional[float]:
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        return datetime.fromisoformat(text).timestamp() * 1000
    except ValueError:
        return None


def legacy_delegation(credential: Any, now_ms: int) -> Dict[str, Any]:
    """The shape section 6.2 requires: ``{"delegation": ...}`` or ``{"refusal": why}``."""
    if not isinstance(credential, dict):
        return {"refusal": "not a credential object"}
    types = credential.get("type")
    if not isinstance(types, list) or "VerifiableCredential" not in types or "DelegationCredential" not in types:
        return {"refusal": "not a DelegationCredential"}
    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict) or any(key not in ("id", "delegation") for key in subject):
        return {"refusal": "credentialSubject carries more than id and delegation"}
    delegation = subject.get("delegation")
    if not isinstance(delegation, dict) or not all(isinstance(delegation.get(field), str) for field in ("id", "issuerDid", "subjectDid")):
        return {"refusal": "delegation is malformed"}
    if delegation.get("status") != "active":
        return {"refusal": "delegation is not active"}
    if issuer_did(credential.get("issuer")) is None:
        return {"refusal": "no issuer"}
    expiration = credential.get("expirationDate")
    if isinstance(expiration, str):
        expires = _parse_date(expiration)
        if expires is not None and expires <= now_ms:
            return {"refusal": "expired"}
    constraints = delegation.get("constraints") if isinstance(delegation.get("constraints"), dict) else {}
    not_after, not_before = constraints.get("notAfter"), constraints.get("notBefore")
    if isinstance(not_after, (int, float)) and not isinstance(not_after, bool) and not_after * 1000 <= now_ms:
        return {"refusal": "expired (notAfter)"}
    if isinstance(not_before, (int, float)) and not isinstance(not_before, bool) and not_before * 1000 > now_ms:
        return {"refusal": "not yet valid (notBefore)"}
    return {"delegation": delegation}


def _scopes(delegation: Mapping[str, Any]) -> List[str]:
    out: List[str] = []
    constraints = delegation.get("constraints") if isinstance(delegation.get("constraints"), dict) else {}
    for scopes in (delegation.get("scopes"), constraints.get("scopes")):
        if isinstance(scopes, list):
            for scope in scopes:
                if isinstance(scope, str) and scope not in out:
                    out.append(scope)
    return out


def _audience_admits(delegation: Mapping[str, Any], server_did: str) -> bool:
    constraints = delegation.get("constraints") if isinstance(delegation.get("constraints"), dict) else {}
    audience = constraints.get("audience")
    if audience is None or audience == "":
        return True
    if isinstance(audience, str):
        return audience == server_did
    return isinstance(audience, list) and server_did in audience


def legacy_chain_refusal(
    chain: Sequence[Any], server_did: str, documents: Mapping[str, Any], now_ms: int, verified: Optional[Set[int]] = None
) -> Optional[str]:
    """A section 6.2 chain, root first: None when it holds, else why not (see legacy.ts)."""
    verified = verified or set()
    delegations = []
    for credential in chain:
        shaped = legacy_delegation(credential, now_ms)
        if "refusal" in shaped:
            return shaped["refusal"]
        delegations.append(shaped["delegation"])
    seen: Set[str] = set()
    parent: Optional[Mapping[str, Any]] = None
    for index, delegation in enumerate(delegations):
        if delegation["id"] in seen:
            return f"delegation {delegation['id']} repeats"
        seen.add(delegation["id"])
        issuer = issuer_did(chain[index].get("issuer"))
        if parent is None:
            if delegation.get("parentId"):
                return "the root names a parent"
            if issuer != delegation["issuerDid"]:
                return "the root is not issued by its issuerDid"
        else:
            if delegation.get("parentId") != parent["id"]:
                return f"delegation {delegation['id']} does not name its parent"
            if delegation["issuerDid"] != parent["subjectDid"] or issuer != parent["subjectDid"]:
                return f"delegation {delegation['id']} is not issued by its parent's subject"
            parent_scopes, child_scopes = _scopes(parent), _scopes(delegation)
            widens = (len(child_scopes) > 0) if not parent_scopes else (not child_scopes or any(scope not in parent_scopes for scope in child_scopes))
            if widens:
                return f"delegation {delegation['id']} widens its parent's scopes"
        if not _audience_admits(delegation, server_did):
            return f"delegation {delegation['id']} is for another audience"
        parent = delegation
    for credential in chain:
        if id(credential) in verified:
            continue
        refusal = verify_legacy_proof(credential, documents)
        if refusal is not None:
            return refusal
    return None


Credential = Union[Dict[str, Any], str]
