# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The Ed25519 key a DID names, as raw bytes and as a JWK (KYA-OS story L1-A,
conformance Core L1.6 to L1.8), the same answer helix-core's
src/core/did/resolve.ts gives.

- did:key is decoded locally: multibase ``z``, base58btc, multicodec 0xed01,
  32 bytes. Its document has the shape the KYA-OS reference implementation
  builds: one verification method ``<did>#<multibase>`` with both key forms.
- did:web is fetched over HTTPS (plain HTTP for a loopback host, as
  helix-core does for local stacks); the served document's id must be the DID.

Cross-border rule (stories, rule 4): this module reads the DID and the
document the network serves, nothing else. It never asks a Helix database
anything, and never goes through HelixClient; the fetch is its only seam.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional
from urllib.parse import unquote

from .agent_key import public_key_from_did_key, to_public_key_jwk
from .crypto.jws import base64url_decode_strict, select_assertion_method, verification_method_to_jwk
from .errors import UnsupportedDIDMethodError, ValidationError

DID_WEB_CONTEXTS = (
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
)

FetchJson = Callable[[str], Any]


@dataclass(frozen=True)
class ResolvedKey:
    did: str
    #: Verification-method id, ``<did>#<fragment>``: the ``kid`` a JWS from this key carries.
    kid: str
    #: The 32 raw bytes of the Ed25519 public key.
    raw_key: bytes
    #: The same key as {"kty": "OKP", "crv": "Ed25519", "x": ..., "kid": ...}.
    jwk: Dict[str, Any]
    #: The document the key was read from.
    document: Dict[str, Any]


def did_key_document(did: str) -> Dict[str, Any]:
    """The document a did:key resolves to (L1.6); raises for anything but an Ed25519 did:key."""
    if not isinstance(did, str) or not did.startswith("did:key:"):
        raise UnsupportedDIDMethodError(str(did))
    public_key = public_key_from_did_key(did)
    if public_key is None:
        raise ValidationError(f"{did} is not an Ed25519 did:key whose public key decodes")
    multibase = did[len("did:key:"):]
    method_id = f"{did}#{multibase}"
    return {
        "@context": list(DID_WEB_CONTEXTS),
        "id": did,
        "verificationMethod": [
            {
                "id": method_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyJwk": to_public_key_jwk(public_key),
                "publicKeyMultibase": multibase,
            }
        ],
        "authentication": [method_id],
        "assertionMethod": [method_id],
    }


def _first_assertion_method_id(document: Mapping[str, Any]) -> Optional[str]:
    entries = document.get("assertionMethod")
    first = entries[0] if isinstance(entries, list) and entries else None
    identifier = first if isinstance(first, str) else first.get("id") if isinstance(first, Mapping) else None
    if not isinstance(identifier, str):
        return None
    return f"{document['id']}{identifier}" if identifier.startswith("#") else identifier


def key_from_document(document: Any, did: str, kid: Optional[str] = None) -> ResolvedKey:
    """The key ``kid`` (or the first assertion method) names in ``document``, in both forms."""
    if kid is None:
        wanted = _first_assertion_method_id(document) if isinstance(document, Mapping) else None
    elif kid.startswith("#"):
        wanted = f"{did}{kid}"
    elif "#" in kid:
        wanted = kid
    else:
        wanted = f"{did}#{kid}"
    if wanted is None:
        raise ValidationError(f"DID document {did} lists no assertion method")
    method = select_assertion_method(document, did, wanted)
    jwk = verification_method_to_jwk(method)
    raw_key = base64url_decode_strict(jwk["x"])
    assert raw_key is not None  # verification_method_to_jwk only returns strict base64url of 32 bytes
    return ResolvedKey(
        did=did,
        kid=wanted,
        raw_key=raw_key,
        jwk={"kty": "OKP", "crv": "Ed25519", "x": jwk["x"], "kid": wanted},
        document=dict(document),
    )


def resolve_did_key(did: str, kid: Optional[str] = None) -> ResolvedKey:
    """did:key, decoded locally."""
    return key_from_document(did_key_document(did), did, kid)


def _is_loopback(host: str) -> bool:
    return host.lower() in ("localhost", "127.0.0.1")


def did_web_to_url(did: str) -> str:
    """The URL a did:web document is served at: https, or http for a loopback host
    (``did:web:localhost%3A3000:agents:x``). A port is read only from the encoded
    host: a raw ``did:web:localhost:3000:x`` is host ``localhost``, path ``3000/x``."""
    parts = did.split(":")
    if len(parts) < 3 or parts[0] != "did" or parts[1] != "web" or not parts[2]:
        raise ValidationError(f"Invalid did:web DID: {did}")
    decoded = [unquote(part) for part in parts[2:]]
    host, path = decoded[0], decoded[1:]
    hostname = host.split(":")[0]
    scheme = "http" if _is_loopback(hostname) else "https"
    suffix = "/.well-known/did.json" if not path else "/" + "/".join(path) + "/did.json"
    return f"{scheme}://{host}{suffix}"


def _fetch_json_over_http(url: str) -> Any:
    import requests

    response = requests.get(url, headers={"accept": "application/did+json, application/json"}, timeout=10)
    if not response.ok:
        raise ValidationError(f"did:web resolution failed with HTTP {response.status_code}")
    return response.json()


def resolve_did_web(did: str, kid: Optional[str] = None, fetch_json: Optional[FetchJson] = None) -> ResolvedKey:
    """did:web, fetched over HTTPS; ``fetch_json(url)`` replaces the network when given."""
    if not isinstance(did, str) or not did.startswith("did:web:"):
        raise UnsupportedDIDMethodError(str(did))
    document = (fetch_json or _fetch_json_over_http)(did_web_to_url(did))
    if not isinstance(document, Mapping) or document.get("id") != did or not isinstance(document.get("verificationMethod"), list):
        raise ValidationError(f"Invalid DID document for {did}")
    return key_from_document(document, did, kid)


def resolve_did(did: str, kid: Optional[str] = None, fetch_json: Optional[FetchJson] = None) -> ResolvedKey:
    """{raw_key, jwk, kid} of the key ``did`` names: did:key decoded locally, did:web
    fetched over HTTPS. No database is consulted."""
    if not isinstance(did, str):
        raise ValidationError("did must be a string")
    if did.startswith("did:key:"):
        return resolve_did_key(did, kid)
    if did.startswith("did:web:"):
        return resolve_did_web(did, kid, fetch_json)
    raise UnsupportedDIDMethodError(did)
