# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The DID resolution a verifier's seams are built from (KYA-OS story F-2):
did:key locally, from the DID itself (SPEC.md section 4.3), and did:web from
the document at its well-known URL (section 4.4) over an injected fetch.
Nothing here reads a Helix database (stories rule 4). Mirrors helix-sdk-js
``verifier/resolve.ts``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Mapping, Optional
from urllib.parse import unquote_to_bytes
from urllib.request import Request, urlopen

from ..crypto.jws import base64url_decode_strict, base64url_encode, verification_method_to_jwk
from ..vp_crypto import base58btc_decode

_ED25519_MULTICODEC = b"\xed\x01"
_ED25519_KEY_LENGTH = 32
_MAX_DID_KEY_BASE58_LENGTH = 64

JsonFetch = Callable[[str], Any]


def public_key_of_did_key(did: str) -> Optional[bytes]:
    """The 32 raw bytes of an Ed25519 did:key, or None for any other DID."""
    if not did.startswith("did:key:z6Mk"):
        return None
    encoded = did[len("did:key:z"):]
    if len(encoded) > _MAX_DID_KEY_BASE58_LENGTH:
        return None
    try:
        raw = base58btc_decode(encoded)
    except Exception:  # noqa: BLE001 - not base58
        return None
    if len(raw) != len(_ED25519_MULTICODEC) + _ED25519_KEY_LENGTH or raw[:2] != _ED25519_MULTICODEC:
        return None
    return raw[2:]


def did_key_document(did: str) -> Optional[Dict[str, Any]]:
    """The DID document an Ed25519 did:key resolves to, or None when ``did`` is not one."""
    public_key = public_key_of_did_key(did)
    if public_key is None:
        return None
    fragment = did[len("did:key:"):]
    method_id = f"{did}#{fragment}"
    method = {
        "id": method_id,
        "type": "Ed25519VerificationKey2020",
        "controller": did,
        "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": base64url_encode(public_key)},
        "publicKeyMultibase": fragment,
    }
    return {"id": did, "verificationMethod": [method], "authentication": [method_id], "assertionMethod": [method_id]}


def _decode_part(part: str) -> Optional[str]:
    """One percent-decode of a did:web part; None when a ``%`` is not an escape or the bytes are not UTF-8."""
    if "%" not in part:
        return part
    if re.search(r"%(?![0-9A-Fa-f]{2})", part):
        return None
    try:
        return unquote_to_bytes(part).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _did_web_host(label: str) -> Optional[str]:
    """A did:web host that is a host and nothing more, with an optional port, or None."""
    host = _decode_part(label)
    if host is None or not host or re.search(r"[@/\\?#%\s]", host) or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in host):
        return None
    after_literal = host[host.find("]") + 1:] if host.startswith("[") else host
    return host if after_literal.count(":") <= 1 else None


def did_web_document_url(did: str) -> Optional[str]:
    """The HTTPS URL of a did:web document, or None when ``did`` is not a did:web that names one."""
    if not did.startswith("did:web:"):
        return None
    parts = did[len("did:web:"):].split(":")
    host = _did_web_host(parts[0])
    if host is None:
        return None
    path: List[str] = []
    for part in parts[1:]:
        segment = _decode_part(part)
        if segment is None or segment in ("", ".", "..") or re.search(r"[/\\?#%]", segment):
            return None
        path.append(segment)
    if not path:
        return f"https://{host}/.well-known/did.json"
    return f"https://{host}/{'/'.join(path)}/did.json"


def _default_fetch(url: str) -> Any:
    if not url.startswith("https://"):
        raise ValueError("only https: URLs are fetched")
    with urlopen(Request(url, headers={"accept": "application/json"}), timeout=5) as response:  # noqa: S310 - https only
        return json.loads(response.read().decode("utf-8"))


def create_did_resolver(fetch_json: Optional[JsonFetch] = None, rewrite_url: Optional[Callable[[str], str]] = None) -> Callable[[str], Optional[Mapping[str, Any]]]:
    """A ``resolve_did`` seam: did:key offline, did:web through ``fetch_json`` (``url -> parsed JSON``)."""
    do_fetch = fetch_json or _default_fetch

    def resolve(did: str) -> Optional[Mapping[str, Any]]:
        if did.startswith("did:key:"):
            return did_key_document(did)
        url = did_web_document_url(did)
        if url is None:
            return None
        document = do_fetch(rewrite_url(url) if rewrite_url else url)
        if not isinstance(document, Mapping) or document.get("id") != did:
            return None
        return document

    return resolve


def ed25519_keys_of(document: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Every Ed25519 key a DID document publishes under ``verificationMethod``, as public JWKs with their ``kid``."""
    keys: List[Dict[str, Any]] = []
    methods = document.get("verificationMethod")
    for method in methods if isinstance(methods, list) else []:
        if not isinstance(method, Mapping) or not isinstance(method.get("id"), str):
            continue
        try:
            jwk = verification_method_to_jwk(method)
        except Exception:  # noqa: BLE001 - a method without a usable key publishes nothing here
            continue
        raw = base64url_decode_strict(jwk["x"])
        if raw is None or len(raw) != 32:
            continue
        kid = f"{document.get('id')}{method['id']}" if method["id"].startswith("#") else method["id"]
        keys.append({"kty": "OKP", "crv": "Ed25519", "x": jwk["x"], "kid": kid})
    return keys


def create_did_keys_resolver(resolve_did: Callable[[str], Optional[Mapping[str, Any]]]) -> Callable[[str], List[Dict[str, Any]]]:
    """A ``resolve_did_keys`` seam over a ``resolve_did`` seam."""

    def resolve_keys(did: str) -> List[Dict[str, Any]]:
        document = resolve_did(did)
        if document is None:
            raise LookupError(f"DID {did} did not resolve")
        return ed25519_keys_of(document)

    return resolve_keys
