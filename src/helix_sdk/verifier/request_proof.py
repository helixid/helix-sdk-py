# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The per-request holder-of-key proof ``org.kya-os/proof.v1``
(SPEC-ENTITY-CARD.md section 8): the shape, the ``requestHash`` binding
(``sha-256=:<base64>:`` over the JCS of ``{method, params}`` with
``params._meta`` removed), the covered claims the detached JWS signs, the
RFC 7638 thumbprint and the window rules. Mirrors helix-sdk-js
``verifier/request-proof.ts``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Mapping, Optional

import nacl.exceptions
import nacl.signing

from ..crypto.jcs import canonicalize
from ..crypto.jws import Signer, base64url_decode_strict, base64url_encode

REQUEST_PROOF_META_KEY = "org.kya-os/request-proof"
LEGACY_REQUEST_PROOF_META_KEY = "org.kya-os/proof@1"
DELEGATION_CHAIN_META_KEY = "org.kya-os/delegation-chain"

PROOF_PROFILE_V1 = "org.kya-os/proof.v1"
LEGACY_PROOF_PROFILE = "org.kya-os/proof@1"

MAX_PROOF_TTL_SECONDS = 60
DEFAULT_PROOF_SKEW_SECONDS = 5

_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")
_DID = re.compile(r"did:[a-z0-9]+:.+")
_KID = re.compile(r"did:[a-z0-9]+:.+#.+", re.DOTALL)
_MEMBERS = {"prf", "alg", "did", "kid", "audience", "nonce", "created", "expires", "requestHash", "cnf", "jws", "httpSig"}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def read_request_proof(meta: Any) -> Any:
    """The proof ``_meta`` carries: the canonical key, else the legacy key; None when neither is present."""
    if not isinstance(meta, Mapping):
        return None
    canonical = meta.get(REQUEST_PROOF_META_KEY)
    if canonical is not None:
        return canonical
    return meta.get(LEGACY_REQUEST_PROOF_META_KEY)


def read_carried_chain(meta: Any) -> Any:
    if not isinstance(meta, Mapping):
        return None
    return meta.get(DELEGATION_CHAIN_META_KEY)


def parse_request_proof(value: Any) -> Optional[Dict[str, Any]]:
    """The proof typed, or None when ``value`` is not an org.kya-os/proof.v1 object."""
    if not isinstance(value, Mapping):
        return None
    if any(name not in _MEMBERS for name in value):
        return None
    if value.get("prf") not in (PROOF_PROFILE_V1, LEGACY_PROOF_PROFILE):
        return None
    if value.get("alg") not in ("EdDSA", "ES256"):
        return None
    for name, pattern in (("did", _DID), ("kid", _KID), ("audience", _DID), ("nonce", _BASE64URL)):
        member = value.get(name)
        if not isinstance(member, str) or pattern.fullmatch(member) is None:
            return None
    for name in ("created", "expires"):
        if not _is_int(value.get(name)) or value[name] < 0:
            return None
    for name in ("requestHash", "jws"):
        if not isinstance(value.get(name), str) or not value[name]:
            return None
    if "httpSig" in value and (not isinstance(value["httpSig"], str) or not value["httpSig"]):
        return None
    if "cnf" in value:
        cnf = value["cnf"]
        if not isinstance(cnf, Mapping) or set(cnf) != {"jkt"} or not isinstance(cnf["jkt"], str) or _BASE64URL.fullmatch(cnf["jkt"]) is None:
            return None
    return dict(value)


def covered_request(request: Mapping[str, Any]) -> Dict[str, Any]:
    """Section 8.3: ``{method, params}`` with ``params._meta`` removed; ``{method}`` alone without params."""
    params = request.get("params")
    if "params" not in request or params is None and "params" not in request:
        return {"method": request["method"]}
    if "params" not in request:
        return {"method": request["method"]}
    if not isinstance(params, Mapping) or "_meta" not in params:
        return {"method": request["method"], "params": params}
    rest = {name: member for name, member in params.items() if name != "_meta"}
    return {"method": request["method"], "params": rest}


def request_hash_content_digest(request: Mapping[str, Any]) -> str:
    """``sha-256=:<base64>:`` (RFC 9421 Content-Digest form) over the JCS of the covered request."""
    digest = hashlib.sha256(canonicalize(covered_request(request)).encode("utf-8")).digest()
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


def covered_claims(proof: Mapping[str, Any]) -> Dict[str, Any]:
    claims = {name: proof[name] for name in ("prf", "alg", "did", "kid", "audience", "nonce", "created", "expires", "requestHash")}
    if proof.get("cnf") is not None:
        claims["cnf"] = {"jkt": proof["cnf"]["jkt"]}
    return claims


def covered_claims_bytes(proof: Mapping[str, Any]) -> bytes:
    return canonicalize(covered_claims(proof)).encode("utf-8")


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 thumbprint of an Ed25519 public JWK: SHA-256 of ``{"crv","kty","x"}`` in that order, base64url."""
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":"))
    return base64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def did_of_kid(kid: str) -> str:
    hash_at = kid.find("#")
    return kid if hash_at == -1 else kid[:hash_at]


def verify_detached_jws(proof: Mapping[str, Any], public_key: bytes) -> bool:
    """The detached JWS over the recomputed covered claims, header pinned to the proof's alg and kid."""
    parts = proof["jws"].split(".")
    if len(parts) != 3 or parts[1] != "" or not parts[0]:
        return False
    header_bytes = base64url_decode_strict(parts[0])
    signature = base64url_decode_strict(parts[2])
    if header_bytes is None or signature is None or len(signature) != 64:
        return False
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(header, dict) or header.get("alg") != proof["alg"] or header.get("kid") != proof["kid"]:
        return False
    signing_input = f"{parts[0]}.{base64url_encode(covered_claims_bytes(proof))}".encode("utf-8")
    try:
        nacl.signing.VerifyKey(public_key).verify(signing_input, signature)
        return True
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError, ValueError):
        return False


def window_problems(proof: Mapping[str, Any], now_seconds: int, skew_seconds: int, max_ttl_seconds: int = MAX_PROOF_TTL_SECONDS) -> List[str]:
    problems: List[str] = []
    if proof["expires"] <= proof["created"]:
        problems.append("invalid_window")
    if proof["expires"] - proof["created"] > max_ttl_seconds:
        problems.append("ttl_too_long")
    if proof["created"] > now_seconds + skew_seconds:
        problems.append("created_in_future")
    if proof["expires"] < now_seconds - skew_seconds:
        problems.append("expired")
    return problems


def sign_request_proof(
    request: Mapping[str, Any],
    signer: Signer,
    *,
    audience: str,
    now_ms: Optional[int] = None,
    ttl_seconds: int = MAX_PROOF_TTL_SECONDS,
    nonce: Optional[str] = None,
    cnf_jkt: Optional[str] = None,
    profile: str = PROOF_PROFILE_V1,
) -> Dict[str, Any]:
    """Mints an org.kya-os/proof.v1 for ``request``, signed by ``signer`` as a detached EdDSA JWS (section 8.4)."""
    import time

    created = int((now_ms if now_ms is not None else time.time() * 1000) // 1000)
    fragment = signer.kid[1:] if signer.kid.startswith("#") else signer.kid
    kid = f"{signer.did}#{fragment}"
    claims: Dict[str, Any] = {
        "prf": profile,
        "alg": "EdDSA",
        "did": signer.did,
        "kid": kid,
        "audience": audience,
        "nonce": nonce if nonce is not None else base64url_encode(os.urandom(16)),
        "created": created,
        "expires": created + ttl_seconds,
        "requestHash": request_hash_content_digest(request),
    }
    if cnf_jkt is not None:
        claims["cnf"] = {"jkt": cnf_jkt}
    protected = base64url_encode(json.dumps({"alg": "EdDSA", "kid": kid}, separators=(",", ":")))
    signing_input = f"{protected}.{base64url_encode(covered_claims_bytes(claims))}".encode("utf-8")
    signature = signer.sign(signing_input)
    return {**claims, "jws": f"{protected}..{base64url_encode(signature)}"}
