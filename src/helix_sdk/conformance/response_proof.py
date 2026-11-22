# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The legacy session-bound response proof (SPEC.md sections 7.3, 7.4) read for
the ``signed-proof`` vector category (KYA-OS story F-2): its form, its signer,
its time, its JWS over the payload rebuilt from ``meta``, and the request and
response it binds. helix-sdk-js reads it with story L2-A's
``verifyDetachedProof``; story L2-A's Python ``response_proof`` module is not
on this branch's base, so the reading the vectors need is held here.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, Mapping, Optional

from ..crypto.jcs import canonicalize, hash_json
from ..crypto.jws import base64url_decode_strict, base64url_encode
from .delegation_binding import read_json
from .legacy import _verifies

ENVELOPE_PROFILE = "org.kya-os/response-proof.envelope"
OUTCOMES = ("allowed", "denied", "step_up_required", "needs_authorization")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REQUIRED = ("did", "kid", "nonce", "audience", "sessionId")
_OPTIONAL_CLAIMS = ("scopeId", "delegationRef", "delegationChainDigest", "clientDid", "outcome", "reason", "prf")


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def proof_of_its_form(proof: Any) -> bool:
    """A detached proof of the form schemas/detached-proof.json gives one."""
    if not isinstance(proof, dict) or not isinstance(proof.get("jws"), str) or not proof["jws"]:
        return False
    meta = proof.get("meta")
    if not isinstance(meta, dict) or not all(isinstance(meta.get(name), str) and meta[name] for name in _REQUIRED):
        return False
    ts = meta.get("ts")
    if not _number(ts) or not float(ts).is_integer() or ts <= 0 or not _digest(meta.get("requestHash")):
        return False
    return (
        all(name not in meta or _digest(meta[name]) for name in ("responseHash", "delegationChainDigest"))
        and all(name not in meta or isinstance(meta[name], str) for name in ("scopeId", "delegationRef", "clientDid", "reason"))
        and ("outcome" not in meta or meta["outcome"] in OUTCOMES)
        and ("prf" not in meta or meta["prf"] == ENVELOPE_PROFILE)
    )


def signed_payload(meta: Mapping[str, Any]) -> bytes:
    """The payload a proof signs, rebuilt from its ``meta`` (section 7.4)."""
    payload: Dict[str, Any] = {"aud": meta["audience"], "sub": meta["did"], "iss": meta["did"], "requestHash": meta["requestHash"]}
    if "responseHash" in meta:
        payload["responseHash"] = meta["responseHash"]
    payload.update(ts=meta["ts"], nonce=meta["nonce"], sessionId=meta["sessionId"])
    payload.update((name, meta[name]) for name in _OPTIONAL_CLAIMS if meta.get(name))
    return canonicalize(payload).encode("utf-8")


def _segment_json(segment: str) -> Any:
    data = base64url_decode_strict(segment)
    if data is None:
        raise ValueError("not a strict base64url segment")
    return read_json(data.decode("utf-8"))


def proof_verifies(proof: Any, jwk: Any, now: Any, skew: Any) -> Optional[str]:
    """None when the proof's form, signer, time and signature hold, else why not."""
    if not proof_of_its_form(proof):
        return "not a detached proof of its form"
    meta = proof["meta"]
    kid = meta["kid"]
    if kid.startswith("did:") and kid.split("#")[0] != meta["did"]:
        return "kid names a key of another DID"
    if not _number(now) or not _number(skew) or not math.isfinite(float(skew)):
        return "now and skewSeconds are numbers"
    if not abs(float(now) - float(meta["ts"])) <= float(skew):
        return "ts is outside the skew"
    segments = proof["jws"].split(".")
    if len(segments) != 3:
        return "a JWS is three segments"
    try:
        header = _segment_json(segments[0])
        if segments[1]:
            _segment_json(segments[1])
        signature = base64url_decode_strict(segments[2])
        if signature is None:
            return "signature is not strict base64url"
        if not isinstance(header, dict) or header.get("alg") != "EdDSA" or header.get("kid") != kid:
            return "the header does not name EdDSA and meta.kid"
        if not isinstance(jwk, dict) or (jwk.get("kty"), jwk.get("crv"), jwk.get("kid")) != ("OKP", "Ed25519", kid) or not isinstance(jwk.get("x"), str):
            return "not the Ed25519 JWK of the key the proof names"
        key = base64url_decode_strict(jwk["x"])
        if key is None or len(key) != 32:
            return "the key is not 32 bytes"
    except (ValueError, UnicodeDecodeError):
        return "a segment does not read as base64url, UTF-8 or JSON"
    rebuilt = base64url_encode(signed_payload(meta))
    signed = [rebuilt] + ([segments[1]] if segments[1] not in ("", rebuilt) else [])
    if not all(_verifies(signature, (segments[0] + "." + payload).encode("utf-8"), key) for payload in signed):
        return "the signature does not verify over the claims"
    outcome = meta.get("outcome") or "allowed"
    has_response = outcome in ("allowed", "needs_authorization")
    if has_response != ("responseHash" in meta):
        return "responseHash is present exactly when the outcome carries a response"
    return None


def _without(members: Mapping[str, Any], drop: str) -> Dict[str, Any]:
    return {key: value for key, value in members.items() if key != drop}


def request_hash(request: Mapping[str, Any]) -> str:
    """Section 7.3: ``sha256:<hex>`` over JCS of the covered request (``params._meta`` and ``_kyaos*`` arguments removed)."""
    covered: Dict[str, Any] = {"method": request["method"]}
    params = request.get("params")
    if params is not None:
        params = dict(params) if isinstance(params, dict) else params
        if isinstance(params, dict):
            params.pop("_meta", None)
            if request["method"] == "tools/call":
                arguments = params.get("arguments")
                params["arguments"] = {k: v for k, v in (arguments if isinstance(arguments, dict) else {}).items() if not k.startswith("_kyaos")}
        covered["params"] = params
    return hash_json(covered)


def response_hash(response: Any, profile: Any) -> str:
    if not isinstance(response, dict) or "data" not in response:
        raise ValueError("a response is an object with data")
    data = response["data"]
    if profile == ENVELOPE_PROFILE and isinstance(data, dict):
        data = _without(data, "_meta")
    return hash_json(data)
