# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS detached response proofs, the client's side (story L2-A; conformance
L2.11 to L2.13, L2.17), mirroring helix-sdk-js's core/kyaos/response-proof.ts
and hash.ts.

A proof is ``{"jws", "meta"}``: ``meta`` is the ProofMeta in the clear and
``jws`` an EdDSA compact JWS whose payload is the RFC 8785 canonical JSON of
the same facts as claims (``iss`` and ``sub`` the signer's DID, ``aud`` the
audience, the rest by name). ``verify_detached_proof`` checks the signature
against the signer's key or DID document, that the payload is exactly what
``meta`` says, that ``ts`` is fresh and that ``responseHash`` is present
exactly when the outcome carries a response. ``verify_response_proof`` then
recomputes ``requestHash`` from the request the client sent and
``responseHash`` from the result it received, so a swapped body fails.

Reads ``_meta["org.kya-os/response-proof"]`` and, through 1.x, the prior keys
``org.kya-os/proof`` and bare ``proof``; every other ``_meta`` key is ignored
(L2.17). Cross-border rule: the only input besides the proof, request and
response is the DID document the injected resolver returns.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

from .crypto.jcs import canonicalize, hash_json
from .crypto.jws import verify_jws, verify_jws_by_kid
from .errors import ResponseProofError

RESPONSE_PROOF_META_KEY = "org.kya-os/response-proof"
LEGACY_RESPONSE_PROOF_META_KEYS = ("org.kya-os/proof", "proof")
REQUEST_PROOF_META_KEY = "org.kya-os/request-proof"
RESPONSE_PROOF_ENVELOPE_PROFILE = "org.kya-os/response-proof.envelope"
CONTROL_ARGUMENT_PREFIX = "_kyaos"
PROOF_OUTCOMES = ("allowed", "denied", "step_up_required", "needs_authorization")
DEFAULT_CLOCK_SKEW_SECONDS = 120


class ProofReasons:
    """Why a response proof was refused; the same strings as helix-sdk-js."""

    MISSING = "proof_missing"
    MALFORMED = "proof_malformed"
    META_INVALID = "proof_meta_invalid"
    PROFILE_UNKNOWN = "proof_profile_unknown"
    SIGNER_MISMATCH = "proof_signer_mismatch"
    PAYLOAD_MISMATCH = "proof_payload_mismatch"
    TIMESTAMP_SKEW = "proof_timestamp_skew"
    RESPONSE_HASH_MISSING = "response_hash_missing"
    RESPONSE_HASH_UNEXPECTED = "response_hash_unexpected"
    REQUEST_HASH_MISMATCH = "request_hash_mismatch"
    RESPONSE_HASH_MISMATCH = "response_hash_mismatch"


DidResolver = Callable[[str], Optional[Mapping[str, Any]]]

_SHA256 = re.compile(r"^sha256:[a-f0-9]{64}$")
_DID = re.compile(r"^did:[a-z0-9]+:.+$")
_META_MEMBERS = {
    "did", "kid", "ts", "nonce", "audience", "sessionId", "requestHash", "responseHash",
    "outcome", "reason", "clientDid", "scopeId", "delegationRef", "delegationChainDigest", "prf",
}
_OPTIONAL_STRINGS = ("reason", "clientDid", "scopeId", "delegationRef")


def _refuse(reason: str, message: str) -> None:
    raise ResponseProofError(reason, message)


def _is_record(value: Any) -> bool:
    return isinstance(value, Mapping)


# ── hashes (SPEC 7.3) ─────────────────────────────────────────────────────────


def is_control_argument(name: str) -> bool:
    return name.startswith(CONTROL_ARGUMENT_PREFIX)


def strip_control_arguments(args: Mapping[str, Any]) -> Dict[str, Any]:
    """``args`` without its ``_kyaos*`` members."""
    return {name: value for name, value in args.items() if not is_control_argument(name)}


def wire_json(value: Any) -> Any:
    """The JSON value ``value`` serialises to: what the other side receives."""
    return json.loads(json.dumps(value))


def covered_request(request: Mapping[str, Any]) -> Dict[str, Any]:
    """The covered request: method and params minus ``_meta``, arguments minus ``_kyaos*``; no params where there are none."""
    covered: Dict[str, Any] = {"method": request["method"]}
    params = request.get("params")
    if params is not None:
        params = dict(params)
        params.pop("_meta", None)
        if request["method"] == "tools/call":
            args = params.get("arguments")
            params["arguments"] = strip_control_arguments(args if _is_record(args) else {})
        covered["params"] = params
    return covered


def hash_request(request: Mapping[str, Any]) -> str:
    """``sha256:<hex>`` of the covered request."""
    return hash_json(covered_request(wire_json(request)))


def covered_response(result: Any, profile: Optional[str] = None) -> Any:
    """The response value a proof's responseHash covers under ``profile``: as is, or minus top-level ``_meta`` (envelope)."""
    wire = wire_json(result)
    if profile == RESPONSE_PROOF_ENVELOPE_PROFILE and _is_record(wire):
        return {name: value for name, value in wire.items() if name != "_meta"}
    return wire


def hash_response(result: Any, profile: Optional[str] = None) -> str:
    """``sha256:<hex>`` of the covered response."""
    return hash_json(covered_response(result, profile))


# ── proof meta and claims ─────────────────────────────────────────────────────


def outcome_has_response(outcome: str) -> bool:
    """Whether proofs with this outcome carry a response body, and so a responseHash."""
    return outcome in ("allowed", "needs_authorization")


def proof_claims(meta: Mapping[str, Any]) -> Dict[str, Any]:
    """The claims a server signs for ``meta``: ``iss``/``sub`` the DID, ``aud`` the audience, the rest by name; ``kid`` is header-only."""
    claims: Dict[str, Any] = {}
    for name, value in meta.items():
        if value is None or name == "kid":
            continue
        if name == "did":
            claims["iss"] = value
            claims["sub"] = value
        elif name == "audience":
            claims["aud"] = value
        else:
            claims[name] = value
    return claims


def proof_payload(meta: Mapping[str, Any]) -> str:
    """The exact payload text a proof over ``meta`` is signed over: canonical JSON of its claims."""
    return canonicalize(proof_claims(meta))


def validate_proof_meta(value: Any) -> Dict[str, Any]:
    """Checks ``value`` against the ProofMeta schema and returns it as a dict."""
    if not _is_record(value):
        _refuse(ProofReasons.META_INVALID, "proof meta must be an object")
    meta = dict(value)
    for name in meta:
        if name not in _META_MEMBERS:
            _refuse(ProofReasons.META_INVALID, f"proof meta has an unknown member {name}")
    did = meta.get("did")
    if not isinstance(did, str) or not _DID.match(did):
        _refuse(ProofReasons.META_INVALID, "proof meta did must be a DID")
    kid = meta.get("kid")
    if not isinstance(kid, str) or kid == "":
        _refuse(ProofReasons.META_INVALID, "proof meta kid must be a non-empty string")
    ts = meta.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, int) or ts < 1:
        _refuse(ProofReasons.META_INVALID, "proof meta ts must be a positive integer")
    for name in ("nonce", "audience", "sessionId"):
        member = meta.get(name)
        if not isinstance(member, str) or member == "":
            _refuse(ProofReasons.META_INVALID, f"proof meta {name} must be a non-empty string")
    request_hash = meta.get("requestHash")
    if not isinstance(request_hash, str) or not _SHA256.match(request_hash):
        _refuse(ProofReasons.META_INVALID, "proof meta requestHash must be sha256:<hex>")
    for name in ("responseHash", "delegationChainDigest"):
        digest = meta.get(name)
        if digest is not None and (not isinstance(digest, str) or not _SHA256.match(digest)):
            _refuse(ProofReasons.META_INVALID, f"proof meta {name} must be sha256:<hex>")
    outcome = meta.get("outcome")
    if outcome is not None and outcome not in PROOF_OUTCOMES:
        _refuse(ProofReasons.META_INVALID, f"proof meta outcome must be one of {', '.join(PROOF_OUTCOMES)}")
    for name in _OPTIONAL_STRINGS:
        if meta.get(name) is not None and not isinstance(meta[name], str):
            _refuse(ProofReasons.META_INVALID, f"proof meta {name} must be a string")
    prf = meta.get("prf")
    if prf is not None and prf != RESPONSE_PROOF_ENVELOPE_PROFILE:
        # An unknown profile is never verified under weaker, body-only semantics.
        _refuse(ProofReasons.PROFILE_UNKNOWN, f"proof profile {prf!r} is not known")
    return meta


def read_response_proof(meta: Any) -> Optional[Dict[str, Any]]:
    """The response proof in a result's ``_meta``, or None. Current key first, then the 1.x keys; other members are ignored."""
    if not _is_record(meta):
        return None
    for key in (RESPONSE_PROOF_META_KEY,) + LEGACY_RESPONSE_PROOF_META_KEYS:
        candidate = meta.get(key)
        if candidate is None:
            continue
        if not _is_record(candidate) or not isinstance(candidate.get("jws"), str) or not _is_record(candidate.get("meta")):
            _refuse(ProofReasons.MALFORMED, f'_meta["{key}"] must be {{jws, meta}}')
        for name in candidate:
            if name not in ("jws", "meta"):
                _refuse(ProofReasons.MALFORMED, f'_meta["{key}"] has an unknown member {name}')
        return {"jws": candidate["jws"], "meta": validate_proof_meta(candidate["meta"])}
    return None


# ── verification ──────────────────────────────────────────────────────────────


@dataclass
class VerifiedProof:
    meta: Dict[str, Any]
    outcome: str
    did: str
    kid: str
    profile: Optional[str]
    request_hash: Optional[str] = None
    response_hash: Optional[str] = None


def verify_detached_proof(
    proof: Any,
    *,
    jwk: Optional[Mapping[str, Any]] = None,
    resolve_did: Optional[DidResolver] = None,
    now: Optional[float] = None,
    skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    expected_did: Optional[str] = None,
) -> VerifiedProof:
    """Verifies a detached proof on its own against one Ed25519 public JWK or
    the assertion method ``meta.kid`` names in the resolved DID document.
    ``now`` is Unix seconds (default ``time.time()``). Raises
    ResponseProofError, or InvalidJWSError from the JWS layer."""
    if (jwk is None) == (resolve_did is None):
        raise ValueError("verify_detached_proof: give exactly one of jwk or resolve_did")
    if not _is_record(proof) or not isinstance(proof.get("jws"), str):
        _refuse(ProofReasons.MALFORMED, "proof must be {jws, meta}")
    meta = validate_proof_meta(proof.get("meta"))
    if expected_did is not None and expected_did != meta["did"]:
        _refuse(ProofReasons.SIGNER_MISMATCH, f"proof is signed by {meta['did']}, not {expected_did}")
    if jwk is not None:
        verification = verify_jws(proof["jws"], jwk, expected_kid=meta["kid"], expected_did=meta["did"])
    else:
        verification = verify_jws_by_kid(proof["jws"], resolve_did, expected_kid=meta["kid"], expected_did=meta["did"])  # type: ignore[arg-type]
    if verification.payload_bytes.decode("utf-8", errors="replace") != proof_payload(meta):
        _refuse(ProofReasons.PAYLOAD_MISMATCH, "the signed payload is not the canonical form of the proof meta")
    now_seconds = int(time.time() if now is None else now)
    if abs(now_seconds - meta["ts"]) > skew_seconds:
        _refuse(ProofReasons.TIMESTAMP_SKEW, f"proof ts {meta['ts']} is outside the skew window around {now_seconds}")
    outcome = meta.get("outcome") or "allowed"
    if outcome_has_response(outcome) and meta.get("responseHash") is None:
        _refuse(ProofReasons.RESPONSE_HASH_MISSING, f"a {outcome} proof must carry responseHash")
    if not outcome_has_response(outcome) and meta.get("responseHash") is not None:
        _refuse(ProofReasons.RESPONSE_HASH_UNEXPECTED, f"a {outcome} proof carries no response and so no responseHash")
    return VerifiedProof(meta=meta, outcome=outcome, did=verification.did, kid=verification.kid, profile=meta.get("prf"))


def verify_response_proof(
    response: Any,
    server_did: str,
    resolve_did: DidResolver,
    *,
    request: Mapping[str, Any],
    proof: Optional[Mapping[str, Any]] = None,
    now: Optional[float] = None,
    skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> VerifiedProof:
    """Verifies the proof on ``response`` (or ``proof``, given out of band)
    against ``server_did``, recomputing requestHash from ``request`` (a
    JSON-RPC ``{method, params}``) and responseHash from ``response``."""
    found = dict(proof) if proof is not None else read_response_proof(response.get("_meta") if _is_record(response) else None)
    if found is None:
        _refuse(ProofReasons.MISSING, f'the response carries no _meta["{RESPONSE_PROOF_META_KEY}"]')
    verified = verify_detached_proof(found, resolve_did=resolve_did, now=now, skew_seconds=skew_seconds, expected_did=server_did)
    verified.request_hash = hash_request(request)
    if verified.request_hash != verified.meta["requestHash"]:
        _refuse(ProofReasons.REQUEST_HASH_MISMATCH, "the proof does not bind the request that was sent")
    if verified.meta.get("responseHash") is not None:
        verified.response_hash = hash_response(response, verified.profile)
        if verified.response_hash != verified.meta["responseHash"]:
            _refuse(ProofReasons.RESPONSE_HASH_MISMATCH, "the proof does not bind the response that was received")
    return verified
