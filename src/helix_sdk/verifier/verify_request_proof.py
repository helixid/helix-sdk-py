# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Verification of the per-request holder-of-key proof ``org.kya-os/proof.v1``
(KYA-OS story C-C, SPEC-ENTITY-CARD.md section 11.2), in the exact order the
spec gives, stopping at the first broken binding. Mirrors helix-sdk-js
``verifier/verify-request-proof.ts``: same steps, same reason codes.

 1. schema (``malformed_proof``);
 2. ``kid`` names a key of ``did`` (``kid_did_mismatch``);
 3. the signing key resolved from ``did``'s document (``key_unresolvable``);
 4. its RFC 7638 thumbprint is among the keys the DID publishes
    (``kid_not_in_did_document``; no ``resolve_did_keys`` seam fails closed
    with ``did_membership_unverifiable``);
 5. ``audience`` is this verifier (``audience_mismatch``);
 6. ``requestHash`` recomputes over the request (``request_hash_mismatch``);
 7. the window, with +/-5 s skew by default (``invalid_window``,
    ``ttl_too_long``, ``created_in_future``, ``expired``);
 8. the nonce is unseen for ``did`` in the replay store (``nonce_replayed``;
    no store fails closed with ``nonce_seam_missing``);
 9. the detached JWS over the recomputed covered claims (``invalid_signature``);
10. the ``cnf`` fusion (section 8.6): ``L3`` when the token's ``cnf.jkt``, the
    proof's and the key's thumbprint agree, ``L3-minus`` without a token ``cnf``.

A proof under the legacy carrier key ``org.kya-os/proof@1``, or with the
legacy ``prf``, verifies the same way (``read_request_proof``,
``parse_request_proof``). Pure: everything external comes through the seams,
and a missing seam is refused at the step that needs it, never skipped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from ..crypto.jws import base64url_decode_strict, select_assertion_method, verification_method_to_jwk
from ..errors import InvalidJWSError
from .codes import ReasonCodes
from .request_proof import (
    DEFAULT_PROOF_SKEW_SECONDS,
    MAX_PROOF_TTL_SECONDS,
    did_of_kid,
    jwk_thumbprint,
    parse_request_proof,
    request_hash_content_digest,
    verify_detached_jws,
    window_problems,
)

CNF_PRESENT_BUT_TOKEN_UNFUSED = "cnf_present_but_token_unfused"
"""The non-fatal diagnostic of section 8.6: the proof carries ``cnf`` but no token ``cnf`` was given to fuse it with."""

PROOF_ASSURANCES = ("L3", "L3-minus")
"""``L3`` on a full ``cnf`` fusion, ``L3-minus`` without a token ``cnf`` (section 8.6)."""


@dataclass
class RequestProofSeams:
    """The seams section 11.2 reads: the caller's DID document and keys, the replay store and the time.
    :class:`helix_sdk.verifier.VerifierSeams` has the same members and may be passed instead."""

    resolve_did: Optional[Callable[[str], Any]] = None
    resolve_did_keys: Optional[Callable[[str], Sequence[Mapping[str, Any]]]] = None
    nonce_store: Any = None
    """``insert(nonce, did, expires_at_ms) -> bool``: one atomic conditional insert."""
    clock: Optional[Callable[[], int]] = None
    """Milliseconds since the epoch."""


@dataclass
class RequestProofOptions:
    expected_audience: str
    """This verifier's own DID: the proof's ``audience`` must equal it."""
    skew_seconds: Optional[int] = None
    """Clock skew on the window, in seconds; default 5."""
    max_ttl_seconds: Optional[int] = None
    """The longest lifetime accepted, in seconds; default 60."""
    token_cnf_jkt: Optional[str] = None
    """The access token's RFC 9449 ``cnf.jkt``; absent means L3-minus."""


@dataclass
class RequestProofVerification:
    ok: bool
    reasons: List[str]
    """The reason codes of the step that failed; empty iff ``ok``."""
    messages: List[str]
    did: Optional[str] = None
    """The accountable principal, once every binding held."""
    assurance: Optional[str] = None
    proof: Optional[Dict[str, Any]] = None
    """The parsed proof, once step 1 passed."""
    warnings: List[str] = field(default_factory=list)
    """Non-fatal diagnostics: ``cnf_present_but_token_unfused`` (section 8.6)."""


def _refused_at(code: str, message: str, proof: Optional[Dict[str, Any]] = None) -> RequestProofVerification:
    return RequestProofVerification(False, [code], [message], proof=proof)


def verify_request_proof(
    value: Any,
    request: Optional[Mapping[str, Any]],
    seams: Any,
    options: RequestProofOptions,
) -> RequestProofVerification:
    """Verifies one request proof against ``request`` in the section 11.2 order.
    Never raises for a bad proof or a failing seam: each is a reason code."""
    clock = getattr(seams, "clock", None)
    if not callable(clock):
        return _refused_at(ReasonCodes.CLOCK_SEAM_MISSING, "no clock seam: the window cannot be checked")
    if not isinstance(options.expected_audience, str) or not options.expected_audience.startswith("did:"):
        return _refused_at(ReasonCodes.CONFIGURATION_ERROR, "expectedAudience must be this verifier's DID")
    if value is None:
        return _refused_at(ReasonCodes.PROOF_MISSING, "the request carries no org.kya-os/request-proof")

    # 1. Schema.
    proof = parse_request_proof(value)
    if proof is None:
        return _refused_at(ReasonCodes.MALFORMED_PROOF, "the request proof is not an org.kya-os/proof.v1 object")

    # 2. kid <-> did.
    if did_of_kid(proof["kid"]) != proof["did"]:
        return _refused_at(ReasonCodes.KID_DID_MISMATCH, "kid does not belong to did", proof)

    # 3. The signing key, from did's document (CID section 3.3 assertion rule); only EdDSA keys are read.
    resolve_did = getattr(seams, "resolve_did", None)
    if not callable(resolve_did):
        return _refused_at(ReasonCodes.DID_RESOLVER_MISSING, "no resolve_did seam: the signing key cannot be read", proof)
    if proof["alg"] != "EdDSA":
        return _refused_at(ReasonCodes.ALG_UNSUPPORTED, f"proof alg {proof['alg']} is not EdDSA", proof)
    try:
        document = resolve_did(proof["did"])
    except Exception as exc:  # noqa: BLE001 - a resolver that throws leaves the document unread
        return _refused_at(ReasonCodes.DID_UNRESOLVED, f"could not resolve {proof['did']}: {exc}", proof)
    if document is None:
        return _refused_at(ReasonCodes.DID_UNRESOLVED, f"{proof['did']} did not resolve", proof)
    try:
        jwk = verification_method_to_jwk(select_assertion_method(document, proof["did"], proof["kid"]))
    except InvalidJWSError as exc:
        return _refused_at(ReasonCodes.KEY_UNRESOLVABLE, f"{exc.reason}: {exc}", proof)
    public_key = base64url_decode_strict(jwk["x"])
    key_jwk = {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"], "kid": proof["kid"]}

    # 4. DID membership: the key's RFC 7638 thumbprint is one the DID publishes.
    resolve_did_keys = getattr(seams, "resolve_did_keys", None)
    if not callable(resolve_did_keys):
        return _refused_at(ReasonCodes.DID_MEMBERSHIP_UNVERIFIABLE, "no resolve_did_keys seam: the key cannot be shown to belong to the DID", proof)
    try:
        published = list(resolve_did_keys(proof["did"]))
    except Exception as exc:  # noqa: BLE001
        return _refused_at(ReasonCodes.DID_KEYS_UNRESOLVABLE, f"could not list the keys of {proof['did']}: {exc}", proof)
    key_jkt = jwk_thumbprint(key_jwk)
    listed = False
    for candidate in published:
        try:
            listed = listed or jwk_thumbprint(candidate) == key_jkt
        except Exception:  # noqa: BLE001 - a key that is no JWK has no thumbprint
            continue
    if not listed:
        return _refused_at(ReasonCodes.KID_NOT_IN_DID_DOCUMENT, f"{proof['kid']} is not a key {proof['did']} publishes", proof)

    # 5. Audience.
    if proof["audience"] != options.expected_audience:
        return _refused_at(ReasonCodes.AUDIENCE_MISMATCH, f"audience {proof['audience']} is not this verifier ({options.expected_audience})", proof)

    # 6. requestHash, recomputed with params._meta stripped (section 8.3).
    if request is None:
        return _refused_at(ReasonCodes.REQUEST_MISSING, "no request to recompute requestHash from", proof)
    try:
        computed: Optional[str] = request_hash_content_digest(request)
    except Exception:  # noqa: BLE001 - a request with no canonical form hashes to nothing
        computed = None
    if computed != proof["requestHash"]:
        return _refused_at(ReasonCodes.REQUEST_HASH_MISMATCH, "requestHash does not recompute from the request", proof)

    # 7. Window: every way it fails, as one step.
    skew_seconds = options.skew_seconds if options.skew_seconds is not None else DEFAULT_PROOF_SKEW_SECONDS
    max_ttl = options.max_ttl_seconds if options.max_ttl_seconds is not None else MAX_PROOF_TTL_SECONDS
    problems = window_problems(proof, clock() // 1000, skew_seconds, max_ttl)
    if problems:
        return RequestProofVerification(False, list(problems), [f"proof window: {problem}" for problem in problems], proof=proof)

    # 8. Replay: the nonce unseen for did, kept until expires + skew + 1 s.
    store = getattr(seams, "nonce_store", None)
    if store is None or not callable(getattr(store, "insert", None)):
        return _refused_at(ReasonCodes.NONCE_SEAM_MISSING, "no nonce_store seam: there is no replay defense to run", proof)
    try:
        if not store.insert(proof["nonce"], proof["did"], (proof["expires"] + skew_seconds + 1) * 1000):
            return _refused_at(ReasonCodes.NONCE_REPLAYED, f"nonce {proof['nonce']} was already used by {proof['did']}", proof)
    except Exception as exc:  # noqa: BLE001 - a store that cannot answer fails closed
        return _refused_at(ReasonCodes.NONCE_STORE_UNAVAILABLE, f"the nonce store could not answer: {exc}", proof)

    # 9. The detached JWS over the recomputed covered claims.
    if public_key is None or not verify_detached_jws(proof, public_key):
        return _refused_at(ReasonCodes.INVALID_SIGNATURE, "the detached JWS does not verify over the covered claims", proof)

    # 10. cnf fusion.
    warnings: List[str] = []
    cnf = proof.get("cnf")
    if cnf is not None and cnf["jkt"] != key_jkt:
        return _refused_at(ReasonCodes.CNF_KEY_MISMATCH, "cnf.jkt is not the thumbprint of the signing key", proof)
    if options.token_cnf_jkt is None:
        if cnf is not None:
            warnings.append(CNF_PRESENT_BUT_TOKEN_UNFUSED)
        assurance = "L3-minus"
    elif cnf is None:
        return _refused_at(ReasonCodes.CNF_REQUIRED_BY_TOKEN, "the token is sender-constrained but the proof carries no cnf", proof)
    elif cnf["jkt"] != options.token_cnf_jkt:
        return _refused_at(ReasonCodes.CNF_TOKEN_MISMATCH, "cnf.jkt is not the token cnf.jkt", proof)
    else:
        assurance = "L3"
    return RequestProofVerification(True, [], [], did=proof["did"], assurance=assurance, proof=proof, warnings=warnings)
