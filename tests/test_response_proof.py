# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story L2-A: the client side of the detached response proof
(L2.11 to L2.13, L2.17), the same checks as helix-sdk-js's
core/kyaos/response-proof.ts, plus the signed-proof vectors of the vendored
conformance suite read from the sibling helix-core checkout (or
HELIX_CORE_FIXTURES_DIR)."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from helix_sdk import response_proof as rp
from helix_sdk.crypto.jcs import canonicalize, hash_json
from helix_sdk.crypto.jws import EnvSigner, public_key_hex_to_jwk, sign_jws
from helix_sdk.did import build_did_document
from helix_sdk.errors import InvalidJWSError, ResponseProofError
from helix_sdk.keys import generate_key_pair

SERVER = "did:web:orders.example"
NOW = 1_750_000_000
KEYS = generate_key_pair()
OTHER_KEYS = generate_key_pair()
SIGNER = EnvSigner(SERVER, env_var="K", env={"K": KEYS.private_key})
DOCUMENT = build_did_document(SERVER, KEYS.public_key)
JWK = public_key_hex_to_jwk(KEYS.public_key, f"{SERVER}#key-1")


def resolve_did(did: str) -> Optional[Dict[str, Any]]:
    return DOCUMENT if did == SERVER else None


REQUEST = {"method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": "ORD-1001", "_kyaos_session": "kyaos_x"}, "_meta": {"traceparent": "t"}}}
BODY = {"content": [{"type": "text", "text": '{"id":"ORD-1001"}'}], "structuredContent": {"id": "ORD-1001"}}
EMPTY_ARGS = "sha256:5057521f310b536837b619f0ac040ef8064f8c597da8ec22a56801b435744033"
MSG_HI = "sha256:c8f3d59959c9247211de8c76b94ef17f0c279f09362350ced67f69ecdb89d6c7"


def meta_for(outcome: Optional[str] = None, **extra: Any) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "did": SERVER,
        "kid": f"{SERVER}#key-1",
        "ts": NOW,
        "nonce": "b6VZmm9hXn-otOETBkvlvQ",
        "audience": SERVER,
        "sessionId": "kyaos_11111111-2222-4333-8444-555555555555",
        "requestHash": rp.hash_request(REQUEST),
    }
    if outcome is None or rp.outcome_has_response(outcome):
        meta["responseHash"] = rp.hash_response(BODY, rp.RESPONSE_PROOF_ENVELOPE_PROFILE)
    if outcome is not None:
        meta["outcome"] = outcome
    meta["prf"] = rp.RESPONSE_PROOF_ENVELOPE_PROFILE
    meta.update(extra)
    return {k: v for k, v in meta.items() if v is not None}


def proof_for(meta: Dict[str, Any], signer: EnvSigner = SIGNER) -> Dict[str, Any]:
    return {"jws": sign_jws(rp.proof_payload(meta), signer), "meta": meta}


def with_proof(proof: Dict[str, Any], key: str = rp.RESPONSE_PROOF_META_KEY, **extra_meta: Any) -> Dict[str, Any]:
    return {**BODY, "_meta": {key: proof, **extra_meta}}


def reason_of(run: Any) -> str:
    try:
        run()
    except (ResponseProofError, InvalidJWSError) as error:
        return error.reason
    return "verified"


# ── hashes ────────────────────────────────────────────────────────────────────


class TestHashes:
    def test_covered_request_and_hash_request_match_spec_c1(self) -> None:
        request = {"method": "tools/call", "params": {"name": "echo", "arguments": {}}}
        assert canonicalize(rp.covered_request(request)) == '{"method":"tools/call","params":{"arguments":{},"name":"echo"}}'
        assert rp.hash_request(request) == EMPTY_ARGS
        noisy = {"method": "tools/call", "params": {"name": "echo", "arguments": {"_kyaos_proof": {"jws": "..."}}, "_meta": {"traceparent": "x"}}}
        assert rp.hash_request(noisy) == EMPTY_ARGS
        assert rp.hash_request({"method": "tools/call", "params": {"name": "echo"}}) == EMPTY_ARGS
        assert rp.hash_request({"method": "tools/call", "params": {"name": "echo", "arguments": "nope"}}) == EMPTY_ARGS
        business = {"method": "tools/call", "params": {"name": "echo", "arguments": {"msg": "hi", "_kyaos_delegation": {"id": "x"}}, "_meta": {"progressToken": 7}}}
        assert rp.hash_request(business) == MSG_HI
        assert rp.covered_request({"method": "tools/call"}) == {"method": "tools/call"}
        assert rp.covered_request({"method": "tools/list", "params": {"cursor": "c", "_meta": {"x": 1}}}) == {"method": "tools/list", "params": {"cursor": "c"}}

    def test_control_arguments(self) -> None:
        assert rp.is_control_argument("_kyaos_session") and rp.is_control_argument("_kyaos")
        assert not rp.is_control_argument("kyaos") and not rp.is_control_argument("_meta")
        assert rp.strip_control_arguments({"a": 1, "_kyaos_session": "s", "_other": 2}) == {"a": 1, "_other": 2}

    def test_hash_response_under_both_profiles(self) -> None:
        result = {"content": [{"type": "text", "text": "hi"}], "isError": False, "_meta": {rp.RESPONSE_PROOF_META_KEY: {"jws": "x", "meta": {}}}}
        assert rp.covered_response(result) == result
        assert rp.hash_response(result) == hash_json(result)
        rest = {k: v for k, v in result.items() if k != "_meta"}
        assert rp.covered_response(result, rp.RESPONSE_PROOF_ENVELOPE_PROFILE) == rest
        assert rp.hash_response(result, rp.RESPONSE_PROOF_ENVELOPE_PROFILE) == hash_json(rest)
        assert rp.covered_response([{"_meta": 1}], rp.RESPONSE_PROOF_ENVELOPE_PROFILE) == [{"_meta": 1}]
        assert rp.covered_response(None, rp.RESPONSE_PROOF_ENVELOPE_PROFILE) is None
        assert rp.wire_json({"a": (1, 2)}) == {"a": [1, 2]}
        assert rp.hash_response([{"type": "text", "text": "released r-1"}]) == hash_json([{"type": "text", "text": "released r-1"}])


# ── claims and meta ───────────────────────────────────────────────────────────


class TestClaims:
    def test_proof_claims_and_payload(self) -> None:
        meta = meta_for("denied", reason="nope", clientDid="did:key:z6Mkagent", delegationRef="urn:uuid:1")
        assert rp.proof_claims(meta) == {
            "iss": SERVER,
            "sub": SERVER,
            "aud": SERVER,
            "ts": NOW,
            "nonce": meta["nonce"],
            "sessionId": meta["sessionId"],
            "requestHash": meta["requestHash"],
            "outcome": "denied",
            "reason": "nope",
            "clientDid": "did:key:z6Mkagent",
            "delegationRef": "urn:uuid:1",
            "prf": rp.RESPONSE_PROOF_ENVELOPE_PROFILE,
        }
        assert "responseHash" not in rp.proof_claims({**meta_for(), "responseHash": None})
        assert rp.proof_payload(meta) == canonicalize(rp.proof_claims(meta))
        assert rp.proof_payload(meta).startswith('{"aud":')

    def test_outcome_has_response(self) -> None:
        assert rp.PROOF_OUTCOMES == ("allowed", "denied", "step_up_required", "needs_authorization")
        assert rp.outcome_has_response("allowed") and rp.outcome_has_response("needs_authorization")
        assert not rp.outcome_has_response("denied") and not rp.outcome_has_response("step_up_required")

    def test_validate_proof_meta_accepts_every_member(self) -> None:
        meta = meta_for("allowed", reason="r", clientDid="did:key:x", scopeId="s", delegationRef="d", delegationChainDigest="sha256:" + "0" * 64)
        assert rp.validate_proof_meta(meta) == meta

    @pytest.mark.parametrize(
        "patch,reason",
        [
            ("meta", rp.ProofReasons.META_INVALID),
            ({**meta_for(), "extra": 1}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "did": "orders"}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "did": 7}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "kid": ""}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "ts": 0}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "ts": True}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "ts": "1"}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "nonce": ""}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "sessionId": 1}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "requestHash": "sha256:short"}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "responseHash": "md5:x"}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "delegationChainDigest": "x"}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "outcome": "maybe"}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "reason": 1}, rp.ProofReasons.META_INVALID),
            ({**meta_for(), "prf": "org.example/unknown-profile.v9"}, rp.ProofReasons.PROFILE_UNKNOWN),
        ],
        ids=lambda v: v if isinstance(v, str) else "patch",
    )
    def test_validate_proof_meta_refuses(self, patch: Any, reason: str) -> None:
        assert reason_of(lambda: rp.validate_proof_meta(patch)) == reason

    def test_read_response_proof_keys_and_tolerance(self) -> None:
        proof = proof_for(meta_for())
        other = proof_for(meta_for("denied"))
        assert rp.LEGACY_RESPONSE_PROOF_META_KEYS == ("org.kya-os/proof", "proof")
        assert rp.read_response_proof({rp.RESPONSE_PROOF_META_KEY: proof, "org.kya-os/proof": other, "proof": other}) == proof
        assert rp.read_response_proof({"org.kya-os/proof": proof, "proof": other}) == proof
        assert rp.read_response_proof({"proof": proof}) == proof
        assert rp.read_response_proof({rp.RESPONSE_PROOF_META_KEY: None, "proof": proof}) == proof
        noisy = {rp.RESPONSE_PROOF_META_KEY: proof, "traceparent": "t", "tracestate": "s", "baggage": "b", "io.modelcontextprotocol/trace": "x", rp.REQUEST_PROOF_META_KEY: {"jws": "x", "meta": {}}}
        assert rp.read_response_proof(noisy) == proof
        assert rp.read_response_proof(None) is None
        assert rp.read_response_proof("meta") is None
        assert rp.read_response_proof({"traceparent": "t"}) is None
        assert rp.read_response_proof({rp.REQUEST_PROOF_META_KEY: proof}) is None
        assert reason_of(lambda: rp.read_response_proof({rp.RESPONSE_PROOF_META_KEY: "jws"})) == rp.ProofReasons.MALFORMED
        assert reason_of(lambda: rp.read_response_proof({rp.RESPONSE_PROOF_META_KEY: {"jws": proof["jws"]}})) == rp.ProofReasons.MALFORMED
        assert reason_of(lambda: rp.read_response_proof({rp.RESPONSE_PROOF_META_KEY: {**proof, "extra": 1}})) == rp.ProofReasons.MALFORMED
        assert reason_of(lambda: rp.read_response_proof({"proof": {"jws": proof["jws"], "meta": {"did": "x"}}})) == rp.ProofReasons.META_INVALID


# ── verification ──────────────────────────────────────────────────────────────


class TestVerifyDetachedProof:
    def test_verifies_by_jwk_and_by_resolver(self) -> None:
        proof = proof_for(meta_for())
        by_jwk = rp.verify_detached_proof(proof, jwk=JWK, now=NOW)
        assert (by_jwk.meta, by_jwk.outcome, by_jwk.did, by_jwk.kid, by_jwk.profile) == (proof["meta"], "allowed", SERVER, f"{SERVER}#key-1", rp.RESPONSE_PROOF_ENVELOPE_PROFILE)
        by_did = rp.verify_detached_proof(proof, resolve_did=resolve_did, now=NOW, expected_did=SERVER)
        assert by_did == by_jwk
        assert rp.verify_detached_proof(proof_for(meta_for("denied", reason="x")), jwk=JWK, now=NOW).outcome == "denied"
        body_profile = proof_for({k: v for k, v in meta_for("needs_authorization").items() if k != "prf"})
        assert rp.verify_detached_proof(body_profile, jwk=JWK, now=NOW).profile is None
        with pytest.raises(ValueError):
            rp.verify_detached_proof(proof, now=NOW)
        with pytest.raises(ValueError):
            rp.verify_detached_proof(proof, jwk=JWK, resolve_did=resolve_did)

    def test_refusals(self) -> None:
        proof = proof_for(meta_for())
        assert reason_of(lambda: rp.verify_detached_proof("x", jwk=JWK)) == rp.ProofReasons.MALFORMED
        assert reason_of(lambda: rp.verify_detached_proof({"meta": meta_for()}, jwk=JWK)) == rp.ProofReasons.MALFORMED
        assert reason_of(lambda: rp.verify_detached_proof({"jws": "a.b.c", "meta": "m"}, jwk=JWK)) == rp.ProofReasons.META_INVALID
        assert reason_of(lambda: rp.verify_detached_proof(proof, jwk=JWK, now=NOW, expected_did="did:web:other.example")) == rp.ProofReasons.SIGNER_MISMATCH
        assert reason_of(lambda: rp.verify_detached_proof(proof, jwk=public_key_hex_to_jwk(OTHER_KEYS.public_key), now=NOW)) == "jws_signature_invalid"
        other_kid = proof_for(meta_for(kid=f"{SERVER}#key-2"))
        assert reason_of(lambda: rp.verify_detached_proof(other_kid, jwk=JWK, now=NOW)) == "jws_kid_mismatch"
        foreign = EnvSigner("did:web:other.example", env_var="K", env={"K": OTHER_KEYS.private_key})
        assert reason_of(lambda: rp.verify_detached_proof(proof_for(meta_for(), foreign), resolve_did=resolve_did, now=NOW)) == "jws_kid_did_mismatch"
        assert reason_of(lambda: rp.verify_detached_proof(proof, resolve_did=lambda did: None, now=NOW)) == "jws_did_unresolved"

    def test_meta_must_be_what_was_signed(self) -> None:
        proof = proof_for(meta_for())

        def tampered(**patch: Any) -> Dict[str, Any]:
            return {"jws": proof["jws"], "meta": {**proof["meta"], **patch}}

        assert reason_of(lambda: rp.verify_detached_proof(tampered(requestHash="sha256:" + "de" * 32), jwk=JWK, now=NOW)) == rp.ProofReasons.PAYLOAD_MISMATCH
        stripped = {"jws": proof["jws"], "meta": {k: v for k, v in proof["meta"].items() if k != "prf"}}
        assert reason_of(lambda: rp.verify_detached_proof(stripped, jwk=JWK, now=NOW)) == rp.ProofReasons.PAYLOAD_MISMATCH
        assert reason_of(lambda: rp.verify_detached_proof(tampered(nonce="nonce-other"), jwk=JWK, now=NOW)) == rp.ProofReasons.PAYLOAD_MISMATCH
        assert reason_of(lambda: rp.verify_detached_proof(tampered(sessionId="sess_other"), jwk=JWK, now=NOW)) == rp.ProofReasons.PAYLOAD_MISMATCH
        uncanonical = {"jws": sign_jws(json.dumps(rp.proof_claims(proof["meta"])), SIGNER), "meta": proof["meta"]}
        assert reason_of(lambda: rp.verify_detached_proof(uncanonical, jwk=JWK, now=NOW)) == rp.ProofReasons.PAYLOAD_MISMATCH
        binary = {"jws": sign_jws(b"\xff\xfe", SIGNER), "meta": proof["meta"]}
        assert reason_of(lambda: rp.verify_detached_proof(binary, jwk=JWK, now=NOW)) == rp.ProofReasons.PAYLOAD_MISMATCH

    def test_timestamp_skew(self) -> None:
        proof = proof_for(meta_for())
        assert rp.verify_detached_proof(proof, jwk=JWK, now=NOW + 120).outcome == "allowed"
        assert rp.verify_detached_proof(proof, jwk=JWK, now=NOW - 119.9).outcome == "allowed"
        assert reason_of(lambda: rp.verify_detached_proof(proof, jwk=JWK, now=NOW + 121)) == rp.ProofReasons.TIMESTAMP_SKEW
        assert reason_of(lambda: rp.verify_detached_proof(proof, jwk=JWK, now=NOW - 121)) == rp.ProofReasons.TIMESTAMP_SKEW
        assert rp.verify_detached_proof(proof, jwk=JWK, now=NOW + 300, skew_seconds=300).outcome == "allowed"
        assert reason_of(lambda: rp.verify_detached_proof(proof, jwk=JWK, now=NOW + 31, skew_seconds=30)) == rp.ProofReasons.TIMESTAMP_SKEW
        assert reason_of(lambda: rp.verify_detached_proof(proof, jwk=JWK)) == rp.ProofReasons.TIMESTAMP_SKEW
        import time

        fresh = proof_for(meta_for(ts=int(time.time())))
        assert rp.verify_detached_proof(fresh, jwk=JWK).outcome == "allowed"

    def test_response_hash_presence_rule(self) -> None:
        no_hash = proof_for({k: v for k, v in meta_for().items() if k != "responseHash"})
        assert reason_of(lambda: rp.verify_detached_proof(no_hash, jwk=JWK, now=NOW)) == rp.ProofReasons.RESPONSE_HASH_MISSING
        no_hash_needs = proof_for({k: v for k, v in meta_for("needs_authorization").items() if k != "responseHash"})
        assert reason_of(lambda: rp.verify_detached_proof(no_hash_needs, jwk=JWK, now=NOW)) == rp.ProofReasons.RESPONSE_HASH_MISSING
        for outcome in ("denied", "step_up_required"):
            with_hash = proof_for(meta_for(outcome, responseHash=rp.hash_response(BODY)))
            assert reason_of(lambda: rp.verify_detached_proof(with_hash, jwk=JWK, now=NOW)) == rp.ProofReasons.RESPONSE_HASH_UNEXPECTED
            assert rp.verify_detached_proof(proof_for(meta_for(outcome)), jwk=JWK, now=NOW).outcome == outcome


class TestVerifyResponseProof:
    def test_recomputes_both_hashes(self) -> None:
        proof = proof_for(meta_for())
        verified = rp.verify_response_proof(with_proof(proof), SERVER, resolve_did, request=REQUEST, now=NOW)
        assert verified.outcome == "allowed"
        assert verified.request_hash == proof["meta"]["requestHash"]
        assert verified.response_hash == proof["meta"]["responseHash"]
        noisy = with_proof(proof, traceparent="t", **{"io.modelcontextprotocol/trace": "x", rp.REQUEST_PROOF_META_KEY: {"jws": "x", "meta": {}}})
        assert rp.verify_response_proof(noisy, SERVER, resolve_did, request=REQUEST, now=NOW).outcome == "allowed"
        for key in rp.LEGACY_RESPONSE_PROOF_META_KEYS:
            assert rp.verify_response_proof(with_proof(proof, key), SERVER, resolve_did, request=REQUEST, now=NOW).outcome == "allowed"
        bare = {"method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}}}
        assert rp.verify_response_proof(with_proof(proof), SERVER, resolve_did, request=bare, now=NOW).outcome == "allowed"

    def test_refusals(self) -> None:
        proof = proof_for(meta_for())
        assert reason_of(lambda: rp.verify_response_proof(BODY, SERVER, resolve_did, request=REQUEST, now=NOW)) == rp.ProofReasons.MISSING
        assert reason_of(lambda: rp.verify_response_proof(None, SERVER, resolve_did, request=REQUEST, now=NOW)) == rp.ProofReasons.MISSING
        assert reason_of(lambda: rp.verify_response_proof(with_proof(proof), "did:web:other.example", resolve_did, request=REQUEST, now=NOW)) == rp.ProofReasons.SIGNER_MISMATCH
        other_request = {"method": "tools/call", "params": {"name": "refund_order", "arguments": {"orderId": "ORD-1001"}}}
        assert reason_of(lambda: rp.verify_response_proof(with_proof(proof), SERVER, resolve_did, request=other_request, now=NOW)) == rp.ProofReasons.REQUEST_HASH_MISMATCH
        swapped = {**with_proof(proof), "structuredContent": {"id": "ORD-9999"}}
        assert reason_of(lambda: rp.verify_response_proof(swapped, SERVER, resolve_did, request=REQUEST, now=NOW)) == rp.ProofReasons.RESPONSE_HASH_MISMATCH

    def test_denied_and_body_profile_out_of_band(self) -> None:
        denied = proof_for(meta_for("denied", reason="insufficient scope"))
        verified = rp.verify_response_proof({"error": "insufficient_scope"}, SERVER, resolve_did, request=REQUEST, proof=denied, now=NOW)
        assert (verified.outcome, verified.response_hash, verified.meta["reason"]) == ("denied", None, "insufficient scope")
        data = [{"type": "text", "text": "released r-1"}]
        body_proof = proof_for({**{k: v for k, v in meta_for().items() if k != "prf"}, "responseHash": rp.hash_response(data)})
        assert rp.verify_response_proof(data, SERVER, resolve_did, request=REQUEST, proof=body_proof, now=NOW).response_hash == rp.hash_response(data)
        assert reason_of(lambda: rp.verify_response_proof(data + [{"type": "text", "text": "x"}], SERVER, resolve_did, request=REQUEST, proof=body_proof, now=NOW)) == rp.ProofReasons.RESPONSE_HASH_MISMATCH

    def test_error_shape(self) -> None:
        with pytest.raises(ResponseProofError) as caught:
            rp.verify_response_proof(BODY, SERVER, resolve_did, request=REQUEST, now=NOW)
        assert caught.value.code == "RESPONSE_PROOF_INVALID"
        assert caught.value.details == {"reason": rp.ProofReasons.MISSING}
        assert ResponseProofError("x").message == "Response proof is invalid"


# ── signed-proof vectors ──────────────────────────────────────────────────────

FIXTURES_DIR = Path(os.environ.get("HELIX_CORE_FIXTURES_DIR") or Path(__file__).resolve().parents[2] / "helix-core" / "fixtures")


def _vectors(name: str) -> List[Dict[str, Any]]:
    path = FIXTURES_DIR / "kya-os" / "conformance" / "vectors" / name
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)["vectors"]


DELEGATION_LAYER = {
    "signed-proof/delegation-chain-refused-outcome-unstated",
    "signed-proof/delegation-chain-substituted",
    "signed-proof/delegation-chain-unbound",
    "signed-proof/delegation-chain-no-signed-form",
    "signed-proof/delegation-ref-substituted",
    "signed-proof/delegation-chain-nested-past-bound",
    "signed-proof/delegation-chain-number-read-as-binary64",
}

EXPECTED_REFUSALS = {
    "signed-proof/tampered-signature": "jws_signature_invalid",
    "signed-proof/tampered-meta": rp.ProofReasons.PAYLOAD_MISMATCH,
    "signed-proof/wrong-key": "jws_kid_mismatch",
    "signed-proof/timestamp-skew-exceeded": rp.ProofReasons.TIMESTAMP_SKEW,
    "signed-proof/envelope-tampered-structured-content": rp.ProofReasons.RESPONSE_HASH_MISMATCH,
    "signed-proof/prf-stripped-downgrade": rp.ProofReasons.PAYLOAD_MISMATCH,
    "signed-proof/unknown-profile": rp.ProofReasons.PROFILE_UNKNOWN,
    "signed-proof/delegation-chain-digest-stripped": rp.ProofReasons.PAYLOAD_MISMATCH,
    "signed-proof/delegation-proof-signature-stray-character": "jws_malformed",
    "signed-proof/delegation-proof-signature-stray-characters": "jws_malformed",
    "signed-proof/delegation-proof-signature-base64": "jws_malformed",
    "signed-proof/delegation-proof-signature-white-space": "jws_malformed",
    "signed-proof/delegation-proof-signature-padded": "jws_malformed",
    "signed-proof/delegation-proof-fourth-segment": "jws_malformed",
    "signed-proof/delegation-proof-header-non-ascii": "jws_malformed",
    "signed-proof/delegation-proof-request-hash-altered": rp.ProofReasons.PAYLOAD_MISMATCH,
    "signed-proof/delegation-proof-nonce-altered": rp.ProofReasons.PAYLOAD_MISMATCH,
    "signed-proof/delegation-proof-session-altered": rp.ProofReasons.PAYLOAD_MISMATCH,
    "signed-proof/delegation-proof-request-substituted": rp.ProofReasons.REQUEST_HASH_MISMATCH,
    "signed-proof/delegation-proof-header-algorithm": "jws_alg_unsupported",
    "signed-proof/delegation-proof-header-key": "jws_kid_mismatch",
    "signed-proof/delegation-proof-signer-of-another-did": "jws_kid_did_mismatch",
}


class TestSignedProofVectors:
    """L2.11 to L2.13, L2.17 over the vendored signed-proof category. Fail
    vectors whose refusal is the delegation chain's (F-2, C-C) verify here
    with the outcome the server signed."""

    def test_fixtures_present(self) -> None:
        if not _vectors("signed-proof.json"):
            pytest.skip(f"{FIXTURES_DIR} has no vectors: check out helix-core beside this repo or set HELIX_CORE_FIXTURES_DIR")
        assert len(_vectors("signed-proof.json")) == 52
        assert len(EXPECTED_REFUSALS) + len(DELEGATION_LAYER) == sum(1 for v in _vectors("signed-proof.json") if v["expected"] == "fail")

    @pytest.mark.parametrize("vector", _vectors("signed-proof.json"), ids=lambda v: v["id"])
    def test_vector(self, vector: Dict[str, Any]) -> None:
        proof = vector["input"]["proof"]
        jwk = vector["input"]["publicKeyJwk"]
        now = vector["input"]["now"]
        skew = vector["input"]["skewSeconds"]
        expected = vector["input"].get("expected")
        did = proof["meta"]["did"]

        def resolver(wanted: str) -> Optional[Dict[str, Any]]:
            if wanted != did:
                return None
            return {"id": did, "verificationMethod": [{"id": proof["meta"]["kid"], "controller": did, "publicKeyJwk": jwk}], "assertionMethod": [proof["meta"]["kid"]]}

        def run() -> Any:
            detached = rp.verify_detached_proof(proof, jwk=jwk, now=now, skew_seconds=skew)
            if not expected:
                return detached
            response = (expected.get("response") or {}).get("data")
            return rp.verify_response_proof(response, did, resolver, request=expected["request"], proof=proof, now=now, skew_seconds=skew)

        verdict = reason_of(run)
        if vector["expected"] == "pass" or vector["id"] in DELEGATION_LAYER:
            assert verdict == "verified", vector["reason"]
        else:
            assert verdict == EXPECTED_REFUSALS[vector["id"]], vector["reason"]

    def test_refused_chain_vector_reports_denied(self) -> None:
        vectors = [v for v in _vectors("signed-proof.json") if v["id"] == "signed-proof/delegation-chain-refused"]
        if not vectors:
            pytest.skip("no vectors")
        v = vectors[0]["input"]
        verified = rp.verify_detached_proof(v["proof"], jwk=v["publicKeyJwk"], now=v["now"], skew_seconds=v["skewSeconds"])
        assert verified.outcome == "denied"
        assert "responseHash" not in verified.meta
