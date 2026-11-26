# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story C-C in Python: the agent side (``mint_request_proof``,
``request_hash_content_digest``, ``attach_chain``, ``with_request_proof``)
and ``verify_request_proof`` step by step in the section 11.2 order. The
shared fixture cases are in test_request_proof_fixtures.py; this file covers
what they do not reach, and rule 7: no request ever carries private key
material.
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any, Dict, List, Optional

import pytest

from helix_sdk import kyaos
from helix_sdk.agent_key import generate_agent_key, to_did_key, to_public_key_jwk
from helix_sdk.credentials import derive_conformance_level
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.verifier import (
    CNF_PRESENT_BUT_TOKEN_UNFUSED,
    DELEGATION_CHAIN_META_KEY,
    REQUEST_PROOF_META_KEY,
    MemoryNonceStore,
    ReasonCodes,
    RequestProofOptions,
    RequestProofSeams,
    RequestProofVerification,
    did_key_document,
    ed25519_keys_of,
    jwk_thumbprint,
    verify_request_proof,
)

NOW_MS = 1_780_272_000_000
SERVICE = "did:web:orders.example.com"
CALL = {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}}


class Agent:
    def __init__(self) -> None:
        key = generate_agent_key()
        self.private_key_hex = key.private_key_hex
        self.did = to_did_key(key.public_key_hex)
        self.signer = EnvSigner(self.did, kid=self.did.split(":")[-1], env_var="AGENT_KEY", env={"AGENT_KEY": key.private_key_hex})
        self.jkt = jwk_thumbprint(to_public_key_jwk(key.public_key_hex))


def seams(**overrides: Any) -> RequestProofSeams:
    base = RequestProofSeams(
        resolve_did=did_key_document,
        resolve_did_keys=lambda did: ed25519_keys_of(did_key_document(did) or {}),
        nonce_store=MemoryNonceStore(now_ms=lambda: NOW_MS),
        clock=lambda: NOW_MS,
    )
    for name, value in overrides.items():
        setattr(base, name, value)
    return base


def check(proof: Any, request: Any, *, seam: Optional[RequestProofSeams] = None, **options: Any) -> RequestProofVerification:
    return verify_request_proof(proof, request, seam or seams(), RequestProofOptions(expected_audience=SERVICE, **options))


def signed(agent: Agent, call: Dict[str, Any] = CALL, **options: Any) -> Dict[str, Any]:
    return kyaos.with_request_proof(call, agent.signer, audience=SERVICE, now_ms=NOW_MS, **options)


# ── the agent side ─────────────────────────────────────────────────────────


class TestAgentSide:
    def test_a_tool_call_is_sent_as_tools_call(self) -> None:
        assert kyaos.to_proof_request(CALL) == {"method": "tools/call", "params": CALL}
        assert kyaos.to_proof_request({"name": "t"}) == {"method": "tools/call", "params": {"name": "t"}}
        assert kyaos.to_proof_request({"name": "t", "_meta": {"a": 1}}) == {"method": "tools/call", "params": {"name": "t", "_meta": {"a": 1}}}
        request = {"method": "resources/read", "params": {"uri": "x"}}
        assert kyaos.to_proof_request(request) == request
        for bad in ({}, {"name": ""}, {"name": 3}, "tools/call"):
            with pytest.raises(kyaos.RequestProofError):
                kyaos.to_proof_request(bad)  # type: ignore[arg-type]

    def test_the_digest_covers_method_and_params_but_not_meta(self) -> None:
        digest = kyaos.request_hash_content_digest(CALL)
        assert digest.startswith("sha-256=:") and digest.endswith(":")
        assert len(base64.b64decode(digest[len("sha-256=:"):-1])) == 32
        assert kyaos.request_hash_content_digest({**CALL, "_meta": {"traceparent": "x"}}) == digest
        assert kyaos.request_hash_content_digest({"method": "tools/call", "params": CALL}) == digest
        assert kyaos.request_hash_content_digest({"name": "lookup_order", "arguments": {"orderId": "ORD-1002"}}) != digest

    def test_mint_signs_one_fresh_proof_per_call(self) -> None:
        agent = Agent()
        first = kyaos.mint_request_proof(CALL, agent.signer, audience=SERVICE, now_ms=NOW_MS)
        second = kyaos.mint_request_proof(CALL, agent.signer, audience=SERVICE, now_ms=NOW_MS)
        assert first["nonce"] != second["nonce"]
        assert first["prf"] == "org.kya-os/proof.v1" and first["alg"] == "EdDSA"
        assert first["did"] == agent.did and first["kid"].startswith(f"{agent.did}#")
        assert first["audience"] == SERVICE
        assert first["expires"] - first["created"] == 60
        assert first["requestHash"] == kyaos.request_hash_content_digest(CALL)
        assert "cnf" not in first
        pinned = kyaos.mint_request_proof(CALL, agent.signer, audience=SERVICE, now_ms=NOW_MS, ttl_seconds=10, nonce="n" * 22, cnf_jkt=agent.jkt)
        assert pinned["nonce"] == "n" * 22 and pinned["expires"] - pinned["created"] == 10 and pinned["cnf"] == {"jkt": agent.jkt}

    @pytest.mark.parametrize(
        "options",
        [
            {"audience": "orders.example.com"},
            {"audience": ""},
            {"audience": SERVICE, "ttl_seconds": 0},
            {"audience": SERVICE, "ttl_seconds": 61},
            {"audience": SERVICE, "ttl_seconds": 1.5},
            {"audience": SERVICE, "ttl_seconds": True},
            {"audience": SERVICE, "nonce": "short"},
            {"audience": SERVICE, "nonce": "not base64url but long enough!!"},
            {"audience": SERVICE, "cnf_jkt": "too-short"},
        ],
    )
    def test_mint_refuses_what_no_verifier_accepts(self, options: Dict[str, Any]) -> None:
        with pytest.raises(kyaos.RequestProofError):
            kyaos.mint_request_proof(CALL, Agent().signer, **options)

    def test_attach_chain_carries_signed_hops_root_to_leaf(self) -> None:
        hop = {"issuer": "did:key:z1", "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "proofPurpose": "assertionMethod"}}
        assert kyaos.attach_chain([hop, hop]) == {DELEGATION_CHAIN_META_KEY: [hop, hop]}
        assert kyaos.attach_chain((hop,)) == {DELEGATION_CHAIN_META_KEY: [hop]}
        unsigned = {"issuer": "did:key:z1"}
        wrong_suite = {"proof": {**hop["proof"], "cryptosuite": "ecdsa-rdfc-2019"}}
        for bad in ([], [hop] * 11, [hop, unsigned], [wrong_suite], ["hop"], "hops"):
            with pytest.raises(kyaos.RequestProofError):
                kyaos.attach_chain(bad)  # type: ignore[arg-type]

    def test_with_request_proof_puts_the_proof_and_chain_in_meta_and_keeps_other_members(self) -> None:
        agent = Agent()
        hop = {"proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "proofPurpose": "assertionMethod"}}
        sent = kyaos.with_request_proof({**CALL, "_meta": {"progressToken": "p-1"}}, agent.signer, audience=SERVICE, chain=[hop], now_ms=NOW_MS)
        meta = sent["params"]["_meta"]
        assert sent["method"] == "tools/call" and sent["params"]["arguments"] == CALL["arguments"]
        assert meta["progressToken"] == "p-1" and meta[DELEGATION_CHAIN_META_KEY] == [hop]
        assert meta[REQUEST_PROOF_META_KEY]["requestHash"] == kyaos.request_hash_content_digest(sent)

    def test_a_request_without_params_is_signed_as_sent(self) -> None:
        agent = Agent()
        sent = kyaos.with_request_proof({"method": "tools/list"}, agent.signer, audience=SERVICE, now_ms=NOW_MS)
        assert set(sent["params"]) == {"_meta"}
        assert check(sent["params"]["_meta"][REQUEST_PROOF_META_KEY], sent).ok
        with pytest.raises(kyaos.RequestProofError):
            kyaos.with_request_proof({"method": "tools/call", "params": [1, 2]}, agent.signer, audience=SERVICE)

    def test_no_request_carries_private_key_material(self) -> None:
        """Rule 7: every encoding of the key is absent from what is sent."""
        agent = Agent()
        seed = bytes.fromhex(agent.private_key_hex)
        forms = [agent.private_key_hex, agent.private_key_hex.upper(), base64.b64encode(seed).decode(), base64.urlsafe_b64encode(seed).decode().rstrip("=")]
        sent = json.dumps(signed(agent, cnf_jkt=agent.jkt))
        for form in forms:
            assert form not in sent
        assert agent.private_key_hex not in repr(agent.signer) and agent.private_key_hex not in str(vars(agent.signer))


# ── verify_request_proof, step by step ─────────────────────────────────────


class TestVerifyRequestProof:
    def test_a_signed_request_verifies_at_l3_minus_without_a_token(self) -> None:
        agent = Agent()
        sent = signed(agent)
        verdict = check(sent["params"]["_meta"][REQUEST_PROOF_META_KEY], sent)
        assert verdict.ok and verdict.did == agent.did and verdict.assurance == "L3-minus" and verdict.reasons == [] and verdict.warnings == []
        assert verdict.proof is not None and verdict.proof["did"] == agent.did

    def test_seams_and_configuration_fail_closed(self) -> None:
        agent = Agent()
        sent = signed(agent)
        proof = sent["params"]["_meta"][REQUEST_PROOF_META_KEY]
        assert check(proof, sent, seam=seams(clock=None)).reasons == [ReasonCodes.CLOCK_SEAM_MISSING]
        assert verify_request_proof(proof, sent, seams(), RequestProofOptions(expected_audience="orders")).reasons == [ReasonCodes.CONFIGURATION_ERROR]
        assert check(None, sent).reasons == [ReasonCodes.PROOF_MISSING]
        assert check({"prf": "x"}, sent).reasons == [ReasonCodes.MALFORMED_PROOF]
        assert check(proof, sent, seam=seams(resolve_did=None)).reasons == [ReasonCodes.DID_RESOLVER_MISSING]
        assert check(proof, sent, seam=seams(resolve_did_keys=None)).reasons == [ReasonCodes.DID_MEMBERSHIP_UNVERIFIABLE]
        assert check(proof, sent, seam=seams(nonce_store=None)).reasons == [ReasonCodes.NONCE_SEAM_MISSING]

    def test_each_step_has_its_own_reason(self) -> None:
        agent = Agent()
        sent = signed(agent)
        proof = sent["params"]["_meta"][REQUEST_PROOF_META_KEY]
        assert check({**proof, "kid": "did:key:zOther#k"}, sent).reasons == [ReasonCodes.KID_DID_MISMATCH]
        assert check({**proof, "alg": "ES256"}, sent).reasons == [ReasonCodes.ALG_UNSUPPORTED]

        def raises(_did: str) -> Any:
            raise RuntimeError("resolver down")

        assert check(proof, sent, seam=seams(resolve_did=raises)).reasons == [ReasonCodes.DID_UNRESOLVED]
        assert check(proof, sent, seam=seams(resolve_did=lambda _did: None)).reasons == [ReasonCodes.DID_UNRESOLVED]
        assert check(proof, sent, seam=seams(resolve_did=lambda _did: {"id": agent.did})).reasons == [ReasonCodes.KEY_UNRESOLVABLE]
        assert check(proof, sent, seam=seams(resolve_did_keys=raises)).reasons == [ReasonCodes.DID_KEYS_UNRESOLVABLE]
        assert check(proof, sent, seam=seams(resolve_did_keys=lambda _did: [{"not": "a jwk"}])).reasons == [ReasonCodes.KID_NOT_IN_DID_DOCUMENT]
        assert verify_request_proof(proof, sent, seams(), RequestProofOptions(expected_audience="did:web:elsewhere")).reasons == [ReasonCodes.AUDIENCE_MISMATCH]
        assert check(proof, None).reasons == [ReasonCodes.REQUEST_MISSING]
        assert check(proof, {"method": "tools/call", "params": {**CALL, "arguments": {"orderId": "ORD-1002"}}}).reasons == [ReasonCodes.REQUEST_HASH_MISMATCH]
        assert check(proof, {"method": float("nan")}).reasons == [ReasonCodes.REQUEST_HASH_MISMATCH]

    def test_the_window_reports_every_problem_in_one_step(self) -> None:
        agent = Agent()
        late = signed(agent, ttl_seconds=60)
        proof = late["params"]["_meta"][REQUEST_PROOF_META_KEY]
        verdict = check(proof, late, seam=seams(clock=lambda: NOW_MS + 120_000))
        assert verdict.reasons == ["expired"] and verdict.messages == ["proof window: expired"]
        assert check(proof, late, seam=seams(clock=lambda: NOW_MS - 120_000)).reasons == ["created_in_future"]
        assert check(proof, late, max_ttl_seconds=30).reasons == ["ttl_too_long"]
        assert check(proof, late, seam=seams(clock=lambda: NOW_MS + 64_000)).ok  # within the 5 s skew
        assert check(proof, late, seam=seams(clock=lambda: NOW_MS + 64_000), skew_seconds=1).reasons == ["expired"]

    def test_replay_is_refused_before_the_signature_and_a_failing_store_fails_closed(self) -> None:
        agent = Agent()
        sent = signed(agent)
        proof = sent["params"]["_meta"][REQUEST_PROOF_META_KEY]
        store = seams()
        assert check(proof, sent, seam=store).ok
        assert check(proof, sent, seam=store).reasons == [ReasonCodes.NONCE_REPLAYED]
        forged = {**proof, "jws": proof["jws"][:-4] + "AAAA"}
        assert check(forged, sent, seam=store).reasons == [ReasonCodes.NONCE_REPLAYED]

        class Down:
            def insert(self, *_args: Any) -> bool:
                raise RuntimeError("redis down")

        assert check(proof, sent, seam=seams(nonce_store=Down())).reasons == [ReasonCodes.NONCE_STORE_UNAVAILABLE]
        assert check(forged, sent).reasons == [ReasonCodes.INVALID_SIGNATURE]

    def test_cnf_fusion(self) -> None:
        agent = Agent()
        with_cnf = signed(agent, cnf_jkt=agent.jkt)
        proof = with_cnf["params"]["_meta"][REQUEST_PROOF_META_KEY]
        fused = check(proof, with_cnf, token_cnf_jkt=agent.jkt)
        assert fused.ok and fused.assurance == "L3" and fused.warnings == []
        unfused = check(proof, with_cnf)
        assert unfused.ok and unfused.assurance == "L3-minus" and unfused.warnings == [CNF_PRESENT_BUT_TOKEN_UNFUSED]
        assert check(proof, with_cnf, token_cnf_jkt=Agent().jkt).reasons == [ReasonCodes.CNF_TOKEN_MISMATCH]
        bare = signed(agent)
        assert check(bare["params"]["_meta"][REQUEST_PROOF_META_KEY], bare, token_cnf_jkt=agent.jkt).reasons == [ReasonCodes.CNF_REQUIRED_BY_TOKEN]
        other = signed(agent, cnf_jkt=Agent().jkt)
        assert check(other["params"]["_meta"][REQUEST_PROOF_META_KEY], other).reasons == [ReasonCodes.CNF_KEY_MISMATCH]

    def test_the_legacy_carrier_key_and_profile_verify(self) -> None:
        agent = Agent()
        sent = signed(agent)
        proof = sent["params"]["_meta"].pop(REQUEST_PROOF_META_KEY)
        sent["params"]["_meta"]["org.kya-os/proof@1"] = proof
        carried = kyaos.verifier.read_request_proof(sent["params"]["_meta"])
        assert carried == proof and check(carried, sent).ok


class TestConformanceLevel:
    def test_the_proof_floor_is_a_bool_or_a_verification(self) -> None:
        attested = {"verified": ["orders:read"], "unverified": []}
        assert derive_conformance_level(attested) == "L2"
        assert derive_conformance_level(attested, True) == "L3"
        assert derive_conformance_level(attested, {"ok": True}) == "L3"
        assert derive_conformance_level(attested, {"ok": False}) == "L2"
        assert derive_conformance_level(attested, {"ok": "yes"}) == "L2"
        assert derive_conformance_level(attested, RequestProofVerification(True, [], [])) == "L3"
        assert derive_conformance_level(attested, RequestProofVerification(False, ["x"], ["x"])) == "L2"
        assert derive_conformance_level(attested, None) == "L2"
        assert derive_conformance_level(attested, {"ok": True}, False) == "L2"
        assert derive_conformance_level({"verified": [], "unverified": []}, {"ok": True}) == "L1"
