# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story C-C in helix_mcp_middleware, the Python twin of helix-sdk-js
mcp-middleware/tests/level.test.ts: the minimum Card level per tool
(``minimum_level``, ``tools[name]["minimum_level"]``, ``l3_minus_satisfies_l3``),
checked after the scopes; a bearer token next to a proof as its sender
constraint (the section 8.6 ``cnf`` fusion); a chain without a proof
verified at L2 at most; and the level, assurance and ``cnf`` diagnostics in
the audit trail and the HTTP refusal.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from helix_sdk.agent_key import to_public_key_jwk
from helix_sdk.keys import derive_public_key
from helix_sdk.verifier import DELEGATION_CHAIN_META_KEY, REQUEST_PROOF_META_KEY, jwk_thumbprint, sign_request_proof
from helix_mcp_middleware import (
    DEFAULT_MINIMUM_LEVEL,
    MINIMUM_LEVELS,
    PROOF_LEVEL_INSUFFICIENT,
    AuthResult,
    LevelError,
    LevelPolicy,
    MCPMiddlewareOptions,
    ProofError,
    assert_level_policy,
    async_helixid_mcp_middleware,
    cnf_jkt_of,
    create_helix_audit_sink,
    create_local_verifier,
    derive_conformance_level,
    derived_level_of,
    extract_credential,
    helixid_mcp_middleware,
    meets_minimum_level,
    minimum_level_for,
    request_of,
    to_http_error_response,
    verify_request_proof,
)
from mcp_proof_helpers import NOW_MS, fixture_signer, fixture_verifier_options, have_verifier_fixtures, load_environment, valid_chain

ENV = load_environment() if have_verifier_fixtures() else None
needs_fixtures = pytest.mark.skipif(ENV is None, reason="helix-core fixtures/verifier not found")
SERVICE = ENV["keys"]["service"]["did"] if ENV else "did:web:orders.example"
AGENT = ENV["keys"]["agent"]["did"] if ENV else "did:web:agent.example"
TOOLS = {"lookup": ["read:orders"], "refund": ["write:orders"]}
METADATA_URL = "https://orders.example/.well-known/oauth-protected-resource/mcp"


def agent_jkt() -> str:
    assert ENV is not None
    return jwk_thumbprint(to_public_key_jwk(derive_public_key(ENV["keys"]["agent"]["private_key_hex"])))


def signed_meta(name: str = "lookup", cnf_jkt: Optional[str] = None, chain: bool = True) -> Dict[str, Any]:
    assert ENV is not None
    proof = sign_request_proof(
        {"method": "tools/call", "params": {"name": name}}, fixture_signer(ENV, "agent"), audience=SERVICE, now_ms=NOW_MS, cnf_jkt=cnf_jkt
    )
    meta: Dict[str, Any] = {REQUEST_PROOF_META_KEY: proof}
    if chain:
        meta[DELEGATION_CHAIN_META_KEY] = valid_chain()
    return meta


def gate(events: Optional[List[Dict[str, Any]]] = None, **options: Any) -> Any:
    assert ENV is not None
    verifier = create_local_verifier(fixture_verifier_options(SERVICE, env=ENV, cards={AGENT: ENV["cards"]["attested"]}, catalog=["read:orders", "write:orders"]))
    sink = events.append if events is not None else None
    return helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier, service_did=SERVICE, tool_scopes=TOOLS, audit_sink=sink, **options))


def refusal(fn: Any) -> Any:
    with pytest.raises(Exception) as caught:  # noqa: PT011
        fn()
    return caught.value


# ── the level helpers ──────────────────────────────────────────────────────


class TestLevelHelpers:
    def test_levels_and_the_default(self) -> None:
        assert MINIMUM_LEVELS == ("L1", "L2", "L3") and DEFAULT_MINIMUM_LEVEL == "L3"
        assert derive_conformance_level({"verified": ["a"], "unverified": []}, {"ok": True}) == "L3"

    def test_minimum_level_for_a_tool(self) -> None:
        policy = LevelPolicy(minimum_level="L2", tools={"a": {"minimum_level": "L1"}, "b": {"minimumLevel": "L3"}, "c": SimpleNamespace(minimum_level="L1"), "d": {}})
        assert [minimum_level_for(policy, name) for name in ("a", "b", "c", "d", "e", None)] == ["L1", "L3", "L1", "L2", "L2", "L2"]
        assert minimum_level_for(LevelPolicy(), "a") == "L3"

    def test_a_typo_never_lowers_a_bar(self) -> None:
        assert_level_policy(LevelPolicy(minimum_level="L1", tools={"a": {"minimum_level": "L2"}}))
        for policy in (LevelPolicy(minimum_level="L0"), LevelPolicy(minimum_level="l3"), LevelPolicy(tools={"a": {"minimum_level": "L4"}})):
            with pytest.raises(ValueError, match="must be one of L1, L2, L3"):
                assert_level_policy(policy)
        with pytest.raises(ValueError):
            helixid_mcp_middleware(MCPMiddlewareOptions(minimum_level="L3-minus"))

    def test_derived_level_and_meeting_a_minimum(self) -> None:
        assert derived_level_of("L3", "L3-minus") == "L3-minus"
        assert derived_level_of("L3", "L3") == "L3" and derived_level_of("L2", "L3-minus") == "L2" and derived_level_of("L1", None) == "L1"
        assert meets_minimum_level("L3", "L3") and meets_minimum_level("L2", "L1") and not meets_minimum_level("L2", "L3")
        assert meets_minimum_level("L3-minus", "L3") and not meets_minimum_level("L3-minus", "L3", False)
        assert meets_minimum_level("L3-minus", "L2", False) and not meets_minimum_level("L1", "L2")

    def test_level_error_is_a_proof_error_with_its_levels(self) -> None:
        error = LevelError("L2", "L3")
        assert isinstance(error, ProofError) and error.code == PROOF_LEVEL_INSUFFICIENT and error.http_status == 401
        assert (error.derived_level, error.required_level, error.reasons) == ("L2", "L3", ("proof_level_insufficient",))
        response = to_http_error_response(error, METADATA_URL)
        assert response is not None and response.status == 401
        assert response.body == {
            "error": "insufficient_user_authentication",
            "error_description": "This tool needs Card level L3; the call came to L2",
            "derivedLevel": "L2",
            "requiredLevel": "L3",
        }
        assert 'error="insufficient_user_authentication"' in response.headers["WWW-Authenticate"]


class TestTokenCnf:
    def test_cnf_jkt_of_claims(self) -> None:
        assert cnf_jkt_of({"cnf": {"jkt": "abc"}}) == "abc"
        for claims in (None, {}, {"cnf": "abc"}, {"cnf": {"jkt": ""}}, {"cnf": {"jkt": 3}}, "claims"):
            assert cnf_jkt_of(claims) is None  # type: ignore[arg-type]

    def test_a_bearer_next_to_a_proof_or_a_chain(self) -> None:
        proof_and_bearer = extract_credential({"authorization": "Bearer t"}, {REQUEST_PROOF_META_KEY: {"p": 1}})
        assert proof_and_bearer is not None and (proof_and_bearer.kind, proof_and_bearer.bearer) == ("proof", "t")
        chain_only = extract_credential(None, {DELEGATION_CHAIN_META_KEY: [{"hop": 1}]})
        assert chain_only is not None and chain_only.kind == "proof" and chain_only.proof is None and chain_only.chain == [{"hop": 1}]
        with pytest.raises(Exception) as caught:  # noqa: PT011
            extract_credential({"authorization": "Bearer t"}, {DELEGATION_CHAIN_META_KEY: [{"hop": 1}]})
        assert caught.value.code == "CREDENTIAL_CONFLICT"  # type: ignore[attr-defined]


# ── the gate ───────────────────────────────────────────────────────────────


@needs_fixtures
class TestGate:
    def test_a_proven_attested_agent_is_l3_minus_and_meets_the_default_l3(self) -> None:
        events: List[Dict[str, Any]] = []
        caller = gate(events).authorize({"name": "lookup", "_meta": signed_meta()})
        assert (caller.level, caller.proof_assurance, caller.proof_floor, caller.agent_did, caller.cnf_diagnostics) == ("L3", "L3-minus", True, AGENT, None)
        assert events[-1]["event"] == "AUTHZ_GRANTED" and events[-1]["proofAssurance"] == "L3-minus" and events[-1]["l3Minus"] is True
        assert "requiredLevel" not in events[-1] and "cnfDiagnostics" not in events[-1]

    def test_l3_minus_can_be_refused_for_l3_tools_and_the_refusal_is_audited(self) -> None:
        events: List[Dict[str, Any]] = []
        mw = gate(events, l3_minus_satisfies_l3=False)
        error = refusal(lambda: mw({"name": "lookup", "_meta": signed_meta()}))
        assert isinstance(error, LevelError) and (error.derived_level, error.required_level) == ("L3-minus", "L3")
        assert events[-1]["event"] == "AUTHZ_DENIED" and events[-1]["requiredLevel"] == "L3"
        assert events[-1]["reason"] == "level_insufficient: L3-minus < L3" and events[-1]["l3Minus"] is True

    def test_the_level_is_checked_after_the_scopes(self) -> None:
        mw = gate(minimum_level="L3", l3_minus_satisfies_l3=False)
        meta = signed_meta("delete")
        assert refusal(lambda: mw({"name": "delete", "_meta": meta})).code == "TOOL_NOT_PERMITTED"

    def test_a_chain_without_a_proof_is_l2_at_most(self) -> None:
        events: List[Dict[str, Any]] = []
        chain_only = {DELEGATION_CHAIN_META_KEY: valid_chain()}
        error = refusal(lambda: gate(events)({"name": "lookup", "_meta": chain_only}))
        assert isinstance(error, LevelError) and error.derived_level == "L2"
        caller = gate(tools={"lookup": {"minimum_level": "L2"}}).authorize({"name": "lookup", "_meta": chain_only})
        assert (caller.level, caller.proof_floor, caller.agent_did, caller.proof_assurance) == ("L2", False, AGENT, None)
        assert gate(minimum_level="L2").authorize({"name": "lookup", "_meta": chain_only}).level == "L2"

    def test_a_token_cnf_fuses_with_the_proof_for_l3(self) -> None:
        jkt = agent_jkt()
        tokens = {
            "fused": AuthResult(sub="agent-op", scopes=[], cnf_jkt=jkt),
            "claims": {"sub": "agent-op", "scopes": [], "claims": {"cnf": {"jkt": jkt}}},
            "camel": {"sub": "agent-op", "scopes": [], "cnfJkt": jkt},
            "plain": {"sub": "agent-op", "scopes": []},
        }
        # One gate per call, as in the JS twin: a second call on one verifier reads its status from the
        # status cache, which is not fresh, and so comes to L2 (story L3-C point 4).
        def mw() -> Any:
            return gate(validate_oauth_token=lambda token: tokens[token], l3_minus_satisfies_l3=False)

        for token in ("fused", "claims", "camel"):
            caller = mw().authorize({"name": "lookup", "headers": {"authorization": f"Bearer {token}"}, "_meta": signed_meta(cnf_jkt=jkt)})
            assert (caller.auth_method, caller.level, caller.proof_assurance) == ("kyaos", "L3", "L3"), token
        # A token cnf with no proof cnf is refused; a proof cnf with no token cnf is L3-minus with a diagnostic.
        refused = refusal(lambda: mw()({"name": "lookup", "headers": {"authorization": "Bearer fused"}, "_meta": signed_meta()}))
        assert isinstance(refused, ProofError) and refused.reasons == ("cnf_required_by_token",)
        unfused = refusal(lambda: mw()({"name": "lookup", "headers": {"authorization": "Bearer plain"}, "_meta": signed_meta(cnf_jkt=jkt)}))
        assert isinstance(unfused, LevelError) and unfused.derived_level == "L3-minus"
        events: List[Dict[str, Any]] = []
        caller = gate(events).authorize({"name": "lookup", "_meta": signed_meta(cnf_jkt=jkt)})
        assert caller.cnf_diagnostics == ["cnf_present_but_token_unfused"] and events[-1]["cnfDiagnostics"] == ["cnf_present_but_token_unfused"]

    def test_a_bad_bearer_next_to_a_proof_is_refused_as_a_bad_token(self) -> None:
        def reject(_token: str) -> Any:
            raise ValueError("unknown token")

        call = {"name": "lookup", "headers": {"authorization": "Bearer nope"}, "_meta": signed_meta()}
        assert refusal(lambda: gate(validate_oauth_token=reject)(call)).code == "OAUTH_TOKEN_INVALID"
        assert refusal(lambda: gate()(call)).code == "OAUTH_TOKEN_INVALID"

    def test_the_async_gate_applies_the_same_levels(self) -> None:
        assert ENV is not None
        # One gate per call: a second call on one verifier would read its status from the cache, at L2 (story L3-C).
        def mw() -> Any:
            verifier = create_local_verifier(fixture_verifier_options(SERVICE, env=ENV, cards={AGENT: ENV["cards"]["attested"]}, catalog=["read:orders"]))
            return async_helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier, service_did=SERVICE, tool_scopes=TOOLS))

        chain_only = {"name": "lookup", "_meta": {DELEGATION_CHAIN_META_KEY: valid_chain()}}
        with pytest.raises(LevelError):
            asyncio.run(mw()(chain_only))
        assert asyncio.run(mw().authorize({"name": "lookup", "_meta": signed_meta()})).level == "L3"

    def test_the_proof_alone_with_the_verifiers_seams(self) -> None:
        assert ENV is not None
        verifier = create_local_verifier(fixture_verifier_options(SERVICE, env=ENV))
        call = {"name": "lookup", "_meta": signed_meta(cnf_jkt=agent_jkt(), chain=False)}
        verdict = verify_request_proof(verifier, call, token_cnf_jkt=agent_jkt(), skew_seconds=5)
        assert verdict.ok and verdict.did == AGENT and verdict.assurance == "L3"
        assert verify_request_proof(verifier, call).reasons == ["nonce_replayed"]
        assert request_of({"request": {"method": "x"}}) == {"method": "x"}
        assert request_of({"name": "t", "input": {"a": 1}, "_meta": {"k": 1}}) == {"method": "tools/call", "params": {"name": "t", "arguments": {"a": 1}, "_meta": {"k": 1}}}
        assert request_of({}) == {"method": "tools/call", "params": {}}

    def test_the_report_names_the_leaf_for_a_chain_without_a_proof(self) -> None:
        assert ENV is not None
        reports: List[Dict[str, Any]] = []
        verifier = create_local_verifier(fixture_verifier_options(SERVICE, env=ENV, cards={AGENT: ENV["cards"]["attested"]}, report_verification=reports.append))
        assert verifier.verify_call({"name": "lookup", "_meta": {"other": 1}}) is None
        result = verifier.verify_call({"name": "lookup", "_meta": {DELEGATION_CHAIN_META_KEY: valid_chain()}, "require_proof": False})
        assert result is not None and result.ok and result.agent_did == AGENT and result.proof_did is None
        assert (reports[-1]["agentDid"], reports[-1]["proofFloor"], reports[-1]["level"], reports[-1]["l3Minus"]) == (AGENT, False, "L2", False)
        required = verifier.verify_call({"name": "lookup", "_meta": {DELEGATION_CHAIN_META_KEY: valid_chain()}})
        assert required is not None and required.reasons == ["proof_missing"]


class TestAuditSink:
    def test_carries_the_c_c_fields_in_the_typed_events(self) -> None:
        """A-1's strict events hold no C-C member: L3-minus and the cnf diagnostic enter the
        verification code, and a level refusal is authorization.denied with its own reason."""
        posted: List[Dict[str, Any]] = []

        class Http:
            def post(self, url: str, data: bytes, headers: Dict[str, str], timeout: float) -> Any:
                posted.append(json.loads(data))
                return SimpleNamespace(status_code=201)

        sink = create_helix_audit_sink("http://api.test", "hak", service_did="did:web:svc", http=Http())
        sink({
            "event": "AUTHZ_DENIED", "result": "denied", "timestamp": "t", "authMethod": "kyaos", "agentDid": "did:key:z6Mk", "effectiveScopes": [],
            "level": "L3", "fresh": True, "proofAssurance": "L3-minus", "l3Minus": True, "cnfDiagnostics": ["cnf_present_but_token_unfused"],
            "requiredLevel": "L3", "reason": "level_insufficient: L3-minus < L3",
        })
        sink({"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "authMethod": "kyaos", "agentDid": "did:key:z6Mk", "effectiveScopes": [], "level": "L3", "proofAssurance": "L3", "cnfDiagnostics": []})
        sink({"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "authMethod": "kyaos", "agentDid": "did:key:z6Mk", "effectiveScopes": [], "level": "L3", "proofAssurance": "L3-minus", "fresh": False})
        assert [b["eventType"] for b in posted] == [
            "proof.verified", "authorization.denied", "proof.verified", "authorization.approved", "proof.verified", "authorization.approved",
        ]
        assert posted[0]["details"]["verificationCode"] == "KYAOS_PROOF_L3_MINUS_CNF_UNFUSED"
        assert posted[1]["reason"] == {"code": "proof_level_insufficient"}
        assert posted[1]["authorization"] == {"source": "delegation", "decision": "denied"}
        assert posted[2]["details"]["verificationCode"] == "KYAOS_PROOF_L3"
        assert posted[4]["details"]["verificationCode"] == "KYAOS_PROOF_L3_MINUS_CACHED"
        for body in posted:
            text = json.dumps(body)
            assert not any(key in text for key in ("proofAssurance", "l3Minus", "cnfDiagnostics", "requiredLevel"))
