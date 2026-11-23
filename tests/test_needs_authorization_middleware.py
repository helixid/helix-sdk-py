# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story L3-E in helix_mcp_middleware: the signed needs_authorization
challenge, the resume token and the retry seam (L3.25, L3.26), the same cases
as helix-sdk-js's mcp-middleware/tests/kyaos/needs-authorization.test.ts,
plus the async gate's bridge."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

import helix_mcp_middleware as middleware
from helix_mcp_middleware import (
    DEFAULT_RESUME_TTL_SECONDS,
    ChallengeContext,
    KyaOsNeedsAuthorization,
    KyaOsOptions,
    MCPMiddlewareOptions,
    MemoryNonceStore,
    MemoryResumeTokenStore,
    NeedsAuthorizationError,
    NeedsAuthorizationOptions,
    ResumeRefusedError,
    ResumeTokenRecord,
    RetryAuthorization,
    RetryAuthorizerInput,
    async_helixid_mcp_middleware,
    challenge_tool_result,
    create_kyaos,
    create_needs_authorization,
    helixid_mcp_middleware,
    is_needs_authorization_error,
    read_resume_retry,
    to_http_error_response,
)
from helix_mcp_middleware.needs_authorization_guard import caller_id
from helix_sdk import kyaos
from helix_sdk.did import build_did_document
from helix_sdk.keys import generate_key_pair

SERVER = "did:web:orders.example"
AGENT = "did:key:z6Mkagent"
OTHER = "did:key:z6Mkother"
NOW = 1_750_000_000.0
CONSENT = "https://consent.example/authorize"
TOOL = "refund_order"
SCOPES = ["orders:admin"]
CONTEXT = ChallengeContext(agent_did=AGENT, tool=TOOL, scopes=SCOPES)
TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")
KEYS = generate_key_pair()
SIGNER = kyaos.EnvSigner(SERVER, env_var="K", env={"K": KEYS.private_key})
DOCUMENT = build_did_document(SERVER, KEYS.public_key)

#: A credential the test authorizer accepts: it grants whatever ``allowedAction`` says.
HOP = {"type": ["VerifiableCredential", "DelegationCredential"], "credentialSubject": {"invoker": AGENT, "invocationTarget": SERVER, "allowedAction": ["orders:admin"]}}


def resolve_did(did: str) -> Optional[Dict[str, Any]]:
    return DOCUMENT if did == SERVER else None


def accepting_authorizer(request: RetryAuthorizerInput) -> RetryAuthorization:
    subject = request.credential.get("credentialSubject", {})
    if subject.get("invoker") != request.agent_did:
        raise ValueError("invoker is not the caller")
    return RetryAuthorization(scopes=subject.get("allowedAction", []))


class Clock:
    def __init__(self) -> None:
        self.current = NOW

    def now(self) -> float:
        return self.current


def layer(**overrides: Any) -> Any:
    clock = Clock()
    events: List[Dict[str, Any]] = []
    options: Dict[str, Any] = {"authorization_url": CONSENT, "audit_sink": events.append, "now": clock.now, "service_did": SERVER, **overrides}
    return create_needs_authorization(NeedsAuthorizationOptions(**options)), clock, events


def refusal(run: Any) -> str:
    try:
        run()
    except ResumeRefusedError as error:
        return error.reason
    raise AssertionError("expected a refusal")


class TestCreate:
    def test_validates_its_options(self) -> None:
        for ttl in (0, -1, float("nan"), float("inf"), True):
            with pytest.raises(ValueError, match="ttl_seconds"):
                create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, ttl_seconds=ttl))
        na = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT))
        assert na.ttl_seconds == DEFAULT_RESUME_TTL_SECONDS == 600
        assert isinstance(na.store, MemoryResumeTokenStore)
        assert na.read_retry is read_resume_retry or na.read_retry({"input": {"_kyaos_resume": "t"}}).resume_token == "t"

    def test_builds_the_spec_challenge_with_a_bound_token_and_audits_it(self) -> None:
        na, _clock, events = layer(ttl_seconds=300, display={"title": "Orders", "hint": ["link"]})
        error = na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES, effective_scopes=["orders:read"], auth_method="oauth", oauth_subject="sub-1", level="L2", fresh=True)
        assert isinstance(error, NeedsAuthorizationError)
        assert is_needs_authorization_error(error) and is_needs_authorization_error(MagicMock(code="NEEDS_AUTHORIZATION"))
        assert not is_needs_authorization_error(ValueError("x"))
        assert (error.code, error.http_status, str(error)) == ("NEEDS_AUTHORIZATION", 403, "refund_order requires delegation with scope: orders:admin")
        challenge = error.challenge
        assert challenge == {
            "error": "needs_authorization",
            "message": "refund_order requires delegation with scope: orders:admin",
            "authorizationUrl": CONSENT,
            "resumeToken": challenge["resumeToken"],
            "expiresAt": int(NOW) + 300,
            "scopes": ["orders:admin"],
            "display": {"title": "Orders", "hint": ["link"]},
        }
        assert TOKEN.match(challenge["resumeToken"])
        assert na.store.has(challenge["resumeToken"])
        assert na.store.consume(challenge["resumeToken"]) == ResumeTokenRecord(AGENT, TOOL, ["orders:admin"], NOW + 300)
        assert events == [
            {
                "event": "AUTHZ_DENIED",
                "result": "denied",
                "timestamp": datetime.fromtimestamp(NOW, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "authMethod": "oauth",
                "agentDid": AGENT,
                "oauthSubject": "sub-1",
                "level": "L2",
                "fresh": True,
                "toolName": TOOL,
                "requiredScope": "orders:admin",
                "effectiveScopes": ["orders:read"],
                "reason": "needs_authorization",
                "serviceDid": SERVER,
            }
        ]
        assert challenge_tool_result(challenge) == {
            "isError": True,
            "content": [{"type": "text", "text": json.dumps(challenge, separators=(",", ":"))}],
            "structuredContent": challenge,
        }

    def test_takes_url_message_and_display_from_the_context_and_records_the_first_missing_scope(self) -> None:
        na, _clock, events = layer(
            authorization_url=lambda c: f"{CONSENT}?tool={c.tool}&scope={'+'.join(c.scopes)}",
            message=lambda c: f"grant {', '.join(c.scopes)} to {c.agent_did}",
        )
        error = na.challenge(agent_did=AGENT, tool=TOOL, scopes=["orders:read", "orders:admin"], missing=["orders:admin"], display={"hint": ["qr"], "qrUrl": "https://consent.example/qr"})
        assert error.challenge["authorizationUrl"] == "https://consent.example/authorize?tool=refund_order&scope=orders:read+orders:admin"
        assert error.challenge["message"] == "grant orders:read, orders:admin to did:key:z6Mkagent"
        assert error.challenge["display"] == {"hint": ["qr"], "qrUrl": "https://consent.example/qr"}
        assert events[0]["requiredScope"] == "orders:admin" and events[0]["effectiveScopes"] == [] and events[0]["authMethod"] == "kyaos"
        assert "oauthSubject" not in events[0]
        plain = na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES, message="please", missing=[])
        assert plain.challenge["message"] == "please" and "display" not in plain.challenge
        # The URL is normalised the way the JS URL class serialises it.
        assert layer(authorization_url="HTTPS://Consent.Example")[0].challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES).challenge["authorizationUrl"] == "https://consent.example/"
        with pytest.raises(ValueError, match="at least one scope"):
            na.challenge(agent_did=AGENT, tool=TOOL, scopes=[])
        for bad in ("ftp://consent.example", "not a url", "/authorize"):
            with pytest.raises(ValueError, match="absolute http"):
                create_needs_authorization(NeedsAuthorizationOptions(authorization_url=bad)).challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES)

    def test_never_lets_an_audit_failure_block_the_challenge(self) -> None:
        seen: List[BaseException] = []

        def broken(_event: Dict[str, Any]) -> None:
            raise RuntimeError("sink down")

        na = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, audit_sink=broken, on_audit_error=seen.append))
        assert na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES).challenge["error"] == "needs_authorization"
        assert len(seen) == 1
        silent = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, audit_sink=broken))
        assert silent.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES).challenge["scopes"] == SCOPES

    def test_refuses_async_seams_behind_the_sync_layer(self) -> None:
        async def sink(_event: Dict[str, Any]) -> None:
            return None

        seen: List[BaseException] = []
        na = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, audit_sink=sink, on_audit_error=seen.append))
        na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES)
        assert isinstance(seen[0], TypeError) and "async_helixid_mcp_middleware" in str(seen[0])

        async def authorizer(_request: RetryAuthorizerInput) -> RetryAuthorization:
            return RetryAuthorization(scopes=SCOPES)

        na = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, authorizer=authorizer))
        token = na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES).challenge["resumeToken"]
        assert refusal(lambda: na.authorize_retry(token, HOP, CONTEXT)) == "delegation_refused"


class TestAuthorizeRetry:
    def test_refuses_by_default_so_consent_alone_never_authorises_the_call(self) -> None:
        na, _clock, _events = layer()
        token = na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES).challenge["resumeToken"]
        assert refusal(lambda: na.authorize_retry(token, HOP, CONTEXT)) == "retry_authorizer_missing"

    def test_consumes_the_token_first(self) -> None:
        na, clock, _events = layer(authorizer=accepting_authorizer, ttl_seconds=60)
        issue = lambda: na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES).challenge["resumeToken"]  # noqa: E731
        token = issue()
        assert na.authorize_retry(token, HOP, CONTEXT) == RetryAuthorization(scopes=["orders:admin"])
        assert refusal(lambda: na.authorize_retry(token, HOP, CONTEXT)) == "resume_token_unknown"
        expiring = issue()
        clock.current += 60
        assert refusal(lambda: na.authorize_retry(expiring, HOP, CONTEXT)) == "resume_token_unknown"
        assert refusal(lambda: na.authorize_retry("nope", HOP, CONTEXT)) == "resume_token_malformed"
        assert refusal(lambda: na.authorize_retry(None, HOP, CONTEXT)) == "resume_token_malformed"
        assert refusal(lambda: na.authorize_retry("k7Hy9mNpQrStUvWxYz01AB", HOP, CONTEXT)) == "resume_token_unknown"
        # A retry without the credential spends the token too.
        spent = issue()
        assert refusal(lambda: na.authorize_retry(spent, None, CONTEXT)) == "delegation_missing"
        assert refusal(lambda: na.authorize_retry(spent, HOP, CONTEXT)) == "resume_token_unknown"

    def test_checks_the_binding(self) -> None:
        na, _clock, _events = layer(authorizer=accepting_authorizer)
        issue = lambda scopes=SCOPES: na.challenge(agent_did=AGENT, tool=TOOL, scopes=scopes).challenge["resumeToken"]  # noqa: E731
        assert refusal(lambda: na.authorize_retry(issue(), HOP, ChallengeContext(OTHER, TOOL, SCOPES))) == "resume_token_agent_mismatch"
        assert refusal(lambda: na.authorize_retry(issue(), HOP, ChallengeContext(AGENT, "lookup_order", SCOPES))) == "resume_token_tool_mismatch"
        assert refusal(lambda: na.authorize_retry(issue(), HOP, ChallengeContext(AGENT, TOOL, ["orders:admin", "orders:export"]))) == "resume_token_scope_mismatch"
        # Fewer scopes than the challenge asked for are within the binding.
        assert na.authorize_retry(issue(["orders:read", "orders:admin"]), HOP, CONTEXT).scopes == ["orders:admin"]

    def test_hands_the_credential_to_the_authorizer_and_maps_its_refusal(self) -> None:
        seen: List[RetryAuthorizerInput] = []

        def recording(request: RetryAuthorizerInput) -> Dict[str, Any]:
            seen.append(request)
            return {"scopes": ["orders:admin", 7]}

        na, _clock, _events = layer(authorizer=recording)
        token = na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES).challenge["resumeToken"]
        assert na.authorize_retry(token, HOP, CONTEXT) == RetryAuthorization(scopes=["orders:admin"])
        assert seen == [RetryAuthorizerInput(credential=HOP, token=ResumeTokenRecord(AGENT, TOOL, SCOPES, NOW + 600), agent_did=AGENT, tool=TOOL, scopes=SCOPES)]

        def raising(error: BaseException) -> Any:
            def authorizer(_request: RetryAuthorizerInput) -> Any:
                raise error

            return authorizer

        for authorizer, message in (
            (raising(ValueError("chain does not verify")), "the delegation credential was refused: chain does not verify"),
            (raising(ResumeRefusedError("delegation_refused", "own words")), "own words"),
        ):
            na, _clock, _events = layer(authorizer=authorizer)
            token = na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES).challenge["resumeToken"]
            with pytest.raises(ResumeRefusedError) as caught:
                na.authorize_retry(token, HOP, CONTEXT)
            assert (caught.value.reason, str(caught.value), caught.value.code, caught.value.http_status) == ("delegation_refused", message, "RESUME_REFUSED", 403)
        for answer in (None, {}, {"scopes": "orders:admin"}):
            na, _clock, _events = layer(authorizer=lambda _r, answer=answer: answer)
            token = na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES).challenge["resumeToken"]
            assert na.authorize_retry(token, HOP, CONTEXT) == RetryAuthorization(scopes=[])

    def test_reads_the_retry_from_the_control_arguments(self) -> None:
        assert read_resume_retry({}) is None
        assert read_resume_retry({"input": {"orderId": "ORD-1"}}) is None
        assert read_resume_retry({"input": "x"}) is None
        retry = read_resume_retry({"input": {"orderId": "ORD-1", "_kyaos_resume": "tok"}})
        assert retry is not None and (retry.resume_token, retry.credential) == ("tok", None)
        retry = read_resume_retry({"input": {"_kyaos_resume": "tok", "_kyaos_delegation": HOP}})
        assert retry is not None and retry.credential == HOP


TOKENS = {"agent": {"sub": AGENT, "scopes": ["orders:read"]}, "other": {"sub": OTHER, "scopes": ["orders:read"]}}


def validate(token: str) -> Dict[str, Any]:
    if token not in TOKENS:
        raise ValueError("unknown")
    return TOKENS[token]


def call(name: Optional[str], token: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"name": name, "input": args or {}, "headers": {"authorization": f"Bearer {token}"}}


def gate_options(na: Any, events: List[Dict[str, Any]], **overrides: Any) -> MCPMiddlewareOptions:
    options: Dict[str, Any] = {
        "validate_oauth_token": validate,
        "tool_scopes": {"lookup_order": ["orders:read"], "refund_order": ["orders:admin"]},
        "audit_sink": events.append,
        "needs_authorization": na,
        "service_did": SERVER,
        **overrides,
    }
    return MCPMiddlewareOptions(**options)


class TestGate:
    def test_challenge_then_retry_once_and_never_without_the_credential(self) -> None:
        events: List[Dict[str, Any]] = []
        na = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, authorizer=accepting_authorizer, audit_sink=events.append, now=lambda: NOW))
        gate = helixid_mcp_middleware(gate_options(na, events))
        assert gate.authorize(call("lookup_order", "agent")).oauth_subject == AGENT  # type: ignore[attr-defined]

        def challenge() -> Dict[str, Any]:
            with pytest.raises(NeedsAuthorizationError) as caught:
                gate.authorize(call(TOOL, "agent"))  # type: ignore[attr-defined]
            return caught.value.challenge

        token = challenge()["resumeToken"]
        assert [(e["event"], e.get("reason")) for e in events] == [("AUTHZ_GRANTED", None), ("AUTHZ_DENIED", "needs_authorization")]
        with pytest.raises(ResumeRefusedError) as missing:
            gate.authorize(call(TOOL, "agent", {"_kyaos_resume": token}))  # type: ignore[attr-defined]
        assert missing.value.reason == "delegation_missing"
        with pytest.raises(ResumeRefusedError) as spent:
            gate.authorize(call(TOOL, "agent", {"_kyaos_resume": token, "_kyaos_delegation": HOP}))  # type: ignore[attr-defined]
        assert spent.value.reason == "resume_token_unknown"
        caller = gate.authorize(call(TOOL, "agent", {"orderId": "ORD-1001", "_kyaos_resume": challenge()["resumeToken"], "_kyaos_delegation": HOP}))  # type: ignore[attr-defined]
        assert (caller.auth_method, caller.scopes, caller.oauth_subject) == ("oauth", ["orders:read", "orders:admin"], AGENT)
        assert events[-1]["event"] == "AUTHZ_GRANTED" and events[-1]["effectiveScopes"] == ["orders:read", "orders:admin"]
        with pytest.raises(ResumeRefusedError) as stolen:
            gate.authorize(call(TOOL, "other", {"_kyaos_resume": challenge()["resumeToken"], "_kyaos_delegation": HOP}))  # type: ignore[attr-defined]
        assert stolen.value.reason == "resume_token_agent_mismatch"
        with pytest.raises(ResumeRefusedError) as tool:
            gate.authorize(call("lookup_order", "agent", {"_kyaos_resume": challenge()["resumeToken"], "_kyaos_delegation": HOP}))  # type: ignore[attr-defined]
        assert tool.value.reason == "resume_token_tool_mismatch"

    def test_a_retry_that_grants_too_little_gets_the_plain_403_never_a_second_challenge(self) -> None:
        events: List[Dict[str, Any]] = []
        na = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, authorizer=lambda _r: RetryAuthorization(["orders:export"]), now=lambda: NOW))
        gate = helixid_mcp_middleware(gate_options(na, events))
        with pytest.raises(NeedsAuthorizationError) as caught:
            gate.authorize(call(TOOL, "agent"))  # type: ignore[attr-defined]
        with pytest.raises(middleware.ToolScopeError):
            gate.authorize(call(TOOL, "agent", {"_kyaos_resume": caught.value.challenge["resumeToken"], "_kyaos_delegation": HOP}))  # type: ignore[attr-defined]
        assert events[-1]["reason"] == "insufficient scope" and events[-1]["requiredScope"] == "orders:admin"

    def test_keeps_the_plain_403_without_an_identity_to_bind_to_and_when_off(self) -> None:
        na = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, now=lambda: NOW))
        from types import SimpleNamespace

        class Verifier:
            """A verified proof whose principal the local verifier did not name (story F-2): nothing to bind the token to."""

            def verify_call(self, call: Any) -> Any:
                return SimpleNamespace(ok=True, effective_scopes=["orders:read"], proof_did=None, agent_did=None, level="L1", proof_assurance=None, fresh=True, reasons=[], proof_floor=True, warnings=[])

        anonymous = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=Verifier(), tool_scopes={TOOL: ["orders:admin"]}, needs_authorization=na))
        with pytest.raises(middleware.ToolScopeError):
            anonymous.authorize({"name": TOOL, "_meta": {"org.kya-os/request-proof": {"prf": "org.kya-os/proof.v1"}}})  # type: ignore[attr-defined]
        unnamed = helixid_mcp_middleware(MCPMiddlewareOptions(validate_oauth_token=validate, required_scopes=["orders:admin"], needs_authorization=na))
        with pytest.raises(middleware.ToolScopeError):
            unnamed.authorize({"headers": {"authorization": "Bearer agent"}})  # type: ignore[attr-defined]
        off = helixid_mcp_middleware(MCPMiddlewareOptions(validate_oauth_token=validate, tool_scopes={TOOL: ["orders:admin"]}))
        with pytest.raises(middleware.ToolScopeError):
            off.authorize({"name": TOOL, "input": {"_kyaos_resume": "x"}, "headers": {"authorization": "Bearer agent"}})  # type: ignore[attr-defined]
        assert caller_id({"agentDid": AGENT}) == AGENT and caller_id({"oauthSubject": "s"}) == "s" and caller_id({}) is None

    def test_the_async_gate_bridges_async_store_authorizer_and_audit_sink_onto_the_loop(self) -> None:
        events: List[Dict[str, Any]] = []
        backing = MemoryResumeTokenStore(now=lambda: NOW)

        class AsyncStore:
            async def issue(self, binding: Any, expires_at: float) -> str:
                return backing.issue(binding, expires_at)

            async def consume(self, token: str) -> Any:
                return backing.consume(token)

        async def authorizer(request: RetryAuthorizerInput) -> RetryAuthorization:
            await asyncio.sleep(0)
            return accepting_authorizer(request)

        async def sink(event: Dict[str, Any]) -> None:
            events.append(event)

        na = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, store=AsyncStore(), authorizer=authorizer, audit_sink=sink, now=lambda: NOW))
        gate = async_helixid_mcp_middleware(gate_options(na, events, audit_sink=sink))

        async def scenario() -> Any:
            try:
                await gate.authorize(call(TOOL, "agent"))  # type: ignore[attr-defined]
            except NeedsAuthorizationError as error:
                token = error.challenge["resumeToken"]
            caller = await gate.authorize(call(TOOL, "agent", {"_kyaos_resume": token, "_kyaos_delegation": HOP}))  # type: ignore[attr-defined]
            try:
                await gate.authorize(call(TOOL, "agent", {"_kyaos_resume": token, "_kyaos_delegation": HOP}))  # type: ignore[attr-defined]
            except ResumeRefusedError as error:
                return caller, error.reason
            raise AssertionError("replay accepted")

        caller, reason = asyncio.run(scenario())
        assert caller.scopes == ["orders:read", "orders:admin"] and reason == "resume_token_unknown"
        assert [e.get("reason") for e in events if e["event"] == "AUTHZ_DENIED"] == ["needs_authorization"]
        assert len(backing) == 0


class TestRuntimeSignsTheChallenge:
    def test_outcome_and_response_hash_over_the_whole_result_so_a_tampered_url_fails_the_sdk_check(self) -> None:
        clock = Clock()
        na = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, now=clock.now))
        kya = create_kyaos(KyaOsOptions(signer=SIGNER, now=clock.now, nonce_store=MemoryNonceStore(now=clock.now)))
        request = {"method": "tools/call", "params": {"name": TOOL, "arguments": {"orderId": "ORD-1001", "_kyaos_other": "never hashed"}}}

        def authorize() -> Any:
            raise na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES)

        started = asyncio.run(kya.start({"name": TOOL, "arguments": request["params"]["arguments"]}, authorize=authorize, client_did=AGENT))
        assert isinstance(started, KyaOsNeedsAuthorization) and started.outcome == "needs_authorization"
        assert isinstance(started.error, NeedsAuthorizationError)
        assert TOKEN.match(started.challenge["resumeToken"])
        assert started.result == {**challenge_tool_result(started.challenge), "_meta": {"org.kya-os/response-proof": started.proof}}
        meta = started.proof["meta"]
        assert (meta["did"], meta["outcome"], meta["reason"], meta["clientDid"], meta["sessionId"], meta["prf"]) == (
            SERVER, "needs_authorization", "requires delegation with scope: orders:admin", AGENT, "none", kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE
        )
        assert meta["requestHash"] == kyaos.hash_request(request)
        assert meta["responseHash"] == kyaos.hash_response(started.result, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE)
        handled = kyaos.handle_needs_authorization(started.result, SERVER, resolve_did, request=request, now=NOW)
        assert handled.challenge.to_dict() == started.challenge
        tampered = {**started.result, "structuredContent": {**started.challenge, "authorizationUrl": "https://evil.example/authorize"}}
        with pytest.raises(kyaos.ResponseProofError) as caught:
            kyaos.handle_needs_authorization(tampered, SERVER, resolve_did, request=request, now=NOW)
        assert caught.value.reason == "response_hash_mismatch"
        # call() hands the outcome back instead of running the tool.
        ran: List[bool] = []
        outcome = asyncio.run(kya.call({"name": TOOL, "arguments": {}}, lambda _a, _c: ran.append(True), authorize=authorize))
        assert isinstance(outcome, KyaOsNeedsAuthorization) and ran == []


class TestHttpErrorResponse:
    def test_the_challenge_is_a_403_whose_body_is_the_challenge_and_a_refused_retry_is_insufficient_scope(self) -> None:
        na = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=CONSENT, now=lambda: NOW))
        error = na.challenge(agent_did=AGENT, tool=TOOL, scopes=SCOPES)
        response = to_http_error_response(error, "https://orders.example/.well-known/oauth-protected-resource/mcp")
        assert response is not None and response.status == 403
        assert response.body == {**error.challenge, "error_description": str(error)}
        assert 'error="needs_authorization"' in response.headers["WWW-Authenticate"]
        refused = to_http_error_response(ResumeRefusedError("resume_token_unknown", "spent"), "x")
        assert refused is not None and refused.status == 403 and refused.body == {"error": "insufficient_scope", "error_description": "spent"}


class TestExports:
    def test_exports_the_l3e_layer(self) -> None:
        for name in (
            "create_needs_authorization", "NeedsAuthorization", "NeedsAuthorizationOptions", "NeedsAuthorizationError", "ResumeRefusedError",
            "ResumeRefusalReasons", "RetryAuthorizerInput", "RetryAuthorization", "ChallengeContext", "challenge_tool_result",
            "read_resume_retry", "MemoryResumeTokenStore", "RedisResumeTokenStore", "ResumeTokenStore", "KyaOsNeedsAuthorization",
        ):
            assert name in middleware.__all__, name
            assert getattr(middleware, name) is not None
        assert middleware.RESUME_CONTROL_ARGUMENT == "_kyaos_resume"
        assert middleware.DELEGATION_CONTROL_ARGUMENT == "_kyaos_delegation"
        assert kyaos.handle_needs_authorization is not None and kyaos.retry_with_resume is not None
