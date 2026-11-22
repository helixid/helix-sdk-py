# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story L3-E in examples/mcp_order_management: a call without the
authority gets the signed needs_authorization challenge as the tool result,
and the retry with the resume token and the delegation credential runs the
tool, through the real MCP Streamable HTTP transport; plus the
KYAOS_AUTHORIZATION_URL / AUDIT_LOG_FILE environment and the demo
authorizer. The same cases as the JS sample's tests/needs-authorization.test.ts.
Needs the `mcp` extra, so Python 3.10+.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

pytest.importorskip("mcp")
pytest.importorskip("starlette")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from starlette.testclient import TestClient  # noqa: E402

from helix_sdk import kyaos  # noqa: E402
from helix_sdk.audit import MemoryAuditSink  # noqa: E402
from helix_sdk.did import build_did_document  # noqa: E402
from helix_sdk.keys import generate_key_pair  # noqa: E402
from helix_mcp_middleware import (  # noqa: E402
    KyaOsOptions,
    MCPMiddlewareOptions,
    MemoryNonceStore,
    MemoryResumeTokenStore,
    NeedsAuthorizationOptions,
    RedisResumeTokenStore,
    create_kyaos,
    create_mcp_audit_trail,
    create_needs_authorization,
)
from mcp_order_management import __main__ as entry  # noqa: E402
from mcp_order_management.app import create_order_app  # noqa: E402
from mcp_order_management.demo_authorizer import demo_retry_authorizer  # noqa: E402

BASE = "http://127.0.0.1:3700"
SERVICE = "did:web:orders.example"
AGENT = "did:key:z6MkdemoAgent"
OTHER = "did:key:z6MkotherAgent"
CONSENT = "https://consent.example/authorize"
KEYS = generate_key_pair()
DOCUMENT = build_did_document(SERVICE, KEYS.public_key)
SIGNER = kyaos.EnvSigner(SERVICE, env_var="SAMPLE_SERVICE_KEY", env={"SAMPLE_SERVICE_KEY": KEYS.private_key})
JSON_HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
TOKENS = {"agent": {"sub": AGENT, "scopes": ["orders:read"]}, "other": {"sub": OTHER, "scopes": ["orders:read"]}}
PROOF = "org.kya-os/response-proof"
REFUND = {"orderId": "ORD-1001", "reason": "damaged"}


def resolve_did(did: str) -> Optional[Dict[str, Any]]:
    return DOCUMENT if did == SERVICE else None


def validate(token: str) -> Dict[str, Any]:
    if token not in TOKENS:
        raise ValueError("unknown token")
    return TOKENS[token]


def hop_for(invoker: str, allowed_action: Any = None, **extra: Any) -> Dict[str, Any]:
    """A §6.10-shaped root hop the demo authorizer accepts (structurally; no signature is verified in DEMO_MODE)."""
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/zcap/v1"],
        "type": ["VerifiableCredential", "DelegationCredential"],
        "issuer": "did:key:z6MkuserConsentKey",
        "validUntil": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "credentialSubject": {"invoker": invoker, "invocationTarget": SERVICE, "parentCapability": SERVICE, "allowedAction": allowed_action if allowed_action is not None else ["orders:admin"]},
        "proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "proofPurpose": "assertionMethod", "proofValue": "z-demo"},
        **extra,
    }


def request(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    return {"method": "tools/call", "params": {"name": name, "arguments": args}}


class Clock:
    def __init__(self) -> None:
        self.current = time.time()

    def now(self) -> float:
        return self.current


class App:
    def __init__(self, with_kyaos: bool) -> None:
        self.clock = Clock()
        self.events: List[Dict[str, Any]] = []
        self.layer = create_needs_authorization(
            NeedsAuthorizationOptions(
                authorization_url=lambda c: f"{CONSENT}?tool={c.tool}&scope={'+'.join(c.scopes)}",
                authorizer=demo_retry_authorizer(SERVICE, now=self.clock.now),
                audit_sink=self.events.append,
                ttl_seconds=60,
                now=self.clock.now,
                service_did=SERVICE,
            )
        )
        options = MCPMiddlewareOptions(service_did=SERVICE, validate_oauth_token=validate, audit_sink=self.events.append, needs_authorization=self.layer)
        runtime = (
            create_kyaos(KyaOsOptions(signer=SIGNER, public_origin=BASE, now=self.clock.now, nonce_store=MemoryNonceStore(now=self.clock.now)))
            if with_kyaos
            else None
        )
        self.http = TestClient(create_order_app(f"{BASE}/mcp", options, kyaos=runtime), base_url=BASE)
        self.next_id = 1

    def call(self, name: str, args: Dict[str, Any], token: str) -> Any:
        self.next_id += 1
        return self.http.post(
            "/mcp",
            headers={**JSON_HEADERS, "authorization": f"Bearer {token}"},
            json={"jsonrpc": "2.0", "id": self.next_id, "method": "tools/call", "params": {"name": name, "arguments": args}},
        )

    def challenge(self) -> Dict[str, Any]:
        response = self.call("refund_order", REFUND, "agent")
        assert response.status_code == 200, response.text
        return response.json()["result"]["structuredContent"]


@pytest.fixture
def app() -> Any:
    instance = App(with_kyaos=True)
    with instance.http:
        yield instance


@pytest.fixture
def plain_app() -> Any:
    instance = App(with_kyaos=False)
    with instance.http:
        yield instance


class TestWithKyaOs:
    def test_a_call_without_the_authority_gets_the_signed_challenge_as_the_tool_result_audited(self, app: App) -> None:
        response = app.call("refund_order", REFUND, "agent")
        assert response.status_code == 200
        body = response.json()
        assert body["id"] == app.next_id
        result = body["result"]
        assert result["isError"] is True
        challenge = result["structuredContent"]
        assert challenge == {
            "error": "needs_authorization",
            "message": "refund_order requires delegation with scope: orders:admin",
            "authorizationUrl": f"{CONSENT}?tool=refund_order&scope=orders:admin",
            "resumeToken": challenge["resumeToken"],
            "expiresAt": int(app.clock.now()) + 60,
            "scopes": ["orders:admin"],
        }
        assert json.loads(result["content"][0]["text"]) == challenge
        proof = result["_meta"][PROOF]
        assert proof["meta"]["outcome"] == "needs_authorization"
        assert proof["meta"]["responseHash"] == kyaos.hash_response(result, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE)
        handled = kyaos.handle_needs_authorization(result, SERVICE, resolve_did, request=request("refund_order", REFUND), now=app.clock.now())
        assert handled.challenge.to_dict() == challenge
        tampered = {**result, "structuredContent": {**challenge, "authorizationUrl": "https://evil.example/"}}
        with pytest.raises(kyaos.ResponseProofError) as caught:
            kyaos.handle_needs_authorization(tampered, SERVICE, resolve_did, request=request("refund_order", REFUND), now=app.clock.now())
        assert caught.value.reason == "response_hash_mismatch"
        assert len(app.events) == 1
        assert {k: app.events[0][k] for k in ("event", "reason", "toolName", "agentDid", "requiredScope", "effectiveScopes", "serviceDid")} == {
            "event": "AUTHZ_DENIED", "reason": "needs_authorization", "toolName": "refund_order", "agentDid": AGENT,
            "requiredScope": "orders:admin", "effectiveScopes": ["orders:read"], "serviceDid": SERVICE,
        }
        # The order was not touched.
        lookup = app.call("lookup_order", {"orderId": "ORD-1001"}, "agent").json()["result"]
        assert json.loads(lookup["content"][0]["text"])["status"] == "shipped"

    def test_the_retry_with_the_token_and_the_hop_runs_the_tool_once_and_a_replay_is_refused(self, app: App) -> None:
        challenge = app.challenge()
        retry = {**REFUND, "_kyaos_resume": challenge["resumeToken"], "_kyaos_delegation": hop_for(AGENT)}
        ok = app.call("refund_order", retry, "agent")
        assert ok.status_code == 200, ok.text
        result = ok.json()["result"]
        assert not result.get("isError")
        order = json.loads(result["content"][0]["text"])
        assert (order["id"], order["status"], order["refundReason"]) == ("ORD-1001", "refunded", "damaged")
        proof = result["_meta"][PROOF]
        assert proof["meta"]["outcome"] == "allowed"
        # The control arguments never reached the tool and are not in the covered request.
        assert proof["meta"]["requestHash"] == kyaos.hash_request(request("refund_order", REFUND))
        assert app.events[-1]["event"] == "AUTHZ_GRANTED" and app.events[-1]["effectiveScopes"] == ["orders:read", "orders:admin"]
        replay = app.call("refund_order", {**retry, "orderId": "ORD-1002"}, "agent")
        assert replay.status_code == 403
        assert replay.json()["error"] == "insufficient_scope"
        assert replay.json()["_meta"][PROOF]["meta"]["outcome"] == "denied" and replay.json()["_meta"][PROOF]["meta"]["reason"] == "RESUME_REFUSED"
        assert "unknown, already used or expired" in replay.json()["error_description"]

    def test_refuses_expired_other_agent_other_tool_no_hop_and_hops_the_demo_authorizer_rejects(self, app: App) -> None:
        token = lambda: app.challenge()["resumeToken"]  # noqa: E731
        expired = token()
        app.clock.current += 61
        assert "unknown, already used or expired" in app.call("refund_order", {**REFUND, "_kyaos_resume": expired, "_kyaos_delegation": hop_for(AGENT)}, "agent").json()["error_description"]
        assert "another agent" in app.call("refund_order", {**REFUND, "_kyaos_resume": token(), "_kyaos_delegation": hop_for(OTHER)}, "other").json()["error_description"]
        wrong_tool = app.call("lookup_order", {"orderId": "ORD-1001", "_kyaos_resume": token(), "_kyaos_delegation": hop_for(AGENT)}, "agent")
        assert wrong_tool.status_code == 403 and "issued for refund_order, not lookup_order" in wrong_tool.json()["error_description"]
        no_hop = app.call("refund_order", {**REFUND, "_kyaos_resume": token()}, "agent")
        assert no_hop.status_code == 403 and "consent alone does not authorise the call" in no_hop.json()["error_description"]
        past = (datetime.fromtimestamp(app.clock.now(), timezone.utc) - timedelta(seconds=1)).isoformat()
        cases = [
            ("not an object", "must be an object"),
            ({**hop_for(AGENT), "type": "VerifiableCredential"}, "not a DelegationCredential"),
            ({**hop_for(AGENT), "credentialSubject": "x"}, "credentialSubject is missing"),
            (hop_for(OTHER), "is not the caller"),
            (hop_for(AGENT, credentialSubject={"invoker": AGENT, "invocationTarget": "did:web:other.example", "allowedAction": ["orders:admin"]}), "is not this service"),
            (hop_for(AGENT, ["orders:read"]), "allowedAction does not cover orders:admin"),
            (hop_for(AGENT, "orders:admin"), "allowedAction does not cover orders:admin"),
            (hop_for(AGENT, validUntil=past), "has expired"),
            ({**hop_for(AGENT), "proof": None}, "carries no proof"),
        ]
        for hop, reason in cases:
            response = app.call("refund_order", {**REFUND, "_kyaos_resume": token(), "_kyaos_delegation": hop}, "agent")
            assert response.status_code == 403, reason
            assert reason in response.json()["error_description"], reason
            assert "the delegation credential was refused" in response.json()["error_description"], reason
        # A single-type credential is read too.
        single = app.call("refund_order", {**REFUND, "_kyaos_resume": token(), "_kyaos_delegation": {**hop_for(AGENT), "type": "DelegationCredential"}}, "agent")
        assert single.status_code == 200, single.text


class TestWithoutKyaOs:
    def test_answers_the_challenge_as_an_unsigned_403_and_still_verifies_the_retry(self, plain_app: App) -> None:
        response = plain_app.call("refund_order", REFUND, "agent")
        assert response.status_code == 403
        body = response.json()
        assert body["error"] == "needs_authorization" and body["authorizationUrl"] == f"{CONSENT}?tool=refund_order&scope=orders:admin"
        assert body["scopes"] == ["orders:admin"] and "_meta" not in body
        ok = plain_app.call("refund_order", {**REFUND, "_kyaos_resume": body["resumeToken"], "_kyaos_delegation": hop_for(AGENT)}, "agent")
        assert ok.status_code == 200, ok.text
        assert json.loads(ok.json()["result"]["content"][0]["text"])["status"] == "refunded"


# ── the environment ──────────────────────────────────────────────────────────


class TestNeedsAuthorizationFromEnv:
    def test_off_without_a_consent_url(self) -> None:
        assert entry.needs_authorization_from_env({}, SERVICE, True, None) is None

    @pytest.mark.parametrize(
        "env,service_did",
        [
            ({"KYAOS_RESUME_TTL_SECONDS": "60"}, SERVICE),
            ({"KYAOS_AUTHORIZATION_URL": CONSENT}, None),
            ({"KYAOS_AUTHORIZATION_URL": "ftp://consent.example"}, SERVICE),
            ({"KYAOS_AUTHORIZATION_URL": "/authorize"}, SERVICE),
            ({"KYAOS_AUTHORIZATION_URL": CONSENT, "KYAOS_RESUME_TTL_SECONDS": "-1"}, SERVICE),
            ({"KYAOS_AUTHORIZATION_URL": CONSENT, "KYAOS_RESUME_TTL_SECONDS": "abc"}, SERVICE),
        ],
    )
    def test_refuses_a_bad_setting(self, env: Dict[str, str], service_did: Optional[str]) -> None:
        with pytest.raises(SystemExit):
            entry.needs_authorization_from_env(env, service_did, True, None)

    def test_builds_the_layer(self) -> None:
        events: List[Dict[str, Any]] = []
        layer = entry.needs_authorization_from_env({"KYAOS_AUTHORIZATION_URL": f"{CONSENT}?brand=orders", "KYAOS_RESUME_TTL_SECONDS": "30"}, SERVICE, True, events.append)
        assert layer is not None and layer.ttl_seconds == 30 and isinstance(layer.store, MemoryResumeTokenStore)
        challenge = layer.challenge(agent_did=AGENT, tool="refund_order", scopes=["orders:admin"]).challenge
        assert challenge["authorizationUrl"] == f"{CONSENT}?brand=orders&agent=did%3Akey%3Az6MkdemoAgent&tool=refund_order&scope=orders%3Aadmin"
        assert events[0]["reason"] == "needs_authorization"
        # DEMO_MODE: the demo authorizer; outside it, every retry is refused.
        assert layer.authorize_retry(challenge["resumeToken"], hop_for(AGENT), entry_context()).scopes == ["orders:admin"]
        strict = entry.needs_authorization_from_env({"KYAOS_AUTHORIZATION_URL": CONSENT}, SERVICE, False, None)
        assert strict is not None
        token = strict.challenge(agent_did=AGENT, tool="refund_order", scopes=["orders:admin"]).challenge["resumeToken"]
        from helix_mcp_middleware import ResumeRefusedError

        with pytest.raises(ResumeRefusedError) as caught:
            strict.authorize_retry(token, hop_for(AGENT), entry_context())
        assert caught.value.reason == "retry_authorizer_missing"

    def test_the_resume_store_follows_the_replay_store_through_the_middleware(self) -> None:
        pytest.importorskip("redis")
        memory = entry.needs_authorization_from_env({"KYAOS_AUTHORIZATION_URL": CONSENT}, SERVICE, True, None)
        assert memory is not None and isinstance(memory.store, MemoryResumeTokenStore)
        env = {"KYAOS_AUTHORIZATION_URL": CONSENT, "KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "redis://127.0.0.1:6380"}
        shared = entry.needs_authorization_from_env(env, SERVICE, True, None)
        assert shared is not None and isinstance(shared.store, RedisResumeTokenStore)
        # A bad replay-store setting stops the sample at startup.
        with pytest.raises(SystemExit):
            entry.needs_authorization_from_env({"KYAOS_AUTHORIZATION_URL": CONSENT, "KYAOS_NONCE_STORE": "postgres"}, SERVICE, True, None)

    def test_the_audit_log_file_gets_every_event_as_a_json_line(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        forwarded: List[Dict[str, Any]] = []
        sink = entry._file_audit_sink(str(path), forwarded.append)
        sink({"event": "AUTHZ_DENIED", "reason": "needs_authorization"})
        entry._file_audit_sink(str(path), None)({"event": "AUTHZ_GRANTED"})
        assert [json.loads(line) for line in path.read_text().splitlines()] == [{"event": "AUTHZ_DENIED", "reason": "needs_authorization"}, {"event": "AUTHZ_GRANTED"}]
        assert forwarded == [{"event": "AUTHZ_DENIED", "reason": "needs_authorization"}]

    def test_main_wires_the_layer_and_the_audit_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        captured: Dict[str, Any] = {}
        monkeypatch.setattr(entry.uvicorn, "run", lambda app, **kw: captured.update(app=app, **kw))
        monkeypatch.setattr(entry, "create_order_app", lambda resource, auth, **kw: captured.update(auth=auth) or object())
        for name in list(entry.os.environ):
            if name.startswith(("KYAOS_", "OAUTH_", "HELIX_", "SERVICE_", "AUDIT_")) or name in ("DEMO_MODE", "PORT", "HOST", "MCP_RESOURCE"):
                monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("DEMO_MODE", "1")
        monkeypatch.setenv("SERVICE_DID", SERVICE)
        monkeypatch.setenv("KYAOS_AUTHORIZATION_URL", CONSENT)
        monkeypatch.setenv("AUDIT_LOG_FILE", str(tmp_path / "audit.jsonl"))
        entry.main()
        auth = captured["auth"]
        assert auth.needs_authorization is not None and auth.audit_sink is not None
        assert entry.DEMO_TOKENS["demo-agent"].sub.startswith("did:key:") and entry.DEMO_TOKENS["demo-agent"].scopes == ["orders:read"]
        out = capsys.readouterr().out
        assert f"needs_authorization challenges to {CONSENT}" in out and "checked structurally (DEMO_MODE" in out and "file " in out
        monkeypatch.delenv("KYAOS_AUTHORIZATION_URL")
        monkeypatch.delenv("AUDIT_LOG_FILE")
        entry.main()
        assert captured["auth"].needs_authorization is None
        assert "Consent:     off" in capsys.readouterr().out


def entry_context() -> Any:
    from helix_mcp_middleware import ChallengeContext

    return ChallengeContext(agent_did=AGENT, tool="refund_order", scopes=["orders:admin"])


class TestWithTheTypedAuditTrail:
    """KYA-OS story A-1 with L3-E: the challenge is a denied call by reason needs_authorization, the retry a completed one."""

    @pytest.mark.parametrize("with_kyaos", [True, False])
    def test_records_the_challenge_as_a_denied_call_then_the_retry_as_a_completed_one(self, with_kyaos: bool) -> None:
        clock = Clock()
        sink = MemoryAuditSink()
        audit = create_mcp_audit_trail(sink, SERVICE)
        layer = create_needs_authorization(
            NeedsAuthorizationOptions(
                authorization_url=CONSENT,
                authorizer=demo_retry_authorizer(SERVICE, now=clock.now),
                audit_sink=audit.tool_audit_sink(),
                now=clock.now,
                service_did=SERVICE,
            )
        )
        options = MCPMiddlewareOptions(service_did=SERVICE, validate_oauth_token=validate, audit_sink=audit.tool_audit_sink(), needs_authorization=layer)
        runtime = (
            create_kyaos(KyaOsOptions(signer=SIGNER, public_origin=BASE, now=clock.now, nonce_store=MemoryNonceStore(now=clock.now)))
            if with_kyaos
            else None
        )
        http = TestClient(create_order_app(f"{BASE}/mcp", options, audit=audit, kyaos=runtime), base_url=BASE)

        def call(args: Dict[str, Any]) -> Any:
            return http.post(
                "/mcp",
                headers={**JSON_HEADERS, "authorization": "Bearer agent"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "refund_order", "arguments": args}},
            )

        with http:
            first = call(REFUND)
            assert first.status_code == (200 if with_kyaos else 403), first.text
            challenge = first.json()["result"]["structuredContent"] if with_kyaos else first.json()
            assert challenge["error"] == "needs_authorization" and challenge["scopes"] == ["orders:admin"]
            assert sink.event_types == ["session.established", "authorization.denied", "tool.call.denied"]
            assert sink.events[1]["reason"] == {"code": "needs_authorization"}
            assert sink.events[1]["authorization"]["scopeId"] == "orders:admin"
            assert sink.events[2]["outcome"] == "denied" and sink.events[2]["reason"] == {"code": "needs_authorization"}
            assert len({event["correlationId"] for event in sink.events}) == 1

            del sink.entries[:]
            ok = call({**REFUND, "_kyaos_resume": challenge["resumeToken"], "_kyaos_delegation": hop_for(AGENT)})
            assert ok.status_code == 200, ok.text
            assert json.loads(ok.json()["result"]["content"][0]["text"])["status"] == "refunded"
            assert sink.event_types == ["session.established", "authorization.approved", "tool.call.started", "tool.call.completed"]
            assert all(challenge["resumeToken"] not in entry.canonical for entry in sink.entries)
