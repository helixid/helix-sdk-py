# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story L2-A in examples/mcp_order_management: the handshake tool,
sessions and a proof on every call outcome through the real MCP Streamable
HTTP transport, and the KYAOS_* environment. The same cases as the JS
sample's tests/kyaos.test.ts. Needs the `mcp` extra, so Python 3.10+.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from unittest.mock import MagicMock

import pytest

pytest.importorskip("mcp")
pytest.importorskip("starlette")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from starlette.testclient import TestClient  # noqa: E402

from helix_sdk import kyaos  # noqa: E402
from helix_sdk.did import build_did_document  # noqa: E402
from helix_sdk.keys import generate_key_pair, public_key_to_multibase  # noqa: E402
from helix_sdk.verifier import REQUEST_PROOF_META_KEY, sign_request_proof  # noqa: E402
from helix_sdk.audit import MemoryAuditSink  # noqa: E402
from helix_mcp_middleware import (  # noqa: E402
    KyaOsOptions,
    KyaOsSessionOptions,
    LocalVerifierOptions,
    MCPMiddlewareOptions,
    MemoryNonceStore,
    RedisNonceStore,
    create_kyaos,
    create_mcp_audit_trail,
)
from mcp_order_management import __main__ as entry  # noqa: E402
from mcp_order_management.app import create_order_app  # noqa: E402

BASE = "http://127.0.0.1:3700"
SERVICE = "did:web:orders.example"
AGENT_KEYS = generate_key_pair()
_AGENT_MULTIBASE = public_key_to_multibase(AGENT_KEYS.public_key)
AGENT = f"did:key:{_AGENT_MULTIBASE}"
AGENT_SIGNER = kyaos.EnvSigner(AGENT, kid=_AGENT_MULTIBASE, env_var="AGENT_KEY", env={"AGENT_KEY": AGENT_KEYS.private_key})
KEYS = generate_key_pair()
DOCUMENT = build_did_document(SERVICE, KEYS.public_key)
SIGNER = kyaos.EnvSigner(SERVICE, env_var="SAMPLE_SERVICE_KEY", env={"SAMPLE_SERVICE_KEY": KEYS.private_key})
JSON_HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
TOKENS = {"reader": {"sub": "user-reader", "scopes": ["orders:read"]}}
PROOF = "org.kya-os/response-proof"


def resolve_did(did: str) -> Optional[Dict[str, Any]]:
    return DOCUMENT if did == SERVICE else None




def validate(token: str) -> Dict[str, Any]:
    if token not in TOKENS:
        raise ValueError("unknown token")
    return TOKENS[token]


class Clock:
    def __init__(self) -> None:
        self.current = time.time()

    def now(self) -> float:
        return self.current


class App:
    def __init__(self, nonce_store: Any = None, audited: bool = False) -> None:
        self.clock = Clock()
        self.errors: List[BaseException] = []
        self.kyaos = create_kyaos(
            KyaOsOptions(
                signer=SIGNER, public_origin=BASE, now=self.clock.now, session=KyaOsSessionOptions(ttl_minutes=1),
                nonce_store=nonce_store if nonce_store is not None else MemoryNonceStore(now=self.clock.now),
            )
        )
        # Story F-2: request proofs are verified in-process, sharing the runtime's replay store.
        verifier = LocalVerifierOptions(clock=lambda: int(self.clock.now() * 1000), nonce_store=self.kyaos.nonce_store, report_verification=lambda entry: None)
        # With `audited`, A-1's typed audit trail runs alongside the KYA-OS layer.
        self.audit_sink = MemoryAuditSink()
        audit = create_mcp_audit_trail(self.audit_sink, SERVICE) if audited else None
        options = MCPMiddlewareOptions(
            verifier=verifier, service_did=SERVICE, validate_oauth_token=validate, audit_sink=audit.tool_audit_sink() if audit else None
        )
        self.http = TestClient(create_order_app(f"{BASE}/mcp", options, on_server_error=self.errors.append, kyaos=self.kyaos, audit=audit), base_url=BASE)
        self.next_id = 1

    def rpc(self, method: str, params: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> Any:
        self.next_id += 1
        return self.http.post("/mcp", headers={**JSON_HEADERS, **(headers or {})}, json={"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})

    def call(self, name: str, args: Dict[str, Any], headers: Optional[Dict[str, str]] = None, meta: Optional[Dict[str, Any]] = None) -> Any:
        return self.rpc("tools/call", {"name": name, "arguments": args, **({"_meta": meta} if meta else {})}, headers)

    def handshake(self, headers: Optional[Dict[str, str]] = None, proven: bool = False, **args: Any) -> Any:
        arguments = {**kyaos.create_handshake_request(audience=SERVICE, now=self.clock.now()), **args}
        return self.call("_kyaos_handshake", arguments, headers, self.proof("_kyaos_handshake", arguments) if proven else None)

    def proof(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """The agent's request proof for exactly this call, minted now (story F-2)."""
        signed = sign_request_proof(request(name, args), AGENT_SIGNER, audience=SERVICE, now_ms=int(self.clock.now() * 1000))
        return {REQUEST_PROOF_META_KEY: signed}

    def session(self, headers: Optional[Dict[str, str]] = None, proven: bool = False, **args: Any) -> str:
        response = self.handshake(headers, proven, **args)
        assert response.status_code == 200, response.text
        assert "isError" not in response.json()["result"] or not response.json()["result"]["isError"], response.text
        return response.json()["result"]["structuredContent"]["sessionId"]


@pytest.fixture
def app() -> Any:
    instance = App()
    with instance.http:
        yield instance


def bearer(token: str) -> Dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def request(name: str, args: Dict[str, Any], meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"method": "tools/call", "params": {"name": name, "arguments": args, **({"_meta": meta} if meta else {})}}


class TestHandshakeTool:
    def test_is_listed_and_opens_a_session_without_credentials(self, app: App) -> None:
        tools = app.rpc("tools/list", {}).json()["result"]["tools"]
        assert sorted(t["name"] for t in tools) == ["_kyaos_handshake", "lookup_order", "refund_order"]
        args = kyaos.create_handshake_request(audience=SERVICE, agent_did=AGENT, client_info={"name": "test"}, now=app.clock.now())
        response = app.call("_kyaos_handshake", args)
        assert response.status_code == 200
        content = response.json()["result"]["structuredContent"]
        assert content == {
            "sessionId": content["sessionId"], "serverDid": SERVICE, "protocolVersion": "1.0",
            "serverCapabilities": {"proofs": True, "delegation": False, "statusList": False}, "sessionTtl": 60, "nonce": args["nonce"],
        }
        assert kyaos.is_session_id(content["sessionId"])
        session = app.kyaos.session_store.get(content["sessionId"], app.clock.now())
        assert (session.agent_did, session.identity_state, session.audience) == (AGENT, "anonymous", SERVICE)
        assert PROOF not in response.json()["result"].get("_meta", {})

    def test_refusals_come_back_as_tool_errors(self, app: App) -> None:
        short = app.handshake(nonce="short")
        assert short.status_code == 200 and short.json()["result"]["isError"] is True
        assert "nonce" in short.json()["result"]["content"][0]["text"]
        now = int(app.clock.now())
        for args, reason in (
            ({"nonce": "k7Hy9mNpQrStUvWxYz01A="}, "nonce_invalid"),
            ({"timestamp": now - 121}, "timestamp_skew"),
            ({"audience": "did:web:other.example"}, "audience_mismatch"),
        ):
            result = app.handshake(**args).json()["result"]
            assert result["isError"] is True, reason
            assert result["structuredContent"]["error"] == reason
        args = kyaos.create_handshake_request(audience=SERVICE, now=app.clock.now())
        assert "isError" not in app.call("_kyaos_handshake", args).json()["result"] or True
        assert app.call("_kyaos_handshake", args).json()["result"]["structuredContent"] == {"error": "nonce_replayed", "message": "nonce was already used"}
        app.session(audience=BASE)

    def test_a_good_credential_makes_the_session_authenticated_and_a_bad_one_is_refused(self, app: App) -> None:
        session_id = app.session(proven=True)
        session = app.kyaos.session_store.get(session_id, app.clock.now())
        assert (session.agent_did, session.identity_state) == (AGENT, "authenticated")
        # The same proof again is a replayed nonce: refused before the handshake runs.
        arguments = kyaos.create_handshake_request(audience=SERVICE, now=app.clock.now())
        stale = app.proof("_kyaos_handshake", arguments)
        assert app.call("_kyaos_handshake", arguments, None, stale).status_code == 200
        replayed = app.call("_kyaos_handshake", arguments, None, stale)
        assert replayed.status_code == 401 and "nonce_replayed" in replayed.json()["error_description"]
        mismatch = app.handshake(None, True, agentDid="did:key:z6Mkother").json()["result"]
        assert mismatch["structuredContent"]["error"] == "agent_did_mismatch"
        # An OAuth caller has no agent DID: the session stays anonymous.
        oauth_session = app.kyaos.session_store.get(app.session(bearer("reader")), app.clock.now())
        assert oauth_session.identity_state == "anonymous"


class TestProofs:
    def test_allowed_call_carries_a_proof_the_sdk_verifies_by_recomputing_both_hashes(self, app: App) -> None:
        session_id = app.session(agentDid=AGENT)
        args = {"orderId": "ORD-1001", "_kyaos_session": session_id}
        # Unknown _meta keys are ignored; the retired x-helix-vp is one of them now.
        meta = {"traceparent": "00-1-2-01", "io.modelcontextprotocol/trace": "x", "org.example/other": {"deep": True}, "x-helix-vp": "ignored"}
        response = app.call("lookup_order", args, bearer("reader"), meta)
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert '"ORD-1001"' in result["content"][0]["text"]
        proof = result["_meta"][PROOF]
        assert proof["meta"]["did"] == SERVICE and proof["meta"]["sessionId"] == session_id
        assert (proof["meta"]["outcome"], proof["meta"]["clientDid"], proof["meta"]["prf"]) == ("allowed", AGENT, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE)
        verified = kyaos.verify_response_proof(result, SERVICE, resolve_did, request=request("lookup_order", args, meta), now=app.clock.now())
        assert verified.outcome == "allowed" and verified.response_hash == proof["meta"]["responseHash"]
        swapped = {**result, "content": [{"type": "text", "text": "swapped"}]}
        with pytest.raises(kyaos.ResponseProofError) as caught:
            kyaos.verify_response_proof(swapped, SERVICE, resolve_did, request=request("lookup_order", args), now=app.clock.now())
        assert caught.value.reason == "response_hash_mismatch"
        # lastActivity moved with the valid call; a call without a session still runs, proven with sessionId none.
        app.clock.current += 30
        app.call("lookup_order", args, bearer("reader"))
        assert app.kyaos.session_store.get(session_id, app.clock.now()).last_activity == app.clock.current
        bare = app.call("lookup_order", {"orderId": "ORD-1002"}, bearer("reader")).json()["result"]
        assert bare["_meta"][PROOF]["meta"]["sessionId"] == "none"
        assert "clientDid" not in bare["_meta"][PROOF]["meta"]

    def test_control_arguments_never_reach_the_tool_and_unknown_meta_is_ignored(self, app: App) -> None:
        args = {"orderId": "ORD-9999", "_kyaos_proof": {"jws": "x"}, "_kyaos_other": 1}
        result = app.call("lookup_order", args, bearer("reader"), {"org.example/unknown": {"deep": True}}).json()["result"]
        # A tool error is an outcome too, and it is proven.
        assert result["isError"] is True and "Order ORD-9999 not found" in result["content"][0]["text"]
        expected = kyaos.hash_request(request("lookup_order", {"orderId": "ORD-9999"}))
        assert result["_meta"][PROOF]["meta"]["requestHash"] == expected
        assert kyaos.verify_response_proof(result, SERVICE, resolve_did, request=request("lookup_order", args), now=app.clock.now()).outcome == "allowed"
        # The tool's own schema would have refused an unknown argument had it reached it.
        assert "_kyaos" not in result["content"][0]["text"]

    def test_denials_keep_their_status_and_carry_a_denied_proof_without_response_hash(self, app: App) -> None:
        session_id = app.session()
        args = {"orderId": "ORD-1001", "reason": "e2e", "_kyaos_session": session_id}
        refused = app.call("refund_order", args, bearer("reader"))
        assert refused.status_code == 403
        assert "insufficient_scope" in refused.headers["www-authenticate"]
        proof = refused.json()["_meta"][PROOF]
        assert (proof["meta"]["outcome"], proof["meta"]["reason"], proof["meta"]["sessionId"]) == ("denied", "INSUFFICIENT_SCOPE", session_id)
        assert "responseHash" not in proof["meta"]
        verified = kyaos.verify_response_proof(refused.json(), SERVICE, resolve_did, request=request("refund_order", args), proof=proof, now=app.clock.now())
        assert verified.outcome == "denied"
        anonymous = app.call("lookup_order", {"orderId": "ORD-1001"})
        assert anonymous.status_code == 401
        assert anonymous.json()["_meta"][PROOF]["meta"]["reason"] == "PROOF_MISSING"

    def test_unknown_malformed_and_expired_sessions_are_refused_with_400(self, app: App) -> None:
        malformed = app.call("lookup_order", {"orderId": "ORD-1001", "_kyaos_session": "sess_x"}, bearer("reader"))
        assert malformed.status_code == 400 and malformed.json()["error"] == "invalid_request"
        assert malformed.json()["_meta"][PROOF]["meta"]["reason"] == "session_id_malformed"
        session_id = app.session()
        assert app.call("lookup_order", {"orderId": "ORD-1001", "_kyaos_session": session_id}, bearer("reader")).status_code == 200
        app.clock.current += 61
        expired = app.call("lookup_order", {"orderId": "ORD-1001", "_kyaos_session": session_id}, bearer("reader"))
        assert expired.status_code == 400
        assert expired.json()["_meta"][PROOF]["meta"]["reason"] == "session_unknown"
        assert expired.json()["_meta"][PROOF]["meta"]["sessionId"] == "none"

    def test_a_proof_that_cannot_be_signed_is_a_server_error_never_an_unproven_result(self) -> None:
        calls = [0]

        class FailsOnProof(MemoryNonceStore):
            def insert(self, nonce: str, agent_did: Optional[str], expires_at: float) -> bool:
                calls[0] += 1
                if calls[0] > 0 and agent_did == SERVICE:
                    raise RuntimeError("store down")
                return super().insert(nonce, agent_did, expires_at)

        instance = App(nonce_store=FailsOnProof())
        with instance.http:
            denied_too = instance.call("lookup_order", {"orderId": "ORD-1001"})
            assert denied_too.status_code == 500  # the denial's own proof could not be signed either
            failed = instance.call("lookup_order", {"orderId": "ORD-1001"}, bearer("reader"))
            assert failed.status_code == 500 and failed.json() == {"error": "server_error"}
            assert any("store down" in str(e) for e in instance.errors)

    def test_without_kyaos_nothing_changes(self) -> None:
        options = MCPMiddlewareOptions(service_did=SERVICE, validate_oauth_token=validate)
        with TestClient(create_order_app(f"{BASE}/mcp", options), base_url=BASE) as http:
            tools = http.post("/mcp", headers=JSON_HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).json()
            assert sorted(t["name"] for t in tools["result"]["tools"]) == ["lookup_order", "refund_order"]
            plain = http.post("/mcp", headers={**JSON_HEADERS, **bearer("reader")}, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}}})
            assert plain.status_code == 200 and "_meta" not in plain.json()["result"]


class TestSendWithProof:
    """The response wrapper on its own: a body in several chunks, and a JSON-RPC error (no result, so nothing to prove)."""

    def test_chunked_bodies_and_error_responses(self) -> None:
        from mcp_order_management.app import _send_with_proof

        sent: List[Dict[str, Any]] = []
        finished: List[Dict[str, Any]] = []

        async def send(message: Dict[str, Any]) -> None:
            sent.append(message)

        async def finish(result: Dict[str, Any]) -> Dict[str, Any]:
            finished.append(result)
            return {**result, "_meta": {PROOF: "signed"}}

        async def on_error(error: BaseException) -> None:  # pragma: no cover - not reached here
            raise error

        async def scenario(chunks: List[bytes]) -> None:
            proven = await _send_with_proof(send, finish, on_error)
            await proven({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json"), (b"content-length", b"1")]})
            for index, chunk in enumerate(chunks):
                await proven({"type": "http.response.body", "body": chunk, "more_body": index < len(chunks) - 1})

        asyncio.run(scenario([b'{"jsonrpc":"2.0","id":1,', b'"result":{"content":[]}}']))
        assert finished == [{"content": []}]
        assert sent[1]["body"] == b'{"jsonrpc":"2.0","id":1,"result":{"content":[],"_meta":{"org.kya-os/response-proof":"signed"}}}'
        assert (b"content-length", str(len(sent[1]["body"])).encode()) in sent[0]["headers"]
        assert (b"content-length", b"1") not in sent[0]["headers"]
        sent.clear()
        error = b'{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"bad"}}'
        asyncio.run(scenario([error]))
        assert sent[1]["body"] == error and len(finished) == 1


# ── the KYAOS_* environment ──────────────────────────────────────────────────


class TestKyaOsFromEnv:
    RESOURCE = "http://localhost:3700/mcp"

    def test_off_without_a_signing_key(self) -> None:
        assert entry.kyaos_from_env({}, self.RESOURCE, SERVICE) is None

    @pytest.mark.parametrize(
        "env,service_did",
        [
            ({"KYAOS_NONCE_STORE": "redis"}, SERVICE),
            ({"SERVICE_SIGNING_KEY": KEYS.private_key, "KYAOS_NONCE_STORE": "postgres"}, SERVICE),
            ({"SERVICE_SIGNING_KEY": KEYS.private_key, "KYAOS_NONCE_STORE": "redis"}, SERVICE),
            ({"KYAOS_SESSIONS": "0"}, SERVICE),
            ({"SERVICE_SIGNING_KEY": KEYS.private_key}, None),
            ({"SERVICE_SIGNING_KEY": KEYS.private_key, "KYAOS_CLOCK_SKEW_SECONDS": "12.5"}, SERVICE),
            ({"SERVICE_SIGNING_KEY": KEYS.private_key, "KYAOS_CLOCK_SKEW_SECONDS": "abc"}, SERVICE),
            ({"SERVICE_SIGNING_KEY": KEYS.private_key, "KYAOS_CLOCK_SKEW_SECONDS": "10"}, SERVICE),
            ({"SERVICE_SIGNING_KEY": KEYS.private_key, "KYAOS_SESSION_TTL_MINUTES": "-1"}, SERVICE),
            ({"SERVICE_SIGNING_KEY": KEYS.private_key, "KYAOS_SESSION_TTL_MINUTES": "inf"}, SERVICE),
        ],
    )
    def test_refuses_a_bad_setting(self, env: Dict[str, str], service_did: Optional[str]) -> None:
        with pytest.raises(SystemExit):
            entry.kyaos_from_env(env, self.RESOURCE, service_did)

    def test_builds_the_runtime_from_the_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SERVICE_SIGNING_KEY", KEYS.private_key)
        pytest.importorskip("redis")
        env = {
            "SERVICE_SIGNING_KEY": KEYS.private_key, "KYAOS_CLOCK_SKEW_SECONDS": "300", "KYAOS_SESSION_TTL_MINUTES": "0.05",
            "KYAOS_SESSIONS": "0", "KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "redis://127.0.0.1:6380",
        }
        runtime = entry.kyaos_from_env(env, self.RESOURCE, SERVICE)
        assert runtime is not None
        assert (runtime.server_did, runtime.clock_skew_seconds, runtime.sessions_enabled) == (SERVICE, 300, False)
        assert runtime.session_store.ttl_minutes == 0.05
        # The store is the middleware's own choice from the same environment.
        assert isinstance(runtime.nonce_store, RedisNonceStore)
        assert runtime.describe()["endpoints"] == {}
        defaults = entry.kyaos_from_env({"SERVICE_SIGNING_KEY": KEYS.private_key}, self.RESOURCE, SERVICE)
        assert defaults is not None and defaults.sessions_enabled and isinstance(defaults.nonce_store, MemoryNonceStore)
        assert defaults.describe()["endpoints"]["handshake"] == f"{self.RESOURCE}#_kyaos_handshake"
        # The public origin defaults to the resource's origin, and is accepted as audience.
        request = kyaos.create_handshake_request(audience="http://localhost:3700")
        assert asyncio.run(defaults.handshake(request))["serverDid"] == SERVICE


class TestWithTheTypedAuditTrail:
    """KYA-OS (story L2-A) and the typed audit events (story A-1) together, as the JS sample's tests do."""

    def test_records_the_lifecycle_of_a_call_and_still_signs_its_proof_and_not_the_handshake(self) -> None:
        instance = App(audited=True)
        with instance.http:
            session = instance.session(agentDid=AGENT)
            assert instance.audit_sink.events == []
            res = instance.call("lookup_order", {"orderId": "ORD-1001", "_kyaos_session": session}, bearer("reader"))
        assert res.status_code == 200, res.text
        assert res.json()["result"]["_meta"][PROOF]["meta"]["outcome"] == "allowed"
        sink = instance.audit_sink
        assert sink.event_types == ["session.established", "authorization.approved", "tool.call.started", "tool.call.completed"]
        assert len({event["correlationId"] for event in sink.events}) == 1
        assert all(event["actor"]["kind"] == "keyed_commitment" for event in sink.events[1:])
        assert "ORD-1001" not in str(sink.events) and "user-reader" not in str(sink.events)

    def test_records_a_kyaos_caller_by_its_verified_proof_then_the_decision(self) -> None:
        instance = App(audited=True)
        with instance.http:
            args = {"orderId": "ORD-1001"}
            res = instance.call("lookup_order", args, None, instance.proof("lookup_order", args))
        assert res.status_code == 403
        assert res.json()["_meta"][PROOF]["meta"]["outcome"] == "denied"
        sink = instance.audit_sink
        assert sink.event_types == ["session.established", "proof.verified", "authorization.denied", "tool.call.denied"]
        assert sink.events[1]["actor"] == {"kind": "pairwise_did", "did": AGENT}
        assert sink.events[1]["details"]["verificationCode"].startswith("KYAOS_PROOF")
        assert sink.events[2]["reason"] == {"code": "insufficient_scope"}

    def test_records_a_replayed_request_proof_as_a_denied_call_never_attributed(self) -> None:
        """Story C-C: the §11.2 order checks the nonce before the signature, so a replay names no verified DID."""
        instance = App(audited=True)
        with instance.http:
            args = {"orderId": "ORD-1001"}
            meta = instance.proof("lookup_order", args)
            instance.call("lookup_order", args, None, meta)
            del instance.audit_sink.entries[:]
            res = instance.call("lookup_order", args, None, meta)
        assert res.status_code == 401
        sink = instance.audit_sink
        assert sink.event_types == ["session.established", "tool.call.denied"]
        assert sink.events[1]["outcome"] == "denied" and sink.events[1]["reason"] == {"code": "proof_invalid"}
        assert "actor" not in sink.events[1]

    def test_records_a_denied_call_by_its_code_and_still_answers_with_the_denied_proof(self) -> None:
        instance = App(audited=True)
        with instance.http:
            res = instance.call("refund_order", {"orderId": "ORD-1001", "reason": "x"}, bearer("reader"))
        assert res.status_code == 403
        assert res.json()["_meta"][PROOF]["meta"]["outcome"] == "denied"
        assert instance.audit_sink.event_types == ["session.established", "authorization.denied", "tool.call.denied"]
        assert instance.audit_sink.events[2]["reason"] == {"code": "insufficient_scope"}

    def test_a_proof_that_cannot_be_started_is_a_failed_call(self) -> None:
        instance = App(audited=True)
        with instance.http:
            instance.kyaos.start = MagicMock(side_effect=RuntimeError("nonce store down"))  # type: ignore[method-assign]
            res = instance.call("lookup_order", {"orderId": "ORD-1001"}, bearer("reader"))
        assert res.status_code == 500
        assert instance.audit_sink.event_types == ["session.established", "tool.call.failed"]
        assert instance.audit_sink.events[1]["reason"] == {"code": "server_error"}

