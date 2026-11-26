# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""The one-line HTTP gate, HelixMcpGate (parity with helix-sdk-js's http-gate.test.ts): metadata, method
policy, refusals mapped to HTTP, the audited call, the KYA-OS session layer, and the request replayed to
the app behind it."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

pytest.importorskip("starlette")

from starlette.testclient import TestClient  # noqa: E402

from helix_sdk.audit import MemoryAuditSink  # noqa: E402
from helix_mcp_middleware import (  # noqa: E402
    AUTHENTICATED_AGENT_STATE_KEY,
    HelixMcpGate,
    HelixMcpGateOptions,
    LocalVerifierOptions,
    create_mcp_audit_trail,
)
from helix_mcp_middleware.errors import AuthorizationServerUnavailableError  # noqa: E402
from helix_mcp_middleware.delegation.outbound import current_delegation  # noqa: E402
from helix_mcp_middleware.kyaos.nonce_store import MemoryNonceStore  # noqa: E402
from helix_mcp_middleware.kyaos.runtime import KyaOsAllowed, KyaOsDenied, KyaOsNeedsAuthorization  # noqa: E402

SERVICE = "did:web:orders.helix.test"
READER = {"authorization": "Bearer reader"}
RESOURCE = "http://testserver/mcp"


def validate(token: str) -> Dict[str, Any]:
    if token == "reader":
        return {"sub": "user-1", "scopes": ["orders:read"]}
    raise ValueError("unknown token")


class Behind:
    """The app behind the gate: echoes the body it was replayed, the scope state and the delegation it runs in."""

    def __init__(self, result: Optional[Dict[str, Any]] = None) -> None:
        self.seen: List[Dict[str, Any]] = []
        self.result = result

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        message = await receive()
        body = json.loads(message["body"]) if message.get("body") else None
        self.seen.append({"path": scope["path"], "body": body, "state": dict(scope.get("state", {})), "delegation": current_delegation()})
        payload = {"jsonrpc": "2.0", "id": 1, "result": self.result} if self.result is not None else {"path": scope["path"], "body": body}
        raw = json.dumps(payload).encode()
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())]})
        await send({"type": "http.response.body", "body": raw})


def client(behind: Any = None, **options: Any) -> Any:
    app = behind if behind is not None else Behind()
    settings: Dict[str, Any] = {"resource": RESOURCE, "validate_oauth_token": validate, "tool_scopes": {"lookup_order": ["orders:read"], "refund_order": ["orders:admin"]}}
    settings.update(options)
    gate = HelixMcpGate(app, **settings)
    return TestClient(gate), gate, app


def rpc(http: Any, method: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None, **extra: Any) -> Any:
    body = {"jsonrpc": "2.0", "id": 1, "method": method, **({"params": params} if params is not None else {}), **extra}
    return http.post("/mcp", json=body, headers=headers or {})


def test_serves_metadata_passes_other_paths_and_answers_405() -> None:
    http, gate, behind = client(resource_name="Orders", authorization_servers=["https://login.example"], resource_scopes={"file:///a": ["docs:read"]})
    assert gate.mcp_path == "/mcp" and gate.metadata_url == "http://testserver/.well-known/oauth-protected-resource/mcp"
    assert http.get("/.well-known/oauth-protected-resource/mcp").json() == {
        "resource": RESOURCE,
        "authorization_servers": ["https://login.example"],
        "scopes_supported": ["orders:read", "orders:admin", "docs:read"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Orders",
    }
    assert http.get("/elsewhere").json() == {"path": "/elsewhere", "body": None}
    res = http.get("/mcp")
    assert (res.status_code, res.headers["allow"]) == (405, "POST")


def test_open_methods_pass_and_the_rest_need_a_caller() -> None:
    http, _, behind = client(scopes_supported=["custom"])
    assert rpc(http, "initialize", {"protocolVersion": "2025-06-18"}).status_code == 200
    assert behind.seen[-1]["body"]["method"] == "initialize"
    listed = rpc(http, "resources/list", {})
    assert listed.status_code == 401 and 'resource_metadata="http://testserver/.well-known/oauth-protected-resource/mcp"' in listed.headers["www-authenticate"]
    assert rpc(http, "ping").status_code == 401
    assert rpc(http, "tools/call", {"name": "lookup_order", "arguments": {}}).status_code == 401
    scoped = rpc(http, "tools/call", {"name": "refund_order", "arguments": {}}, READER)
    assert (scoped.status_code, scoped.json()["error"]) == (403, "insufficient_scope")
    assert rpc(http, "tools/call", {"name": "lookup_order", "arguments": {"orderId": "ORD-1"}}, READER).status_code == 200
    assert behind.seen[-1]["body"]["params"]["arguments"] == {"orderId": "ORD-1"}


def test_refuses_bad_json_an_oversized_body_and_a_batch_and_stops_when_the_client_leaves() -> None:
    http, gate, _ = client(max_body_bytes=40)
    assert http.post("/mcp", content=b"not json").status_code == 400
    big = rpc(http, "initialize", {"pad": "x" * 100})
    assert (big.status_code, big.json()["error"]["message"]) == (413, "Request body too large")
    batch = client()[0].post("/mcp", json=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}])
    assert (batch.status_code, batch.json()["error"]["code"]) == (400, -32600)
    sent: List[Any] = []

    async def gone() -> Dict[str, Any]:
        return {"type": "http.disconnect"}

    async def send(message: Any) -> None:
        sent.append(message)

    import asyncio

    asyncio.run(gate({"type": "http", "path": "/mcp", "method": "POST", "headers": []}, gone, send))
    assert sent == []


def test_a_down_authorization_server_is_503_and_other_faults_500_reported() -> None:
    faults: List[BaseException] = []

    def down(token: str) -> Any:
        raise AuthorizationServerUnavailableError("down")

    http, _, _ = client(validate_oauth_token=down, on_server_error=faults.append)
    res = rpc(http, "tools/call", {"name": "lookup_order"}, READER)
    assert (res.status_code, res.headers["retry-after"], res.json()["error"]) == (503, "5", "temporarily_unavailable")
    # A proof with no verifier configured is this server's fault: 500, for a tool call and for any other method.
    broken, _, _ = client(on_server_error=faults.append)
    meta = {"org.kya-os/request-proof": {"prf": "x"}}
    assert rpc(broken, "tools/call", {"name": "lookup_order", "_meta": meta}).status_code == 500
    assert rpc(broken, "resources/list", {"_meta": meta}).status_code == 500
    assert len(faults) == 3

    class Crashes:
        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            raise RuntimeError("behind")

    crash, _, _ = client(behind=Crashes(), on_server_error=faults.append)
    assert rpc(crash, "initialize").status_code == 500
    assert len(faults) == 4


def test_records_the_call_and_runs_it_in_the_callers_delegation() -> None:
    sink = MemoryAuditSink()
    audit = create_mcp_audit_trail(reporter=sink, service_did=SERVICE)
    events: List[Dict[str, Any]] = []
    http, _, behind = client(audit=audit, service_did=SERVICE, trust_proxy=True)
    assert rpc(http, "tools/call", {"name": "lookup_order", "arguments": {}}, {**READER, "x-forwarded-for": "203.0.113.9, 10.0.0.1"}).status_code == 200
    assert sink.event_types == ["session.established", "authorization.approved"]
    assert behind.seen[-1]["delegation"] is None  # an OAuth caller carries no chain to forward
    assert rpc(http, "tools/call", {"name": "lookup_order"}).status_code == 401
    assert sink.event_types[2:] == ["session.established", "authorization.denied", "tool.call.denied"]
    # The gate's own sink, when given, is used as is; the forwarded address reaches it only with trust_proxy.
    own, _, _ = client(audit=audit, audit_sink=events.append)
    rpc(own, "tools/call", {"name": "lookup_order"}, {"x-forwarded-for": "203.0.113.9"})
    assert events[0]["clientIp"] == "testclient" and events[0]["reasonCode"] == "proof_missing"
    trusted, _, _ = client(audit_sink=events.append, trust_proxy=True)
    rpc(trusted, "ping", None, {"x-forwarded-for": "203.0.113.9"})
    rpc(trusted, "ping")
    assert [event["clientIp"] for event in events[1:]] == ["203.0.113.9", "testclient"]


def test_builds_the_verifier_with_the_replay_store_from_env_the_runtimes_or_the_given_one() -> None:
    fake = SimpleNamespace(handshake_tool_name="_kyaos_handshake", nonce_store=MemoryNonceStore())
    from_env = HelixMcpGate(Behind(), resource=RESOURCE, verifier=LocalVerifierOptions(service_did=SERVICE), env={})
    assert isinstance(from_env.gate.verifier.nonce_store, MemoryNonceStore)  # type: ignore[attr-defined]
    clocked = HelixMcpGate(Behind(), resource=RESOURCE, verifier=LocalVerifierOptions(service_did=SERVICE, clock=lambda: 1_000), env={})
    assert clocked.gate.verifier is not None  # type: ignore[attr-defined]
    store = MemoryNonceStore()
    given = HelixMcpGate(Behind(), resource=RESOURCE, verifier=LocalVerifierOptions(service_did=SERVICE, nonce_store=store))
    assert given.gate.verifier.nonce_store is store  # type: ignore[attr-defined]
    runtime = HelixMcpGate(Behind(), resource=RESOURCE, verifier=LocalVerifierOptions(service_did=SERVICE), kyaos=fake)
    assert runtime.gate.verifier.nonce_store is fake.nonce_store  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="not both"):
        HelixMcpGate(Behind(), HelixMcpGateOptions(resource=RESOURCE), resource=RESOURCE)
    with pytest.raises(ValueError, match="http"):
        HelixMcpGate(Behind(), resource="ftp://x/mcp")


class FakeKyaOs:
    """A KYA-OS runtime stand-in: the handshake tool, and ``start`` answering as told."""

    handshake_tool_name = "_kyaos_handshake"

    def __init__(self, outcomes: Optional[List[Any]] = None) -> None:
        self.nonce_store = MemoryNonceStore()
        self.outcomes = outcomes or []

    def is_handshake(self, name: Optional[str]) -> bool:
        return name == self.handshake_tool_name

    async def start(self, call: Dict[str, Any], authorize: Any) -> Any:
        return await self.outcomes.pop(0)(authorize)


def test_the_handshake_is_open_to_anonymous_agents_and_a_credential_on_it_must_be_good() -> None:
    sink = MemoryAuditSink()
    http, _, behind = client(kyaos=FakeKyaOs(), audit=create_mcp_audit_trail(reporter=sink, service_did=SERVICE))
    assert rpc(http, "tools/call", {"name": "_kyaos_handshake", "arguments": {}}).status_code == 200
    assert AUTHENTICATED_AGENT_STATE_KEY not in behind.seen[-1]["state"]
    assert rpc(http, "tools/call", {"name": "_kyaos_handshake", "arguments": {}}, {"authorization": "Bearer nope"}).status_code == 401
    assert rpc(http, "tools/call", {"name": "_kyaos_handshake", "arguments": {}}, READER).status_code == 200
    assert AUTHENTICATED_AGENT_STATE_KEY in behind.seen[-1]["state"]  # an OAuth caller names no agent DID: None
    assert sink.event_types == ["authorization.denied", "authorization.approved"]  # the gate's decisions; no audited tool call


def test_answers_a_denied_start_a_needs_authorization_and_signs_an_allowed_result() -> None:
    async def denied(authorize: Any) -> Any:
        try:
            await authorize()
        except Exception as error:  # noqa: BLE001
            return KyaOsDenied(reason="proof_missing", error=error, proof={"jws": "j", "meta": {"outcome": "denied"}}, request_hash="h")
        raise AssertionError("expected a refusal")  # pragma: no cover

    async def challenged(authorize: Any) -> Any:
        error = RuntimeError("needs authorization")
        error.code = "NEEDS_AUTHORIZATION"  # type: ignore[attr-defined]
        return KyaOsNeedsAuthorization(challenge={}, error=error, proof={}, request_hash="h", result={"isError": True, "_meta": {"p": 1}})

    async def allowed(authorize: Any) -> Any:
        await authorize()

        async def finish(result: Any) -> Dict[str, Any]:
            return {**result, "_meta": {"signed": True}}

        return KyaOsAllowed(arguments={"orderId": "ORD-1"}, request_hash="h", _finish=finish, session=SimpleNamespace(id="s1"))

    async def broken(authorize: Any) -> Any:
        raise RuntimeError("nonce store down")

    faults: List[BaseException] = []
    sink = MemoryAuditSink()
    http, _, behind = client(Behind(result={"content": []}), kyaos=FakeKyaOs([denied, challenged, allowed, broken]), audit=create_mcp_audit_trail(reporter=sink, service_did=SERVICE), on_server_error=faults.append)
    res = rpc(http, "tools/call", {"name": "lookup_order", "arguments": {}})
    assert (res.status_code, res.json()["_meta"]["org.kya-os/response-proof"]) == (401, {"jws": "j", "meta": {"outcome": "denied"}})
    challenge = rpc(http, "tools/call", {"name": "lookup_order", "arguments": {}}, READER)
    assert challenge.json() == {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "_meta": {"p": 1}}}
    ok = rpc(http, "tools/call", {"name": "lookup_order", "arguments": {"orderId": "ORD-1", "_kyaos_session": "s1"}}, READER)
    assert ok.json()["result"] == {"content": [], "_meta": {"signed": True}}
    assert behind.seen[-1]["body"]["params"]["arguments"] == {"orderId": "ORD-1"}
    assert rpc(http, "tools/call", {"name": "lookup_order", "arguments": {}}, READER).status_code == 500
    assert [str(f) for f in faults] == ["nonce store down"]
    assert sink.event_types.count("tool.call.failed") == 1
