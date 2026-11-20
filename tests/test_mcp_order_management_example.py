# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
examples/mcp_order_management against a real ASGI stack (the MCP Python
SDK's Streamable HTTP transport behind the gate), with a fake HelixID client
and fixed tokens. The same cases as the JS sample's tests. Needs the `mcp`
extra, so Python 3.10+.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

pytest.importorskip("mcp")
pytest.importorskip("starlette")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from starlette.testclient import TestClient  # noqa: E402

from helix_sdk.audit import AUDIT_BINDING_MCP, AuditTrail, MemoryAuditSink, pairwise_did, validate_audit_event  # noqa: E402
from helix_sdk.vp_transport import encode_helix_vp  # noqa: E402
from helix_mcp_middleware import AuthorizationServerUnavailableError, McpAuditTrail, MCPMiddlewareOptions  # noqa: E402
from mcp_order_management.app import create_order_app  # noqa: E402

BASE = "http://127.0.0.1:3700"
RESOURCE = f"{BASE}/mcp"
METADATA = f"{BASE}/.well-known/oauth-protected-resource/mcp"
TOKENS = {
    "reader": {"sub": "user-reader", "scopes": ["orders:read"]},
    "admin": {"sub": "user-admin", "scopes": ["orders:read", "orders:admin"]},
}
JSON_HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}


def fake_client() -> MagicMock:
    """Stands in for the HelixID API: any VP whose id starts with "vp:ok" verifies, with read scope."""
    client = MagicMock()
    client.verify_vp.side_effect = lambda vp, **kw: (
        {"valid": True, "agentDid": "did:key:agent", "privilegeScopes": ["orders:read"], "effectiveScopes": ["orders:read"], "vpId": vp["id"], "delegationChain": []}
        if vp["id"].startswith("vp:ok")
        else {"valid": False, "error": "bad signature"}
    )
    return client


def validate(token: str) -> Dict[str, Any]:
    if token not in TOKENS:
        raise ValueError("unknown token")
    return TOKENS[token]


SERVICE_DID = "did:web:orders.example"


class App:
    """The sample app with typed audit through a MemoryAuditSink-backed
    McpAuditTrail (tool names recorded); `self.audit` is the typed events.
    Pass `audit_sink=` to use the legacy decision sink alone."""

    def __init__(self, **auth: Any) -> None:
        self.sink = MemoryAuditSink()
        self.errors: List[BaseException] = []
        self.trail: Optional[McpAuditTrail] = None
        options = {"client": fake_client(), "service_did": SERVICE_DID, "validate_oauth_token": validate, **auth}
        if "audit_sink" not in auth:
            self.trail = McpAuditTrail(
                AuditTrail(sink=self.sink, source_id="orders-test", producer=pairwise_did(SERVICE_DID), tenant_ref=pairwise_did(SERVICE_DID), binding=AUDIT_BINDING_MCP, include_tool_names=True),
                service_did=SERVICE_DID,
            )
            options["audit_sink"] = self.trail.tool_audit_sink()
        self.http = TestClient(
            create_order_app(RESOURCE, MCPMiddlewareOptions(**options), authorization_servers=["https://as.example.com"], on_server_error=self.errors.append, audit=self.trail),
            base_url=BASE,
        )
        self._id = 0

    @property
    def audit(self) -> List[Dict[str, Any]]:
        return self.sink.events

    @property
    def event_types(self) -> List[str]:
        return self.sink.event_types

    def rpc(self, method: str, params: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> Any:
        self._id += 1
        return self.http.post("/mcp", json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}, headers={**JSON_HEADERS, **(headers or {})})

    def call(self, name: str, args: Dict[str, Any], headers: Optional[Dict[str, str]] = None, meta: Optional[Dict[str, Any]] = None) -> Any:
        return self.rpc("tools/call", {"name": name, "arguments": args, **({"_meta": meta} if meta else {})}, headers)


@pytest.fixture()
def app() -> Any:
    instance = App()
    with instance.http:  # runs the lifespan: the MCP session manager
        yield instance


def bearer(token: str) -> Dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def text(res: Any) -> str:
    return res.json()["result"]["content"][0]["text"]


VP_OK = encode_helix_vp({"id": "vp:ok:1"})


def test_serves_rfc9728_metadata(app: App) -> None:
    res = app.http.get("/.well-known/oauth-protected-resource/mcp")
    assert res.status_code == 200
    assert res.json() == {
        "resource": RESOURCE,
        "authorization_servers": ["https://as.example.com"],
        "scopes_supported": ["orders:read", "orders:admin"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Order Management (HelixID sample)",
    }


def test_initialize_and_tools_list_are_open(app: App) -> None:
    init = app.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}})
    assert init.status_code == 200, init.text
    assert init.json()["result"]["serverInfo"]["name"] == "order-management"
    listed = app.rpc("tools/list", {})
    assert sorted(t["name"] for t in listed.json()["result"]["tools"]) == ["lookup_order", "refund_order"]


def test_no_credentials_is_401_with_both_challenges(app: App) -> None:
    res = app.call("lookup_order", {"orderId": "ORD-1001"})
    assert res.status_code == 401
    challenge = res.headers["www-authenticate"]
    assert f'Bearer resource_metadata="{METADATA}"' in challenge and "HelixVP resource_metadata=" in challenge
    # No identified caller, so the gate reports nothing; the call itself is still recorded as denied.
    assert app.event_types == ["session.established", "tool.call.denied"]
    assert app.audit[1]["reason"] == {"code": "vp_missing"} and app.audit[1]["action"] == {"category": "tool.call", "name": "lookup_order"}
    assert app.audit[0]["correlationId"] == app.audit[1]["correlationId"]


def test_unknown_bearer_is_401_invalid_token(app: App) -> None:
    res = app.call("lookup_order", {"orderId": "ORD-1001"}, bearer("nope"))
    assert res.status_code == 401
    assert 'error="invalid_token"' in res.headers["www-authenticate"]


def test_reader_can_look_up_but_not_refund_and_both_are_audited(app: App) -> None:
    lookup = app.call("lookup_order", {"orderId": "ORD-1001"}, bearer("reader"))
    assert lookup.status_code == 200, lookup.text
    assert json.loads(text(lookup))["status"] == "shipped"

    refund = app.call("refund_order", {"orderId": "ORD-1001", "reason": "damaged"}, bearer("reader"))
    assert refund.status_code == 403
    assert 'error="insufficient_scope"' in refund.headers["www-authenticate"]
    assert 'scope="orders:admin"' in refund.headers["www-authenticate"]
    assert refund.json()["error"] == "insufficient_scope"

    assert app.event_types == [
        "session.established", "authorization.approved", "tool.call.started", "tool.call.completed",
        "session.established", "authorization.denied", "tool.call.denied",
    ]
    granted, denied_event, denied_call = app.audit[1], app.audit[5], app.audit[6]
    assert granted["action"] == {"category": "authorization", "name": "lookup_order"} and granted["outcome"] == "succeeded"
    assert granted["authorization"] == {"source": "policy", "decision": "allowed"}
    assert denied_event["authorization"] == {"source": "policy", "decision": "denied", "scopeId": "orders:admin"}
    assert denied_event["reason"] == {"code": "insufficient_scope"} and denied_call["reason"] == {"code": "insufficient_scope"}
    assert denied_call["action"] == {"category": "tool.call", "name": "refund_order"}
    # The OAuth subject is a keyed commitment, the same for both calls, never the subject itself.
    assert granted["actor"]["kind"] == "keyed_commitment" and granted["actor"] == denied_event["actor"] == denied_call["actor"]
    assert "user-reader" not in json.dumps(app.audit)
    assert all(e["resource"] == {"kind": "public_did", "did": SERVICE_DID} for e in app.audit)
    assert len({e["correlationId"] for e in app.audit[:4]}) == 1 and len({e["correlationId"] for e in app.audit}) == 2
    assert [e["source"]["sourceSequence"] for e in app.audit] == [str(i) for i in range(1, 8)]
    assert all(validate_audit_event(e) == (True, e) for e in app.audit)


def test_admin_refunds_once(app: App) -> None:
    first = app.call("refund_order", {"orderId": "ORD-1002", "reason": "customer request"}, bearer("admin"))
    assert first.status_code == 200, first.text
    refunded = json.loads(text(first))
    assert (refunded["status"], refunded["refundReason"]) == ("refunded", "customer request")
    again = app.call("refund_order", {"orderId": "ORD-1002", "reason": "again"}, bearer("admin"))
    assert again.status_code == 200 and again.json()["result"]["isError"] is True
    assert "already refunded" in text(again)


def test_missing_order_and_bad_arguments_are_tool_errors_not_auth_errors(app: App) -> None:
    missing = app.call("lookup_order", {"orderId": "ORD-9999"}, bearer("reader"))
    assert missing.status_code == 200 and missing.json()["result"]["isError"] is True
    malformed = app.call("lookup_order", {"orderId": "nope"}, bearer("reader"))
    assert malformed.status_code == 200 and malformed.json()["result"]["isError"] is True


def test_unlisted_tool_is_denied_even_for_an_admin(app: App) -> None:
    res = app.call("delete_order", {"orderId": "ORD-1001"}, bearer("admin"))
    assert res.status_code == 403
    assert app.event_types[-2:] == ["authorization.denied", "tool.call.denied"]
    assert app.audit[-2]["reason"] == {"code": "tool_not_permitted"} and app.audit[-1]["reason"] == {"code": "tool_not_permitted"}
    assert app.audit[-1]["action"] == {"category": "tool.call", "name": "delete_order"}


def test_helix_vp_in_the_authorization_header_and_in_meta(app: App) -> None:
    via_header = app.call("lookup_order", {"orderId": "ORD-1001"}, {"authorization": f"HelixVP {VP_OK}"})
    assert via_header.status_code == 200, via_header.text
    via_meta = app.call("lookup_order", {"orderId": "ORD-1001"}, {}, {"x-helix-vp": VP_OK})
    assert via_meta.status_code == 200, via_meta.text
    assert app.event_types == ["session.established", "proof.verified", "authorization.approved", "tool.call.started", "tool.call.completed"] * 2
    assert all(e["actor"] == {"kind": "pairwise_did", "did": "did:key:agent"} for e in app.audit if e["eventType"] != "session.established")
    assert app.audit[1]["details"] == {"family": "proof", "phase": "verified", "verificationCode": "VP_VERIFIED"}
    assert app.audit[2]["authorization"] == {"source": "delegation", "decision": "allowed"}


def test_bad_vp_is_401_and_vp_plus_bearer_is_400(app: App) -> None:
    bad = app.call("lookup_order", {"orderId": "ORD-1001"}, {"authorization": f"HelixVP {encode_helix_vp({'id': 'vp:bad'})}"})
    assert bad.status_code == 401
    both = app.call("lookup_order", {"orderId": "ORD-1001"}, {**bearer("reader"), "x-helix-vp": VP_OK})
    assert both.status_code == 400 and both.json()["error"] == "invalid_request"


def test_malformed_body_wrong_method_unknown_path(app: App) -> None:
    assert app.http.post("/mcp", content="{", headers=JSON_HEADERS).status_code == 400
    assert app.http.get("/mcp").status_code == 405
    assert app.http.get("/elsewhere").status_code == 404
    assert app.http.post("/mcp", content=b"x" * 1_000_001, headers=JSON_HEADERS).status_code == 413


def test_unreachable_authorization_server_is_503_not_401() -> None:
    def down(token: str) -> Any:
        raise AuthorizationServerUnavailableError("JWKS unreachable")

    instance = App(validate_oauth_token=down)
    with instance.http:
        res = instance.call("lookup_order", {"orderId": "ORD-1001"}, bearer("anything"))
    assert res.status_code == 503 and res.headers["retry-after"] == "5"
    assert res.json()["error"] == "temporarily_unavailable"
    assert len(instance.errors) == 1
    assert instance.event_types == ["session.established", "tool.call.failed"]
    assert instance.audit[1]["reason"] == {"code": "authorization_server_unavailable"}


def test_a_server_side_fault_is_500() -> None:
    instance = App(client=None)
    with instance.http:
        res = instance.call("lookup_order", {"orderId": "ORD-1001"}, {"authorization": f"HelixVP {VP_OK}"})
    assert res.status_code == 500 and "www-authenticate" not in res.headers
    assert len(instance.errors) == 1
    assert instance.event_types == ["session.established", "tool.call.failed"]
    assert instance.audit[1]["reason"] == {"code": "server_error"}


def test_batches_are_refused_before_the_gate_so_nothing_is_audited(app: App) -> None:
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}}}
    res = app.http.post("/mcp", json=[call, {**call, "id": 2}], headers={**JSON_HEADERS, **bearer("reader")})
    assert res.status_code == 400 and res.json()["error"]["code"] == -32600
    assert app.audit == []


def test_a_transport_refusal_after_the_gate_is_a_failed_call(app: App) -> None:
    # The MCP transport wants `accept: application/json, text/event-stream`; without it the
    # call was authorized but never ran, so it is recorded as failed, not completed.
    res = app.http.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}}},
        headers={"content-type": "application/json", "accept": "text/plain", **bearer("reader")},
    )
    assert res.status_code == 406
    assert app.event_types == ["session.established", "authorization.approved", "tool.call.started", "tool.call.failed"]
    assert app.audit[-1]["reason"] == {"code": "handler_error"}


def test_the_legacy_audit_sink_alone_still_receives_decisions() -> None:
    legacy: List[Dict[str, Any]] = []
    instance = App(audit_sink=legacy.append)
    with instance.http:
        assert instance.call("lookup_order", {"orderId": "ORD-1001"}, bearer("reader")).status_code == 200
        assert instance.call("refund_order", {"orderId": "ORD-1001", "reason": "x"}, bearer("reader")).status_code == 403
    assert [(e["event"], e["toolName"], e["oauthSubject"], e.get("requiredScope")) for e in legacy] == [
        ("AUTHZ_GRANTED", "lookup_order", "user-reader", None),
        ("AUTHZ_DENIED", "refund_order", "user-reader", "orders:admin"),
    ]
    assert legacy[0]["serviceDid"] == SERVICE_DID and legacy[0]["authMethod"] == "oauth"
    assert instance.audit == []  # no typed trail was wired


def test_absurdly_nested_body_is_400(app: App) -> None:
    assert app.http.post("/mcp", content=b"[" * 200_000, headers=JSON_HEADERS).status_code == 400


def test_body_arriving_in_chunks_is_limited_and_replayed(app: App) -> None:
    def chunks(data: bytes, size: int = 7) -> Any:
        for i in range(0, len(data), size):
            yield data[i : i + size]

    body = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}}}).encode()
    ok = app.http.post("/mcp", content=chunks(body), headers={**JSON_HEADERS, **bearer("reader")})
    assert ok.status_code == 200 and json.loads(text(ok))["id"] == "ORD-1001"
    assert app.http.post("/mcp", content=chunks(b"x" * 1_000_001, 65536), headers=JSON_HEADERS).status_code == 413


def test_host_and_origin_are_limited_to_this_server_and_loopback() -> None:
    options = MCPMiddlewareOptions(validate_oauth_token=validate)
    public = TestClient(create_order_app("https://Orders.Example.com:443/mcp", options), base_url="https://orders.example.com")
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}}}
    with public:
        headers = {**JSON_HEADERS, **bearer("reader")}
        assert public.post("/mcp", json=call, headers=headers).status_code == 200  # Host without the port, any case in the URL
        assert public.post("/mcp", json=call, headers={**headers, "host": "orders.example.com:443"}).status_code == 200
        assert public.post("/mcp", json=call, headers={**headers, "origin": "https://orders.example.com"}).status_code == 200
        assert public.post("/mcp", json=call, headers={**headers, "host": "localhost"}).status_code == 200
        assert public.post("/mcp", json=call, headers={**headers, "host": "evil.example.com"}).status_code == 421
        assert public.post("/mcp", json=call, headers={**headers, "origin": "https://evil.example.com"}).status_code == 403
    for bad in ("localhost:3700/mcp", "ftp://x/mcp", "/mcp"):
        with pytest.raises(ValueError, match="http"):
            create_order_app(bad, options)
