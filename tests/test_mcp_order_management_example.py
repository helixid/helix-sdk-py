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

from helix_sdk.vp_transport import encode_helix_vp  # noqa: E402
from helix_mcp_middleware import AuthorizationServerUnavailableError, MCPMiddlewareOptions  # noqa: E402
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


class App:
    def __init__(self, **auth: Any) -> None:
        self.audit: List[Dict[str, Any]] = []
        self.errors: List[BaseException] = []
        options = MCPMiddlewareOptions(
            **{"client": fake_client(), "service_did": "did:web:orders.example", "validate_oauth_token": validate, "audit_sink": self.audit.append, **auth}
        )
        self.http = TestClient(
            create_order_app(RESOURCE, options, authorization_servers=["https://as.example.com"], on_server_error=self.errors.append),
            base_url=BASE,
        )
        self._id = 0

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
    assert app.audit == []


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

    assert [(e["event"], e["toolName"], e["oauthSubject"], e.get("requiredScope")) for e in app.audit] == [
        ("AUTHZ_GRANTED", "lookup_order", "user-reader", None),
        ("AUTHZ_DENIED", "refund_order", "user-reader", "orders:admin"),
    ]
    assert app.audit[0]["serviceDid"] == "did:web:orders.example" and app.audit[0]["authMethod"] == "oauth"


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
    assert (app.audit[-1]["event"], app.audit[-1]["toolName"]) == ("AUTHZ_DENIED", "delete_order")


def test_helix_vp_in_the_authorization_header_and_in_meta(app: App) -> None:
    via_header = app.call("lookup_order", {"orderId": "ORD-1001"}, {"authorization": f"HelixVP {VP_OK}"})
    assert via_header.status_code == 200, via_header.text
    via_meta = app.call("lookup_order", {"orderId": "ORD-1001"}, {}, {"x-helix-vp": VP_OK})
    assert via_meta.status_code == 200, via_meta.text
    assert [(e["event"], e["agentDid"], e["authMethod"]) for e in app.audit] == [("AUTHZ_GRANTED", "did:key:agent", "helixvp")] * 2


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


def test_a_server_side_fault_is_500(app: App) -> None:
    instance = App(client=None)
    with instance.http:
        res = instance.call("lookup_order", {"orderId": "ORD-1001"}, {"authorization": f"HelixVP {VP_OK}"})
    assert res.status_code == 500 and "www-authenticate" not in res.headers
