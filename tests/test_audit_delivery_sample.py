# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Story A-2 through the order-management sample over its ASGI stack: no
refund without a recorded intent, the degraded marker when the completion
is not recorded. Needs the `mcp` extra, so Python 3.10+ (the SDK's delivery
tests in test_audit_delivery.py run everywhere)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from starlette.testclient import TestClient  # noqa: E402

from helix_sdk.audit import create_audit_delivery  # noqa: E402
from helix_mcp_middleware import AUDIT_META_KEY, MCPMiddlewareOptions, create_mcp_audit_trail  # noqa: E402
from mcp_order_management.app import create_order_app  # noqa: E402
from mcp_order_management.orders import create_order_store  # noqa: E402
from test_audit_delivery import FakeRecorder  # noqa: E402

def sample(recorder: FakeRecorder) -> Any:
    audit = create_mcp_audit_trail(create_audit_delivery(recorder), "did:web:orders.example", on_error=lambda error: None)
    store = create_order_store()
    options = MCPMiddlewareOptions(service_did="did:web:orders.example", validate_oauth_token=lambda token: {"sub": "admin", "scopes": ["orders:read", "orders:admin"]}, audit_sink=audit.tool_audit_sink())
    app = create_order_app("http://127.0.0.1:3700/mcp", options, store=store, audit=audit)
    return TestClient(app, base_url="http://127.0.0.1:3700"), store


def refund(client: Any) -> Any:
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "refund_order", "arguments": {"orderId": "ORD-1001", "reason": "test"}}},
        headers={"content-type": "application/json", "accept": "application/json, text/event-stream", "authorization": "Bearer admin"},
    )


def test_the_sample_does_not_refund_when_the_intent_cannot_be_recorded() -> None:
    recorder = FakeRecorder()
    recorder.fail_on.add("tool.call.started")
    client, store = sample(recorder)
    with client:
        res = refund(client)
    assert res.status_code == 200
    assert res.json()["id"] == 7
    assert res.json()["result"]["isError"] is True
    assert json.loads(res.json()["result"]["content"][0]["text"])["error"]["code"] == "audit_delivery_failed"
    assert store.get("ORD-1001")["status"] != "refunded"


def test_the_sample_marks_a_refund_degraded_when_its_completion_cannot_be_recorded() -> None:
    recorder = FakeRecorder()
    recorder.fail_on.add("tool.call.completed")
    client, store = sample(recorder)
    with client:
        res = refund(client)
    assert store.get("ORD-1001")["status"] == "refunded"
    result = res.json()["result"]
    assert result["isError"] is True
    assert result["_meta"][AUDIT_META_KEY] == {"status": "degraded", "reason": "Required terminal audit delivery failed after the tool ran"}
    assert int(res.headers["content-length"]) == len(res.content)


def test_the_sample_records_the_whole_call_when_the_recorder_answers() -> None:
    recorder = FakeRecorder()
    client, store = sample(recorder)
    with client:
        res = refund(client)
    assert res.json()["result"].get("isError") in (None, False)
    assert store.get("ORD-1001")["status"] == "refunded"
    assert recorder.recorded == ["session.established", "authorization.approved", "tool.call.started", "tool.call.completed"]
