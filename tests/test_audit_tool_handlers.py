# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""audit_tool_handlers (story A-2), the twin of the JS middleware's
auditToolHandlers: every tool a FastMCP server registers runs audited, its
intent recorded before it runs and its completion after, under the tool call
of the current context (or the one given). Needs the ``mcp`` extra (3.10+)."""

from __future__ import annotations

import asyncio
import json
from typing import Any, List

import pytest

pytest.importorskip("mcp")

from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.types import CallToolResult, TextContent  # noqa: E402

from helix_mcp_middleware import AUDIT_META_KEY, audit_tool_handlers  # noqa: E402
from test_audit_delivery import FakeRecorder, mcp_trail  # noqa: E402


def result_of(value: Any) -> CallToolResult:
    """What FastMCP answers for a tool: the CallToolResult the wrapper returned."""
    assert isinstance(value, CallToolResult), value
    return value


def text_of(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


def server_with_tools(ran: List[str], **options: Any) -> FastMCP:
    server = audit_tool_handlers(FastMCP("t"), **options)

    @server.tool(structured_output=False)
    def lookup_order(orderId: str) -> str:  # noqa: N803 - the wire name
        ran.append(f"lookup:{orderId}")
        return json.dumps({"id": orderId})

    @server.tool(structured_output=False)
    async def count_orders() -> dict:
        ran.append("count")
        return {"count": 2}

    def native(orderId: str) -> CallToolResult:  # noqa: N803
        ran.append("native")
        return CallToolResult(content=[TextContent(type="text", text=orderId)], _meta={"other": 1})

    server.add_tool(native, structured_output=False)
    return server


def test_wraps_every_tool_a_server_registers_and_records_intent_before_and_completion_after() -> None:
    recorder = FakeRecorder()
    audit = mcp_trail(recorder)
    ran: List[str] = []
    server = server_with_tools(ran)

    async def scenario() -> None:
        with audit.begin_tool_call("lookup_order"):
            answer = result_of(await server.call_tool("lookup_order", {"orderId": "ORD-1"}))
            assert json.loads(text_of(answer)) == {"id": "ORD-1"} and not answer.isError
        with audit.begin_tool_call("count_orders"):
            assert json.loads(text_of(result_of(await server.call_tool("count_orders", {})))) == {"count": 2}
        with audit.begin_tool_call("native"):
            native = result_of(await server.call_tool("native", {"orderId": "ORD-2"}))
            assert text_of(native) == "ORD-2" and native.meta == {"other": 1}

    asyncio.run(scenario())
    assert ran == ["lookup:ORD-1", "count", "native"]
    assert recorder.recorded == ["session.established", "tool.call.started", "tool.call.completed"] * 3
    # The input schema is the original function's.
    tool = next(t for t in asyncio.run(server.list_tools()) if t.name == "lookup_order")
    assert tool.inputSchema["required"] == ["orderId"]


def test_outside_a_tool_call_the_tool_runs_unaudited() -> None:
    ran: List[str] = []
    server = server_with_tools(ran)
    answer = asyncio.run(server.call_tool("count_orders", {}))
    assert ran == ["count"]
    assert not isinstance(answer, CallToolResult)  # FastMCP's own conversion: no audit wrapper result


def test_does_not_run_a_tool_whose_intent_cannot_be_recorded_and_marks_a_failed_completion() -> None:
    recorder = FakeRecorder()
    audit = mcp_trail(recorder)
    ran: List[str] = []
    phases: List[str] = []
    server = server_with_tools(ran, on_audit_error=lambda error, phase: phases.append(phase))

    async def scenario() -> None:
        recorder.fail_on.add("tool.call.started")
        with audit.begin_tool_call("lookup_order"):
            refused = result_of(await server.call_tool("lookup_order", {"orderId": "ORD-1"}))
        assert refused.isError and json.loads(text_of(refused))["error"]["code"] == "audit_delivery_failed"
        assert ran == []
        recorder.fail_on = {"tool.call.completed"}
        with audit.begin_tool_call("lookup_order"):
            degraded = result_of(await server.call_tool("lookup_order", {"orderId": "ORD-1"}))
        assert ran == ["lookup:ORD-1"]
        assert degraded.isError and (degraded.meta or {})[AUDIT_META_KEY]["status"] == "degraded"

    asyncio.run(scenario())
    assert phases == ["intent", "terminal"]


def test_an_explicit_call_is_used_even_outside_its_context_and_a_failing_tool_is_recorded_failed() -> None:
    recorder = FakeRecorder()
    audit = mcp_trail(recorder)
    with audit.begin_tool_call("boom") as call:
        pass
    server = audit_tool_handlers(FastMCP("t"), call)

    @server.tool(structured_output=False)
    def boom() -> str:
        raise ValueError("no such order")

    with pytest.raises(Exception, match="no such order"):
        asyncio.run(server.call_tool("boom", {}))
    assert recorder.recorded == ["session.established", "tool.call.started", "tool.call.failed"]
