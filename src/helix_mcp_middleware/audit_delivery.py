# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Audit delivery for MCP tool calls (story A-2 point 3), the Python twin of
helix-sdk-js ``mcp-middleware/src/audit-delivery.ts``.

``create_helix_audit_delivery`` is the sink an ``McpAuditTrail`` reports
through: submissions to the HelixID recorder (``POST /v1/audit/submissions``)
under ``audit.delivery``: ``required`` by default, ``buffered`` with a durable
outbox directory (an ephemeral outbox is refused at startup), ``best-effort``
only with AAP-1 accepted explicitly.

``run_audited_tool`` wraps one tool handler: the intent (``tool.call.started``)
must be recorded before the handler runs, so a failed intent answers
``audit_delivery_failed`` and the handler never runs; a terminal append that
fails after the handler ran returns the result marked degraded
(``_meta["org.kya-os/audit"] = {"status": "degraded", "reason": ...}`` with
``isError``), the reference middleware's marker.

``audit_tool_handlers`` (``auditToolHandlers``) wraps every tool a FastMCP
server registers in ``async_run_audited_tool``. Python servers are usually
built once, not per request, so the call defaults to the tool call
``McpAuditTrail.begin_tool_call`` opened in the current context."""

from __future__ import annotations

import functools
import inspect
import json
import typing
from typing import Any, Awaitable, Callable, Dict, Optional, TypeVar, Union

from helix_sdk.audit import (
    AuditDeliverySink,
    DurableOutbox,
    HttpAuditRecorderClient,
    MemoryAuditOutbox,
)

from .audit import ToolCallAudit, current_tool_call

AUDIT_META_KEY = "org.kya-os/audit"
"""The ``_meta`` member the reference middleware reports audit status under."""

INTENT_FAILED = "Required intent audit delivery failed; the tool did not run"
TERMINAL_FAILED = "Required terminal audit delivery failed after the tool ran"


def mark_audit_degraded(result: Dict[str, Any], reason: str) -> Dict[str, Any]:
    """A copy of a tool result marked as an error whose audit delivery failed."""
    meta = dict(result.get("_meta") or {})
    previous = meta.get(AUDIT_META_KEY)
    meta[AUDIT_META_KEY] = {**(previous if isinstance(previous, dict) else {}), "status": "degraded", "reason": reason}
    return {**result, "_meta": meta, "isError": True}


def audit_unavailable_response(reason: str = INTENT_FAILED) -> Dict[str, Any]:
    """The answer when the intent could not be recorded: the handler did not run."""
    return {
        "content": [{"type": "text", "text": json.dumps({"success": False, "error": {"code": "audit_delivery_failed", "message": reason}})}],
        "isError": True,
        "_meta": {AUDIT_META_KEY: {"status": "degraded", "reason": reason}},
    }


def _record(step: Callable[[], Any], phase: str, on_audit_error: Optional[Callable[[BaseException, str], None]]) -> bool:
    """Runs one append; False when it raised or the trail swallowed a failure (returned None)."""
    try:
        recorded = step()
    except Exception as error:  # noqa: BLE001 - reported to the caller
        if on_audit_error is not None:
            on_audit_error(error, phase)
        return False
    return recorded is not None


def run_audited_tool(
    call: ToolCallAudit,
    handler: Callable[[], Dict[str, Any]],
    on_audit_error: Optional[Callable[[BaseException, str], None]] = None,
) -> Dict[str, Any]:
    """Runs a synchronous handler as one audited tool call (see the module docstring)."""
    if not _record(call.started, "intent", on_audit_error):
        return audit_unavailable_response()
    try:
        result = handler()
    except Exception:
        _record(lambda: call.failed("handler_error"), "terminal", on_audit_error)
        raise
    if not _record(call.completed, "terminal", on_audit_error):
        return mark_audit_degraded(result, TERMINAL_FAILED)
    return result


async def async_run_audited_tool(
    call: ToolCallAudit,
    handler: Callable[[], Union[Awaitable[Dict[str, Any]], Dict[str, Any]]],
    on_audit_error: Optional[Callable[[BaseException, str], None]] = None,
) -> Dict[str, Any]:
    """``run_audited_tool`` for an async (or sync) handler."""
    if not _record(call.started, "intent", on_audit_error):
        return audit_unavailable_response()
    try:
        result = handler()
        if inspect.isawaitable(result):
            result = await result
    except Exception:
        _record(lambda: call.failed("handler_error"), "terminal", on_audit_error)
        raise
    if not _record(call.completed, "terminal", on_audit_error):
        return mark_audit_degraded(result, TERMINAL_FAILED)  # type: ignore[arg-type]
    return result  # type: ignore[return-value]


def _as_tool_result(value: Any) -> Dict[str, Any]:
    """A tool function's return value as a tool result: a ``CallToolResult`` as
    it is, text as one text block, anything else as its JSON text."""
    dump = getattr(value, "model_dump", None)
    if callable(dump) and type(value).__name__ == "CallToolResult":
        return dump(by_alias=True, exclude_none=True, mode="json")
    text = value if isinstance(value, str) else json.dumps(value)
    return {"content": [{"type": "text", "text": text}]}


_Server = TypeVar("_Server")


def audit_tool_handlers(
    server: _Server,
    call: Optional[ToolCallAudit] = None,
    on_audit_error: Optional[Callable[[BaseException, str], None]] = None,
) -> _Server:
    """Wraps every tool callback the FastMCP ``server`` registers from now on
    (``@server.tool(...)`` and ``server.add_tool(...)``) in
    ``async_run_audited_tool``, so the intent is recorded before the tool runs
    and the completion after. ``call`` defaults to the current context's tool
    call (``current_tool_call()``); with none, the tool runs unaudited. Call
    it before the tools are registered. The wrapped tool answers a
    ``CallToolResult`` (``audit_delivery_failed``, or the result marked
    degraded, when delivery fails); its parameters, and so its input schema,
    are the original function's."""
    from mcp.types import CallToolResult  # the mcp extra (Python 3.10+)

    def audited(fn: Callable[..., Any]) -> Callable[..., Any]:
        hints = typing.get_type_hints(fn, include_extras=True)
        signature = inspect.signature(fn)
        resolved = signature.replace(
            parameters=[parameter.replace(annotation=hints.get(name, parameter.annotation)) for name, parameter in signature.parameters.items()],
            return_annotation=CallToolResult,
        )

        @functools.wraps(fn)
        async def tool(*args: Any, **kwargs: Any) -> Any:
            current = call if call is not None else current_tool_call()
            if current is None:
                value = fn(*args, **kwargs)
                return await value if inspect.isawaitable(value) else value

            async def handler() -> Dict[str, Any]:
                value = fn(*args, **kwargs)
                if inspect.isawaitable(value):
                    value = await value
                return _as_tool_result(value)

            result = await async_run_audited_tool(current, handler, on_audit_error)
            return CallToolResult.model_validate(result)

        # FastMCP reads the parameters (resolved here, so string annotations
        # need not resolve in this module) and passes a CallToolResult through.
        tool.__signature__ = resolved  # type: ignore[attr-defined]
        tool.__annotations__ = {**hints, "return": CallToolResult}
        return tool

    # FastMCP's @server.tool(...) registers through add_tool, so wrapping it covers both.
    add_tool = server.add_tool  # type: ignore[attr-defined]
    server.add_tool = lambda fn, *args, **kwargs: add_tool(audited(fn), *args, **kwargs)  # type: ignore[attr-defined]
    return server


def create_helix_audit_delivery(
    base_url: str,
    api_key: str,
    delivery: str = "required",
    outbox_dir: Optional[str] = None,
    outbox: Any = None,
    accept_aap1: bool = False,
    flush_interval_seconds: float = 1.0,
    ledger_id: Optional[str] = None,
    timeout_seconds: float = 5.0,
    http: Any = None,
    on_delivery_failure: Optional[Callable[[BaseException, Any], None]] = None,
) -> AuditDeliverySink:
    """The delivery sink for a Helix-recorded MCP server. Misconfiguration
    (buffered without a durable outbox, best-effort without accepting AAP-1)
    raises here, at startup. ``outbox="memory"`` asks for the ephemeral outbox,
    which buffered delivery refuses. A buffered sink starts flushing."""
    chosen = MemoryAuditOutbox() if outbox == "memory" else outbox if outbox is not None else DurableOutbox(outbox_dir) if outbox_dir else None
    sink = AuditDeliverySink(
        HttpAuditRecorderClient(base_url, api_key, timeout_seconds=timeout_seconds, http=http),
        delivery=delivery,
        outbox=chosen,
        accept_aap1=accept_aap1,
        ledger_id=ledger_id,
        on_delivery_failure=on_delivery_failure,
    )
    sink.start(flush_interval_seconds)
    return sink
