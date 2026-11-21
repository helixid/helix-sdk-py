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
``isError``), the reference middleware's marker."""

from __future__ import annotations

import inspect
import json
from typing import Any, Awaitable, Callable, Dict, Optional, Union

from helix_sdk.audit import (
    AuditDeliverySink,
    DurableOutbox,
    HttpAuditRecorderClient,
    MemoryAuditOutbox,
)

from .audit import ToolCallAudit

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
