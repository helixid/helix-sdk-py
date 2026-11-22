# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""An MCP server over Streamable HTTP (stateless, JSON responses) with every
tool call gated by helix_mcp_middleware.

The gate runs at the HTTP layer, in front of the MCP transport, so a missing
or invalid credential gets a real HTTP 401 with `WWW-Authenticate` pointing
at the RFC 9728 metadata (which is how OAuth clients discover the
authorization server), and a scope failure gets a 403. Only `tools/call` is
gated: `initialize` and `tools/list` stay open, so HelixID clients that send
their VP in `params._meta` (not a header) keep working, and a VP is verified
once per tool call, not once per request.

With an `audit` trail (McpAuditTrail), every gated tools/call is bracketed
by typed KYA-OS audit events: `session.established` before the gate, the
gate's own decision events (`proof.verified`, `delegation.verified` for a
HelixID VP, `authorization.approved` / `denied`), then `tool.call.started`
and `tool.call.completed` / `tool.call.failed`, or `tool.call.denied` when
the gate refused, all under one correlationId. An audit write that fails
fails the call (a 500): a call that cannot be recorded does not run."""

from __future__ import annotations

import json
from contextlib import nullcontext
from dataclasses import replace
from typing import Any, Callable, Optional, Sequence
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from helix_sdk import decode_helix_vp
from helix_mcp_middleware import (
    AuthorizationServerUnavailableError,
    audit_unavailable_response,
    mark_audit_degraded,
    McpAuditTrail,
    MCPMiddlewareOptions,
    async_helixid_mcp_middleware,
    build_protected_resource_metadata,
    extract_credential,
    protected_resource_metadata_url,
    to_http_error_response,
)

from helix_mcp_middleware.audit_delivery import TERMINAL_FAILED

from .orders import TOOL_SCOPES, OrderStore, create_order_store, register_order_tools

MAX_BODY_BYTES = 1_000_000


def create_order_app(
    resource: str,
    auth: MCPMiddlewareOptions,
    authorization_servers: Optional[Sequence[str]] = None,
    store: Optional[OrderStore] = None,
    on_server_error: Optional[Callable[[BaseException], None]] = None,
    audit: Optional[McpAuditTrail] = None,
) -> Any:
    """An ASGI app. `resource` is this server's MCP endpoint URL (MCP is
    served at its path); `auth` is everything except the scopes, which this
    sample fixes in TOOL_SCOPES; `audit` records each tool call as typed
    events (pair it with `auth.audit_sink = audit.tool_audit_sink()`)."""
    url = urlsplit(resource)
    if url.scheme not in ("http", "https") or not url.hostname:
        raise ValueError(f"resource must be an http(s) URL, got {resource!r}")
    host = f"[{url.hostname}]" if ":" in url.hostname else url.hostname  # lower-cased, no port or userinfo
    mcp_path = url.path or "/"
    metadata_url = protected_resource_metadata_url(resource)
    metadata_path = urlsplit(metadata_url).path
    metadata = build_protected_resource_metadata(
        resource,
        authorization_servers=authorization_servers,
        scopes_supported=list(dict.fromkeys(s for scopes in TOOL_SCOPES.values() for s in scopes)),
        resource_name="Order Management (HelixID sample)",
    )
    gate = async_helixid_mcp_middleware(replace(auth, tool_scopes=TOOL_SCOPES, required_scopes=[]))

    server = FastMCP(
        "order-management",
        stateless_http=True,
        json_response=True,
        streamable_http_path=mcp_path,
        # DNS-rebinding protection stays on: only this server's own host and loopback
        # are accepted, as Host and as Origin, with or without a port.
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[h for name in (host, "127.0.0.1", "localhost", "[::1]") for h in (name, f"{name}:*")],
            allowed_origins=[
                o
                for origin in (f"{url.scheme}://{host}", "http://127.0.0.1", "http://localhost", "http://[::1]")
                for o in (origin, f"{origin}:*")
            ],
        ),
    )
    register_order_tools(server, store if store is not None else create_order_store())
    mcp_app = server.streamable_http_app()

    async def app(scope: Any, receive: Any, raw_send: Any) -> None:
        if scope["type"] != "http":  # lifespan: the MCP session manager starts and stops with the app
            await mcp_app(scope, receive, raw_send)
            return
        started = False

        async def send(message: Any) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await raw_send(message)

        async def respond(status: int, body: Any, headers: Optional[dict] = None) -> None:
            await JSONResponse(body, status_code=status, headers=headers)(scope, receive, send)

        path, method = scope["path"], scope["method"]
        if path == metadata_path and method == "GET":
            await respond(200, metadata)
            return
        if path != mcp_path:
            await respond(404, {"error": "not_found"})
            return
        if method != "POST":
            # Stateless server: no SSE stream to open (GET) and no session to end (DELETE).
            await respond(405, {"error": "method_not_allowed"}, {"allow": "POST"})
            return

        chunks, size, more = [], 0, True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                return  # client went away
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                await respond(413, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Request body too large"}})
                return
            chunks.append(chunk)
            more = message.get("more_body", False)
        raw = b"".join(chunks)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):  # RecursionError: absurdly nested JSON
            await respond(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Request body is not valid JSON"}})
            return
        if isinstance(body, list):
            # The MCP Python transport refuses batches. Answer before the gate, or
            # every entry would be verified and audited as granted for calls that never run.
            await respond(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Batch requests are not supported"}})
            return

        if not (isinstance(body, dict) and body.get("method") == "tools/call"):
            await handle(scope, raw, receive, send, None)
            return
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        name = params.get("name")
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else None
        headers = Headers(scope=scope)
        try:
            audit_scope = (
                audit.begin_tool_call(name if isinstance(name, str) else None, credential=_presented_vp(headers, meta))
                if audit is not None
                else nullcontext()
            )
            with audit_scope as call_audit:
                try:
                    await gate({
                        "name": name,
                        "input": params.get("arguments") if isinstance(params.get("arguments"), dict) else {},
                        "_meta": meta,
                        "headers": headers,
                    })
                except Exception as error:  # noqa: BLE001
                    denial = to_http_error_response(error, metadata_url)
                    if denial is not None:
                        if call_audit is not None:
                            call_audit.denied(_reason_code(error))
                        await respond(denial.status, denial.body, {"www-authenticate": denial.headers["WWW-Authenticate"]})
                        return
                    if call_audit is not None:
                        call_audit.failed(_reason_code(error))
                    raise
                await handle(scope, raw, receive, send, call_audit)
        except Exception as error:  # noqa: BLE001 - not the caller's fault: a 500 (or 503), reported
            if on_server_error is not None:
                on_server_error(error)
            if started:
                return
            if isinstance(error, AuthorizationServerUnavailableError):
                # The caller's token was not shown to be bad; its authorization
                # server could not be asked. Say so, and invite a retry.
                await respond(
                    503,
                    {"error": "temporarily_unavailable", "error_description": "The authorization server could not be reached"},
                    {"retry-after": "5"},
                )
            else:
                await respond(500, {"error": "server_error"})

    async def handle(scope: Any, raw: bytes, receive: Any, send: Any, call_audit: Any) -> None:
        """Hands the request, body intact, to the MCP transport; with a tool
        call's audit, `tool.call.started` first and `completed` on a 2xx
        answer, else `failed`. Under required delivery (A-2) the tool does not
        run when its intent cannot be recorded (`audit_delivery_failed`), and an
        answer whose completion cannot be recorded is marked degraded
        (`_meta["org.kya-os/audit"]`), so the answer is held until then."""
        replayed = False
        messages: list = []

        async def replay() -> Any:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return await receive()

        async def capture(message: Any) -> None:
            messages.append(message)

        if call_audit is None:
            await mcp_app(scope, replay, send)
            return
        if not _recorded(call_audit.started):
            await _send_json(send, 200, {"jsonrpc": "2.0", "id": _rpc_id(raw), "result": audit_unavailable_response()})
            return
        try:
            await mcp_app(scope, replay, capture)
        except Exception:
            _recorded(lambda: call_audit.failed("handler_error"))
            raise
        status = next((m["status"] for m in messages if m["type"] == "http.response.start"), None)
        if status is not None and 200 <= status < 300:
            if not _recorded(call_audit.completed):
                messages = _degraded(messages)
        else:
            _recorded(lambda: call_audit.failed("handler_error"))
        for message in messages:
            await send(message)

    return app


def _recorded(step: Callable[[], Any]) -> bool:
    """One audit append: False when it raised or the trail swallowed a failure."""
    try:
        return step() is not None
    except Exception:  # noqa: BLE001 - the caller answers for a failed append
        return False


def _rpc_id(raw: bytes) -> Any:
    try:
        message = json.loads(raw)
    except ValueError:
        return None
    first = message[0] if isinstance(message, list) and message else message
    return first.get("id") if isinstance(first, dict) else None


async def _send_json(send: Any, status: int, body: Any) -> None:
    payload = json.dumps(body).encode("utf-8")
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]})
    await send({"type": "http.response.body", "body": payload, "more_body": False})


def _degraded(messages: list) -> list:
    """The held answer with every tool result marked degraded: the completion was not recorded."""
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    try:
        answer = json.loads(body)
    except ValueError:
        return messages
    replies = answer if isinstance(answer, list) else [answer]
    for reply in replies:
        if isinstance(reply, dict) and isinstance(reply.get("result"), dict):
            reply["result"] = mark_audit_degraded(reply["result"], TERMINAL_FAILED)
    payload = json.dumps(answer).encode("utf-8")
    headers = [(k, v) for k, v in start.get("headers", []) if k.lower() != b"content-length"] + [(b"content-length", str(len(payload)).encode())]
    return [{**start, "headers": headers}, {"type": "http.response.body", "body": payload, "more_body": False}]


def _reason_code(error: BaseException) -> str:
    """The code a refused or failed call is audited with: the error's code (never its message), lower-cased, else `server_error`."""
    code = getattr(error, "code", None)
    return code.lower() if isinstance(code, str) and code else "server_error"


def _presented_vp(headers: Any, meta: Optional[dict]) -> Optional[dict]:
    """The HelixID VP a tool call presents, decoded, so the audit trail can
    derive the delegation evidence (SPEC section 7.8). None when there is none
    or it does not decode: the gate, not this, answers a bad credential."""
    try:
        credential = extract_credential(headers, meta)
        return decode_helix_vp(credential.value) if credential is not None and credential.kind == "vp" else None
    except Exception:  # noqa: BLE001
        return None
