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
fails the call (a 500): a call that cannot be recorded does not run.

With `kyaos` set, the same layer runs the KYA-OS session and proof flow (story
L2-A): the `_kyaos_handshake` tool opens a session (credentials, when present,
make it an authenticated one); every other tool call is started before the
transport sees it (session lookup, authorization, control arguments stripped)
and its JSON-RPC result is finished on the way out, where it is hashed and the
proof signed into `_meta["org.kya-os/response-proof"]`. A refusal carries its
`denied` proof in the 400/401/403 body.

With `auth.needs_authorization` set (story L3-E), a caller whose delegation
does not cover the tool gets the signed `needs_authorization` challenge as the
call's result, and a retry carrying `_kyaos_resume` and `_kyaos_delegation` is
verified through that layer before the tool runs."""

from __future__ import annotations

import json
from contextlib import nullcontext
from dataclasses import replace
from typing import Annotated, Any, Awaitable, Callable, Dict, Optional, Sequence
from urllib.parse import urlsplit

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent
from pydantic import Field, StrictInt
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from helix_sdk import decode_helix_vp
from helix_mcp_middleware import (
    AuthorizationServerUnavailableError,
    KyaOsDenied,
    KyaOsNeedsAuthorization,
    KyaOsRuntime,
    McpAuditTrail,
    MCPMiddlewareOptions,
    WellKnownMcp,
    async_helixid_mcp_middleware,
    build_protected_resource_metadata,
    extract_credential,
    protected_resource_metadata_url,
    to_http_error_response,
)

from .orders import TOOL_SCOPES, OrderStore, create_order_store, register_order_tools

MAX_BODY_BYTES = 1_000_000

# Where the ASGI layer leaves the agent the handshake call's credentials identified, for the handshake tool to read.
_AUTHENTICATED_AGENT = "kyaos_authenticated_agent_did"


def _register_handshake(server: FastMCP, kyaos: KyaOsRuntime) -> None:
    @server.tool(
        name=kyaos.handshake_tool_name,
        title="KYA-OS handshake",
        description="Opens a KYA-OS session: a fresh nonce, this server as audience, the current Unix time.",
    )
    async def kyaos_handshake(
        nonce: Annotated[str, Field(min_length=22)],
        audience: Annotated[str, Field(min_length=1)],
        timestamp: Annotated[StrictInt, Field(ge=0)],
        ctx: Context,  # type: ignore[type-arg]
        agentDid: Optional[str] = None,  # noqa: N803 - the wire names, shared with the JS sample
        clientInfo: Optional[Dict[str, Any]] = None,  # noqa: N803
        clientProtocolVersion: Optional[str] = None,  # noqa: N803
        clientCapabilities: Optional[Dict[str, Any]] = None,  # noqa: N803
    ) -> CallToolResult:
        args = {
            "nonce": nonce, "audience": audience, "timestamp": timestamp, "agentDid": agentDid,
            "clientInfo": clientInfo, "clientProtocolVersion": clientProtocolVersion, "clientCapabilities": clientCapabilities,
        }
        request = ctx.request_context.request
        verified = getattr(request.state, _AUTHENTICATED_AGENT, None) if request is not None else None
        result = await kyaos.handshake_tool_result({k: v for k, v in args.items() if v is not None}, authenticated_agent_did=verified)
        return CallToolResult(
            content=[TextContent(type="text", text=result["content"][0]["text"])],
            structuredContent=result["structuredContent"],
            isError=bool(result.get("isError", False)),
        )


async def _send_with_proof(
    send: Callable[[Any], Awaitable[None]],
    finish: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
    on_error: Callable[[BaseException], Awaitable[None]],
) -> Callable[[Any], Awaitable[None]]:
    """A `send` that holds the MCP transport's JSON response, signs the proof
    over its `result` and sends the result with the proof in `_meta`."""
    start: Dict[str, Any] = {}
    parts: list = []

    async def proven(message: Any) -> None:
        if message["type"] == "http.response.start":
            start.update(message)
            return
        if message["type"] != "http.response.body":  # pragma: no cover - nothing else comes on a JSON response
            await send(message)
            return
        parts.append(message.get("body", b""))
        if message.get("more_body", False):
            return
        body = b"".join(parts)
        try:
            payload = json.loads(body.decode("utf-8")) if body else None
            if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
                payload["result"] = await finish(payload["result"])
                body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        except Exception as error:  # noqa: BLE001 - an unproven result is never sent
            await on_error(error)
            return
        headers = [(k, v) for k, v in start.get("headers", []) if k.lower() != b"content-length"]
        await send({**start, "headers": headers + [(b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    return proven


def create_order_app(
    resource: str,
    auth: MCPMiddlewareOptions,
    authorization_servers: Optional[Sequence[str]] = None,
    store: Optional[OrderStore] = None,
    on_server_error: Optional[Callable[[BaseException], None]] = None,
    audit: Optional[McpAuditTrail] = None,
    kyaos: Optional[KyaOsRuntime] = None,
    well_known: Optional[WellKnownMcp] = None,
) -> Any:
    """An ASGI app. `resource` is this server's MCP endpoint URL (MCP is
    served at its path); `auth` is everything except the scopes, which this
    sample fixes in TOOL_SCOPES. `audit` records each tool call as typed
    events (pair it with `auth.audit_sink = audit.tool_audit_sink()`);
    `kyaos` turns on the KYA-OS layer (story L2-A): the handshake tool,
    sessions, the replay store and a server-signed proof on every tool call
    outcome. `well_known` serves the KYA-OS discovery document at
    `/.well-known/mcp` (story L1-D, from create_well_known_mcp()); a disabled
    one answers 404."""
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
    if kyaos is not None:
        _register_handshake(server, kyaos)
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

        if well_known is not None and await well_known.handle(scope, receive, send):
            return
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

        headers = Headers(scope=scope)
        is_tool_call = isinstance(body, dict) and body.get("method") == "tools/call"
        first_params = body.get("params") if is_tool_call and isinstance(body.get("params"), dict) else {}
        first_name = first_params.get("name") if isinstance(first_params.get("name"), str) else None
        first_meta = first_params.get("_meta") if isinstance(first_params.get("_meta"), dict) else None
        # One audited call per tools/call; the KYA-OS handshake is no gated tool call, so it is not audited as one.
        audited = audit is not None and is_tool_call and not (kyaos is not None and kyaos.is_handshake(first_name))
        try:
            audit_scope = (
                audit.begin_tool_call(first_name, credential=_presented_vp(headers, first_meta))  # type: ignore[union-attr]
                if audited
                else nullcontext()
            )
            with audit_scope as call_audit:

                async def server_error(error: BaseException) -> None:
                    if on_server_error is not None:
                        on_server_error(error)
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

                async def refuse(error: BaseException, proof: Optional[Dict[str, Any]] = None) -> None:
                    # Audited by its code (never its message): denied when the caller
                    # is answered 401/403, failed when it is a server fault.
                    denial = to_http_error_response(error, metadata_url, proof=proof)
                    if denial is None:
                        if call_audit is not None:
                            call_audit.failed(_reason_code(error))
                        await server_error(error)
                        return
                    if call_audit is not None:
                        call_audit.denied(_reason_code(error))
                    await respond(denial.status, denial.body, {"www-authenticate": denial.headers["WWW-Authenticate"]})

                # KYA-OS: the proof of an allowed call is signed over the result on its way out.
                finish: Optional[Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]] = None
                for message in [body]:
                    if not isinstance(message, dict) or message.get("method") != "tools/call":
                        continue
                    params = message.get("params") if isinstance(message.get("params"), dict) else {}
                    name = params.get("name")
                    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
                    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else None
                    tool_call = {"name": name, "input": arguments, "_meta": meta, "headers": headers}

                    if kyaos is not None and kyaos.is_handshake(name):
                        # The handshake is open to anonymous agents; a credential, when
                        # sent, must be good and makes the session an authenticated one.
                        try:
                            caller = await gate.authorize({**tool_call, "name": "lookup_order"})  # type: ignore[attr-defined]
                        except Exception as error:  # noqa: BLE001
                            if getattr(error, "code", None) != "VP_MISSING":
                                await refuse(error)
                                return
                        else:
                            scope = {**scope, "state": {**scope.get("state", {}), _AUTHENTICATED_AGENT: caller.agent_did}}
                        continue

                    if kyaos is None:
                        try:
                            await gate(tool_call)
                        except Exception as error:  # noqa: BLE001
                            await refuse(error)
                            return
                        continue

                    try:
                        started_call = await kyaos.start(
                            {"name": name, "arguments": arguments, "_meta": meta},
                            authorize=lambda call=tool_call: gate.authorize(call),  # type: ignore[attr-defined]
                        )
                    except Exception as error:  # noqa: BLE001 - the proof could not be signed (its nonce store is down, say)
                        if call_audit is not None:
                            call_audit.failed(_reason_code(error))
                        await server_error(error)
                        return
                    if isinstance(started_call, KyaOsDenied):
                        await refuse(started_call.error, started_call.proof)
                        return
                    if isinstance(started_call, KyaOsNeedsAuthorization):
                        # KYA-OS story L3-E: the signed challenge is the call's result (a tool error result with the
                        # proof in _meta), answered here since the tool itself never runs: audited as a denied call.
                        if call_audit is not None:
                            call_audit.denied(_reason_code(started_call.error))
                        await respond(200, {"jsonrpc": "2.0", "id": message.get("id"), "result": started_call.result})
                        return
                    # Control arguments (`_kyaos*`) never reach the tool.
                    message["params"] = {**params, "arguments": started_call.arguments}
                    raw = json.dumps(body).encode("utf-8")
                    finish = started_call.finish

                await handle(scope, raw, receive, send, call_audit, finish, server_error)
        except Exception as error:  # noqa: BLE001 - not the caller's fault: a 500 (or 503), reported
            if on_server_error is not None:
                on_server_error(error)
            if started:
                return
            if isinstance(error, AuthorizationServerUnavailableError):
                await respond(
                    503,
                    {"error": "temporarily_unavailable", "error_description": "The authorization server could not be reached"},
                    {"retry-after": "5"},
                )
            else:
                await respond(500, {"error": "server_error"})

    async def handle(
        scope: Any,
        raw: bytes,
        receive: Any,
        send: Any,
        call_audit: Any,
        finish: Optional[Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]] = None,
        server_error: Optional[Callable[[BaseException], Awaitable[None]]] = None,
    ) -> None:
        """Hands the request (its control arguments stripped) to the MCP
        transport: with KYA-OS the result is signed on its way out; with a tool
        call's audit, `tool.call.started` first and `completed` on a 2xx
        answer, else `failed`."""
        replayed = False
        status: Optional[int] = None

        async def replay() -> Any:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return await receive()

        async def observe(message: Any) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        target = observe if call_audit is not None else send
        if finish is not None:
            target = await _send_with_proof(target, finish, server_error)
        if call_audit is None:
            await mcp_app(scope, replay, target)
            return
        call_audit.started()
        try:
            await mcp_app(scope, replay, target)
        except Exception:
            call_audit.failed("handler_error")
            raise
        if status is not None and 200 <= status < 300:
            call_audit.completed()
        else:
            call_audit.failed("handler_error")

    return app


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
