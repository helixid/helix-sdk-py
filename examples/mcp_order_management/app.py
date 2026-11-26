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
authorization server), and a scope failure gets a 403. Every request goes
through the gate, which decides: its open methods (``initialize``,
``notifications/initialized`` and ``tools/list`` by default, so a client can
see what is offered) pass, every other method needs a verified caller, and
the middleware audits every refusal itself. A KYA-OS request proof (in
`params._meta`) is verified once per call, in-process, over the JSON-RPC
request exactly as received (story F-2).

With an `audit` trail (McpAuditTrail), every gated tools/call is bracketed
by typed KYA-OS audit events: `session.established` before the gate, the
gate's own decision events (`proof.verified` or `proof.rejected` for a
KYA-OS request proof, `authorization.approved` / `denied`), then `tool.call.started`
and `tool.call.completed` / `tool.call.failed`, or `tool.call.denied` when
the gate refused, all under one correlationId. A session that cannot be
recorded fails the call (a 500) before the gate. Each tool runs through
``audit_tool_handlers`` (A-2, as the JS sample): under required delivery a
tool whose intent cannot be recorded does not run and answers
``audit_delivery_failed``, and an answer whose completion cannot be recorded
is marked degraded (``_meta["org.kya-os/audit"]``).

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

from dataclasses import fields
from typing import Annotated, Any, Callable, Dict, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent
from pydantic import Field, StrictInt
from starlette.responses import JSONResponse

from helix_mcp_middleware import (
    AUTHENTICATED_AGENT_STATE_KEY,
    HelixMcpGate,
    HelixMcpGateOptions,
    KyaOsRuntime,
    McpAuditTrail,
    MCPMiddlewareOptions,
    ServeIdentityOptions,
    WellKnownMcp,
    audit_tool_handlers,
    serve_identity,
)

from .downstream import FORWARD_TOOL_SCOPES, DownstreamOptions, register_forward_tool
from .orders import TOOL_SCOPES, OrderStore, create_order_store, register_order_tools



def _register_handshake(server: MCPServer, kyaos: KyaOsRuntime) -> None:
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
        verified = getattr(request.state, AUTHENTICATED_AGENT_STATE_KEY, None) if request is not None else None
        result = await kyaos.handshake_tool_result({k: v for k, v in args.items() if v is not None}, authenticated_agent_did=verified)
        return CallToolResult(
            content=[TextContent(type="text", text=result["content"][0]["text"])],
            structuredContent=result["structuredContent"],
            isError=bool(result.get("isError", False)),
        )


def create_order_app(
    resource: str,
    auth: MCPMiddlewareOptions,
    authorization_servers: Optional[Sequence[str]] = None,
    store: Optional[OrderStore] = None,
    on_server_error: Optional[Callable[[BaseException], None]] = None,
    audit: Optional[McpAuditTrail] = None,
    identity: Optional[ServeIdentityOptions] = None,
    kyaos: Optional[KyaOsRuntime] = None,
    revocation_webhook: Optional[Tuple[str, Callable[[Any, Any, Any], Any]]] = None,
    well_known: Optional[WellKnownMcp] = None,
    downstream: Optional[DownstreamOptions] = None,
) -> Any:
    """An ASGI app. `resource` is this server's MCP endpoint URL (MCP is
    served at its path); `auth` is everything except the scopes, which this
    sample fixes in TOOL_SCOPES. `audit` records each tool call as typed
    events (pair it with `auth.audit_sink = audit.tool_audit_sink()`);
    `identity` (KYA-OS story C-A) serves this server's own did.json and
    card.json from its origin. `kyaos` turns on the KYA-OS layer (story
    L2-A): the handshake tool, sessions, the replay store and a server-signed
    proof on every tool call outcome. `well_known` serves the KYA-OS discovery
    document at `/.well-known/mcp` (story L1-D, from create_well_known_mcp());
    a disabled one answers 404. `revocation_webhook` (KYA-OS story L3-C) is
    `(path, asgi_app)`: the RFC 8935 receiver of Helix's revocation signals
    (`RevocationSignalClient.asgi_webhook()`), mounted at `path`. `downstream`
    (KYA-OS story L3-D) adds `forward_lookup_order`, which calls another order
    service on the agent's behalf, forwarding its delegation."""
    url = urlsplit(resource)
    if url.scheme not in ("http", "https") or not url.hostname:
        raise ValueError(f"resource must be an http(s) URL, got {resource!r}")
    host = f"[{url.hostname}]" if ":" in url.hostname else url.hostname  # lower-cased, no port or userinfo
    mcp_path = url.path or "/"
    served_identity = serve_identity(identity) if identity is not None else None
    tool_scopes = {**TOOL_SCOPES, **FORWARD_TOOL_SCOPES} if downstream is not None else TOOL_SCOPES

    # MCP Python SDK 2.x: MCPServer (FastMCP in 1.x); the HTTP settings go to streamable_http_app() below.
    server = MCPServer("order-management")
    if audit is not None:
        # A-2: each tool runs audited, under the tool call the gate opens per request
        # (the handshake, opened without one, runs unaudited).
        audit_tool_handlers(server)
    register_order_tools(server, store if store is not None else create_order_store())
    if downstream is not None:
        register_forward_tool(server, downstream)
    if kyaos is not None:
        _register_handshake(server, kyaos)
    mcp_app = server.streamable_http_app(
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

    # The one line: everything HTTP-side of the HelixID check (helix_mcp_middleware.HelixMcpGate).
    auth_options = {f.name: getattr(auth, f.name) for f in fields(MCPMiddlewareOptions)}
    gate = HelixMcpGate(
        mcp_app,
        HelixMcpGateOptions(
            **{**auth_options, "tool_scopes": tool_scopes, "required_scopes": []},
            resource=resource,
            authorization_servers=authorization_servers,
            resource_name="Order Management (HelixID sample)",
            audit=audit,
            kyaos=kyaos,
            on_server_error=on_server_error,
        ),
    )

    async def app(scope: Any, receive: Any, send: Any) -> None:
        """The routes that are not the gate's (discovery, the revocation webhook, identity), then the gate."""
        if scope["type"] == "http":
            if well_known is not None and await well_known.handle(scope, receive, send):
                return
            if revocation_webhook is not None and scope["path"] == revocation_webhook[0]:
                await revocation_webhook[1](scope, receive, send)
                return
            if served_identity is not None and await served_identity.handle(scope, receive, send):
                return
            if scope["path"] not in (mcp_path, urlsplit(gate.metadata_url).path):
                await JSONResponse({"error": "not_found"}, status_code=404)(scope, receive, send)
                return
        await gate(scope, receive, send)

    return app
