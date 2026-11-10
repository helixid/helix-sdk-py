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
once per tool call, not once per request."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Callable, Optional, Sequence
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from helix_mcp_middleware import (
    AuthorizationServerUnavailableError,
    MCPMiddlewareOptions,
    async_helixid_mcp_middleware,
    build_protected_resource_metadata,
    protected_resource_metadata_url,
    to_http_error_response,
)

from .orders import TOOL_SCOPES, OrderStore, create_order_store, register_order_tools

MAX_BODY_BYTES = 1_000_000


def create_order_app(
    resource: str,
    auth: MCPMiddlewareOptions,
    authorization_servers: Optional[Sequence[str]] = None,
    store: Optional[OrderStore] = None,
    on_server_error: Optional[Callable[[BaseException], None]] = None,
) -> Any:
    """An ASGI app. `resource` is this server's MCP endpoint URL (MCP is
    served at its path); `auth` is everything except the scopes, which this
    sample fixes in TOOL_SCOPES."""
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

    async def app(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":  # lifespan: the MCP session manager starts and stops with the app
            await mcp_app(scope, receive, send)
            return

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

        headers = Headers(scope=scope)
        for message in [body]:
            if not isinstance(message, dict) or message.get("method") != "tools/call":
                continue
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            try:
                await gate({
                    "name": params.get("name"),
                    "input": params.get("arguments") if isinstance(params.get("arguments"), dict) else {},
                    "_meta": params.get("_meta") if isinstance(params.get("_meta"), dict) else None,
                    "headers": headers,
                })
            except Exception as error:  # noqa: BLE001
                denial = to_http_error_response(error, metadata_url)
                if denial is not None:
                    await respond(denial.status, denial.body, {"www-authenticate": denial.headers["WWW-Authenticate"]})
                    return
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
                return

        # Hand the request, body intact, to the MCP transport.
        replayed = False

        async def replay() -> Any:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return await receive()

        await mcp_app(scope, replay, send)

    return app
