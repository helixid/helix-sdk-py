# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""The one-line HTTP gate for an MCP server (parity with helix-sdk-js's
``helixMcpGate``): an ASGI middleware in front of the MCP Streamable HTTP app.

    app = HelixMcpGate(mcp.streamable_http_app(stateless_http=True, json_response=True), resource=..., verifier=..., tool_scopes=...)
    # or, on Starlette / FastAPI:
    app.add_middleware(HelixMcpGate, resource=..., verifier=..., tool_scopes=...)

For each POST to the MCP path it reads the JSON-RPC body, passes every request
through the gate (open methods pass; every other needs a verified caller, and
every refusal is audited), answers a refusal with 401 / 403 / 400 and
``WWW-Authenticate`` pointing at the RFC 9728 metadata (503 with Retry-After
when an authorization server is down), runs the KYA-OS session layer when
``kyaos`` is set (signing the response proof over the tool's result on its way
out), runs the call in the caller's delegation context and audit call, and
replays the body to the app behind it. It serves the RFC 9728 metadata itself.
Other methods on the MCP path answer 405 (stateless, JSON responses: every
message is verified); any other path, and lifespan, go to the app behind it."""

from __future__ import annotations

import json
import time
from contextlib import nullcontext
from dataclasses import dataclass, fields, replace
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from helix_sdk.verifier import read_carried_chain, read_request_proof

from .credentials import _header_values
from .delegation.outbound import delegation_context_of, run_with_delegation
from .errors import AuthorizationServerUnavailableError
from .kyaos.nonce_store_env import nonce_store_from_env
from .kyaos.runtime import KyaOsDenied, KyaOsNeedsAuthorization
from .metadata import build_protected_resource_metadata, protected_resource_metadata_url, to_http_error_response
from .middleware import async_helixid_mcp_middleware
from .types import MCPMiddlewareOptions
from .verify_locally import LocalVerifierOptions

AUTHENTICATED_AGENT_STATE_KEY = "helix_mcp_authenticated_agent_did"
"""Where the gate leaves, in the ASGI scope's ``state``, the agent a KYA-OS
handshake's credential identified: the handshake tool reads it
(``request.state.helix_mcp_authenticated_agent_did``)."""

DEFAULT_MAX_BODY_BYTES = 1_000_000


@dataclass
class HelixMcpGateOptions(MCPMiddlewareOptions):
    """The gate's options: the gate's own (``MCPMiddlewareOptions``:
    verifier, tool_scopes, open_methods, resource_scopes, prompt_scopes, oauth,
    audit_sink, needs_authorization, ...) plus where it sits. The same names as
    helix-sdk-js's ``helixMcpGate``."""

    resource: str = ""
    """This server's MCP endpoint URL, e.g. ``https://orders.example/mcp``. Its path is gated; the RFC 9728 metadata is served for it."""
    authorization_servers: Optional[Sequence[str]] = None
    """Advertised in the RFC 9728 metadata for OAuth clients."""
    resource_name: Optional[str] = None
    """``resource_name`` in the RFC 9728 metadata."""
    scopes_supported: Optional[Sequence[str]] = None
    """``scopes_supported``; default every scope in tool_scopes, resource_scopes and prompt_scopes."""
    audit: Any = None
    """An McpAuditTrail: the tool-call lifecycle (``session.established``, ``tool.call.denied`` when the gate refuses; the tools
    record started / completed through ``audit_tool_handlers``). Its ``tool_audit_sink()`` is the gate's audit_sink unless one is given."""
    kyaos: Any = None
    """The KYA-OS runtime (story L2-A): the handshake tool (open to anonymous agents, listed with no scope and any level),
    sessions, and a server-signed proof on every tool call outcome."""
    env: Optional[Mapping[str, str]] = None
    """Where the replay store is read from (KYAOS_NONCE_STORE, ...) when the verifier is built here and names none; default os.environ."""
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    """Largest request body read, in bytes."""
    trust_proxy: bool = False
    """Take the caller's address from the first ``X-Forwarded-For`` entry (only behind a proxy you run); default the socket's."""
    on_server_error: Optional[Callable[[BaseException], None]] = None
    """Called for errors that are not the caller's fault (answered 500, or 503 when an authorization server is down)."""


def _reason_code(error: BaseException) -> str:
    """The code a refused or failed call is audited with: the error's code (never its message), lower-cased, else ``server_error``."""
    code = getattr(error, "code", None)
    return code.lower() if isinstance(code, str) and code else "server_error"


def _carries_credential(headers: Any, meta: Optional[Mapping[str, Any]]) -> bool:
    """Whether a request carries a credential at all: an Authorization header, or a KYA-OS proof or chain in ``_meta``."""
    return bool(_header_values(headers, "authorization")) or read_request_proof(meta) is not None or read_carried_chain(meta) is not None


def _headers_of(scope: Mapping[str, Any]) -> Dict[str, Any]:
    """The request headers as a mapping of lower-case names to values (repeated ones as lists)."""
    out: Dict[str, Any] = {}
    for raw_key, raw_value in scope.get("headers") or []:
        key, value = raw_key.decode("latin-1").lower(), raw_value.decode("latin-1")
        if key in out:
            out[key] = (out[key] if isinstance(out[key], list) else [out[key]]) + [value]
        else:
            out[key] = value
    return out


async def _send_with_proof(
    send: Callable[[Any], Awaitable[None]],
    finish: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
    on_error: Callable[[BaseException], Awaitable[None]],
) -> Callable[[Any], Awaitable[None]]:
    """A ``send`` that holds the MCP transport's JSON response, signs the proof
    over its ``result`` and sends the result with the proof in ``_meta``."""
    start: Dict[str, Any] = {}
    parts: List[bytes] = []

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


class HelixMcpGate:
    """The HTTP layer of an MCP server gated by HelixID, as an ASGI middleware
    (see the module docstring). ``app`` is the MCP Streamable HTTP app; options
    come as a ``HelixMcpGateOptions`` or as keyword arguments (what Starlette's
    ``add_middleware`` passes). ``gate`` is the underlying async gate,
    ``metadata`` / ``metadata_url`` / ``mcp_path`` what it serves."""

    def __init__(self, app: Any, options: Optional[HelixMcpGateOptions] = None, **kwargs: Any) -> None:
        if options is not None and kwargs:
            raise ValueError("HelixMcpGate: pass options or keyword arguments, not both")
        opts = options if options is not None else HelixMcpGateOptions(**kwargs)
        url = urlsplit(opts.resource)
        if url.scheme not in ("http", "https") or not url.hostname:
            raise ValueError(f"HelixMcpGate: resource must be an http(s) URL, got {opts.resource!r}")
        self.app = app
        self.options = opts
        self.mcp_path = url.path or "/"
        self.metadata_url = protected_resource_metadata_url(opts.resource)
        self._metadata_path = urlsplit(self.metadata_url).path
        kyaos = opts.kyaos
        advertised = (
            list(opts.scopes_supported)
            if opts.scopes_supported is not None
            else list(dict.fromkeys(s for table in (opts.tool_scopes, opts.resource_scopes, opts.prompt_scopes) for scopes in (table or {}).values() for s in scopes))
        )
        self.metadata = build_protected_resource_metadata(
            opts.resource, authorization_servers=opts.authorization_servers, scopes_supported=advertised, resource_name=opts.resource_name
        )
        # The gate's own options, with what the HTTP layer adds: the handshake (listed with no scope, at any level),
        # the audit trail's sink, and the replay store the environment names (or the runtime's) for a verifier built here.
        base = {f.name: getattr(opts, f.name) for f in fields(MCPMiddlewareOptions)}
        gate_options = MCPMiddlewareOptions(**base)
        if kyaos is not None and opts.tool_scopes is not None:
            gate_options.tool_scopes = {**opts.tool_scopes, kyaos.handshake_tool_name: []}
        if kyaos is not None:
            gate_options.tools = {**(opts.tools or {}), kyaos.handshake_tool_name: {"minimum_level": "L1"}}
        if opts.audit_sink is None and opts.audit is not None:
            gate_options.audit_sink = opts.audit.tool_audit_sink()
        if isinstance(opts.verifier, LocalVerifierOptions) and opts.verifier.nonce_store is None:
            clock = opts.verifier.clock
            store = kyaos.nonce_store if kyaos is not None else nonce_store_from_env(opts.env, now=(lambda: clock() / 1000) if clock is not None else time.time)
            gate_options.verifier = replace(opts.verifier, nonce_store=store)
        self.gate = async_helixid_mcp_middleware(gate_options)

    def _client_ip(self, scope: Mapping[str, Any], headers: Mapping[str, Any]) -> Optional[str]:
        if self.options.trust_proxy:
            forwarded = headers.get("x-forwarded-for")
            first = (forwarded[0] if isinstance(forwarded, list) else forwarded or "").split(",")[0].strip()
            if first:
                return first
        client = scope.get("client")
        return client[0] if isinstance(client, (list, tuple)) and client and isinstance(client[0], str) else None

    async def __call__(self, scope: Any, receive: Any, raw_send: Any) -> None:
        if scope["type"] != "http":  # lifespan: the app behind (the MCP session manager) starts and stops with it
            await self.app(scope, receive, raw_send)
            return
        opts = self.options
        kyaos = opts.kyaos
        sent = False

        async def send(message: Any) -> None:
            nonlocal sent
            if message["type"] == "http.response.start":
                sent = True
            await raw_send(message)

        async def respond(status: int, body: Any, headers: Optional[Dict[str, str]] = None) -> None:
            raw = json.dumps(body).encode("utf-8")
            extra = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
            await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())] + extra})
            await send({"type": "http.response.body", "body": raw, "more_body": False})

        path, method = scope["path"], scope["method"]
        if path == self._metadata_path and method == "GET":
            await respond(200, self.metadata)
            return
        if path != self.mcp_path:
            await self.app(scope, receive, raw_send)
            return
        if method != "POST":
            # Stateless server: no SSE stream to open (GET) and no session to end (DELETE).
            await respond(405, {"error": "method_not_allowed"}, {"allow": "POST"})
            return

        chunks: List[bytes] = []
        size, more = 0, True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                return  # client went away
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > opts.max_body_bytes:
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

        headers = _headers_of(scope)
        client_ip = self._client_ip(scope, headers)
        is_tool_call = isinstance(body, dict) and body.get("method") == "tools/call"
        first_params = body.get("params") if is_tool_call and isinstance(body.get("params"), dict) else {}
        first_name = first_params.get("name") if isinstance(first_params.get("name"), str) else None
        # One audited call per tools/call; the KYA-OS handshake is no gated tool call, so it is not audited as one.
        audited = opts.audit is not None and is_tool_call and not (kyaos is not None and kyaos.is_handshake(first_name))

        async def server_error(error: BaseException) -> None:
            if opts.on_server_error is not None:
                opts.on_server_error(error)
            if sent:
                return
            if isinstance(error, AuthorizationServerUnavailableError):
                # The caller's token was not shown to be bad; its authorization server could not be asked. Say so, and invite a retry.
                await respond(503, {"error": "temporarily_unavailable", "error_description": "The authorization server could not be reached"}, {"retry-after": "5"})
            else:
                await respond(500, {"error": "server_error"})

        try:
            with (opts.audit.begin_tool_call(first_name) if audited else nullcontext()) as call_audit:

                async def refuse(error: BaseException, proof: Optional[Dict[str, Any]] = None) -> None:
                    # Audited by its code (never its message): denied when the caller is answered 401/403, failed when it is a server fault.
                    denial = to_http_error_response(error, self.metadata_url, proof=proof)
                    if denial is None:
                        if call_audit is not None:
                            call_audit.failed(_reason_code(error))
                        await server_error(error)
                        return
                    if call_audit is not None:
                        call_audit.denied(_reason_code(error))
                    await respond(denial.status, denial.body, {"www-authenticate": denial.headers["WWW-Authenticate"]})

                finish: Optional[Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]] = None
                delegation: Any = None
                rpc_method = body.get("method") if isinstance(body, dict) else None
                if isinstance(rpc_method, str):
                    params = body.get("params") if isinstance(body.get("params"), dict) else {}
                    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else None
                    if rpc_method != "tools/call":
                        # Every other request goes through the gate too: its open methods pass, the rest are checked and audited.
                        request = {"method": rpc_method, "params": params} if "params" in body else {"method": rpc_method}
                        try:
                            await self.gate.authorize({"method": rpc_method, "request": request, "_meta": meta, "headers": headers, "clientIp": client_ip})  # type: ignore[attr-defined]
                        except Exception as error:  # noqa: BLE001
                            await refuse(error)
                            return
                    else:
                        name = params.get("name")
                        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
                        # The proof's requestHash covers the request as sent (story F-2).
                        tool_call = {"name": name, "input": arguments, "_meta": meta, "headers": headers, "request": {"method": rpc_method, "params": params}, "clientIp": client_ip}
                        if kyaos is not None and kyaos.is_handshake(name):
                            # Open to anonymous agents (so not sent to the gate, which would audit a missing credential
                            # as a refusal); a credential, when sent, must be good and makes the session an authenticated one.
                            if _carries_credential(headers, meta):
                                try:
                                    caller = await self.gate.authorize(tool_call)  # type: ignore[attr-defined]
                                except Exception as error:  # noqa: BLE001
                                    await refuse(error)
                                    return
                                scope = {**scope, "state": {**scope.get("state", {}), AUTHENTICATED_AGENT_STATE_KEY: caller.agent_did}}
                        elif kyaos is None:
                            try:
                                caller = await self.gate.authorize(tool_call)  # type: ignore[attr-defined]
                            except Exception as error:  # noqa: BLE001
                                await refuse(error)
                                return
                            delegation = delegation_context_of(caller, correlation_id=call_audit.correlation_id if call_audit is not None else None)
                        else:
                            callers: list = []

                            async def authorize_and_keep(call: Dict[str, Any] = tool_call) -> Any:
                                kept = await self.gate.authorize(call)  # type: ignore[attr-defined]
                                callers.append(kept)
                                return kept

                            try:
                                started = await kyaos.start({"name": name, "arguments": arguments, "_meta": meta}, authorize=authorize_and_keep)
                            except Exception as error:  # noqa: BLE001 - the proof could not be signed (its nonce store is down, say)
                                if call_audit is not None:
                                    call_audit.failed(_reason_code(error))
                                await server_error(error)
                                return
                            if isinstance(started, KyaOsDenied):
                                await refuse(started.error, started.proof)
                                return
                            if isinstance(started, KyaOsNeedsAuthorization):
                                # KYA-OS story L3-E: the signed challenge is the call's result, answered here since the tool
                                # never runs: audited as a denied call.
                                if call_audit is not None:
                                    call_audit.denied(_reason_code(started.error))
                                await respond(200, {"jsonrpc": "2.0", "id": body.get("id"), "result": started.result})
                                return
                            # Control arguments (`_kyaos*`) never reach the tool.
                            body["params"] = {**params, "arguments": started.arguments}
                            raw = json.dumps(body).encode("utf-8")
                            finish = started.finish
                            if callers:
                                session = started.session
                                delegation = delegation_context_of(
                                    callers[-1],
                                    session_id=session.id if session is not None else None,
                                    correlation_id=call_audit.correlation_id if call_audit is not None else None,
                                )

                replayed = False

                async def replay() -> Any:
                    nonlocal replayed
                    if not replayed:
                        replayed = True
                        return {"type": "http.request", "body": raw, "more_body": False}
                    return await receive()

                target = send if finish is None else await _send_with_proof(send, finish, server_error)
                with run_with_delegation(delegation):
                    await self.app(scope, replay, target)
        except Exception as error:  # noqa: BLE001 - not the caller's fault: a 500 (or 503), reported
            await server_error(error)


__all__ = ["AUTHENTICATED_AGENT_STATE_KEY", "DEFAULT_MAX_BODY_BYTES", "HelixMcpGate", "HelixMcpGateOptions"]
