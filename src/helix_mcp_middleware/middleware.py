# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Server-side MCP tool-call gate, ported from helix-sdk-js's
mcp-middleware/src/middleware.ts.

Call it for every incoming tool call with the tool name, the MCP request's
`_meta` and, over HTTP, the request headers. It identifies the caller (a
HelixID VP, or an OAuth bearer token), checks the tool's scopes, records the
decision, and returns the call or raises. Tool arguments are never consulted.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from helix_sdk import verify_vp
from helix_sdk.errors import HelixError, VPMissingError, VPVerificationFailedError
from helix_sdk.vp_transport import decode_helix_vp

from .credentials import extract_credential
from .errors import (
    OAUTH_TOKEN_INVALID,
    TOOL_NOT_PERMITTED,
    AuthorizationServerUnavailableError,
    MCPAuthError,
    ToolScopeError,
)
from .oauth import AuthResult, create_oauth_validator
from .types import MCPMiddlewareOptions, MCPToolCall

# The HelixID API reports a bad credential the way the local verifier does: as
# a typed error (VC_REVOKED, VP_EXPIRED, VP_SIGNATURE_INVALID, a target
# service mismatch, ...), not as `valid: false`. Those are the caller's fault
# and become a 401. Anything else from the API (our own API key refused, the
# API down) is a server fault and is passed through unmapped.
_CREDENTIAL_FAULT_PREFIXES = ("VP_", "VC_", "DELEGATION_", "CONSENT_GRANT_")
_CREDENTIAL_FAULT_CODES = {
    "DID_NOT_FOUND",
    "INVALID_DID_FORMAT",
    "UNSUPPORTED_DID_METHOD",
    "SELF_SIGNED_VC_NOT_ALLOWED",
    "MAX_DELEGATION_DEPTH_EXCEEDED",
    "SCOPE_ESCALATION_DENIED",
    "CREDENTIAL_NOT_FOR_THIS_AGENT",
    "SERVICE_NOT_FOUND",
    "VALIDATION_ERROR",
}


def _is_credential_fault(err: BaseException) -> bool:
    code = getattr(err, "code", None)
    return isinstance(code, str) and (code.startswith(_CREDENTIAL_FAULT_PREFIXES) or code in _CREDENTIAL_FAULT_CODES)


def _as_auth_result(value: Any) -> Optional[AuthResult]:
    if isinstance(value, AuthResult):
        return value
    if isinstance(value, dict):
        return AuthResult(sub=value.get("sub"), scopes=value.get("scopes") or [], client_id=value.get("client_id"))  # type: ignore[arg-type]
    return None


def helixid_mcp_middleware(options: MCPMiddlewareOptions) -> Callable[[MCPToolCall], MCPToolCall]:
    if options.oauth is not None and options.validate_oauth_token is not None:
        raise ValueError("Provide either `oauth` or `validate_oauth_token`, not both")
    validate_oauth = options.validate_oauth_token or (
        create_oauth_validator(options.oauth) if options.oauth is not None else None
    )
    service_did = options.service_did or options.expected_target_service

    def audit(caller: Dict[str, Any], tool_name: Optional[str], denied: Optional[Dict[str, str]]) -> None:
        if options.audit_sink is None:
            return
        event: Dict[str, Any] = {
            "event": "AUTHZ_DENIED" if denied else "AUTHZ_GRANTED",
            "result": "denied" if denied else "allowed",
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "authMethod": caller["authMethod"],
            "effectiveScopes": list(caller["scopes"]),
        }
        for key in ("agentDid", "oauthSubject", "vpId"):
            if caller.get(key) is not None:
                event[key] = caller[key]
        if tool_name is not None:
            event["toolName"] = tool_name
        if denied:
            if denied.get("scope") is not None:
                event["requiredScope"] = denied["scope"]
            event["reason"] = denied["reason"]
        if service_did is not None:
            event["serviceDid"] = service_did
        try:
            options.audit_sink(event)
        except Exception as exc:  # noqa: BLE001 - a failing sink never blocks a call
            if options.on_audit_error is not None:
                options.on_audit_error(exc)

    def middleware(tool_call: MCPToolCall) -> MCPToolCall:
        # Credentials come from Authorization / X-Helix-VP / _meta only; tool
        # arguments are never consulted. Ambiguous credentials raise.
        credential = extract_credential(tool_call.get("headers"), tool_call.get("_meta"))
        if credential is None:
            raise VPMissingError(
                'No credentials: send Authorization: HelixVP, X-Helix-VP, MCP _meta["x-helix-vp"]'
                + (", or Authorization: Bearer" if validate_oauth else "")
            )

        caller: Dict[str, Any]
        if credential.kind == "vp":
            if options.client is None:
                raise ValueError("helixid_mcp_middleware: `client` is required to verify HelixID VPs")
            vp = decode_helix_vp(credential.value)
            try:
                result = verify_vp(
                    vp,
                    options.client,
                    expected_target_service=options.expected_target_service,
                    allow_self_signed=options.allow_self_signed,
                )
            except HelixError as exc:
                if _is_credential_fault(exc):
                    raise VPVerificationFailedError(exc.message) from exc
                raise
            if not result.get("valid"):
                error_message = result.get("error")
                raise VPVerificationFailedError(error_message) if error_message else VPVerificationFailedError()
            caller = {
                "authMethod": "helixvp",
                "scopes": list(result.get("effectiveScopes") or []),
                "agentDid": result.get("agentDid"),
                "vpId": result.get("vpId"),
            }
        else:
            if validate_oauth is None:
                raise MCPAuthError(OAUTH_TOKEN_INVALID, "Bearer tokens are not accepted by this server")
            try:
                auth = _as_auth_result(validate_oauth(credential.value))
            except (MCPAuthError, AuthorizationServerUnavailableError):
                # Our own verdicts pass through; the authorization server being
                # down is a server fault, not a bad token.
                raise
            except Exception:  # noqa: BLE001 - anything else came from a custom callback and means "rejected"
                raise MCPAuthError(OAUTH_TOKEN_INVALID, "The access token was rejected") from None
            if auth is None or not isinstance(auth.sub, str) or not auth.sub:
                raise MCPAuthError(OAUTH_TOKEN_INVALID, "The access token has no subject")
            caller = {"authMethod": "oauth", "scopes": list(auth.scopes or []), "oauthSubject": auth.sub}

        # Authorization. With a tool_scopes map the default is deny: an
        # unlisted tool (or a call with no tool name) never runs.
        name = tool_call.get("name")
        tool_name = name if isinstance(name, str) else None
        required: List[str]
        if options.tool_scopes is not None:
            if tool_name is None or tool_name not in options.tool_scopes:
                audit(caller, tool_name, {"reason": "tool is not in toolScopes"})
                raise MCPAuthError(TOOL_NOT_PERMITTED, "This tool is not permitted")
            required = list(options.tool_scopes[tool_name] or [])
        else:
            required = list(options.required_scopes or [])

        missing = next((scope for scope in required if scope not in caller["scopes"]), None)
        if missing is not None:
            audit(caller, tool_name, {"scope": missing, "reason": "insufficient scope"})
            raise ToolScopeError(missing, required)

        audit(caller, tool_name, None)
        return tool_call

    return middleware


def async_helixid_mcp_middleware(options: MCPMiddlewareOptions) -> Callable[[MCPToolCall], Awaitable[MCPToolCall]]:
    """The same gate for async MCP servers: runs the (blocking, network-bound)
    check in a worker thread so the event loop stays free."""
    gate = helixid_mcp_middleware(options)

    async def middleware(tool_call: MCPToolCall) -> MCPToolCall:
        return await asyncio.to_thread(gate, tool_call)

    return middleware
