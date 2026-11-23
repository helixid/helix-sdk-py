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
KYA-OS request proof, verified in-process by the local verifier, story F-2;
or an OAuth bearer token), checks the tool's scopes and then its minimum Card
level (story C-C), records the decision, and returns the call or raises. Tool arguments are never consulted, and the
Helix API is never asked about a credential.
"""

from __future__ import annotations

import asyncio
import inspect
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .credentials import extract_credential
from .errors import (
    OAUTH_TOKEN_INVALID,
    PROOF_INVALID,
    PROOF_MISSING,
    TOOL_NOT_PERMITTED,
    AuthorizationServerUnavailableError,
    LevelError,
    MCPAuthError,
    ProofError,
    ToolScopeError,
)
from .level import LevelPolicy, assert_level_policy, derived_level_of, meets_minimum_level, minimum_level_for
from .oauth import AuthResult, cnf_jkt_of, create_oauth_validator
from .needs_authorization_guard import challenge_for, resume_retry
from .types import MCPMiddlewareOptions, MCPToolCall
from .verify_locally import LocalVerifier, LocalVerifierOptions, create_local_verifier


@dataclass(frozen=True)
class AuthorizedCaller:
    """Who a tool call came from, once the gate has identified and authorized
    them: what ``middleware.authorize(tool_call)`` returns (the KYA-OS proof's
    ``clientDid`` comes from ``agent_did``). Mirrors helix-sdk-js's AuthorizedCaller."""

    auth_method: str
    """'kyaos' or 'oauth'."""
    scopes: List[str] = field(default_factory=list)
    agent_did: Optional[str] = None
    oauth_subject: Optional[str] = None
    level: Optional[str] = None
    """KYA-OS callers: the level the local verifier derived (story F-2)."""
    proof_assurance: Optional[str] = None
    fresh: Optional[bool] = None
    """KYA-OS callers: whether every status the level relies on was read live."""
    proof_floor: Optional[bool] = None
    """KYA-OS callers (story C-C): True when a request proof verified; False for a chain verified without one."""
    cnf_diagnostics: Optional[List[str]] = None
    """KYA-OS callers: the ``cnf`` diagnostics (``cnf_present_but_token_unfused``)."""


def _caller_of(caller: Dict[str, Any]) -> AuthorizedCaller:
    return AuthorizedCaller(
        auth_method=caller["authMethod"],
        scopes=list(caller["scopes"]),
        agent_did=caller.get("agentDid"),
        oauth_subject=caller.get("oauthSubject"),
        level=caller.get("level"),
        proof_assurance=caller.get("proofAssurance"),
        fresh=caller.get("fresh"),
        proof_floor=caller.get("proofFloor"),
        cnf_diagnostics=list(caller["cnfDiagnostics"]) if caller.get("cnfDiagnostics") else None,
    )

class _AsyncCallbackError(TypeError):
    """A configuration error (an async callback behind the sync gate), never a verdict on a token."""


def _refuse_awaitable(value: Any, what: str) -> Any:
    """The sync gate cannot await. An async callback would otherwise be dropped
    on the floor: no audit rows, or every token refused."""
    if inspect.isawaitable(value):
        close = getattr(value, "close", None)
        if callable(close):
            close()
        raise _AsyncCallbackError(f"{what} returned an awaitable; use async_helixid_mcp_middleware for async callbacks")
    return value


def _as_auth_result(value: Any) -> Optional[AuthResult]:
    if isinstance(value, AuthResult):
        return value
    if isinstance(value, dict):
        claims = value.get("claims")
        cnf_jkt = value.get("cnf_jkt") or value.get("cnfJkt") or cnf_jkt_of(claims)
        return AuthResult(sub=value.get("sub"), scopes=value.get("scopes") or [], client_id=value.get("client_id"), claims=claims, cnf_jkt=cnf_jkt)  # type: ignore[arg-type]
    return None


def _is_local_verifier(value: Any) -> bool:
    return callable(getattr(value, "verify_call", None))


def _build_verifier(options: MCPMiddlewareOptions, service_did: Optional[str]) -> Any:
    """The local verifier the gate runs: the one given, or one built from its settings."""
    settings = options.verifier
    if settings is None or _is_local_verifier(settings):
        return settings
    if not isinstance(settings, LocalVerifierOptions):
        raise TypeError("`verifier` must be a LocalVerifier or LocalVerifierOptions")
    catalog = settings.catalog
    if catalog is None and options.tool_scopes is not None:
        catalog = list(dict.fromkeys(scope for scopes in options.tool_scopes.values() for scope in scopes))
    return create_local_verifier(replace(settings, service_did=settings.service_did or service_did, catalog=catalog))


def helixid_mcp_middleware(options: MCPMiddlewareOptions) -> Callable[[MCPToolCall], MCPToolCall]:
    """The gate: call it with a tool call; it returns the call unchanged once
    the caller is identified and allowed to run the tool, and raises
    otherwise. ``middleware.authorize(tool_call)`` does the same and returns
    the AuthorizedCaller instead, for hosts that need to know who called (the
    KYA-OS proof's ``clientDid``, say). ``middleware.verifier`` is the local
    verifier the gate runs, when one is configured."""
    if options.oauth is not None and options.validate_oauth_token is not None:
        raise ValueError("Provide either `oauth` or `validate_oauth_token`, not both")
    for name in ("validate_oauth_token", "audit_sink"):
        if inspect.iscoroutinefunction(getattr(options, name)):
            raise ValueError(f"`{name}` is async; use async_helixid_mcp_middleware, which awaits it")
    validate_oauth = options.validate_oauth_token or (
        create_oauth_validator(options.oauth) if options.oauth is not None else None
    )
    # Story C-C: the minimum Card level per tool, checked after the scopes. A typo in a level raises here, never lowers a bar.
    level_policy = LevelPolicy(options.minimum_level, options.tools, options.l3_minus_satisfies_l3)
    assert_level_policy(level_policy)
    l3_minus_satisfies_l3 = options.l3_minus_satisfies_l3 if options.l3_minus_satisfies_l3 is not None else True
    service_did = options.service_did or options.expected_target_service
    # The verifier runs in-process (story F-2): nothing here ever asks the Helix API about a credential.
    local_verifier = _build_verifier(options, service_did)

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
        for key in ("agentDid", "oauthSubject", "level", "fresh", "proofAssurance"):
            if caller.get(key) is not None:
                event[key] = caller[key]
        if caller["authMethod"] == "kyaos" and caller.get("level") is not None:
            event["l3Minus"] = caller["level"] == "L3" and caller.get("proofAssurance") == "L3-minus"
        if caller.get("cnfDiagnostics"):
            event["cnfDiagnostics"] = list(caller["cnfDiagnostics"])
        if denied and denied.get("requiredLevel") is not None:
            event["requiredLevel"] = denied["requiredLevel"]
        if tool_name is not None:
            event["toolName"] = tool_name
        if denied:
            if denied.get("scope") is not None:
                event["requiredScope"] = denied["scope"]
            event["reason"] = denied["reason"]
        if service_did is not None:
            event["serviceDid"] = service_did
        try:
            _refuse_awaitable(options.audit_sink(event), "audit_sink")
        except Exception as exc:  # noqa: BLE001 - a failing sink never blocks a call
            if options.on_audit_error is not None:
                options.on_audit_error(exc)

    def validate_bearer(token: str) -> AuthResult:
        if validate_oauth is None:
            raise MCPAuthError(OAUTH_TOKEN_INVALID, "Bearer tokens are not accepted by this server")
        try:
            auth = _as_auth_result(_refuse_awaitable(validate_oauth(token), "validate_oauth_token"))
        except (MCPAuthError, AuthorizationServerUnavailableError, _AsyncCallbackError):
            # Our own verdicts pass through; the authorization server being
            # down is a server fault, not a bad token.
            raise
        except Exception:  # noqa: BLE001 - anything else came from a custom callback and means "rejected"
            raise MCPAuthError(OAUTH_TOKEN_INVALID, "The access token was rejected") from None
        if auth is None or not isinstance(auth.sub, str) or not auth.sub:
            raise MCPAuthError(OAUTH_TOKEN_INVALID, "The access token has no subject")
        return auth

    def authorize(tool_call: MCPToolCall) -> AuthorizedCaller:
        # Credentials come from Authorization or `_meta` only; tool arguments
        # are never consulted. Ambiguous credentials raise.
        credential = extract_credential(tool_call.get("headers"), tool_call.get("_meta"))
        name = tool_call.get("name")
        tool_name = name if isinstance(name, str) else None
        if credential is None:
            raise ProofError(
                PROOF_MISSING,
                'No credentials: send a KYA-OS request proof in _meta["org.kya-os/request-proof"]'
                + (", or Authorization: Bearer" if validate_oauth else ""),
            )

        caller: Dict[str, Any]
        if credential.kind == "proof":
            if local_verifier is None:
                raise ValueError("helixid_mcp_middleware: `verifier` is required to verify KYA-OS request proofs")
            # A bearer token next to a proof is its sender constraint: its cnf.jkt fuses with the proof's for L3 (section 8.6).
            token_cnf_jkt: Optional[str] = None
            if credential.bearer is not None:
                bearer_auth = validate_bearer(credential.bearer)
                token_cnf_jkt = bearer_auth.cnf_jkt or cnf_jkt_of(bearer_auth.claims)
            # A chain may come without a proof (story C-C): it verifies, at most at L2, and the level check below decides.
            call: Dict[str, Any] = {"name": tool_name, "input": tool_call.get("input"), "_meta": tool_call.get("_meta"), "require_proof": False}
            if tool_call.get("request") is not None:
                call["request"] = tool_call["request"]
            if token_cnf_jkt is not None:
                call["token_cnf_jkt"] = token_cnf_jkt
            result = local_verifier.verify_call(call)
            if result is None:  # pragma: no cover - extract_credential found a proof, so verify_call reads one
                raise ProofError(PROOF_MISSING, "The request carries no KYA-OS request proof")
            if not result.ok:
                refused = ProofError(PROOF_INVALID, f"The request proof was refused: {', '.join(result.reasons)}", result.reasons)
                if result.proof_did is not None:
                    audit(
                        {"authMethod": "kyaos", "scopes": [], "agentDid": result.proof_did, "level": result.level, "fresh": result.fresh},
                        tool_name,
                        {"reason": ",".join(result.reasons)},
                    )
                raise refused
            cnf_diagnostics = [warning for warning in result.warnings if warning.startswith("cnf_")]
            caller = {
                "authMethod": "kyaos",
                "scopes": list(result.effective_scopes),
                "agentDid": result.agent_did,
                "level": result.level,
                "proofAssurance": result.proof_assurance,
                "fresh": result.fresh,
                "proofFloor": result.proof_floor,
            }
            if cnf_diagnostics:
                caller["cnfDiagnostics"] = cnf_diagnostics
        else:
            assert credential.token is not None
            auth = validate_bearer(credential.token)
            caller = {"authMethod": "oauth", "scopes": list(auth.scopes or []), "oauthSubject": auth.sub}

        # Authorization. With a tool_scopes map the default is deny: an
        # unlisted tool (or a call with no tool name) never runs.
        required: List[str]
        if options.tool_scopes is not None:
            if tool_name is None or tool_name not in options.tool_scopes:
                audit(caller, tool_name, {"reason": "tool is not in toolScopes"})
                raise MCPAuthError(TOOL_NOT_PERMITTED, "This tool is not permitted")
            required = list(options.tool_scopes[tool_name] or [])
        else:
            required = list(options.required_scopes or [])

        # KYA-OS story L3-E: a retry after consent carries its resume token and credential (needs_authorization_guard.py).
        retry = resume_retry(options.needs_authorization, caller, tool_call, tool_name, required)
        if retry is not None:
            caller = retry
        missing = next((scope for scope in required if scope not in caller["scopes"]), None)
        if missing is not None:
            # KYA-OS story L3-E: an identified caller without the authority gets a signed challenge instead of the plain 403.
            challenge = challenge_for(options.needs_authorization, caller, tool_name, required) if retry is None else None
            if challenge is not None:
                raise challenge
            audit(caller, tool_name, {"scope": missing, "reason": "insufficient scope"})
            raise ToolScopeError(missing, required)

        # The level, after the scopes (story C-C): how sure we are the caller is that agent right now.
        if caller["authMethod"] == "kyaos":
            required_level = minimum_level_for(level_policy, tool_name)
            derived = derived_level_of(caller.get("level") or "L1", caller.get("proofAssurance"))
            if not meets_minimum_level(derived, required_level, l3_minus_satisfies_l3):
                audit(caller, tool_name, {"reason": f"level_insufficient: {derived} < {required_level}", "requiredLevel": required_level})
                raise LevelError(derived, required_level)

        audit(caller, tool_name, None)
        return _caller_of(caller)

    def middleware(tool_call: MCPToolCall) -> MCPToolCall:
        authorize(tool_call)
        return tool_call

    middleware.authorize = authorize  # type: ignore[attr-defined]
    middleware.verifier = local_verifier  # type: ignore[attr-defined]
    return middleware


_LOOP: "ContextVar[Optional[asyncio.AbstractEventLoop]]" = ContextVar("helix_mcp_middleware_loop", default=None)


def _on_loop(callback: Callable[..., Any]) -> Callable[..., Any]:
    """Lets the worker thread call a callback that may be async: an awaitable
    result is awaited on the event loop the request came from."""

    def call(*args: Any) -> Any:
        result = callback(*args)
        if not inspect.isawaitable(result):
            return result
        loop = _LOOP.get()
        if loop is None:  # pragma: no cover - only reachable outside the async wrapper
            raise RuntimeError("no event loop to await the callback on")

        async def wait() -> Any:
            return await result

        return asyncio.run_coroutine_threadsafe(wait(), loop).result()

    return call


def async_helixid_mcp_middleware(options: MCPMiddlewareOptions) -> Callable[[MCPToolCall], Awaitable[MCPToolCall]]:
    """The same gate for async MCP servers: runs the (blocking, network-bound)
    check in a worker thread so the event loop stays free. `validate_oauth_token`,
    `audit_sink`, `on_audit_error` and the verifier settings'
    `report_verification` may be sync or async here, as may the
    `needs_authorization` layer's store, authorizer and audit sink (story L3-E).
    ``await middleware.authorize(tool_call)`` returns the AuthorizedCaller."""
    if options.oauth is not None and options.validate_oauth_token is not None:
        raise ValueError("Provide either `oauth` or `validate_oauth_token`, not both")
    verifier = options.verifier
    if isinstance(verifier, LocalVerifierOptions) and verifier.report_verification is not None:
        verifier = replace(verifier, report_verification=_on_loop(verifier.report_verification))
    bridged = replace(
        options,
        verifier=verifier,
        validate_oauth_token=_on_loop(options.validate_oauth_token) if options.validate_oauth_token else None,
        audit_sink=_on_loop(options.audit_sink) if options.audit_sink else None,
        on_audit_error=_on_loop(options.on_audit_error) if options.on_audit_error else None,
        needs_authorization=options.needs_authorization.bridged(_on_loop) if options.needs_authorization is not None else None,
    )
    gate = helixid_mcp_middleware(bridged)

    async def authorize(tool_call: MCPToolCall) -> AuthorizedCaller:
        token = _LOOP.set(asyncio.get_running_loop())
        try:
            # to_thread copies the context, so the bridge sees the loop
            return await asyncio.to_thread(gate.authorize, tool_call)  # type: ignore[attr-defined, no-any-return]
        finally:
            _LOOP.reset(token)

    async def middleware(tool_call: MCPToolCall) -> MCPToolCall:
        await authorize(tool_call)
        return tool_call

    middleware.authorize = authorize  # type: ignore[attr-defined]
    middleware.verifier = gate.verifier  # type: ignore[attr-defined]
    return middleware
