# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Types, ported from helix-sdk-js's mcp/src/types.ts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Union

from .oauth import OAuthIssuerOptions
from .verify_locally import LocalVerifier, MiddlewareVerifierOptions

if TYPE_CHECKING:  # pragma: no cover - a type only; the module imports the gate's errors
    from .needs_authorization import NeedsAuthorization

MCPToolCall = Dict[str, Any]
"""A dict with at least 'name' and 'input' keys, matching the JS
MCPToolCall interface's structural typing. The KYA-OS request proof is
carried in '_meta' (the MCP request's params._meta) under
"org.kya-os/request-proof", the delegation chain under
"org.kya-os/delegation-chain"; over HTTP an OAuth token comes in 'headers'
(`Authorization: Bearer <token>`); never in 'input'. 'request' is the
JSON-RPC request as received ({"method", "params"}), when the host has it:
the proof's requestHash is recomputed over exactly this, else the request is
rebuilt from 'name', 'input' and '_meta'."""


@dataclass
class MCPMiddlewareOptions:
    verifier: Optional[Union[LocalVerifier, MiddlewareVerifierOptions]] = None
    """How KYA-OS request proofs are verified: in-process, from the proof and
    the carried chain alone (story F-2), with the Helix API never asked. A
    built LocalVerifier (shared with other gates), or its settings
    (``service_did`` defaults to this middleware's; ``catalog`` to the scopes
    of ``tool_scopes``). Not needed for an OAuth-only server."""
    required_scopes: List[str] = field(default_factory=list)
    """Fallback applied to every tool when `tool_scopes` is not set."""
    expected_target_service: Optional[str] = None
    """This server's own DID: the proof audience. `service_did` is the same setting under its current name."""
    tool_scopes: Optional[Dict[str, List[str]]] = None
    """Per-tool required scopes. Deny by default: when this map is set, a
    tool that is not a key in it is rejected before it runs (an empty list
    allows any authenticated caller). Takes precedence over `required_scopes`."""
    oauth: Optional[Union[OAuthIssuerOptions, Sequence[OAuthIssuerOptions]]] = None
    """Accept `Authorization: Bearer` access tokens from one trusted
    authorization server, or a list of them (see helix_mcp_middleware.oauth
    and the provider presets). Mutually exclusive with `validate_oauth_token`."""
    validate_oauth_token: Optional[Callable[[str], Any]] = None
    """Custom bearer-token validation (your own API keys as bearers). Return
    an AuthResult, or a dict with 'sub' and 'scopes'; raise to reject. May be
    async with async_helixid_mcp_middleware (as may `audit_sink`)."""
    audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None
    """Receives an event for every decision about an identified caller. See
    create_helix_audit_sink."""
    on_audit_error: Optional[Callable[[BaseException], None]] = None
    """Called when `audit_sink` raises. Audit failures never block a tool call."""
    service_did: Optional[str] = None
    """This server's DID: the proof audience, included in audit events; defaults to `expected_target_service`."""
    minimum_level: Optional[str] = None
    """Story C-C: the Card level every tool demands, ``L1``, ``L2`` or ``L3``; default ``L3``.
    Checked after the scopes; a call below it raises LevelError (PROOF_LEVEL_INSUFFICIENT)."""
    tools: Optional[Dict[str, Any]] = None
    """Story C-C: per-tool settings, ``{"lookup_order": {"minimum_level": "L2"}}``."""
    l3_minus_satisfies_l3: Optional[bool] = None
    """Story C-C: whether L3-minus (a proof with no token ``cnf`` to fuse) meets an ``L3`` minimum; default True."""
    needs_authorization: Optional["NeedsAuthorization"] = None
    """KYA-OS story L3-E: answers a call whose delegation is missing or does
    not cover the tool's scopes with a signed `needs_authorization` challenge
    (instead of the plain 403), and verifies the retry that carries the resume
    token and the new delegation credential. See create_needs_authorization."""
