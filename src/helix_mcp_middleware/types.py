# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Types, ported from helix-sdk-js's mcp/src/types.ts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from helix_sdk import HelixClient

from .oauth import OAuthIssuerOptions

MCPToolCall = Dict[str, Any]
"""A dict with at least 'name' and 'input' keys, matching the JS
MCPToolCall interface's structural typing (input is an untyped
Record<string, unknown> on both sides). The VP is carried in '_meta' (the
MCP request's params._meta, key "x-helix-vp") or, over HTTP, in 'headers'
(`Authorization: HelixVP <vp>` or X-Helix-VP; `Authorization: Bearer <token>`
for OAuth) -- never in 'input'."""


@dataclass
class MCPMiddlewareOptions:
    client: Optional[HelixClient] = None
    """Required to verify HelixID VPs (verification calls the API). Not
    needed for an OAuth-only server."""
    required_scopes: List[str] = field(default_factory=list)
    """Fallback applied to every tool when `tool_scopes` is not set."""
    allow_self_signed: bool = False
    expected_target_service: Optional[str] = None
    """This server's own DID. When set, a VP signed for any other service is
    rejected, so a VP meant for one service can't be replayed against another."""
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
    an AuthResult, or a dict with 'sub' and 'scopes'; raise to reject."""
    audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None
    """Receives an event for every decision about an identified caller. See
    create_helix_audit_sink."""
    on_audit_error: Optional[Callable[[BaseException], None]] = None
    """Called when `audit_sink` raises. Audit failures never block a tool call."""
    service_did: Optional[str] = None
    """Included in audit events; defaults to `expected_target_service`."""


@dataclass
class AttachHelixVPOptions:
    """Agent self-custody has been retired -- signing happens server-side
    via `client`, not a local wallet. `agent_did` is the agent's DID,
    previously implied by which wallet file was loaded."""

    client: HelixClient
    agent_did: str
    target_service: str
    user_did: Optional[str] = None
