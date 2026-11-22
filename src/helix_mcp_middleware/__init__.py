# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_mcp_middleware -- MCP (Model Context Protocol) integration for
HelixID, mirroring helix-sdk-js's mcp-middleware package.

- helixid_mcp_middleware() / async_helixid_mcp_middleware(): server-side
  gate for every incoming tool call. Accepts a HelixID VP
  (`Authorization: HelixVP`, `X-Helix-VP`, or MCP `_meta["x-helix-vp"]`) or
  an OAuth 2.1 bearer token, enforces per-tool scopes (deny by default) and
  records each decision.
- OAuth: OAuthIssuerOptions (one trusted issuer or a list), validated by
  JWKS, by RFC 7662 introspection, or with endpoints read from the issuer's
  metadata; presets entra(), auth0(), okta(), keycloak().
- to_http_error_response(), build_protected_resource_metadata(): 401 / 403
  challenges and the RFC 9728 document.
- Audit (KYA-OS AAP-1): McpAuditTrail records typed events through a
  helix_sdk.audit.AuditTrail; create_mcp_audit_trail() /
  create_helix_audit_reporter() build one over `POST /v1/audit-log/events`,
  create_helix_audit_sink() is the one-call legacy `audit_sink` over them.
- TrustedIssuers / DEFAULT_TRUSTED_ISSUERS ("*"), is_trusted_issuer(),
  attestation_trust(): which issuers' capability attestations count (KYA-OS
  story C-B).
- attach_helix_vp(): client-side, attaches a VP signed server-side (via
  HelixClient.sign_vp()) to an outgoing tool call.
- create_kyaos() (KYA-OS story L2-A): the `_kyaos_handshake` tool, sessions,
  a replay store (MemoryNonceStore, RedisNonceStore, DynamoNonceStore) and a
  server-signed detached proof on every tool call outcome at
  `_meta["org.kya-os/response-proof"]`; describe_kyaos() for /.well-known/mcp.
- create_needs_authorization() (KYA-OS story L3-E): a caller whose delegation
  does not cover a tool gets a signed `needs_authorization` challenge with a
  single-use resume token (MemoryResumeTokenStore, RedisResumeTokenStore); the
  retry's DelegationCredential goes to an injected RetryAuthorizer.
"""

from __future__ import annotations

from .attach import attach_helix_vp
from .audit import (
    OAUTH_SUBJECT_KEY_ID,
    AuditContext,
    AuditSink,
    DelegationEvidence,
    McpAuditContext,
    McpAuditTrail,
    ToolAuditEvent,
    ToolCallAudit,
    create_helix_audit_reporter,
    create_helix_audit_sink,
    create_mcp_audit_trail,
    current_tool_call,
    delegation_evidence_of,
)
from .credentials import DEFAULT_TRUSTED_ISSUERS, ExtractedCredential, TrustedIssuers, extract_credential
from .errors import AuthorizationServerUnavailableError, MCPAuthError, ToolScopeError
from .metadata import (
    HttpErrorResponse,
    build_protected_resource_metadata,
    protected_resource_metadata_url,
    to_http_error_response,
)
from .middleware import AuthorizedCaller, async_helixid_mcp_middleware, helixid_mcp_middleware
from .oauth import (
    AuthResult,
    OAuthIntrospectionOptions,
    OAuthIssuerOptions,
    create_introspection_validator,
    create_jwt_validator,
    create_oauth_validator,
)
from .providers import auth0, entra, keycloak, okta
from .types import AttachHelixVPOptions, MCPMiddlewareOptions, MCPToolCall
from .trusted_issuers import attestation_trust, is_trusted_issuer

__all__ = [
    "helixid_mcp_middleware",
    "async_helixid_mcp_middleware",
    "attach_helix_vp",
    "MCPMiddlewareOptions",
    "AttachHelixVPOptions",
    "MCPToolCall",
    "AuthResult",
    "OAuthIssuerOptions",
    "OAuthIntrospectionOptions",
    "create_oauth_validator",
    "create_jwt_validator",
    "create_introspection_validator",
    "entra",
    "auth0",
    "okta",
    "keycloak",
    "extract_credential",
    "ExtractedCredential",
    "TrustedIssuers",
    "DEFAULT_TRUSTED_ISSUERS",
    "is_trusted_issuer",
    "attestation_trust",
    "MCPAuthError",
    "ToolScopeError",
    "AuthorizationServerUnavailableError",
    "to_http_error_response",
    "build_protected_resource_metadata",
    "protected_resource_metadata_url",
    "HttpErrorResponse",
    "create_helix_audit_sink",
    "create_helix_audit_reporter",
    "create_mcp_audit_trail",
    "current_tool_call",
    "delegation_evidence_of",
    "AuditSink",
    "AuditContext",
    "McpAuditContext",
    "DelegationEvidence",
    "McpAuditTrail",
    "ToolAuditEvent",
    "ToolCallAudit",
    "OAUTH_SUBJECT_KEY_ID",
    "AuthorizedCaller",
]

# KYA-OS signed needs_authorization and resume (story L3-E).
from .needs_authorization import *  # noqa: E402,F401,F403
from .needs_authorization import __all__ as _needs_authorization_all  # noqa: E402
from .resume_token_store import *  # noqa: E402,F401,F403
from .resume_token_store import __all__ as _resume_token_store_all  # noqa: E402
from .resume_token_store_env import *  # noqa: E402,F401,F403
from .resume_token_store_env import __all__ as _resume_token_store_env_all  # noqa: E402

__all__ += _needs_authorization_all + _resume_token_store_all + _resume_token_store_env_all

# KYA-OS session, replay store and server response proof (story L2-A).
from .kyaos import *  # noqa: E402,F401,F403
from .kyaos import __all__ as _kyaos_all  # noqa: E402

__all__ += _kyaos_all
