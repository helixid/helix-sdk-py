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
- create_helix_audit_sink(): writes decisions to the HelixID audit log.
- attach_helix_vp(): client-side, attaches a VP signed server-side (via
  HelixClient.sign_vp()) to an outgoing tool call.
"""

from __future__ import annotations

from .attach import attach_helix_vp
from .audit import AuditSink, ToolAuditEvent, create_helix_audit_sink
from .credentials import ExtractedCredential, extract_credential
from .errors import AuthorizationServerUnavailableError, MCPAuthError, ToolScopeError
from .metadata import (
    HttpErrorResponse,
    build_protected_resource_metadata,
    protected_resource_metadata_url,
    to_http_error_response,
)
from .middleware import async_helixid_mcp_middleware, helixid_mcp_middleware
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
    "MCPAuthError",
    "ToolScopeError",
    "AuthorizationServerUnavailableError",
    "to_http_error_response",
    "build_protected_resource_metadata",
    "protected_resource_metadata_url",
    "HttpErrorResponse",
    "create_helix_audit_sink",
    "AuditSink",
    "ToolAuditEvent",
]
