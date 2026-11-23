# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_mcp_middleware -- MCP (Model Context Protocol) integration for
HelixID, mirroring helix-sdk-js's mcp-middleware package.

- helixid_mcp_middleware() / async_helixid_mcp_middleware(): server-side
  gate for every incoming tool call. Accepts a KYA-OS request proof (MCP
  `_meta["org.kya-os/request-proof"]`, with the delegation chain at
  `_meta["org.kya-os/delegation-chain"]`), verified in-process by the local
  verifier, or an OAuth 2.1 bearer token; enforces per-tool scopes (deny by
  default), then the tool's minimum Card level (story C-C: ``minimum_level``,
  ``tools[name]["minimum_level"]``, ``l3_minus_satisfies_l3``; a call below it
  raises LevelError), and records each decision. A bearer token sent with a
  proof is the proof's sender constraint (``cnf`` fusion, L3).
- create_local_verifier() (story F-2): the local verifier the gate runs, from
  the presented proof and chain, public DID documents, status lists and
  cards, a local replay store and local config. The Helix API is never asked.
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
- serve_identity() / resolve_server_card() (KYA-OS story C-A): the service's
  own did.json and card.json from its origin, the server.json projection
  under _meta["org.kya-os/card"], and its reverse.
- create_kyaos() (KYA-OS story L2-A): the `_kyaos_handshake` tool, sessions,
  a replay store (MemoryNonceStore, RedisNonceStore, DynamoNonceStore) and a
  server-signed detached proof on every tool call outcome at
  `_meta["org.kya-os/response-proof"]`; describe_kyaos() for /.well-known/mcp.
- create_needs_authorization() (KYA-OS story L3-E): a caller whose delegation
  does not cover a tool gets a signed `needs_authorization` challenge with a
  single-use resume token (MemoryResumeTokenStore, RedisResumeTokenStore); the
  retry's DelegationCredential goes to an injected RetryAuthorizer.
- create_well_known_mcp() (KYA-OS story L1-D): the /.well-known/mcp discovery
  document, built from config and the KYA-OS description, validated against
  the vendored well-known-mcpi.json schema at startup, served over ASGI.
"""

from __future__ import annotations

from .audit import (
    OAUTH_SUBJECT_KEY_ID,
    AuditContext,
    AuditSink,
    McpAuditContext,
    McpAuditTrail,
    ToolAuditEvent,
    ToolCallAudit,
    create_helix_audit_reporter,
    create_helix_audit_sink,
    create_mcp_audit_trail,
    current_tool_call,
)
from .audit_delivery import (
    AUDIT_META_KEY,
    async_run_audited_tool,
    audit_tool_handlers,
    audit_unavailable_response,
    create_helix_audit_delivery,
    mark_audit_degraded,
    run_audited_tool,
)
from .credentials import DEFAULT_TRUSTED_ISSUERS, ExtractedCredential, TrustedIssuers, extract_credential
from .errors import (
    PROOF_INVALID,
    PROOF_LEVEL_INSUFFICIENT,
    PROOF_MISSING,
    AuthorizationServerUnavailableError,
    LevelError,
    MCPAuthError,
    ProofError,
    ToolScopeError,
)
from .level import (
    DEFAULT_MINIMUM_LEVEL,
    DERIVED_LEVELS,
    MINIMUM_LEVELS,
    LevelPolicy,
    assert_level_policy,
    derive_conformance_level,
    derived_level_of,
    meets_minimum_level,
    minimum_level_for,
)
from .identity import ServedIdentity, ServeIdentityOptions, resolve_server_card, serve_identity
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
    cnf_jkt_of,
    create_introspection_validator,
    create_jwt_validator,
    create_oauth_validator,
)
from .providers import auth0, entra, keycloak, okta
from .types import MCPMiddlewareOptions, MCPToolCall
from .trusted_issuers import attestation_trust, is_trusted_issuer
from .verify_locally import (
    KYA_OS_CARD_SERVICE_TYPE,
    LocalVerifier,
    LocalVerifierOptions,
    MiddlewareVerifierOptions,
    ReportVerification,
    ResolverFetch,
    VerificationReport,
    card_endpoint_of,
    create_local_verifier,
    request_of,
    resolution_url,
    unrecorded_reporter,
)
from .verify_request_proof import verify_request_proof

__all__ = [
    "AUDIT_META_KEY",
    "async_run_audited_tool",
    "audit_tool_handlers",
    "audit_unavailable_response",
    "create_helix_audit_delivery",
    "mark_audit_degraded",
    "run_audited_tool",
    "helixid_mcp_middleware",
    "async_helixid_mcp_middleware",
    "MCPMiddlewareOptions",
    "MiddlewareVerifierOptions",
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
    "ProofError",
    "PROOF_MISSING",
    "PROOF_INVALID",
    "PROOF_LEVEL_INSUFFICIENT",
    "LevelError",
    "LevelPolicy",
    "MINIMUM_LEVELS",
    "DERIVED_LEVELS",
    "DEFAULT_MINIMUM_LEVEL",
    "assert_level_policy",
    "derive_conformance_level",
    "derived_level_of",
    "meets_minimum_level",
    "minimum_level_for",
    "cnf_jkt_of",
    "request_of",
    "verify_request_proof",
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
    "AuditSink",
    "AuditContext",
    "McpAuditContext",
    "McpAuditTrail",
    "ToolAuditEvent",
    "ToolCallAudit",
    "OAUTH_SUBJECT_KEY_ID",
    "serve_identity",
    "resolve_server_card",
    "ServeIdentityOptions",
    "ServedIdentity",
    "create_local_verifier",
    "LocalVerifier",
    "LocalVerifierOptions",
    "VerificationReport",
    "ReportVerification",
    "ResolverFetch",
    "unrecorded_reporter",
    "card_endpoint_of",
    "resolution_url",
    "KYA_OS_CARD_SERVICE_TYPE",
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

# The /.well-known/mcp discovery document (story L1-D).
from .well_known import (  # noqa: E402
    DEFAULT_PROOF_ALGORITHMS,
    DEFAULT_SUPPORTED_DID_METHODS,
    DEFAULT_WELL_KNOWN_VERSION,
    WELL_KNOWN_MCP_INVALID,
    WELL_KNOWN_MCP_PATH,
    WellKnownMcp,
    WellKnownMcpConfig,
    WellKnownMcpError,
    WellKnownMcpResponse,
    WellKnownMcpValidation,
    assert_well_known_mcp,
    build_well_known_mcp,
    create_well_known_mcp,
    validate_well_known_mcp,
)

__all__ += [
    "WELL_KNOWN_MCP_PATH",
    "WELL_KNOWN_MCP_INVALID",
    "DEFAULT_WELL_KNOWN_VERSION",
    "DEFAULT_SUPPORTED_DID_METHODS",
    "DEFAULT_PROOF_ALGORITHMS",
    "WellKnownMcp",
    "WellKnownMcpConfig",
    "WellKnownMcpError",
    "WellKnownMcpResponse",
    "WellKnownMcpValidation",
    "build_well_known_mcp",
    "create_well_known_mcp",
    "validate_well_known_mcp",
    "assert_well_known_mcp",
]
