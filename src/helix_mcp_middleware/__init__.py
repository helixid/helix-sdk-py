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
  default) and records each decision.
- create_local_verifier() (story F-2): the local verifier the gate runs, from
  the presented proof and chain, public DID documents, status lists and
  cards, a local replay store and local config. The Helix API is never asked.
  Status lists are read proof first through a fail-closed revocation checker
  and a StatusCache (story L3-C); RevocationSignalClient invalidates it on a
  revocation SET (SSE, or RFC 8935 push), RedisStatusCacheStore shares it
  between instances, create_resolution_fetch is the default fetch.
- OAuth: OAuthIssuerOptions (one trusted issuer or a list), validated by
  JWKS, by RFC 7662 introspection, or with endpoints read from the issuer's
  metadata; presets entra(), auth0(), okta(), keycloak().
- to_http_error_response(), build_protected_resource_metadata(): 401 / 403
  challenges and the RFC 9728 document.
- create_helix_audit_sink(): writes decisions to the HelixID audit log.
- TrustedIssuers / DEFAULT_TRUSTED_ISSUERS ("*"), is_trusted_issuer(),
  attestation_trust(): which issuers' capability attestations count (KYA-OS
  story C-B).
"""

from __future__ import annotations

from .audit import AuditSink, ToolAuditEvent, create_helix_audit_sink
from .credentials import DEFAULT_TRUSTED_ISSUERS, ExtractedCredential, TrustedIssuers, extract_credential
from .errors import PROOF_INVALID, PROOF_MISSING, AuthorizationServerUnavailableError, MCPAuthError, ProofError, ToolScopeError
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
from .types import MCPMiddlewareOptions, MCPToolCall
from .trusted_issuers import attestation_trust, is_trusted_issuer
from .resolution_fetch import (
    RESOLUTION_MAX_BYTES,
    RESOLUTION_TIMEOUT_MS,
    ResolutionRefusedError,
    create_resolution_fetch,
    is_public_unicast_address,
    resolution_target,
)
from .revocation_signals import (
    PushResponse,
    RevocationSignalClient,
    SignalOutcome,
    SignalReport,
    SseParser,
    create_revocation_signal_client,
)
from .status_cache_store import RedisStatusCacheClient, RedisStatusCacheStore
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
    resolution_url,
    unrecorded_reporter,
)

__all__ = [
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
    "ToolScopeError",
    "AuthorizationServerUnavailableError",
    "to_http_error_response",
    "build_protected_resource_metadata",
    "protected_resource_metadata_url",
    "HttpErrorResponse",
    "create_helix_audit_sink",
    "AuditSink",
    "ToolAuditEvent",
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
    "create_resolution_fetch",
    "resolution_target",
    "is_public_unicast_address",
    "ResolutionRefusedError",
    "RESOLUTION_MAX_BYTES",
    "RESOLUTION_TIMEOUT_MS",
    "RevocationSignalClient",
    "SseParser",
    "SignalReport",
    "SignalOutcome",
    "PushResponse",
    "create_revocation_signal_client",
    "RedisStatusCacheStore",
    "RedisStatusCacheClient",
]
