# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_sdk -- Python SDK for HelixID, mirroring helix-sdk-js's public API
surface (see src/index.ts there).

SDK-API-only architecture (the SDK-API-only design): every SDK,
in every language, depends only on the HelixID API -- never on a shared
"core" package -- except for private-key operations that must stay local:
keygen, sign, canonical-hash, VPBuilder.sign(). verify_vp(), delegation-VC
building, DID resolution, and status checks are all API calls made through
HelixClient.

Agent self-custody has been retired: onboarding (HelixClient.onboard_agent())
is server-side keygen now, no local keypair, no wallet file. AgentWallet and
its encrypted-file load()/save() remain for other actors' key storage (e.g.
an issuer's own key material), not for agent onboarding.
"""

from __future__ import annotations

# Agent
from .wallet import AgentWallet, WalletCredential
from .vp_builder import VPBuilder, VPBuilderSignOverrides

# Verifier
from .verify import verify_vp
from .scope import check_scope, require_scope
from .session_manager import SessionManager, SessionClaims, DelegationLink

# Enrollment / issuer API operations
from .client import HelixClient

# Local-signing primitives
from .keys import (
    KeyPair,
    generate_key_pair,
    derive_public_key,
    sign_data,
    verify_signature,
    public_key_to_multibase,
    multibase_to_public_key_hex,
)

# KYA-OS story L1-A: the agent's own Ed25519 key, generated client side; only
# its public half (JWK, did:key) ever leaves the process. Resolution of did:web
# and did:key to that key never touches a Helix database.
from .agent_key import (
    DEFAULT_AGENT_KEY_ID,
    AgentKey,
    agent_public_key,
    assert_no_private_material,
    decode_base58btc,
    encode_base58btc,
    generate_agent_key,
    public_key_from_did_key,
    public_key_jwk_bytes,
    to_did_key,
    to_public_key_jwk,
)
from .did_resolver import ResolvedKey, did_key_document, resolve_did, resolve_did_key, resolve_did_web
# KYA-OS story C-A: Entity Card discovery through a SafeFetch, the strict card schema and the
# server.json projection, the same names helix-sdk-js's index exports, Python style.
from .entity_card import (
    ENTITY_TYPES,
    KYA_OS_CARD_META_KEY,
    KYA_OS_CARD_REF_KEY,
    KYA_OS_CARD_SERVICE_ID,
    KYA_OS_CARD_SERVICE_TYPE,
    KYA_OS_CARD_WELL_KNOWN_PATH,
    PROOF_PROFILE_V1,
    SAFE_FETCH_MAX_BYTES,
    SAFE_FETCH_MAX_REDIRECTS,
    SAFE_FETCH_TIMEOUT_SECONDS,
    EntityCardError,
    ResolvedEntityCard,
    SafeFetchRefusedError,
    SafeFetchResponse,
    build_entity_card,
    capability_name,
    card_endpoint_of,
    create_safe_fetch,
    default_outbound_fetch,
    did_web_card_url,
    did_web_document_url,
    did_web_for,
    entity_card_summary,
    fetch_entity_card,
    is_loopback_host,
    is_public_unicast_address,
    kya_os_card_service_entry,
    node_transport,
    normalize_did,
    parse_did_web,
    parse_entity_card,
    requests_transport,
    resolve_entity_card,
    resolve_entity_card_from_server_meta,
    same_did,
    server_card_meta,
    validate_entity_card,
)

# KYA-OS story F-3: custody preference. helix_init (self-custody onboarding),
# HelixCustodialSigner (custodial agents sign through the API), the custody
# API client; the agent runtime takes any Signer (VPBuilder.sign_with).
from . import custody  # noqa: F401  (helix-sdk-js exports it as the `custody` namespace)
from .custody import (
    CustodyApiError,
    CustodyLabel,
    DidHostingMode,
    EnvSigner,
    HelixCustodialSigner,
    HelixCustodyClient,
    HelixInitResult,
    KeyCustodyMode,
    Signer,
    activate_agent,
    change_to_self_custody,
    check_own_hosting,
    helix_init,
    rotation_proof,
    verification_method_of,
)

# Errors
from .errors import (  # noqa: F401
    HelixError,
    InvalidJWSError,
    map_api_error,
    ValidationError,
    InternalError,
    DIDNotFoundError,
    DIDDeactivatedError,
    DIDAlreadyExistsError,
    EnrollmentTokenNotFoundError,
    EnrollmentTokenExpiredError,
    EnrollmentTokenAlreadyUsedError,
    ChallengeNotFoundError,
    ChallengeExpiredError,
    ChallengeAlreadyVerifiedError,
    ChallengeSignatureInvalidError,
    AgentAlreadyOnboardedError,
    ServiceNotFoundError,
    ServiceAlreadyExistsError,
    DelegationNotPermittedError,
    DelegationDepthExceededError,
    DelegationScopeEscalationError,
    DelegationChainInvalidError,
    DelegationParentVCNotFoundError,
    DelegationParentVCRevokedError,
    MaxDelegationDepthExceededError,
    ScopeEscalationDeniedError,
    PreparedPayloadNotFoundError,
    PreparedPayloadExpiredError,
    PreparedPayloadAlreadyConsumedError,
    PreparedPayloadSignatureInvalidError,
    PreparedPayloadPurposeMismatchError,
    VCRevokedError,
    VCMissingCredentialStatusError,
    RenewalWindowNotOpenError,
    RenewalWindowExpiredError,
    MaxRenewalCountExceededError,
    VCExpiredError,
    VCNotYetValidError,
    VCSignatureInvalidError,
    SelfSignedVCNotAllowedError,
    VPMissingError,
    VPExpiredError,
    VPVerificationFailedError,
    VPSignatureInvalidError,
    VPInvalidStructureError,
    ConsentGrantSubjectMismatchError,
    ConsentGrantInvalidError,
    NoCredentialInWalletError,
    CredentialNotForThisAgentError,
    CredentialAlreadyInWalletError,
    WalletAlreadyExistsError,
    SDKOnlyModeNoAPIError,
    InsufficientScopeError,
)
from . import codes  # noqa: F401
from .vp_transport import (
    HELIX_VP_HEADER,
    HELIX_VP_META_KEY,
    encode_helix_vp,
    decode_helix_vp,
    helix_vp_headers,
    read_helix_vp_header,
    read_helix_vp_meta,
)

__version__ = "2.1.0"  # x-release-please-version

__all__ = [
    "HELIX_VP_HEADER",
    "HELIX_VP_META_KEY",
    "encode_helix_vp",
    "decode_helix_vp",
    "helix_vp_headers",
    "read_helix_vp_header",
    "read_helix_vp_meta",
    "AgentWallet",
    "WalletCredential",
    "VPBuilder",
    "VPBuilderSignOverrides",
    "verify_vp",
    "check_scope",
    "require_scope",
    "SessionManager",
    "SessionClaims",
    "DelegationLink",
    "HelixClient",
    "KeyPair",
    "generate_key_pair",
    "derive_public_key",
    "sign_data",
    "verify_signature",
    "public_key_to_multibase",
    "multibase_to_public_key_hex",
    "HelixError",
    "map_api_error",
    "codes",
    "custody",
    "CustodyApiError",
    "CustodyLabel",
    "DidHostingMode",
    "EnvSigner",
    "HelixCustodialSigner",
    "HelixCustodyClient",
    "HelixInitResult",
    "KeyCustodyMode",
    "Signer",
    "activate_agent",
    "change_to_self_custody",
    "check_own_hosting",
    "helix_init",
    "rotation_proof",
    "verification_method_of",
    # KYA-OS story C-A: Entity Cards (helix_sdk.entity_card).
    "ENTITY_TYPES",
    "KYA_OS_CARD_META_KEY",
    "KYA_OS_CARD_REF_KEY",
    "KYA_OS_CARD_SERVICE_ID",
    "KYA_OS_CARD_SERVICE_TYPE",
    "KYA_OS_CARD_WELL_KNOWN_PATH",
    "PROOF_PROFILE_V1",
    "SAFE_FETCH_MAX_BYTES",
    "SAFE_FETCH_MAX_REDIRECTS",
    "SAFE_FETCH_TIMEOUT_SECONDS",
    "EntityCardError",
    "ResolvedEntityCard",
    "SafeFetchRefusedError",
    "SafeFetchResponse",
    "build_entity_card",
    "capability_name",
    "card_endpoint_of",
    "create_safe_fetch",
    "default_outbound_fetch",
    "did_web_card_url",
    "did_web_document_url",
    "did_web_for",
    "entity_card_summary",
    "fetch_entity_card",
    "is_loopback_host",
    "is_public_unicast_address",
    "kya_os_card_service_entry",
    "node_transport",
    "normalize_did",
    "parse_did_web",
    "parse_entity_card",
    "requests_transport",
    "resolve_entity_card",
    "resolve_entity_card_from_server_meta",
    "same_did",
    "server_card_meta",
    "validate_entity_card",
]
