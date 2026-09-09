# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_sdk -- Python SDK for HelixID, mirroring helix-sdk-js's public API
surface (see src/index.ts there).

SDK-API-only architecture (docs/proposal-sdk-api-only.md): every SDK,
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
from .delegation import delegate
from .renewal import renew_agent_vc

# Issuer / SP
from .grant import issue_grant, IssuerKeyMaterial

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

# Errors
from .errors import (  # noqa: F401
    HelixError,
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

__version__ = "0.1.1"  # x-release-please-version

__all__ = [
    "AgentWallet",
    "WalletCredential",
    "VPBuilder",
    "VPBuilderSignOverrides",
    "delegate",
    "renew_agent_vc",
    "issue_grant",
    "IssuerKeyMaterial",
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
]
