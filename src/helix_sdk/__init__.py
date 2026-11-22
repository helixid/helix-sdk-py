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
keygen, sign, canonical-hash. Delegation-VC building, DID resolution, and
status checks are API calls made through HelixClient. The Helix VP is gone
(KYA-OS story C-C): an agent signs each request itself
(kyaos.with_request_proof), and a service verifies it in-process
(helix_sdk.verifier.verify, or helix_mcp_middleware).

Agent self-custody has been retired: onboarding (HelixClient.onboard_agent())
is server-side keygen now, no local keypair, no wallet file. AgentWallet and
its encrypted-file load()/save() remain for other actors' key storage (e.g.
an issuer's own key material), not for agent onboarding.
"""

from __future__ import annotations

# Agent
from .wallet import AgentWallet, WalletCredential
# KYA-OS story F-1: the credential split (identity, capability attestations, delegation hops).
from .credential_store import (
    BitstringStatusEntry,
    CapabilityAttestation,
    CredentialSigner,
    CredentialStore,
    CredentialStoreData,
    DataIntegrityProof,
    DelegationHop,
    PresentedChain,
    SignAttestationsOptions,
    StoredCredential,
    sign_attestation_document,
)
from .credentials import (
    CAPABILITY_ATTESTATION_TYPE,
    DELEGATION_CREDENTIAL_TYPE,
    IDENTITY_CREDENTIAL_TYPE,
)

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
    AgentKeyRegistration,
    AgentPublicKeyJwk,
    agent_key_registration,
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

# Errors
from .errors import (  # noqa: F401
    HelixError,
    InvalidJWSError,
    ResponseProofError,
    NeedsAuthorizationError,
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

__version__ = "2.1.0"  # x-release-please-version

__all__ = [
    "AgentWallet",
    "WalletCredential",
    "CredentialStore",
    "sign_attestation_document",
    "CredentialSigner",
    "BitstringStatusEntry",
    "DataIntegrityProof",
    "StoredCredential",
    "CapabilityAttestation",
    "DelegationHop",
    "CredentialStoreData",
    "PresentedChain",
    "SignAttestationsOptions",
    "IDENTITY_CREDENTIAL_TYPE",
    "CAPABILITY_ATTESTATION_TYPE",
    "DELEGATION_CREDENTIAL_TYPE",
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
    # KYA-OS story L1-A: the same names helix-sdk-js's index exports, Python style.
    "DEFAULT_AGENT_KEY_ID",
    "AgentKey",
    "AgentKeyRegistration",
    "AgentPublicKeyJwk",
    "agent_key_registration",
    "agent_public_key",
    "assert_no_private_material",
    "decode_base58btc",
    "encode_base58btc",
    "generate_agent_key",
    "public_key_from_did_key",
    "public_key_jwk_bytes",
    "to_did_key",
    "to_public_key_jwk",
    "ResolvedKey",
    "did_key_document",
    "resolve_did",
    "resolve_did_key",
    "resolve_did_web",
    "HelixError",
    "map_api_error",
    "codes",
    "kyaos",
]

# KYA-OS (story L2-A): canonical JSON hashing, EdDSA JWS and the Signer, the
# session handshake and the client side of the detached response proof, as
# one namespace like helix-sdk-js's `kyaos` export.
from . import kyaos  # noqa: E402
