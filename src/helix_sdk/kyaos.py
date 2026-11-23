# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS primitives in one namespace, the Python twin of helix-sdk-js's
``import { kyaos } from '@helixid/sdk-js'`` (stories rule 24): RFC 8785
canonical JSON and hashing (L1-B), EdDSA JWS and the Signer (L1-C), the
session handshake and the detached response proof (L2-A), the per-request
holder-of-key proof and the carried chain (C-C), the local verifier (F-2,
C-C) as ``kyaos.verifier``, the signed needs_authorization challenge and the
resume retry (L3-E), consent at Helix as ``kyaos.consent`` (L3-H), and reading a server's ``/.well-known/mcp`` discovery
document (L1-D).

    from helix_sdk import kyaos
    request = kyaos.create_handshake_request(audience="did:web:mcp.example.com")
    kyaos.verify_response_proof(result, server_did, resolve_did, request=sent)
    sent = kyaos.with_request_proof({"name": "lookup_order", "arguments": args}, signer, audience=service_did)

The modules behind it stay importable on their own (``helix_sdk.crypto.jcs``,
``helix_sdk.crypto.jws``, ``helix_sdk.handshake``, ``helix_sdk.response_proof``,
``helix_sdk.discovery``).
"""

from __future__ import annotations

from .crypto.jcs import CanonicalJsonError, canonicalize, hash_json
from .crypto.jws import (
    DEFAULT_KID_FRAGMENT,
    default_kid_fragment,
    DEFAULT_SIGNING_KEY_ENV_VAR,
    JWS_ALG,
    DidResolver,
    EnvSigner,
    JwsReasons,
    JwsVerification,
    Signer,
    base64url_decode_strict,
    base64url_encode,
    public_key_hex_to_jwk,
    read_jws_header,
    select_assertion_method,
    sign_jws,
    verification_method_to_jwk,
    verify_jws,
    verify_jws_by_kid,
)
from .errors import InvalidJWSError, ResponseProofError
from .handshake import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    DEFAULT_SESSION_TTL_MINUTES,
    HANDSHAKE_TOOL_NAME,
    MAX_CLOCK_SKEW_SECONDS,
    MIN_CLOCK_SKEW_SECONDS,
    NONCE_BYTES,
    NONCE_MIN_LENGTH,
    PROTOCOL_VERSION,
    SESSION_CONTROL_ARGUMENT,
    SESSION_ID_PREFIX,
    HandshakeFormatProblems,
    HandshakeFormatResult,
    clock_skew_seconds,
    create_handshake_request,
    generate_nonce,
    generate_session_id,
    is_did,
    is_session_id,
    is_valid_nonce,
    validate_handshake_format,
    within_skew,
)
from . import verifier
from . import consent
from .errors import ConsentFlowError
from .request_proof import (
    DELEGATION_CHAIN_META_KEY,
    ProofCall,
    RequestProofError,
    attach_chain,
    mint_request_proof,
    request_hash_content_digest,
    to_proof_request,
    with_request_proof,
)
from .discovery import (
    WELL_KNOWN_MCP_INVALID,
    WELL_KNOWN_MCP_PATH,
    WellKnownMcpError,
    WellKnownMcpProblems,
    fetch_well_known_mcp,
    read_well_known_mcp,
    well_known_mcp_url,
)
from .response_proof import (
    CONTROL_ARGUMENT_PREFIX,
    LEGACY_RESPONSE_PROOF_META_KEYS,
    PROOF_OUTCOMES,
    REQUEST_PROOF_META_KEY,
    RESPONSE_PROOF_ENVELOPE_PROFILE,
    RESPONSE_PROOF_META_KEY,
    ProofReasons,
    VerifiedProof,
    covered_request,
    covered_response,
    hash_request,
    hash_response,
    is_control_argument,
    outcome_has_response,
    proof_claims,
    proof_payload,
    read_response_proof,
    strip_control_arguments,
    validate_proof_meta,
    verify_detached_proof,
    verify_response_proof,
    wire_json,
)
from .errors import NeedsAuthorizationError
from .needs_authorization import (
    DELEGATION_CONTROL_ARGUMENT,
    DISPLAY_HINTS,
    NEEDS_AUTHORIZATION,
    RESUME_CONTROL_ARGUMENT,
    ChallengeReasons,
    HandledChallenge,
    NeedsAuthorizationChallenge,
    RetriedCall,
    find_challenge,
    handle_needs_authorization,
    is_needs_authorization,
    read_challenge,
    retry_with_resume,
    with_resume,
)

__all__ = [
    # jcs
    "CanonicalJsonError", "canonicalize", "hash_json",
    # jws and the Signer
    "DEFAULT_KID_FRAGMENT", "default_kid_fragment", "DEFAULT_SIGNING_KEY_ENV_VAR", "JWS_ALG", "DidResolver", "EnvSigner", "JwsReasons",
    "JwsVerification", "Signer", "base64url_decode_strict", "base64url_encode", "public_key_hex_to_jwk",
    "read_jws_header", "select_assertion_method", "sign_jws", "verification_method_to_jwk", "verify_jws",
    "verify_jws_by_kid", "InvalidJWSError",
    # handshake
    "DEFAULT_CLOCK_SKEW_SECONDS", "DEFAULT_SESSION_TTL_MINUTES", "HANDSHAKE_TOOL_NAME", "MAX_CLOCK_SKEW_SECONDS",
    "MIN_CLOCK_SKEW_SECONDS", "NONCE_BYTES", "NONCE_MIN_LENGTH", "PROTOCOL_VERSION", "SESSION_CONTROL_ARGUMENT",
    "SESSION_ID_PREFIX", "HandshakeFormatProblems", "HandshakeFormatResult", "clock_skew_seconds",
    "create_handshake_request", "generate_nonce", "generate_session_id", "is_did", "is_session_id", "is_valid_nonce",
    "validate_handshake_format", "within_skew",
    # hashes and the response proof
    "CONTROL_ARGUMENT_PREFIX", "LEGACY_RESPONSE_PROOF_META_KEYS", "PROOF_OUTCOMES", "REQUEST_PROOF_META_KEY",
    "RESPONSE_PROOF_ENVELOPE_PROFILE", "RESPONSE_PROOF_META_KEY", "ProofReasons", "VerifiedProof",
    "covered_request", "covered_response", "hash_request", "hash_response", "is_control_argument",
    "outcome_has_response", "proof_claims", "proof_payload", "read_response_proof", "strip_control_arguments",
    "validate_proof_meta", "verify_detached_proof", "verify_response_proof", "wire_json", "ResponseProofError",
    # the request proof and the carried chain (C-C)
    "DELEGATION_CHAIN_META_KEY", "ProofCall", "RequestProofError", "attach_chain", "mint_request_proof",
    "request_hash_content_digest", "to_proof_request", "with_request_proof",
    # the local verifier (F-2, C-C)
    "verifier",
    # needs_authorization and resume (L3-E)
    "DELEGATION_CONTROL_ARGUMENT", "DISPLAY_HINTS", "NEEDS_AUTHORIZATION", "RESUME_CONTROL_ARGUMENT", "ChallengeReasons",
    "HandledChallenge", "NeedsAuthorizationChallenge", "RetriedCall", "find_challenge", "handle_needs_authorization",
    "is_needs_authorization", "read_challenge", "retry_with_resume", "with_resume", "NeedsAuthorizationError",
    # consent at Helix: the user's did:key signs the root hop (L3-H)
    "consent", "ConsentFlowError",
    # discovery: /.well-known/mcp, client side (L1-D)
    "WELL_KNOWN_MCP_INVALID", "WELL_KNOWN_MCP_PATH", "WellKnownMcpError", "WellKnownMcpProblems",
    "fetch_well_known_mcp", "read_well_known_mcp", "well_known_mcp_url",
]
