# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The local verifier (KYA-OS story F-2): the Python port of helix-sdk-js's
``kyaos.verifier``, same seams, same reason codes, same results, driven by
the fixture set helix-core generates (``fixtures/verifier/*.json``).
"""

from .attestation import CapabilityCheck, capability_name, check_capabilities, verify_capability_attestation
from .card_schema import ENTITY_CARD_SCHEMA
from .chain import ChainRules, evaluate_delegation_chain_rules
from .codes import ALL_REASON_CODES, ReasonCodes
from .request_proof import (
    DEFAULT_PROOF_SKEW_SECONDS,
    DELEGATION_CHAIN_META_KEY,
    LEGACY_PROOF_PROFILE,
    LEGACY_REQUEST_PROOF_META_KEY,
    MAX_PROOF_TTL_SECONDS,
    PROOF_PROFILE_V1,
    REQUEST_PROOF_META_KEY,
    covered_claims,
    covered_claims_bytes,
    covered_request,
    did_of_kid,
    jwk_thumbprint,
    parse_request_proof,
    read_carried_chain,
    read_request_proof,
    request_hash_content_digest,
    sign_request_proof,
    verify_detached_jws,
    window_problems,
)
from .resolve import (
    create_did_keys_resolver,
    create_did_resolver,
    did_key_document,
    did_web_document_url,
    ed25519_keys_of,
    public_key_of_did_key,
)
from .status import (
    MAX_STATUS_LIST_BYTES,
    FetchStatusList,
    StatusListRead,
    StatusVerdict,
    check_status_entry,
    decode_status_list_bits,
    decode_status_list_credential,
    parse_status_list_index,
    read_status_bit,
)
from .verify import (
    ChainSummary,
    MemoryNonceStore,
    NonceStore,
    VerifierOptions,
    VerifierResult,
    VerifierSeams,
    validate_entity_card,
    verify,
)

__all__ = [
    "ALL_REASON_CODES",
    "CapabilityCheck",
    "ChainRules",
    "ChainSummary",
    "DEFAULT_PROOF_SKEW_SECONDS",
    "DELEGATION_CHAIN_META_KEY",
    "ENTITY_CARD_SCHEMA",
    "FetchStatusList",
    "LEGACY_PROOF_PROFILE",
    "LEGACY_REQUEST_PROOF_META_KEY",
    "MAX_PROOF_TTL_SECONDS",
    "MAX_STATUS_LIST_BYTES",
    "MemoryNonceStore",
    "NonceStore",
    "PROOF_PROFILE_V1",
    "REQUEST_PROOF_META_KEY",
    "ReasonCodes",
    "StatusListRead",
    "StatusVerdict",
    "VerifierOptions",
    "VerifierResult",
    "VerifierSeams",
    "capability_name",
    "check_capabilities",
    "check_status_entry",
    "covered_claims",
    "covered_claims_bytes",
    "covered_request",
    "create_did_keys_resolver",
    "create_did_resolver",
    "decode_status_list_bits",
    "decode_status_list_credential",
    "did_key_document",
    "did_of_kid",
    "did_web_document_url",
    "ed25519_keys_of",
    "evaluate_delegation_chain_rules",
    "jwk_thumbprint",
    "parse_request_proof",
    "parse_status_list_index",
    "public_key_of_did_key",
    "read_carried_chain",
    "read_request_proof",
    "read_status_bit",
    "request_hash_content_digest",
    "sign_request_proof",
    "validate_entity_card",
    "verify",
    "verify_capability_attestation",
    "verify_detached_jws",
    "window_problems",
]
