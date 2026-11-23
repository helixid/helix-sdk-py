# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Why the local verifier refused (KYA-OS story F-2).

Every code here is the string helix-sdk-js's ``kyaos.verifier.ReasonCodes``
carries, so the shared fixtures (``helix-core/fixtures/verifier/*.json``)
record one set of codes both verifiers return.
"""

from __future__ import annotations

from typing import List


class ReasonCodes:
    # Seams and configuration: a missing seam fails closed, never skips a check.
    CLOCK_SEAM_MISSING = "clock_seam_missing"
    NONCE_SEAM_MISSING = "nonce_seam_missing"
    DID_RESOLVER_MISSING = "did_resolver_missing"
    DID_MEMBERSHIP_UNVERIFIABLE = "did_membership_unverifiable"
    STATUS_SEAM_MISSING = "status_seam_missing"
    CONFIGURATION_ERROR = "configuration_error"

    # The request proof (SPEC-ENTITY-CARD.md sections 8 and 11.2).
    PROOF_MISSING = "proof_missing"
    MALFORMED_PROOF = "malformed_proof"
    REQUEST_MISSING = "request_missing"
    KID_DID_MISMATCH = "kid_did_mismatch"
    AUDIENCE_MISMATCH = "audience_mismatch"
    REQUEST_HASH_MISMATCH = "request_hash_mismatch"
    INVALID_WINDOW = "invalid_window"
    TTL_TOO_LONG = "ttl_too_long"
    CREATED_IN_FUTURE = "created_in_future"
    EXPIRED = "expired"
    DID_UNRESOLVED = "did_unresolved"
    KEY_UNRESOLVABLE = "key_unresolvable"
    ALG_UNSUPPORTED = "alg_unsupported"
    DID_KEYS_UNRESOLVABLE = "did_keys_unresolvable"
    KID_NOT_IN_DID_DOCUMENT = "kid_not_in_did_document"
    INVALID_SIGNATURE = "invalid_signature"
    CNF_KEY_MISMATCH = "cnf_key_mismatch"
    CNF_REQUIRED_BY_TOKEN = "cnf_required_by_token"
    CNF_TOKEN_MISMATCH = "cnf_token_mismatch"
    NONCE_REPLAYED = "nonce_replayed"
    NONCE_STORE_UNAVAILABLE = "nonce_store_unavailable"

    # Key rotation (story C-E): the signing key's validity, the document's version.
    KEY_REVOKED = "key_revoked"
    KEY_SUPERSEDED = "key_superseded"
    KEY_VALIDITY_MALFORMED = "key_validity_malformed"
    DID_DOCUMENT_STALE = "did_document_stale"

    # The carried chain (SPEC.md section 6.10, SPEC-ENTITY-CARD.md sections 10.5 and 11.4).
    CHAIN_TOO_LONG = "chain_too_long"
    CHAIN_INVALID = "chain_invalid"
    DELEGATION_MALFORMED = "delegation_malformed"
    ATTENUATION_VIOLATION = "attenuation_violation"
    DELEGATION_EXPIRED = "delegation_expired"
    DELEGATION_NOT_YET_VALID = "delegation_not_yet_valid"
    UNTRUSTED_ROOT = "untrusted_root"
    ISSUER_UNTRUSTED = "issuer_untrusted"
    HOP_PROOF_INVALID = "hop_proof_invalid"
    LEAF_INVOKER_MISMATCH = "leaf_invoker_mismatch"
    ROOT_NOT_RESPONSIBLE_PARTY = "root_not_responsible_party"
    ACTION_NOT_DELEGATED = "action_not_delegated"

    # Status lists (SPEC.md section 6.6, story L3-C's reads).
    STATUS_UNAVAILABLE = "status_unavailable"
    STATUS_REVOKED = "status_revoked"
    STATUS_STALE = "status_stale"
    STATUS_ENTRY_MALFORMED = "status_entry_malformed"
    STATUS_LIST_MISMATCH = "status_list_mismatch"
    STATUS_LIST_MALFORMED = "status_list_malformed"
    STATUS_LIST_PROOF_INVALID = "status_list_proof_invalid"

    # The Entity Card the attestations come from.
    CARD_MALFORMED = "card_malformed"
    CARD_UNRESOLVABLE = "card_unresolvable"
    CARD_SUBJECT_MISMATCH = "card_subject_mismatch"


ALL_REASON_CODES: List[str] = [value for name, value in vars(ReasonCodes).items() if name.isupper() and isinstance(value, str)]
