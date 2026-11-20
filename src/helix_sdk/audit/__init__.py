# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story A-1: typed audit events (Auditability Protocol v1, AAP-1
Recorded), the Python twin of helix-core's ``src/core/audit``.

- ``AuditTrail``: one producer source; ``record(input)`` fills the envelope,
  bounds every caller-presented reference, validates, sequences, chains and
  digests one event and hands the ``AuditTrailEntry`` to an ``AuditSink``.
- ``validate_audit_event`` / ``parse_audit_event``: the vendored schema,
  strictly.
- ``audit_digest`` and friends: domain-separated ``sha256:`` digests over
  RFC 8785 text.
- ``sanitize_reference``, ``delegation_ref``, ``credential_digest``,
  ``delegation_chain_digest``: SPEC section 7.8 references.
- ``EvidenceEncryptor``, ``EvidenceStore``: the evidence vault for exact
  payloads, which an event names by ``EvidenceRef`` and never carries.

The contract with helix-core is ``fixtures/kya-os-helix/audit-events.json``
and the vendored ``audit-integrity`` vectors (tests/test_audit.py).
"""

from __future__ import annotations

from ..errors import AuditEventInvalidError, AuditEvidenceError
from .digest import (
    audit_digest,
    audit_event_digest,
    digest_bytes,
    digest_text,
    keyed_commitment_value,
    utf16_length,
    wtf8_bytes,
)
from .evidence import (
    EncryptedEvidence,
    EvidenceEncryptor,
    EvidenceStore,
    MemoryEvidenceStore,
    assert_evidence_matches_ref,
    evidence_aad,
)
from .references import (
    MAX_CHAIN_DIGESTS,
    MAX_CREDENTIAL_NESTING,
    MAX_REFERENCE_LENGTH,
    UNKNOWN_DELEGATION_REF,
    UNSEEN_CODE_POINT_RANGES,
    credential_digest,
    credential_shown_id,
    credential_signed_form,
    delegation_chain_digest,
    delegation_chain_digests,
    delegation_ref,
    delegation_reference,
    has_unprintable_character,
    json_text_nesting_depth,
    read_signature_base64,
    sanitize_reference,
    value_nesting_depth,
)
from .schema import DIGEST_PATTERN, parse_audit_event, validate_audit_event
from .sink import AuditSink, CallbackAuditSink, MemoryAuditSink, TeeAuditSink
from .trail import (
    DEFAULT_AUDIT_PRIVACY,
    AuditTrail,
    AuditTrailEvidence,
    keyed_commitment,
    pairwise_did,
    public_did,
)
from .types import (
    AUDIT_BINDING_HELIX,
    AUDIT_BINDING_MCP,
    AUDIT_DIGEST_DOMAINS,
    AUDIT_EVENT_FAMILIES,
    AUDIT_EVENT_SCHEMA,
    AUDIT_EVENT_TYPES,
    AUDIT_EVENT_VERSION,
    AUDIT_INTEGRITY_SUITE,
    AuditEventInput,
    AuditProducerEvent,
    AuditTrailEntry,
    EvidenceRef,
    PartyRef,
    audit_event_family,
)

__all__ = [
    "AUDIT_BINDING_HELIX",
    "AUDIT_BINDING_MCP",
    "AUDIT_DIGEST_DOMAINS",
    "AUDIT_EVENT_FAMILIES",
    "AUDIT_EVENT_SCHEMA",
    "AUDIT_EVENT_TYPES",
    "AUDIT_EVENT_VERSION",
    "AUDIT_INTEGRITY_SUITE",
    "DEFAULT_AUDIT_PRIVACY",
    "DIGEST_PATTERN",
    "MAX_CHAIN_DIGESTS",
    "MAX_CREDENTIAL_NESTING",
    "MAX_REFERENCE_LENGTH",
    "UNKNOWN_DELEGATION_REF",
    "UNSEEN_CODE_POINT_RANGES",
    "AuditEventInput",
    "AuditEventInvalidError",
    "AuditEvidenceError",
    "AuditProducerEvent",
    "AuditSink",
    "AuditTrail",
    "AuditTrailEntry",
    "AuditTrailEvidence",
    "CallbackAuditSink",
    "EncryptedEvidence",
    "EvidenceEncryptor",
    "EvidenceRef",
    "EvidenceStore",
    "MemoryAuditSink",
    "MemoryEvidenceStore",
    "PartyRef",
    "TeeAuditSink",
    "assert_evidence_matches_ref",
    "audit_digest",
    "audit_event_digest",
    "audit_event_family",
    "credential_digest",
    "credential_shown_id",
    "credential_signed_form",
    "delegation_chain_digest",
    "delegation_chain_digests",
    "delegation_ref",
    "delegation_reference",
    "digest_bytes",
    "digest_text",
    "evidence_aad",
    "has_unprintable_character",
    "json_text_nesting_depth",
    "keyed_commitment",
    "keyed_commitment_value",
    "pairwise_did",
    "parse_audit_event",
    "public_did",
    "read_signature_base64",
    "sanitize_reference",
    "utf16_length",
    "validate_audit_event",
    "value_nesting_depth",
    "wtf8_bytes",
]
