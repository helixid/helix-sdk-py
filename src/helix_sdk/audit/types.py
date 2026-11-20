# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS Auditability Protocol v1 (AUDITABILITY.md, AAP-1 Recorded): the
producer event and the values it is made of, ported from helix-core's
``src/core/audit/types.ts``.

Events and event inputs are plain dicts in the wire shape (camelCase keys,
exactly the vendored ``schemas/audit-event.schema.json``); ``schema.py``
enforces that shape and ``trail.py`` emits it. A ``PartyRef`` is one of
``{"kind": "public_did", "did"}``, ``{"kind": "pairwise_did", "did"}``,
``{"kind": "keyed_commitment", "value", "keyId"}`` or
``{"kind": "evidence_ref", "ref"}``; an ``EvidenceRef`` is the vault
object's metadata (see ``evidence.py``), never its bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

PartyRef = Dict[str, Any]
EvidenceRef = Dict[str, Any]
AuditProducerEvent = Dict[str, Any]
AuditEventInput = Dict[str, Any]

AUDIT_EVENT_SCHEMA = "https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0"
AUDIT_EVENT_VERSION = "1.0.0"

AUDIT_DIGEST_DOMAINS: Dict[str, str] = {
    "event": "org.kya-os.audit.event.v1",
    "entry": "org.kya-os.audit.entry.v1",
    "evidenceManifest": "org.kya-os.audit.evidence-manifest.v1",
    "idempotency": "org.kya-os.audit.idempotency.v1",
    "checkpoint": "org.kya-os.audit.checkpoint.v1",
    "observation": "org.kya-os.audit.observation.v1",
    "bundleManifest": "org.kya-os.audit.bundle-manifest.v1",
    # SPEC section 7.8: one credential's signed form.
    "delegationCredential": "org.kya-os.delegation.credential.v1",
    # SPEC section 7.8: the array of credential digests, root first.
    "delegationChain": "org.kya-os.delegation.chain.v1",
}
"""Digest domains (AUDITABILITY.md, Cryptographic suites): ``<domain> NUL JCS(value)``."""

AUDIT_INTEGRITY_SUITE = "KYA-AUDIT-JCS-SHA256-JWS-2026"

AUDIT_BINDING_MCP = "urn:kya-os:audit-binding:mcp:2025-11-25"
"""The MCP binding every middleware and SDK producer uses."""
AUDIT_BINDING_HELIX = "urn:kya-os:audit-binding:helix:2026-11-20"
"""The binding of events the Helix API records about its own operations."""

AUDIT_EVENT_TYPES: Tuple[str, ...] = (
    "session.established",
    "session.rejected",
    "session.expired",
    "session.replay_rejected",
    "tool.call.started",
    "tool.call.completed",
    "tool.call.failed",
    "tool.call.denied",
    "tool.call.challenged",
    "proof.generated",
    "proof.verified",
    "proof.rejected",
    "delegation.issued",
    "delegation.verified",
    "delegation.rejected",
    "delegation.revoked",
    "delegation.cascade_revoked",
    "delegation.outbound_attached",
    "authorization.evaluated",
    "authorization.approved",
    "authorization.denied",
    "authorization.step_up_required",
    "grant.used",
    "consent.requested",
    "consent.approved",
    "consent.denied",
    "credential.required",
    "credential.verified",
    "credential.failed",
    "key.rotated",
    "policy.changed",
    "configuration.changed",
    "integrity_suite.transitioned",
    "ledger.epoch.started",
    "ledger.epoch.transitioned",
    "checkpoint.created",
    "checkpoint.anchored",
    "checkpoint.anchor_failed",
    "evidence.disposed",
    "projection.reconciled",
    "audit.source_high_water",
    "audit.accessed",
    "audit.exported",
    "legal_hold.applied",
    "retention.executed",
)
"""The event catalog (AUDITABILITY.md, Event and privacy model)."""

AUDIT_EVENT_FAMILIES: Tuple[str, ...] = (
    "session",
    "tool",
    "proof",
    "delegation",
    "authorization",
    "consent",
    "key",
    "ledger",
    "administration",
)

_FAMILY_BY_PREFIX = {
    "grant": "authorization",
    "credential": "consent",
    "policy": "key",
    "configuration": "key",
    "integrity_suite": "key",
    "checkpoint": "ledger",
    "evidence": "ledger",
    "projection": "ledger",
}


def audit_event_family(event_type: str) -> str:
    """Which detail family an event type belongs to (the schema's ``allOf`` rules)."""
    prefix = event_type.split(".")[0]
    if prefix in AUDIT_EVENT_FAMILIES:
        return prefix
    # audit, legal_hold, retention (and anything unlisted) are administration
    return _FAMILY_BY_PREFIX.get(prefix, "administration")


@dataclass
class AuditTrailEntry:
    """A recorded event with its canonical text and domain-separated digest, as the sink receives it."""

    event: AuditProducerEvent
    canonical: str
    """RFC 8785 text of ``event``."""
    event_digest: str
    """``sha256:`` over ``org.kya-os.audit.event.v1 NUL canonical``."""
