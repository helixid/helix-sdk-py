# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The producer trail (AUDITABILITY.md, Delivery semantics and Event and
privacy model), ported from helix-core's ``src/core/audit/trail.ts``. One
``AuditTrail`` is one source: it fills in the envelope, bounds every
caller-presented reference, applies the tool-name policy, validates the
event before it claims a source sequence, chains consecutive events by
``previousSourceEventDigest``, digests the canonical event and hands the
entry to its sink.

Inputs are dicts in the wire shape (``AuditEventInput``: everything but
schema, eventVersion, binding, tenantRef, source and privacy, with eventId,
occurredAt, evidence and privacy optional). A member whose value is None is
read as absent, the way an ``undefined`` member is in JavaScript.
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional, Union

from ..crypto.jcs import canonicalize
from ..errors import AuditEvidenceError
from .digest import audit_event_digest
from .evidence import EvidenceEncryptor, EvidenceStore, evidence_aad
from .references import sanitize_reference
from .schema import parse_audit_event
from .sink import AuditSink
from .types import (
    AUDIT_BINDING_HELIX,
    AUDIT_EVENT_SCHEMA,
    AUDIT_EVENT_VERSION,
    AuditEventInput,
    AuditProducerEvent,
    AuditTrailEntry,
    EvidenceRef,
    PartyRef,
)

DEFAULT_AUDIT_PRIVACY: Dict[str, str] = {"classification": "internal", "retentionClass": "audit-indefinite"}

_AUTHORIZATION_REFERENCE_FIELDS = ("scopeId", "delegationRef", "grantRef", "policyId", "policyVersion")
_DETAIL_REFERENCE_FIELDS = {
    "delegation": (("delegationRef", 256), ("parentRef", 256)),
    "authorization": (("grantRef", 256),),
    "consent": (("consentRef", 256),),
    "tool": (("idempotencyRef", 256),),
    "session": (("reasonCode", 128),),
    "proof": (("verificationCode", 128),),
}


def _bounded(value: Any, max_length: int = 256) -> Any:
    """A reference bounded when it is a string; anything else is left for the validator to refuse."""
    return sanitize_reference(value, max_length) if isinstance(value, str) else value


def _bounded_authorization(authorization: Any) -> Any:
    if not isinstance(authorization, dict):
        return authorization
    bounded = dict(authorization)
    for field in _AUTHORIZATION_REFERENCE_FIELDS:
        if field in bounded:
            bounded[field] = _bounded(bounded[field])
    if "verificationCode" in bounded:
        bounded["verificationCode"] = _bounded(bounded["verificationCode"], 128)
    return bounded


def _bounded_details(details: Any) -> Any:
    if not isinstance(details, dict):
        return details
    fields = _DETAIL_REFERENCE_FIELDS.get(details.get("family"))  # type: ignore[arg-type]
    if fields is None:
        return details
    bounded = dict(details)
    for field, max_length in fields:
        if field in bounded:
            bounded[field] = _bounded(bounded[field], max_length)
    return bounded


def _now_ms() -> int:
    return int(time.time() * 1000)


def _new_event_id() -> str:
    return f"audit_{uuid.uuid4()}"


class AuditTrail:
    def __init__(
        self,
        sink: AuditSink,
        source_id: str,
        producer: PartyRef,
        tenant_ref: PartyRef,
        binding: str = AUDIT_BINDING_HELIX,
        privacy: Optional[Dict[str, str]] = None,
        clock: Optional[Callable[[], int]] = None,
        new_event_id: Optional[Callable[[], str]] = None,
        include_tool_names: bool = False,
        evidence: Optional["AuditTrailEvidence"] = None,
    ) -> None:
        """``sink`` receives every entry; ``source_id`` names this producer
        source (sequences and predecessor digests are per source); ``clock``
        returns milliseconds since the epoch; ``new_event_id`` defaults to
        ``audit_<uuid>``. ``include_tool_names`` records ``action.name`` on
        tool events (default False: a tool name is a caller-presented
        reference and often sensitive in itself, so recording it is an
        explicit policy decision). ``evidence`` enables ``evidence()``;
        without it an exact payload cannot be kept and no event carries one."""
        if not isinstance(source_id, str) or len(source_id) == 0 or len(source_id) > 256:
            raise TypeError("sourceId must be 1 to 256 characters")
        self._sink = sink
        self._source_id = source_id
        self._producer = producer
        self._tenant_ref = tenant_ref
        self._binding = binding
        self._privacy = dict(privacy) if privacy is not None else dict(DEFAULT_AUDIT_PRIVACY)
        self._clock = clock or _now_ms
        self._new_event_id = new_event_id or _new_event_id
        self._include_tool_names = include_tool_names
        self._evidence = evidence
        self._next_sequence = 1
        self._last_digest: Optional[str] = None
        self._lock = threading.Lock()

    @property
    def source_id(self) -> str:
        return self._source_id

    @property
    def include_tool_names(self) -> bool:
        return self._include_tool_names

    @property
    def sequence(self) -> int:
        """The sequence the next recorded event claims."""
        return self._next_sequence

    @property
    def previous_source_event_digest(self) -> Optional[str]:
        """The digest of the last event appended, which the next event names as its predecessor."""
        return self._last_digest

    def build(self, input: AuditEventInput) -> AuditProducerEvent:  # noqa: A002 - the reference's name
        """The event as it will be recorded, before any sequence is claimed:
        envelope filled, references bounded, tool-name policy applied,
        strictly validated. Raises ``AuditEventInvalidError`` for an input
        that is not a producer event."""
        given = {name: value for name, value in input.items() if value is not None}
        event_id = given.pop("eventId", None)
        occurred_at = given.pop("occurredAt", None)
        privacy = given.pop("privacy", None)
        evidence = given.pop("evidence", None)
        authorization = given.pop("authorization", None)
        details = given.pop("details", None)
        action = given.pop("action", None)
        correlation_id = given.pop("correlationId", None)
        causation_id = given.pop("causationId", None)

        bounded_action = dict(action) if isinstance(action, dict) else action
        if isinstance(bounded_action, dict) and "name" in bounded_action:
            if isinstance(details, dict) and details.get("family") == "tool" and not self._include_tool_names:
                del bounded_action["name"]
            else:
                bounded_action["name"] = _bounded(bounded_action["name"])

        candidate: Dict[str, Any] = {
            "schema": AUDIT_EVENT_SCHEMA,
            "eventId": event_id if event_id is not None else self._new_event_id(),
            "eventVersion": AUDIT_EVENT_VERSION,
            "binding": self._binding,
            "occurredAt": occurred_at if occurred_at is not None else self._clock(),
            "tenantRef": self._tenant_ref,
            "source": {"producer": self._producer, "sourceId": self._source_id},
        }
        candidate.update(given)
        if correlation_id is not None:
            candidate["correlationId"] = _bounded(correlation_id)
        if causation_id is not None:
            candidate["causationId"] = _bounded(causation_id)
        if action is not None:
            candidate["action"] = bounded_action
        if authorization is not None:
            candidate["authorization"] = _bounded_authorization(authorization)
        reason = given.get("reason")
        if isinstance(reason, dict) and "code" in reason:
            candidate["reason"] = {**reason, "code": _bounded(reason["code"], 128)}
        candidate["evidence"] = evidence if evidence is not None else []
        if details is not None:
            candidate["details"] = _bounded_details(details)
        candidate["privacy"] = {**self._privacy, **privacy} if isinstance(privacy, dict) else privacy if privacy is not None else dict(self._privacy)
        return parse_audit_event(candidate)

    def record(self, input: AuditEventInput) -> AuditTrailEntry:  # noqa: A002 - the reference's name
        """Records one event: builds and validates it, then (serialized per
        trail) claims the next source sequence, links the previous event's
        digest, canonicalizes, digests and appends to the sink. Rejected
        input never consumes a sequence; a sink failure consumes one and
        leaves the predecessor link on the last appended event."""
        built = self.build(input)
        with self._lock:
            sequence = self._next_sequence
            self._next_sequence += 1
            source = {**built["source"], "sourceSequence": str(sequence)}
            if self._last_digest is not None:
                source["previousSourceEventDigest"] = self._last_digest
            event = {**built, "source": source}
            entry = AuditTrailEntry(event=event, canonical=canonicalize(event), event_digest=audit_event_digest(event))
            self._sink.append(entry)
            self._last_digest = entry.event_digest
            return entry

    def evidence(
        self,
        plaintext: Union[bytes, str],
        media_type: str,
        purpose: str,
        commit_plaintext: bool = False,
    ) -> EvidenceRef:
        """Keeps an exact payload as encrypted evidence bound to this trail's
        tenant and ``purpose``, and returns the reference an event may carry.
        Raises ``AuditEvidenceError`` when the trail has no evidence vault."""
        if self._evidence is None:
            raise AuditEvidenceError("This audit trail has no evidence vault; configure one to keep exact payloads")
        encrypted = self._evidence.encryptor.encrypt(
            plaintext, media_type, self.evidence_aad(purpose), commit_plaintext=commit_plaintext
        )
        return self._evidence.store.put_if_absent(encrypted)

    def evidence_aad(self, purpose: str) -> bytes:
        """The authenticated data this trail binds evidence with: its tenant and the purpose."""
        return evidence_aad(self._tenant_ref, purpose)


class AuditTrailEvidence:
    """The vault an ``AuditTrail`` keeps exact payloads in: an encryptor and a store."""

    def __init__(self, encryptor: EvidenceEncryptor, store: EvidenceStore) -> None:
        self.encryptor = encryptor
        self.store = store


def public_did(did: str) -> PartyRef:
    """``{"kind": "public_did", "did": did}``."""
    return {"kind": "public_did", "did": did}


def pairwise_did(did: str) -> PartyRef:
    """``{"kind": "pairwise_did", "did": did}``."""
    return {"kind": "pairwise_did", "did": did}


def keyed_commitment(value: str, key_id: str) -> PartyRef:
    """``{"kind": "keyed_commitment", "value": value, "keyId": key_id}``; see ``keyed_commitment_value`` for the value."""
    return {"kind": "keyed_commitment", "value": value, "keyId": key_id}
