# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Strict validation of the producer event: the vendored
``schemas/audit-event.schema.json`` by hand, every object closed so an
unknown member anywhere fails closed, plus the schema's rule that the detail
family follows the event type. The twin of helix-core's
``src/core/audit/schema.ts`` (zod); the fixture
``fixtures/kya-os-helix/audit-events.json`` carries the rejections both must
agree on, down to the path of the first issue.

Issues are ``{"path": "a.b", "message": ...}`` with ``''`` for the top
level. Within one object the members are checked in schema order, then its
unknown members are reported at the object's own path; the family rule
(path ``details.family``) runs only on a structurally valid event, as zod's
``superRefine`` does.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from ..errors import AuditEventInvalidError
from .digest import utf16_length
from .types import AUDIT_EVENT_SCHEMA, AUDIT_EVENT_TYPES, AUDIT_EVENT_VERSION, AuditProducerEvent, audit_event_family

Issue = Dict[str, str]
Issues = List[Issue]
Validator = Callable[[Any, str, Issues], None]

DIGEST_PATTERN = re.compile(r"sha256:[a-f0-9]{64}")
_DECIMAL_PATTERN = re.compile(r"0|[1-9][0-9]*")
_BINDING_PATTERN = re.compile(r"urn:kya-os:audit-binding:[a-z0-9][a-z0-9._:-]*")
_DID_PATTERN = re.compile(r"did:[^\r\n]+")
_TRACE_ID_PATTERN = re.compile(r"[a-f0-9]{32}")
_SPAN_ID_PATTERN = re.compile(r"[a-f0-9]{16}")
_MAX_SAFE_INTEGER = 2**53 - 1


def _issue(issues: Issues, path: str, message: str) -> None:
    issues.append({"path": path, "message": message})


def _child(path: str, name: Union[str, int]) -> str:
    return f"{path}.{name}" if path else str(name)


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _string(
    min_length: int = 0,
    max_length: Optional[int] = None,
    pattern: Optional["re.Pattern[str]"] = None,
    pattern_message: str = "Invalid",
) -> Validator:
    def validate(value: Any, path: str, issues: Issues) -> None:
        if not isinstance(value, str):
            _issue(issues, path, f"Expected string, received {_type_name(value)}")
            return
        length = utf16_length(value)
        if length < min_length:
            _issue(issues, path, f"String must contain at least {min_length} character(s)")
        elif max_length is not None and length > max_length:
            _issue(issues, path, f"String must contain at most {max_length} character(s)")
        elif pattern is not None and pattern.fullmatch(value) is None:
            _issue(issues, path, pattern_message)

    return validate


def _literal(expected: str) -> Validator:
    def validate(value: Any, path: str, issues: Issues) -> None:
        if value != expected or not isinstance(value, str):
            _issue(issues, path, f'Invalid literal value, expected "{expected}"')

    return validate


def _enum(options: Sequence[str]) -> Validator:
    def validate(value: Any, path: str, issues: Issues) -> None:
        if not isinstance(value, str) or value not in options:
            _issue(issues, path, "Invalid enum value. Expected " + " | ".join(f"'{option}'" for option in options))

    return validate


def _array(item: Validator, max_length: int) -> Validator:
    def validate(value: Any, path: str, issues: Issues) -> None:
        if not isinstance(value, list):
            _issue(issues, path, f"Expected array, received {_type_name(value)}")
            return
        if len(value) > max_length:
            _issue(issues, path, f"Array must contain at most {max_length} element(s)")
            return
        for index, element in enumerate(value):
            item(element, _child(path, index), issues)

    return validate


def _object(members: Sequence[Tuple[str, Validator, bool]]) -> Validator:
    """A closed object: ``members`` are ``(name, validator, required)`` in schema order."""

    known = {name for name, _, _ in members}

    def validate(value: Any, path: str, issues: Issues) -> None:
        if not isinstance(value, dict):
            _issue(issues, path, f"Expected object, received {_type_name(value)}")
            return
        for name, validator, required in members:
            if name in value:
                validator(value[name], _child(path, name), issues)
            elif required:
                _issue(issues, _child(path, name), "Required")
        unknown = [name for name in value if name not in known]
        if unknown:
            _issue(issues, path, "Unrecognized key(s) in object: " + ", ".join(f"'{name}'" for name in unknown))

    return validate


def _discriminated(discriminator: str, variants: Dict[str, Validator]) -> Validator:
    def validate(value: Any, path: str, issues: Issues) -> None:
        if not isinstance(value, dict):
            _issue(issues, path, f"Expected object, received {_type_name(value)}")
            return
        kind = value.get(discriminator)
        variant = variants.get(kind) if isinstance(kind, str) else None
        if variant is None:
            # zod names the discriminator member itself (`actor.kind`, `details.family`).
            _issue(
                issues,
                _child(path, discriminator),
                "Invalid discriminator value. Expected " + " | ".join(f"'{option}'" for option in variants),
            )
            return
        variant(value, path, issues)

    return validate


def _non_negative_safe_integer(value: Any, path: str, issues: Issues) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _issue(issues, path, f"Expected number, received {_type_name(value)}")
    elif isinstance(value, float) and not value.is_integer():
        _issue(issues, path, "Expected integer, received float")
    elif value < 0:
        _issue(issues, path, "Number must be greater than or equal to 0")
    elif value > _MAX_SAFE_INTEGER:
        _issue(issues, path, f"Number must be less than or equal to {_MAX_SAFE_INTEGER}")


_digest = _string(pattern=DIGEST_PATTERN, pattern_message="must be sha256:<64 lowercase hex>")
_decimal = _string(max_length=20, pattern=_DECIMAL_PATTERN, pattern_message="must be a decimal integer")
_reference = _string(min_length=1, max_length=256)
_short_reference = _string(min_length=1, max_length=128)
_did = _string(min_length=5, max_length=2048, pattern=_DID_PATTERN, pattern_message="must be a DID")

signer_ref_validator = _object(
    [("did", _did, True), ("kid", _string(min_length=1, max_length=2304), True), ("alg", _enum(["EdDSA", "ES256"]), True)]
)

evidence_ref_validator = _object(
    [
        ("objectId", _reference, True),
        ("ciphertextDigest", _digest, True),
        ("plaintextCommitment", _digest, False),
        ("mediaType", _reference, True),
        ("size", _decimal, True),
        (
            "encryption",
            _object(
                [
                    ("suite", _literal("A256GCM"), True),
                    ("keyId", _reference, True),
                    ("nonce", _reference, True),
                    ("aadDigest", _digest, True),
                ]
            ),
            True,
        ),
    ]
)

party_ref_validator = _discriminated(
    "kind",
    {
        "public_did": _object([("kind", _literal("public_did"), True), ("did", _did, True)]),
        "pairwise_did": _object([("kind", _literal("pairwise_did"), True), ("did", _did, True)]),
        "keyed_commitment": _object(
            [("kind", _literal("keyed_commitment"), True), ("value", _digest, True), ("keyId", _reference, True)]
        ),
        "evidence_ref": _object([("kind", _literal("evidence_ref"), True), ("ref", evidence_ref_validator, True)]),
    },
)

_evidence_list = _array(evidence_ref_validator, 256)

audit_event_details_validator = _discriminated(
    "family",
    {
        "session": _object(
            [
                ("family", _literal("session"), True),
                ("phase", _enum(["established", "rejected", "expired", "replay_rejected"]), True),
                ("reasonCode", _short_reference, False),
            ]
        ),
        "tool": _object(
            [
                ("family", _literal("tool"), True),
                ("phase", _enum(["started", "completed", "failed", "denied", "challenged"]), True),
                ("attempt", _decimal, True),
                ("idempotencyRef", _reference, False),
            ]
        ),
        "proof": _object(
            [
                ("family", _literal("proof"), True),
                ("phase", _enum(["generated", "verified", "rejected"]), True),
                ("proofDigest", _digest, False),
                ("verificationCode", _short_reference, False),
            ]
        ),
        "delegation": _object(
            [
                ("family", _literal("delegation"), True),
                ("phase", _enum(["issued", "verified", "rejected", "revoked", "cascade_revoked", "outbound_attached"]), True),
                ("delegationRef", _reference, True),
                ("parentRef", _reference, False),
                ("statusEvidence", _evidence_list, False),
            ]
        ),
        "authorization": _object(
            [
                ("family", _literal("authorization"), True),
                ("phase", _enum(["evaluated", "approved", "denied", "step_up_required", "grant_used"]), True),
                ("policyDigest", _digest, False),
                ("grantRef", _reference, False),
            ]
        ),
        "consent": _object(
            [
                ("family", _literal("consent"), True),
                (
                    "phase",
                    _enum(["requested", "approved", "denied", "credential_required", "credential_verified", "credential_failed"]),
                    True,
                ),
                ("consentRef", _reference, False),
            ]
        ),
        "key": _object(
            [
                ("family", _literal("key"), True),
                ("phase", _enum(["rotated", "policy_changed", "configuration_changed", "integrity_suite_transitioned"]), True),
                ("previousSigner", signer_ref_validator, False),
                ("nextSigner", signer_ref_validator, False),
                ("configurationDigest", _digest, False),
            ]
        ),
        "ledger": _object(
            [
                ("family", _literal("ledger"), True),
                (
                    "phase",
                    _enum(
                        [
                            "epoch_started",
                            "epoch_transitioned",
                            "checkpoint_created",
                            "checkpoint_anchored",
                            "checkpoint_anchor_failed",
                            "evidence_disposed",
                            "projection_reconciled",
                        ]
                    ),
                    True,
                ),
                ("checkpointDigest", _digest, False),
                ("previousEpochId", _reference, False),
                ("previousTerminalCheckpointDigest", _digest, False),
                ("successorEpochIds", _array(_reference, 256), False),
                ("targetEvidenceRef", evidence_ref_validator, False),
            ]
        ),
        "administration": _object(
            [
                ("family", _literal("administration"), True),
                ("phase", _enum(["source_high_water", "accessed", "exported", "legal_hold_applied", "retention_executed"]), True),
                ("purpose", _reference, False),
                ("sourceSequence", _decimal, False),
                ("selectionDigest", _digest, False),
            ]
        ),
    },
)

authorization_evidence_validator = _object(
    [
        ("source", _enum(["delegation", "grant", "anonymous", "policy"]), True),
        ("decision", _enum(["allowed", "denied", "step_up_required", "needs_authorization"]), True),
        ("scopeId", _reference, False),
        ("delegationRef", _reference, False),
        ("delegationCredentialDigest", _digest, False),
        ("delegationChainDigests", _array(_digest, 256), False),
        ("statusEvidence", _evidence_list, False),
        ("grantRef", _reference, False),
        ("policyId", _reference, False),
        ("policyVersion", _reference, False),
        ("policyDigest", _digest, False),
        ("verificationCode", _short_reference, False),
    ]
)

_audit_producer_event_validator = _object(
    [
        ("schema", _literal(AUDIT_EVENT_SCHEMA), True),
        ("eventId", _reference, True),
        ("eventType", _enum(AUDIT_EVENT_TYPES), True),
        ("eventVersion", _literal(AUDIT_EVENT_VERSION), True),
        ("binding", _string(max_length=256, pattern=_BINDING_PATTERN, pattern_message="must be urn:kya-os:audit-binding:<id>"), True),
        ("occurredAt", _non_negative_safe_integer, True),
        ("tenantRef", party_ref_validator, True),
        (
            "source",
            _object(
                [
                    ("producer", party_ref_validator, True),
                    ("sourceId", _reference, True),
                    ("sourceSequence", _decimal, False),
                    ("previousSourceEventDigest", _digest, False),
                ]
            ),
            True,
        ),
        ("correlationId", _reference, False),
        ("causationId", _reference, False),
        (
            "trace",
            _object(
                [
                    ("traceId", _string(pattern=_TRACE_ID_PATTERN, pattern_message="Invalid"), False),
                    ("spanId", _string(pattern=_SPAN_ID_PATTERN, pattern_message="Invalid"), False),
                ]
            ),
            False,
        ),
        ("session", _object([("ref", party_ref_validator, True), ("handshakeNonceCommitment", _digest, False)]), False),
        ("actor", party_ref_validator, False),
        ("responsibleParty", party_ref_validator, False),
        ("resource", party_ref_validator, False),
        (
            "action",
            _object([("category", _short_reference, True), ("name", _reference, False), ("detailRef", evidence_ref_validator, False)]),
            True,
        ),
        ("outcome", _enum(["succeeded", "failed", "denied", "challenged", "unknown"]), True),
        ("reason", _object([("code", _short_reference, True), ("detailRef", evidence_ref_validator, False)]), False),
        ("authorization", authorization_evidence_validator, False),
        ("proof", evidence_ref_validator, False),
        ("evidence", _evidence_list, True),
        ("details", audit_event_details_validator, True),
        (
            "privacy",
            _object(
                [
                    ("classification", _enum(["public", "internal", "confidential", "restricted"]), True),
                    ("retentionClass", _short_reference, True),
                    ("legalHold", _reference, False),
                ]
            ),
            True,
        ),
    ]
)


def validate_audit_event(value: Any) -> Tuple[bool, Any]:
    """``(True, event)`` for a producer event, else ``(False, issues)``."""
    issues: Issues = []
    _audit_producer_event_validator(value, "", issues)
    if not issues:
        family = audit_event_family(value["eventType"])
        if value["details"]["family"] != family:
            _issue(issues, "details.family", f'must be "{family}" for {value["eventType"]}')
    if issues:
        return False, issues
    return True, value


def parse_audit_event(value: Any) -> AuditProducerEvent:
    """The event, or ``AuditEventInvalidError``. Fails closed: an unknown member anywhere is a refusal, never dropped."""
    ok, result = validate_audit_event(value)
    if not ok:
        raise AuditEventInvalidError(result)
    return result
