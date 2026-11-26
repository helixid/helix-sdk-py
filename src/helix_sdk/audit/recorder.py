# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The producer's view of the authoritative recorder (story A-2), the Python
twin of helix-sdk-js ``src/audit/recorder-client.ts``.

A producer sends a frozen event and the encrypted evidence it references; the
recorder answers with the signed entry (the original one for a redelivery).
Nothing a producer sends chooses time, sequence, epoch, predecessor or
signature; the producer checks that the answer binds exactly the event it
sent."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple

from ..crypto.jcs import canonicalize
from .digest import audit_event_digest
from .types import AuditProducerEvent

SignedAuditEntry = Dict[str, Any]
"""One journal entry as the recorder returns it: ``{core, eventDigest, entryDigest, recorderReceipt}``."""


@dataclass
class AuditRecorderSubmission:
    """What a producer submits: one frozen event and the evidence it references."""

    producer_event: AuditProducerEvent
    encrypted_evidence: List[Tuple[Dict[str, Any], bytes]] = field(default_factory=list)
    """``(EvidenceRef, ciphertext)`` pairs."""
    ledger_id: Optional[str] = None
    expected_ledger_epoch_id: Optional[str] = None
    """Pins a new append to one epoch; never set for buffered redelivery (AUDITABILITY.md)."""


class AuditRecorderClient(Protocol):
    def submit(self, submission: AuditRecorderSubmission) -> SignedAuditEntry: ...


class AuditDeliveryError(Exception):
    """A submission the recorder did not record: unreachable, refused, or answered with an entry that does not bind the event."""

    def __init__(self, message: str, status: Optional[int] = None, code: Optional[str] = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def assert_entry_binds_submission(entry: Any, submission: AuditRecorderSubmission) -> None:
    """Raises unless the entry binds exactly the submitted event: the same
    ledger (when one was named), the same event digest in both places, the
    same event in canonical form. The epoch is not compared: an entry from an
    earlier retained epoch is a legitimate redelivery answer."""
    digest = audit_event_digest(submission.producer_event)
    core = entry.get("core") if isinstance(entry, dict) else None
    if (
        not isinstance(core, dict)
        or (submission.ledger_id is not None and core.get("ledgerId") != submission.ledger_id)
        or entry.get("eventDigest") != digest
        or core.get("eventDigest") != digest
        or canonicalize(core.get("event")) != canonicalize(submission.producer_event)
    ):
        raise AuditDeliveryError("Recorder response does not bind the submitted frozen producer event")


def audit_submission_wire(submission: AuditRecorderSubmission) -> Dict[str, Any]:
    """The JSON wire form (``POST /v1/audit/submissions``, or an ``audit`` member of another request)."""
    wire: Dict[str, Any] = {}
    if submission.ledger_id is not None:
        wire["ledgerId"] = submission.ledger_id
    if submission.expected_ledger_epoch_id is not None:
        wire["expectedLedgerEpochId"] = submission.expected_ledger_epoch_id
    wire["producerEvent"] = submission.producer_event
    if submission.encrypted_evidence:
        wire["encryptedEvidence"] = [
            {"ref": ref, "ciphertextBase64url": base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii")}
            for ref, ciphertext in submission.encrypted_evidence
        ]
    return wire


class HttpAuditRecorderClient:
    """The recorder over HTTP: ``POST /v1/audit/submissions``, answered with ``{"entry": ...}``."""

    def __init__(self, base_url: str, api_key: str, timeout_seconds: float = 5.0, http: Any = None) -> None:
        self._url = f"{base_url.rstrip('/')}/v1/audit/submissions"
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._http = http

    def submit(self, submission: AuditRecorderSubmission) -> SignedAuditEntry:
        client = self._http
        if client is None:
            import requests

            client = requests
        try:
            res = client.post(
                self._url,
                json=audit_submission_wire(submission),
                headers={"authorization": f"Bearer {self._api_key}"},
                timeout=self._timeout,
            )
        except Exception as error:  # noqa: BLE001 - any transport failure is a delivery failure
            raise AuditDeliveryError("The audit recorder could not be reached") from error
        try:
            body = res.json()
        except Exception:  # noqa: BLE001 - a body that is not JSON is a refusal
            body = None
        entry = body.get("entry") if isinstance(body, dict) else None
        if not 200 <= res.status_code < 300 or entry is None:
            error = body.get("error") if isinstance(body, dict) else None
            code = error.get("code") if isinstance(error, dict) else None
            suffix = f" {code}" if code else ""
            raise AuditDeliveryError(f"The audit recorder refused the submission ({res.status_code}{suffix})", res.status_code, code)
        assert_entry_binds_submission(entry, submission)
        return entry
