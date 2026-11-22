# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Producer delivery modes (story A-2 point 3; AUDITABILITY.md, Delivery
semantics), the Python twin of helix-sdk-js ``src/audit/delivery.ts``, as the
``AuditSink`` behind an ``AuditTrail``:

- ``required`` (default): the recorder's signed receipt is obtained before
  the record returns; a failure raises (AAP-2).
- ``buffered``: the item is acknowledged by a durable outbox and delivered by
  ``flush()`` / ``start()``; an ephemeral outbox is refused at construction.
- ``best-effort``: refused unless ``accept_aap1=True``; failures are only
  reported (AAP-1, capture only).

The producer never sets time, sequence, epoch or signature: it submits the
frozen event and checks that the receipt binds it."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Set

from .outbox import audit_outbox_item_key, AuditOutboxItem
from .recorder import AuditRecorderClient, AuditRecorderSubmission, SignedAuditEntry, assert_entry_binds_submission
from .types import AuditProducerEvent, AuditTrailEntry

AUDIT_DELIVERY_MODES = ("required", "buffered", "best-effort")


class AuditDeliveryConfigError(ValueError):
    """Misconfigured delivery, refused at startup."""


@dataclass
class AuditFlushResult:
    delivered: int
    failed: int


def _now_ms() -> int:
    return int(time.time() * 1000)


class AuditDeliverySink:
    """Delivers each recorded event to the authoritative recorder under the configured mode."""

    def __init__(
        self,
        recorder: AuditRecorderClient,
        delivery: str = "required",
        outbox: Any = None,
        accept_aap1: bool = False,
        ledger_id: Optional[str] = None,
        expected_ledger_epoch_id: Optional[str] = None,
        clock: Optional[Callable[[], int]] = None,
        on_delivery_failure: Optional[Callable[[BaseException, AuditProducerEvent], None]] = None,
        on_acknowledgement_failure: Optional[Callable[[BaseException, AuditProducerEvent], None]] = None,
    ) -> None:
        if delivery not in AUDIT_DELIVERY_MODES:
            raise AuditDeliveryConfigError(f"Unknown audit delivery mode {delivery!r}; use required, buffered or best-effort")
        if delivery == "buffered" and getattr(outbox, "durability", None) != "durable":
            raise AuditDeliveryConfigError("Buffered audit delivery requires a durable outbox; an ephemeral outbox is refused")
        if delivery == "best-effort" and accept_aap1 is not True:
            raise AuditDeliveryConfigError("Best-effort audit delivery is AAP-1 only; set accept_aap1 to accept that explicitly")
        self.delivery = delivery
        self.profile = "AAP-1" if delivery == "best-effort" else "AAP-2"
        self._recorder = recorder
        self._outbox = outbox
        self._ledger_id = ledger_id
        self._expected_epoch = expected_ledger_epoch_id
        self._clock = clock or _now_ms
        self._on_delivery_failure = on_delivery_failure
        self._on_ack_failure = on_acknowledgement_failure
        self._flush_lock = threading.Lock()
        self._timer: Optional[threading.Event] = None
        self._thread: Optional[threading.Thread] = None

    def append(self, entry: AuditTrailEntry) -> Optional[SignedAuditEntry]:
        event = entry.event
        if self.delivery == "buffered":
            # Never epoch-pinned: an item may be delivered after a rollover, where
            # logical-ledger idempotency carries the retry guarantee.
            self._outbox.enqueue(
                AuditOutboxItem(
                    event_id=event["eventId"],
                    submission=AuditRecorderSubmission(producer_event=event, ledger_id=self._ledger_id),
                    enqueued_at=self._clock(),
                )
            )
            return None
        submission = AuditRecorderSubmission(producer_event=event, ledger_id=self._ledger_id, expected_ledger_epoch_id=self._expected_epoch)
        try:
            return self._submit(submission)
        except Exception as error:  # noqa: BLE001 - reported, then raised in required mode
            if self._on_delivery_failure is not None:
                self._on_delivery_failure(error, event)
            if self.delivery == "required":
                raise
            return None

    def flush(self, limit: Optional[int] = None) -> AuditFlushResult:
        """Delivers pending outbox items in order; a failure blocks the rest of
        its source for this pass. Once the recorder committed an item, an
        acknowledgement failure never turns it into a delivery failure."""
        if self.delivery != "buffered":
            return AuditFlushResult(0, 0)
        with self._flush_lock:
            delivered = failed = 0
            blocked: Set[str] = set()
            outbox = self._outbox
            for item in list(outbox.pending(limit)):
                source_id = item.submission.producer_event["source"]["sourceId"]
                if source_id in blocked:
                    continue
                key = audit_outbox_item_key(item) if getattr(outbox, "keyed_by_source", False) else item.event_id
                try:
                    self._submit(item.submission)
                except Exception as error:  # noqa: BLE001 - counted on the item
                    outbox.mark_failed(key, error)
                    if self._on_delivery_failure is not None:
                        self._on_delivery_failure(error, item.submission.producer_event)
                    blocked.add(source_id)
                    failed += 1
                    continue
                delivered += 1
                try:
                    outbox.mark_delivered(key)
                except Exception as error:  # noqa: BLE001 - the commit stands; the item redelivers to the same receipt
                    if self._on_ack_failure is not None:
                        self._on_ack_failure(error, item.submission.producer_event)
            return AuditFlushResult(delivered, failed)

    def start(self, interval_seconds: float = 1.0) -> None:
        """Flushes on a daemon thread every ``interval_seconds`` until ``stop()``."""
        if self.delivery != "buffered" or self._thread is not None:
            return
        stop = threading.Event()

        def loop() -> None:
            while not stop.wait(interval_seconds):
                try:
                    self.flush()
                except Exception:  # noqa: BLE001 - the next pass retries
                    pass

        self._timer = stop
        self._thread = threading.Thread(target=loop, name="helix-audit-outbox", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._timer is not None:
            self._timer.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._timer = None
        self._thread = None

    def _submit(self, submission: AuditRecorderSubmission) -> SignedAuditEntry:
        entry = self._recorder.submit(submission)
        assert_entry_binds_submission(entry, submission)
        return entry


def create_audit_delivery(recorder: AuditRecorderClient, **options: Any) -> AuditDeliverySink:
    """``AuditDeliverySink(recorder, **options)``."""
    return AuditDeliverySink(recorder, **options)
