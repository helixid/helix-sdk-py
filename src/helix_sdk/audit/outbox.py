# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The producer outbox for ``buffered`` delivery (story A-2 point 3), the
Python twin of helix-sdk-js ``src/audit/outbox.ts``.

Items are keyed by ``(sourceId, eventId)``; enqueue is idempotent per key
and refuses divergent content; ``pending()`` yields FIFO per source and
leaves out dead letters; failures are counted persistently. ``DurableOutbox``
keeps one JSON file per item in a directory, written to a temporary name,
flushed and renamed, so an item is wholly there or not at all and survives a
restart; the file format is the JS outbox's, so either SDK can drain it.

``evaluate_audit_outbox_provider_contract`` is the reference outbox contract
(upstream ``provider-contracts.ts`` at a4d7f61), check for check."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass, replace
from typing import Any, Callable, Dict, Iterator, List, Optional, Protocol, Tuple, Union

from ..crypto.jcs import canonicalize
from .recorder import AuditRecorderSubmission


@dataclass
class AuditOutboxItem:
    event_id: str
    submission: AuditRecorderSubmission
    enqueued_at: int
    attempts: int = 0
    """Persisted delivery failures; durable adapters use this for retry and dead-letter policy."""


OutboxKey = Tuple[str, str]
"""``(sourceId, eventId)``: event ids are unique only within a source."""


def audit_outbox_item_key(item: AuditOutboxItem) -> OutboxKey:
    return (item.submission.producer_event["source"]["sourceId"], item.event_id)


class AuditOutboxProvider(Protocol):
    durability: str
    """``ephemeral`` or ``durable``."""
    keyed_by_source: bool

    def enqueue(self, item: AuditOutboxItem) -> None: ...

    def pending(self, limit: Optional[int] = None) -> Iterator[AuditOutboxItem]: ...

    def mark_delivered(self, key: Union[OutboxKey, str]) -> None: ...

    def mark_failed(self, key: Union[OutboxKey, str], error: BaseException) -> None: ...


class AuditOutboxConflictError(Exception):
    """An item whose content differs from the one already enqueued under its key."""

    def __init__(self, key: OutboxKey) -> None:
        super().__init__(f"Audit outbox event identity collision: {key[0]} / {key[1]}")


def same_audit_submission(left: AuditRecorderSubmission, right: AuditRecorderSubmission) -> bool:
    """The same ledger, epoch pin, canonical event and evidence bytes."""
    if (
        left.ledger_id != right.ledger_id
        or left.expected_ledger_epoch_id != right.expected_ledger_epoch_id
        or canonicalize(left.producer_event) != canonicalize(right.producer_event)
        or len(left.encrypted_evidence) != len(right.encrypted_evidence)
    ):
        return False
    return all(
        canonicalize(a_ref) == canonicalize(b_ref) and bytes(a_bytes) == bytes(b_bytes)
        for (a_ref, a_bytes), (b_ref, b_bytes) in zip(left.encrypted_evidence, right.encrypted_evidence)
    )


def _resolve(key: Union[OutboxKey, str], keys: List[OutboxKey]) -> Optional[OutboxKey]:
    """A bare event id names an item only while exactly one source has it pending."""
    if not isinstance(key, str):
        return tuple(key)  # type: ignore[return-value]
    matches = [candidate for candidate in keys if candidate[1] == key]
    if len(matches) > 1:
        raise ValueError(f"Audit outbox event id {key} is pending for several sources; pass its (sourceId, eventId) key")
    return matches[0] if matches else None


class MemoryAuditOutbox:
    """Development-only outbox: buffered delivery refuses it, because it does not survive a restart."""

    durability = "ephemeral"
    keyed_by_source = True

    def __init__(self) -> None:
        self._items: Dict[OutboxKey, AuditOutboxItem] = {}
        self._lock = threading.Lock()

    def enqueue(self, item: AuditOutboxItem) -> None:
        key = audit_outbox_item_key(item)
        with self._lock:
            existing = self._items.get(key)
            if existing is not None:
                if not same_audit_submission(existing.submission, item.submission):
                    raise AuditOutboxConflictError(key)
                return
            self._items[key] = replace(item)

    def pending(self, limit: Optional[int] = None) -> Iterator[AuditOutboxItem]:
        with self._lock:
            items = list(self._items.values())
        return iter(items[:limit] if limit is not None else items)

    def mark_delivered(self, key: Union[OutboxKey, str]) -> None:
        with self._lock:
            stored = _resolve(key, list(self._items))
            if stored is not None:
                self._items.pop(stored, None)

    def mark_failed(self, key: Union[OutboxKey, str], error: BaseException) -> None:
        with self._lock:
            stored = _resolve(key, list(self._items))
            item = self._items.get(stored) if stored is not None else None
            if item is not None:
                self._items[stored] = replace(item, attempts=item.attempts + 1)  # type: ignore[index]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _from_b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _to_stored(item: AuditOutboxItem) -> Dict[str, Any]:
    submission: Dict[str, Any] = {}
    if item.submission.ledger_id is not None:
        submission["ledgerId"] = item.submission.ledger_id
    if item.submission.expected_ledger_epoch_id is not None:
        submission["expectedLedgerEpochId"] = item.submission.expected_ledger_epoch_id
    submission["producerEvent"] = item.submission.producer_event
    submission["encryptedEvidence"] = [{"ref": ref, "ciphertextBase64url": _b64url(ciphertext)} for ref, ciphertext in item.submission.encrypted_evidence]
    return {
        "format": "helix-audit-outbox-item/v1",
        "eventId": item.event_id,
        "enqueuedAt": item.enqueued_at,
        "attempts": item.attempts,
        "submission": submission,
    }


def _from_stored(stored: Dict[str, Any]) -> AuditOutboxItem:
    if stored.get("format") != "helix-audit-outbox-item/v1":
        raise ValueError("Not a helix audit outbox item")
    submission = stored["submission"]
    return AuditOutboxItem(
        event_id=stored["eventId"],
        enqueued_at=stored["enqueuedAt"],
        attempts=stored["attempts"],
        submission=AuditRecorderSubmission(
            producer_event=submission["producerEvent"],
            encrypted_evidence=[(item["ref"], _from_b64url(item["ciphertextBase64url"])) for item in submission.get("encryptedEvidence", [])],
            ledger_id=submission.get("ledgerId"),
            expected_ledger_epoch_id=submission.get("expectedLedgerEpochId"),
        ),
    )


def _fsync_directory(directory: str) -> None:
    """Makes a rename or unlink durable; platforms without directory fsync are tolerated."""
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class DurableOutbox:
    """A durable outbox in a directory: ``pending/<order>-<key digest>.json``
    per item, ``dead/`` for dead letters. One producer process owns one
    directory; operations are serialized per instance."""

    durability = "durable"
    keyed_by_source = True

    def __init__(self, directory: str, max_attempts: Optional[int] = None) -> None:
        self._pending_dir = os.path.join(directory, "pending")
        self._dead_dir = os.path.join(directory, "dead")
        self._max_attempts = max_attempts
        self._lock = threading.RLock()
        self._index: Optional[Dict[OutboxKey, str]] = None
        self._next_order = 0

    def enqueue(self, item: AuditOutboxItem) -> None:
        with self._lock:
            index = self._load()
            key = audit_outbox_item_key(item)
            existing = index.get(key)
            if existing is not None:
                if not same_audit_submission(self._read(os.path.join(self._pending_dir, existing)).submission, item.submission):
                    raise AuditOutboxConflictError(key)
                return
            digest = hashlib.sha256(f"{key[0]}\0{key[1]}".encode("utf-8")).hexdigest()[:32]
            name = f"{self._next_order:016d}-{digest}.json"
            self._next_order += 1
            self._write(os.path.join(self._pending_dir, name), _to_stored(item))
            index[key] = name

    def pending(self, limit: Optional[int] = None) -> Iterator[AuditOutboxItem]:
        with self._lock:
            names = sorted(self._load().values())
        count = 0
        for name in names:
            if limit is not None and count >= limit:
                return
            try:
                item = self._read(os.path.join(self._pending_dir, name))
            except FileNotFoundError:
                continue  # delivered meanwhile
            count += 1
            yield item

    def mark_delivered(self, key: Union[OutboxKey, str]) -> None:
        with self._lock:
            index = self._load()
            stored = _resolve(key, list(index))
            name = index.get(stored) if stored is not None else None
            if name is None:
                return
            try:
                os.unlink(os.path.join(self._pending_dir, name))
            except FileNotFoundError:
                pass
            _fsync_directory(self._pending_dir)
            index.pop(stored, None)  # type: ignore[arg-type]

    def mark_failed(self, key: Union[OutboxKey, str], error: BaseException) -> None:
        with self._lock:
            index = self._load()
            stored = _resolve(key, list(index))
            name = index.get(stored) if stored is not None else None
            if name is None:
                return
            path = os.path.join(self._pending_dir, name)
            current = self._read(path)
            failed = replace(current, attempts=current.attempts + 1)
            if self._max_attempts is not None and failed.attempts >= self._max_attempts:
                self._write(os.path.join(self._dead_dir, name), _to_stored(failed))
                os.unlink(path)
                _fsync_directory(self._pending_dir)
                index.pop(stored, None)  # type: ignore[arg-type]
                return
            self._write(path, _to_stored(failed))

    def dead_letters(self) -> List[AuditOutboxItem]:
        """Items that exhausted their attempts, kept for operator inspection and recovery."""
        if not os.path.isdir(self._dead_dir):
            return []
        return [self._read(os.path.join(self._dead_dir, name)) for name in sorted(os.listdir(self._dead_dir)) if name.endswith(".json")]

    def _load(self) -> Dict[OutboxKey, str]:
        if self._index is not None:
            return self._index
        os.makedirs(self._pending_dir, exist_ok=True)
        os.makedirs(self._dead_dir, exist_ok=True)
        index: Dict[OutboxKey, str] = {}
        for name in sorted(n for n in os.listdir(self._pending_dir) if n.endswith(".json")):
            index[audit_outbox_item_key(self._read(os.path.join(self._pending_dir, name)))] = name
        orders = [int(name[:16]) for name in list(index.values()) + os.listdir(self._dead_dir) if name[:16].isdigit()]
        self._next_order = max(orders) + 1 if orders else 0
        self._index = index
        return index

    @staticmethod
    def _read(path: str) -> AuditOutboxItem:
        with open(path, "r", encoding="utf-8") as handle:
            return _from_stored(json.load(handle))

    @staticmethod
    def _write(path: str, value: Dict[str, Any]) -> None:
        temporary = f"{path}.{uuid.uuid4().hex}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(value, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(os.path.dirname(path))


# -- the reference outbox contract ----------------------------------------------


@dataclass
class AuditOutboxContractCheck:
    name: str
    passed: bool
    error: Optional[BaseException] = None


@dataclass
class AuditOutboxContractReport:
    passed: bool
    checks: List[AuditOutboxContractCheck]
    provider_kind: str = "outbox"


def _contract_event(sequence: int) -> Dict[str, Any]:
    return {
        "schema": "https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0",
        "eventId": f"contract-event-{sequence}",
        "eventType": "tool.call.completed",
        "eventVersion": "1.0.0",
        "binding": "urn:kya-os:audit-binding:contract:1",
        "occurredAt": 1_750_000_000_000 + sequence,
        "tenantRef": {"kind": "pairwise_did", "did": "did:key:zContractTenant"},
        "source": {"producer": {"kind": "pairwise_did", "did": "did:key:zContractProducer"}, "sourceId": "contract-source", "sourceSequence": str(sequence)},
        "action": {"category": "tool.call"},
        "outcome": "succeeded",
        "evidence": [],
        "details": {"family": "tool", "phase": "completed", "attempt": "1"},
        "privacy": {"classification": "internal", "retentionClass": "contract"},
    }


def _contract_item(sequence: int) -> AuditOutboxItem:
    return AuditOutboxItem(
        event_id=f"contract-event-{sequence}",
        submission=AuditRecorderSubmission(producer_event=_contract_event(sequence), ledger_id="contract-ledger", expected_ledger_epoch_id="epoch-1"),
        enqueued_at=1_750_000_000_000 + sequence,
    )


def assert_audit_outbox_contract(report: AuditOutboxContractReport) -> None:
    failures = [check.name for check in report.checks if not check.passed]
    if failures:
        raise AssertionError(f"outbox provider contract failed: {', '.join(failures)}")


def evaluate_audit_outbox_provider_contract(create_provider: Callable[[], Any]) -> AuditOutboxContractReport:
    """FIFO per source, idempotent enqueue refusing divergent content, failure accounting and acknowledgement, source-scoped keys."""
    checks: List[AuditOutboxContractCheck] = []

    def run(name: str, body: Callable[[], None]) -> None:
        try:
            body()
            checks.append(AuditOutboxContractCheck(name, True))
        except Exception as error:  # noqa: BLE001 - every failure is a contract finding
            checks.append(AuditOutboxContractCheck(name, False, error))

    def expect(condition: bool, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    def key_of(provider: Any, item: AuditOutboxItem) -> Union[OutboxKey, str]:
        return audit_outbox_item_key(item) if provider.keyed_by_source else item.event_id

    keyed = {"value": False}

    def fifo() -> None:
        provider = create_provider()
        keyed["value"] = bool(provider.keyed_by_source)
        provider.enqueue(_contract_item(1))
        provider.enqueue(_contract_item(2))
        expect([item.event_id for item in provider.pending()] == ["contract-event-1", "contract-event-2"], "pending items were not yielded in enqueue order")

    def idempotent() -> None:
        provider = create_provider()
        provider.enqueue(_contract_item(1))
        provider.enqueue(copy.deepcopy(_contract_item(1)))
        expect(len(list(provider.pending())) == 1, "redelivered enqueue duplicated the pending item")
        divergent = _contract_item(1)
        divergent.submission = replace(divergent.submission, producer_event={**divergent.submission.producer_event, "action": {"category": "tampered"}})
        rejected = False
        try:
            provider.enqueue(divergent)
        except Exception:  # noqa: BLE001
            rejected = True
        expect(rejected, "divergent content under one event identity was accepted")

    def accounting() -> None:
        provider = create_provider()
        provider.enqueue(_contract_item(1))
        provider.enqueue(_contract_item(2))
        provider.mark_failed(key_of(provider, _contract_item(1)), RuntimeError("offline"))
        pending = list(provider.pending())
        expect(pending[0].attempts == 1, "failed delivery attempt was not persisted")
        provider.mark_delivered(key_of(provider, _contract_item(1)))
        pending = list(provider.pending())
        expect(len(pending) == 1 and pending[0].event_id == "contract-event-2", "acknowledgement removed the wrong pending item")

    def by_source() -> None:
        provider = create_provider()
        own = _contract_item(1)
        other = _contract_item(1)
        other.submission = replace(
            other.submission,
            producer_event={**other.submission.producer_event, "source": {**other.submission.producer_event["source"], "sourceId": "contract-source-2"}},
        )
        provider.enqueue(own)
        provider.enqueue(other)
        expect(len(list(provider.pending())) == 2, "an event ID from one source displaced another source's pending item")
        provider.mark_delivered(audit_outbox_item_key(own))
        pending = list(provider.pending())
        expect(
            len(pending) == 1 and pending[0].submission.producer_event["source"]["sourceId"] == "contract-source-2",
            "acknowledging one source removed another source's pending item",
        )

    run("declares and preserves FIFO order per source", fifo)
    run("enqueues idempotently and rejects divergent content per event identity", idempotent)
    run("accounts for failures and removes only acknowledged items", accounting)
    if keyed["value"]:
        run("keys items by producer source and event identity", by_source)
    return AuditOutboxContractReport(passed=all(check.passed for check in checks), checks=checks)
