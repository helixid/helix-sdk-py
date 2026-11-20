# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Where an ``AuditTrail`` delivers each recorded event, ported from
helix-core's ``src/core/audit/sink.ts``. AAP-1: the sink records what it is
given. Story A-2's recorder (epoch, ledger sequence, signed receipt) replaces
the sink behind this one method; producers never see it."""

from __future__ import annotations

from typing import Callable, List, Protocol, Sequence

from .types import AuditProducerEvent, AuditTrailEntry


class AuditSink(Protocol):
    def append(self, entry: AuditTrailEntry) -> None: ...


class MemoryAuditSink:
    """Keeps every entry in order; for tests and local development."""

    def __init__(self) -> None:
        self.entries: List[AuditTrailEntry] = []

    def append(self, entry: AuditTrailEntry) -> None:
        self.entries.append(entry)

    @property
    def events(self) -> List[AuditProducerEvent]:
        """The recorded events, oldest first."""
        return [entry.event for entry in self.entries]

    @property
    def event_types(self) -> List[str]:
        """The event types recorded, oldest first."""
        return [entry.event["eventType"] for entry in self.entries]


class TeeAuditSink:
    """Delivers every entry to each sink in turn; one failing sink fails the record."""

    def __init__(self, sinks: Sequence[AuditSink]) -> None:
        self._sinks = list(sinks)

    def append(self, entry: AuditTrailEntry) -> None:
        for sink in self._sinks:
            sink.append(entry)


class CallbackAuditSink:
    """Hands every entry to one callable: the smallest adapter between a trail and a transport."""

    def __init__(self, callback: Callable[[AuditTrailEntry], None]) -> None:
        self._callback = callback

    def append(self, entry: AuditTrailEntry) -> None:
        self._callback(entry)
