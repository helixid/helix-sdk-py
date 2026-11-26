# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The resume-token store of the ``needs_authorization`` flow (KYA-OS story
L3-E, SPEC §9.2 and §9.3), mirroring helix-sdk-js's
mcp-middleware/src/resume-token-store.ts. A token is opaque (base64url of 32
random bytes), bound to the agent DID, the tool and the scopes the challenge
asked for, single-use, and gone at ``expires_at``. ``issue`` records the
binding and ``consume`` hands it back exactly once: a replayed, expired or
unknown token answers None, and the caller refuses.

``MemoryResumeTokenStore`` serves one instance. ``RedisResumeTokenStore``
(``SET NX PX`` to issue, ``GETDEL`` to consume) serves several instances
sharing one Redis, the same pattern as L2-A's ``RedisNonceStore``; it writes
the record exactly as helix-sdk-js does (``expiresAt`` in milliseconds), so
JS and Python instances can share one store. Methods answer a value, or an
awaitable when the injected client is async (redis.asyncio).

Times are Unix seconds, as everywhere in this package. Cross-border rule
(stories, rule 4): this store is local state next to the nonce store, never
a Helix database; nothing here asks Helix anything.
"""

from __future__ import annotations

import base64
import inspect
import json
import math
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, List, Optional, Union

from .kyaos._util import then

DEFAULT_RESUME_KEY_PREFIX = "kyaos:resume:"

_TOKEN = re.compile(r"^[A-Za-z0-9_-]{22,}$")

RandomBytes = Callable[[int], bytes]


@dataclass(frozen=True)
class ResumeTokenBinding:
    """What a token is bound to: only this agent, retrying this tool, for no more than these scopes, may resume."""

    agent_did: str
    tool: str
    scopes: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ResumeTokenRecord:
    """A consumed token's binding and its expiry (Unix seconds)."""

    agent_did: str
    tool: str
    scopes: List[str]
    expires_at: float


def generate_resume_token(random: RandomBytes = secrets.token_bytes) -> str:
    """32 random bytes as base64url: 43 characters, no padding."""
    return base64.urlsafe_b64encode(random(32)).rstrip(b"=").decode("ascii")


def is_resume_token(value: Any) -> bool:
    """Whether ``value`` looks like a token a store issues; anything else is refused before any lookup."""
    return isinstance(value, str) and _TOKEN.match(value) is not None


def serialize_record(record: ResumeTokenRecord) -> str:
    """The record as helix-sdk-js writes it: ``expiresAt`` in milliseconds since the epoch."""
    return json.dumps(
        {"agentDid": record.agent_did, "tool": record.tool, "scopes": list(record.scopes), "expiresAt": round(record.expires_at * 1000)},
        separators=(",", ":"),
    )


def parse_record(text: Union[str, bytes]) -> ResumeTokenRecord:
    """Reads a record written by either SDK; raises ValueError when it is malformed."""
    value = json.loads(text.decode("utf-8") if isinstance(text, bytes) else text)
    agent_did, tool, scopes, expires_at = (value.get(k) if isinstance(value, dict) else None for k in ("agentDid", "tool", "scopes", "expiresAt"))
    if (
        not isinstance(agent_did, str)
        or not isinstance(tool, str)
        or not isinstance(scopes, list)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
    ):
        raise ValueError("resume token record is malformed")
    return ResumeTokenRecord(agent_did, tool, [s for s in scopes if isinstance(s, str)], expires_at / 1000)


class ResumeTokenStore:
    """The interface (structural: any object with these two methods will do)."""

    def issue(self, binding: ResumeTokenBinding, expires_at: float) -> Union[str, Awaitable[str]]:  # pragma: no cover - protocol only
        """Records ``binding`` under a fresh opaque token that expires at ``expires_at`` (Unix seconds) and answers the token."""
        raise NotImplementedError

    def consume(self, token: str) -> Union[Optional[ResumeTokenRecord], Awaitable[Optional[ResumeTokenRecord]]]:  # pragma: no cover
        """Answers the record of ``token`` and removes it, atomically: of two
        concurrent consumers exactly one gets the record. None for a token
        that is unknown, already consumed or expired."""
        raise NotImplementedError


class MemoryResumeTokenStore(ResumeTokenStore):
    """Single-instance store: a dict of token to record, swept of expired entries on every call."""

    def __init__(self, now: Callable[[], float] = time.time, random: RandomBytes = secrets.token_bytes) -> None:
        self._entries: "dict[str, ResumeTokenRecord]" = {}
        self._now = now
        self._random = random

    def _sweep(self) -> None:
        now = self._now()
        for token in [t for t, record in self._entries.items() if record.expires_at <= now]:
            del self._entries[token]

    def issue(self, binding: ResumeTokenBinding, expires_at: float) -> str:
        self._sweep()
        token = generate_resume_token(self._random)
        while token in self._entries:
            token = generate_resume_token(self._random)
        self._entries[token] = ResumeTokenRecord(binding.agent_did, binding.tool, list(binding.scopes), expires_at)
        return token

    def consume(self, token: str) -> Optional[ResumeTokenRecord]:
        self._sweep()
        return self._entries.pop(token, None)

    def has(self, token: str) -> bool:
        """Whether ``token`` is live (for tests and diagnostics)."""
        record = self._entries.get(token)
        return record is not None and record.expires_at > self._now()

    def __len__(self) -> int:
        return len(self._entries)


class RedisResumeTokenStore(ResumeTokenStore):
    """Multi-instance store on Redis: ``SET NX PX`` records the binding until
    ``expires_at``, ``GETDEL`` (Redis 6.2+) consumes it atomically. ``client``
    is anything with redis-py's ``set(name, value, px=, nx=)`` and
    ``getdel(name)``: ``redis.Redis`` (sync) or ``redis.asyncio.Redis`` (then
    both methods answer with an awaitable)."""

    def __init__(
        self,
        client: Any,
        key_prefix: str = DEFAULT_RESUME_KEY_PREFIX,
        now: Callable[[], float] = time.time,
        random: RandomBytes = secrets.token_bytes,
    ) -> None:
        self._client = client
        self._prefix = key_prefix
        self._now = now
        self._random = random

    def issue(self, binding: ResumeTokenBinding, expires_at: float) -> Union[str, Awaitable[str]]:
        # An entry already due still has to refuse a concurrent duplicate: keep it one tick.
        ttl_ms = max(1, math.ceil((expires_at - self._now()) * 1000))
        value = serialize_record(ResumeTokenRecord(binding.agent_did, binding.tool, list(binding.scopes), expires_at))

        def attempt(left: int) -> Union[str, Awaitable[str]]:
            if left == 0:
                raise RuntimeError("RedisResumeTokenStore: could not record a fresh resume token")
            token = generate_resume_token(self._random)
            reply = self._client.set(f"{self._prefix}{token}", value, px=ttl_ms, nx=True)
            # redis-py answers True when set and None when NX refused it.
            return then(reply, lambda answer: token if answer is True or answer in ("OK", b"OK") else attempt(left - 1))  # type: ignore[return-value]

        return _flatten(attempt(3))

    def consume(self, token: str) -> Union[Optional[ResumeTokenRecord], Awaitable[Optional[ResumeTokenRecord]]]:
        reply = self._client.getdel(f"{self._prefix}{token}")

        def read(text: Any) -> Optional[ResumeTokenRecord]:
            if text is None:
                return None
            record = parse_record(text)
            # Redis expires on its own clock; the injected one is the one the challenge promised.
            return record if record.expires_at > self._now() else None

        return then(reply, read)


def _flatten(value: Any) -> Any:
    """An awaitable that may resolve to another awaitable (a retried async SET), awaited all the way down."""
    if not inspect.isawaitable(value):
        return value

    async def settle() -> Any:
        result = await value
        while inspect.isawaitable(result):
            result = await result
        return result

    return settle()


__all__ = [
    "DEFAULT_RESUME_KEY_PREFIX",
    "ResumeTokenBinding",
    "ResumeTokenRecord",
    "ResumeTokenStore",
    "MemoryResumeTokenStore",
    "RedisResumeTokenStore",
    "generate_resume_token",
    "is_resume_token",
    "serialize_record",
    "parse_record",
]
