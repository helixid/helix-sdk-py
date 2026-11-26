# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The status cache (KYA-OS story L3-C points 6 and 7; SPEC.md 6.5.2, 6.6).

Verified status lists by URL and per-credential verdicts by credential id,
each with a TTL at or below the revocation propagation target:
``status_cache_ttl`` (default 300 s), ``high_privilege_scopes`` held to
``high_privilege_ttl`` (default and ceiling 60 s), a list kept only when read
inside its window and served past its end no longer than
``max_stale_seconds``. Anything served from the cache is ``fresh: False``.
``invalidate(credential_id)`` deletes the credential's verdict and its list,
or every list when the cache holds no verdict for it.

Keys and stored JSON match helix-sdk-js ``verifier/status-cache.ts`` byte for
byte, so a JavaScript and a Python verifier can share one Redis.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Protocol, Sequence

from ..credentials import clock_skew_ms
from .status import StatusListRead, parse_status_bound

DEFAULT_STATUS_CACHE_TTL_SECONDS = 300
MAX_HIGH_PRIVILEGE_TTL_SECONDS = 60
DEFAULT_MAX_STALE_SECONDS = 60


class StatusCacheStore(Protocol):
    def get(self, key: str) -> Optional[str]: ...  # pragma: no cover - protocol only

    def set(self, key: str, value: str, ttl_ms: float) -> None: ...  # pragma: no cover - protocol only

    def delete(self, key: str) -> None: ...  # pragma: no cover - protocol only

    def increment(self, key: str) -> int: ...  # pragma: no cover - protocol only


def _now_ms() -> int:
    return int(time.time() * 1000)


class MemoryStatusCacheStore:
    """One instance's store: a dict with expiries, swept on access."""

    def __init__(self, now_ms: Optional[Callable[[], int]] = None) -> None:
        self._entries: Dict[str, Any] = {}
        self._now = now_ms or _now_ms

    def get(self, key: str) -> Optional[str]:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry[1] <= self._now():
            del self._entries[key]
            return None
        return entry[0]

    def set(self, key: str, value: str, ttl_ms: float) -> None:
        self._entries[key] = (value, self._now() + max(1, ttl_ms))

    def delete(self, key: str) -> None:
        self._entries.pop(key, None)

    def increment(self, key: str) -> int:
        current = self.get(key)
        try:
            value = int(current) if current is not None else 0
        except ValueError:
            value = 0
        self._entries[key] = (str(value + 1), float("inf"))
        return value + 1

    def __len__(self) -> int:
        return len(self._entries)


@dataclass(frozen=True)
class VerdictKey:
    credential_id: str
    url: str
    index: str
    purpose: str
    issuer: str
    keeper: str


@dataclass(frozen=True)
class CachedVerdict:
    revoked: bool
    code: Optional[str] = None
    message: Optional[str] = None


def _js_json(value: Any) -> str:
    """``JSON.stringify`` of plain data: no spaces, non-ASCII as itself."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _fingerprint(key: VerdictKey) -> str:
    return _js_json([key.url, key.index, key.purpose, key.issuer, key.keeper])


def _positive(value: Optional[float], name: str) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0 or value != value or value == float("inf"):
        raise ValueError(f"{name} must be a positive number of seconds")
    return value


class StatusCache:
    def __init__(
        self,
        store: Optional[StatusCacheStore] = None,
        status_cache_ttl: Optional[float] = None,
        high_privilege_scopes: Sequence[str] = (),
        high_privilege_ttl: Optional[float] = None,
        max_stale_seconds: Optional[float] = None,
        max_clock_skew_ms: Any = None,
        key_prefix: str = "kyaos:status:",
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        self.status_cache_ttl = _positive(status_cache_ttl, "status_cache_ttl") or DEFAULT_STATUS_CACHE_TTL_SECONDS
        high = _positive(high_privilege_ttl, "high_privilege_ttl")
        if high is not None and high > MAX_HIGH_PRIVILEGE_TTL_SECONDS:
            raise ValueError(f"high_privilege_ttl must be at most {MAX_HIGH_PRIVILEGE_TTL_SECONDS} seconds (SPEC.md 6.5.2)")
        self.high_privilege_ttl = min(high if high is not None else MAX_HIGH_PRIVILEGE_TTL_SECONDS, self.status_cache_ttl)
        self.high_privilege_scopes = frozenset(high_privilege_scopes)
        if max_stale_seconds is not None and (isinstance(max_stale_seconds, bool) or not isinstance(max_stale_seconds, (int, float)) or max_stale_seconds < 0):
            raise ValueError("max_stale_seconds must be a non-negative number of seconds")
        self.max_stale_seconds = DEFAULT_MAX_STALE_SECONDS if max_stale_seconds is None else max_stale_seconds
        skew = clock_skew_ms(max_clock_skew_ms)
        if skew is None:
            raise ValueError("max_clock_skew_ms must be from 0 to 600000")
        self._skew_ms = skew
        self._clock = clock or _now_ms
        self._store: StatusCacheStore = store if store is not None else MemoryStatusCacheStore(self._clock)
        self._prefix = key_prefix

    def ttl_for(self, scopes: Sequence[str] = ()) -> float:
        """The TTL, in seconds, for a read made for a request that touches ``scopes``."""
        return self.high_privilege_ttl if any(scope in self.high_privilege_scopes for scope in scopes) else self.status_cache_ttl

    def _generation(self) -> str:
        return self._store.get(f"{self._prefix}generation") or "0"

    def _list_key(self, generation: str, url: str) -> str:
        return f"{self._prefix}list:{generation}:{url}"

    def _verdict_key(self, credential_id: str) -> str:
        return f"{self._prefix}verdict:{credential_id}"

    def _servable_until(self, read_at: int, valid_until: Optional[str], ttl_seconds: float) -> Optional[float]:
        by_ttl = read_at + ttl_seconds * 1000
        if valid_until is None:
            return by_ttl
        until = parse_status_bound(valid_until)
        if until is None:
            return None
        return min(by_ttl, until + self._skew_ms + self.max_stale_seconds * 1000)

    def get_list(self, url: str, scopes: Sequence[str] = ()) -> Optional[StatusListRead]:
        raw = self._store.get(self._list_key(self._generation(), url))
        if raw is None:
            return None
        try:
            stored = json.loads(raw)
            until = self._servable_until(int(stored["readAt"]), stored.get("validUntil"), self.ttl_for(scopes))
            bits = base64.b64decode(stored["bits"])
        except (ValueError, KeyError, TypeError):
            return None
        if until is None or self._clock() > until:
            return None
        return StatusListRead(
            bits=bits,
            issuer=stored.get("issuer"),
            status_purpose=stored.get("statusPurpose"),
            id=stored.get("id"),
            valid_from=stored.get("validFrom"),
            valid_until=stored.get("validUntil"),
            fresh=False,
            proof_verified=True,
        )

    def set_list(self, url: str, read: StatusListRead) -> None:
        """Keeps a live, proof-verified read made inside its window; anything else is not kept."""
        if read.proof_verified is not True or read.fresh is False:
            return
        read_at = self._clock()
        until = self._servable_until(read_at, read.valid_until, self.status_cache_ttl)
        if until is None or until <= read_at:
            return
        stored: Dict[str, Any] = {"bits": base64.b64encode(read.bits).decode("ascii")}
        for name, value in (("issuer", read.issuer), ("statusPurpose", read.status_purpose), ("id", read.id), ("validFrom", read.valid_from), ("validUntil", read.valid_until)):
            if value is not None:
                stored[name] = value
        stored["readAt"] = read_at
        self._store.set(self._list_key(self._generation(), url), _js_json(stored), until - read_at)

    def get_verdict(self, key: VerdictKey, scopes: Sequence[str] = ()) -> Optional[CachedVerdict]:
        raw = self._store.get(self._verdict_key(key.credential_id))
        if raw is None:
            return None
        try:
            stored = json.loads(raw)
            if stored["fingerprint"] != _fingerprint(key):
                return None
            if self._clock() > int(stored["readAt"]) + self.ttl_for(scopes) * 1000:
                return None
            return CachedVerdict(bool(stored["revoked"]), stored.get("code"), stored.get("message"))
        except (ValueError, KeyError, TypeError):
            return None

    def set_verdict(self, key: VerdictKey, verdict: CachedVerdict) -> None:
        stored: Dict[str, Any] = {"revoked": verdict.revoked}
        if verdict.code is not None:
            stored["code"] = verdict.code
        if verdict.message is not None:
            stored["message"] = verdict.message
        stored.update({"fingerprint": _fingerprint(key), "url": key.url, "readAt": self._clock()})
        self._store.set(self._verdict_key(key.credential_id), _js_json(stored), self.status_cache_ttl * 1000)

    def invalidate(self, credential_id: str) -> str:
        """A revocation signal: ``'credential'`` when its verdict and list were dropped, ``'all-lists'`` otherwise."""
        raw = self._store.get(self._verdict_key(credential_id))
        url: Optional[str] = None
        if raw is not None:
            try:
                candidate = json.loads(raw).get("url")
                url = candidate if isinstance(candidate, str) else None
            except (ValueError, AttributeError):
                url = None
        self._store.delete(self._verdict_key(credential_id))
        if url is not None:
            self._store.delete(self._list_key(self._generation(), url))
            return "credential"
        self._store.increment(f"{self._prefix}generation")
        return "all-lists"
