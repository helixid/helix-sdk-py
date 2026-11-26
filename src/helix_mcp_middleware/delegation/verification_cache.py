"""The verification cache (KYA-OS story L3-D point 6, conformance L3.12).
Ported from helix-sdk-js's mcp-middleware/src/delegation/verification-cache.ts.

The outcome of verifying a forwarded chain (every hop's signature, the chain
rules, every status), kept under the leaf credential's id for no longer than
the revocation propagation target: the status cache's TTL, and at most 60 s
when the chain touches a high-privilege scope. Served only for the very
chain (its JCS digest), never for a tool whose minimum level is L3, reported
not fresh, and dropped at once by a revocation signal for any credential of
the chain or an ancestor (the delegation graph names the descendants).
"""

from __future__ import annotations

import hashlib
import threading
import time
import weakref
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from helix_sdk.crypto.jcs import canonicalize
from helix_sdk.verifier.status_cache import DEFAULT_STATUS_CACHE_TTL_SECONDS

from .graph import DelegationGraph

MAX_HIGH_PRIVILEGE_CACHE_TTL_SECONDS = 60


def chain_digest_of(chain: Sequence[Any]) -> str:
    """The JCS sha-256 of a chain: an entry answers only for the chain it was made for."""
    return hashlib.sha256(canonicalize(list(chain)).encode("utf-8")).hexdigest()


def _ids_of(chain: Sequence[Any]) -> List[str]:
    return [hop["id"] for hop in chain if isinstance(hop, dict) and isinstance(hop.get("id"), str)]


@dataclass
class _Entry:
    chain_digest: str
    result: Any
    expires_at: float
    ids: List[str]


def _now_ms() -> int:
    return int(time.time() * 1000)


class VerificationCache:
    def __init__(
        self,
        ttl_seconds: Optional[float] = None,
        high_privilege_ttl: Optional[float] = None,
        high_privilege_scopes: Iterable[str] = (),
        graph: Optional[DelegationGraph] = None,
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        ttl = DEFAULT_STATUS_CACHE_TTL_SECONDS if ttl_seconds is None else ttl_seconds
        if not ttl > 0:
            raise ValueError("ttl_seconds must be a positive number of seconds")
        high = MAX_HIGH_PRIVILEGE_CACHE_TTL_SECONDS if high_privilege_ttl is None else high_privilege_ttl
        if not high > 0 or high > MAX_HIGH_PRIVILEGE_CACHE_TTL_SECONDS:
            raise ValueError(f"high_privilege_ttl must be from 0 to {MAX_HIGH_PRIVILEGE_CACHE_TTL_SECONDS} seconds (SPEC.md §6.5.2)")
        self.ttl_seconds = ttl
        self.high_privilege_ttl = min(high, ttl)
        self.high_privilege_scopes = frozenset(high_privilege_scopes)
        self.graph = graph if graph is not None else DelegationGraph()
        self._clock = clock or _now_ms
        self._entries: Dict[str, _Entry] = {}
        self._lock = threading.Lock()

    @classmethod
    def for_status_cache(cls, status_cache: Any, graph: Optional[DelegationGraph] = None, clock: Optional[Callable[[], int]] = None) -> "VerificationCache":
        """A cache no longer lived than ``status_cache`` (its TTL, high-privilege
        TTL and scopes), linked to it so a revocation signal drops both."""
        cache = cls(
            ttl_seconds=status_cache.status_cache_ttl,
            high_privilege_ttl=status_cache.high_privilege_ttl,
            high_privilege_scopes=status_cache.high_privilege_scopes,
            graph=graph,
            clock=clock,
        )
        link_verification_cache(status_cache, cache)
        return cache

    @property
    def size(self) -> int:
        return len(self._entries)

    def ttl_for(self, scopes: Iterable[str]) -> float:
        """The lifetime for a chain granting ``scopes``, seconds."""
        return self.high_privilege_ttl if any(scope in self.high_privilege_scopes for scope in scopes) else self.ttl_seconds

    def get(self, chain: Sequence[Any]) -> Any:
        """The cached verification of ``chain`` under its leaf credential id, if any and still alive."""
        ids = _ids_of(chain)
        if not ids or len(ids) != len(chain):
            return None
        with self._lock:
            entry = self._entries.get(ids[-1])
            if entry is None:
                return None
            if self._clock() >= entry.expires_at:
                del self._entries[ids[-1]]
                return None
        return entry.result if entry.chain_digest == chain_digest_of(chain) else None

    def set(self, chain: Sequence[Any], result: Any) -> None:
        """Stores a successful verification of ``chain``; a refusal, or a chain whose hops show no ids, is never stored."""
        ids = _ids_of(chain)
        if not getattr(result, "ok", False) or not ids or len(ids) != len(chain):
            return
        try:
            self.graph.register_chain(chain)
        except ValueError:
            return  # a chain the graph cannot hold (an id registered under another parent) is not cached
        summary = getattr(result, "chain_summary", None)
        scopes = [*(getattr(summary, "allowed_action", None) or []), *(getattr(result, "effective_scopes", None) or [])]
        with self._lock:
            self._entries[ids[-1]] = _Entry(chain_digest_of(chain), result, self._clock() + self.ttl_for(scopes) * 1000, ids)

    def invalidate(self, credential_id: str) -> int:
        """Drops at once every entry that rests on ``credential_id``: its own and its descendants'."""
        affected = {credential_id, *(node.id for node in self.graph.get_descendants(credential_id))}
        with self._lock:
            keys = [key for key, entry in self._entries.items() if any(id in affected for id in entry.ids)]
            for key in keys:
                del self._entries[key]
        return len(keys)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_LINKED: "weakref.WeakKeyDictionary[Any, List[Any]]" = weakref.WeakKeyDictionary()


def link_verification_cache(status_cache: Any, cache: Any) -> None:
    """Links ``cache`` to ``status_cache``: a revocation signal that invalidates the one invalidates the other."""
    caches = _LINKED.setdefault(status_cache, [])
    if cache not in caches:
        caches.append(cache)


class _Invalidation:
    def __init__(self, status_cache: Any, caches: Sequence[Any]) -> None:
        self._status_cache = status_cache
        self._caches = caches

    def invalidate(self, credential_id: str) -> Any:
        for cache in {id(c): c for c in [*_LINKED.get(self._status_cache, []), *self._caches]}.values():
            cache.invalidate(credential_id)
        return self._status_cache.invalidate(credential_id)


def revocation_invalidation(status_cache: Any, *verification_caches: Any) -> Any:
    """What a revocation signal client invalidates: the status cache (its
    answer is reported), every verification cache linked to it, and any given
    here. ``create_revocation_signal_client`` uses it by default."""
    return _Invalidation(status_cache, verification_caches)
