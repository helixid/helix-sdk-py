# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The status cache on Redis (KYA-OS story L3-C point 7), ported from
helix-sdk-js's mcp-middleware/src/kyaos/status-cache-store.ts.

In multi-instance mode the verified status lists and per-credential verdicts
live in the shared Redis, so the one delete a revocation signal causes on
whichever instance received it is seen by every instance, and a duplicate
delete is harmless. Keys and values are those of the JS store
(:class:`helix_sdk.verifier.StatusCache` writes the same JSON), so a JS and a
Python verifier can share one Redis. Values are strings with a ``PX`` expiry;
the list namespace's generation counter is a plain ``INCR``.
"""

from __future__ import annotations

import math
from typing import Any, Optional, Protocol


class RedisStatusCacheClient(Protocol):
    """The four Redis commands the store needs, as redis-py (and compatible clients) expose them."""

    def get(self, key: str) -> Any: ...  # pragma: no cover - protocol only

    def set(self, key: str, value: str, px: int) -> Any: ...  # pragma: no cover - protocol only

    def delete(self, key: str) -> Any: ...  # pragma: no cover - protocol only

    def incr(self, key: str) -> int: ...  # pragma: no cover - protocol only


class RedisStatusCacheStore:
    """A :class:`helix_sdk.verifier.StatusCacheStore` over Redis."""

    def __init__(self, client: RedisStatusCacheClient) -> None:
        self._client = client

    def get(self, key: str) -> Optional[str]:
        value = self._client.get(key)
        if value is None:
            return None
        return value.decode("utf-8") if isinstance(value, (bytes, bytearray)) else str(value)

    def set(self, key: str, value: str, ttl_ms: float) -> None:
        self._client.set(key, value, px=max(1, math.ceil(ttl_ms)))

    def delete(self, key: str) -> None:
        self._client.delete(key)

    def increment(self, key: str) -> int:
        return int(self._client.incr(key))
