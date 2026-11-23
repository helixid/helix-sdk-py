# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The last-seen DID document version on Redis (KYA-OS story C-E point 2),
ported from helix-sdk-js's mcp-middleware/src/kyaos/rotation-sequence-store.ts.

In multi-instance mode every instance's resolver reads and raises the same
``rotationSequence`` per DID, so a stale document replayed to one instance is
refused there once any instance has seen a newer one. The raise is one atomic
script (keep the higher); keys and the script are the JS store's, so a JS and
a Python verifier can share one Redis.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol

RAISE_TO_MAX_SCRIPT = (
    "local kept = redis.call('GET', KEYS[1]) if (not kept) or tonumber(kept) < tonumber(ARGV[1]) "
    "then redis.call('SET', KEYS[1], ARGV[1]) end return 1"
)
ROTATION_SEQUENCE_KEY_PREFIX = "kyaos:did-rotation-sequence:"


class RedisRotationSequenceClient(Protocol):
    """The Redis commands the store needs, as redis-py exposes them."""

    def get(self, key: str) -> Any: ...  # pragma: no cover - protocol only

    def eval(self, script: str, numkeys: int, *keys_and_args: Any) -> Any: ...  # pragma: no cover - protocol only


class RedisRotationSequenceStore:
    """A :class:`helix_sdk.verifier.RotationSequenceStore` over Redis."""

    def __init__(self, client: RedisRotationSequenceClient, key_prefix: str = ROTATION_SEQUENCE_KEY_PREFIX) -> None:
        self._client = client
        self._prefix = key_prefix

    def get(self, did: str) -> Optional[int]:
        value = self._client.get(f"{self._prefix}{did}")
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8")
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None

    def raise_to(self, did: str, sequence: int) -> None:
        self._client.eval(RAISE_TO_MAX_SCRIPT, 1, f"{self._prefix}{did}", str(sequence))
