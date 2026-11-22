# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The replay store (KYA-OS story L2-A, conformance L2.5), mirroring
helix-sdk-js's mcp-middleware/src/kyaos/nonce-store.ts: ``(nonce, agent_did,
expiry)`` tuples with one atomic conditional insert. A nonce is accepted the
first time a given agent presents it and refused every time after, until
``expires_at``, which the caller sets to ``ts + skew + 1 s`` so the entry
outlives the acceptance window; nothing is evicted before that.

MemoryNonceStore serves one process. RedisNonceStore (``SET NX PX``) and
DynamoNonceStore (a conditional ``put_item``) serve several instances sharing
one store, so a nonce replayed at a second instance is refused there too. The
keys are the ones helix-sdk-js writes, so JS and Python instances can share
the same Redis or table. Clients are injected (redis-py or redis.asyncio, a
boto3 or aioboto3 DynamoDB client): this package adds no dependency.

Times are Unix seconds, as everywhere in helix_sdk (the JS store takes
milliseconds; the stored values are the same).

Cross-border rule (stories, rule 4): this store and the local config are the
only state the verify path touches; it is never a Helix database.
"""

from __future__ import annotations

import math
import threading
import time
from typing import Any, Awaitable, Callable, Dict, Optional, Union

try:  # Python 3.8+: typing.Protocol
    from typing import Protocol
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol  # type: ignore[assignment]

from ._util import then


class NonceStore(Protocol):
    """Records ``(nonce, agent_did)`` until ``expires_at`` (Unix seconds) and
    answers True, or answers False when that pair is already recorded and not
    yet expired. Atomic: of two concurrent inserts of the same pair exactly
    one answers True. May answer with an awaitable (an async client)."""

    def insert(self, nonce: str, agent_did: Optional[str], expires_at: float) -> Union[bool, Awaitable[bool]]:
        ...  # pragma: no cover


def nonce_key(nonce: str, agent_did: Optional[str]) -> str:
    """One key per ``(nonce, agent_did)`` pair; the separator cannot occur in a base64url nonce."""
    return f"{agent_did or ''}|{nonce}"


class MemoryNonceStore:
    """Single-process store: a dict of key to expiry, swept of expired entries
    on every insert, never earlier. Thread-safe."""

    def __init__(self, now: Callable[[], float] = time.time) -> None:
        self._entries: Dict[str, float] = {}
        self._now = now
        self._lock = threading.Lock()

    def insert(self, nonce: str, agent_did: Optional[str], expires_at: float) -> bool:
        with self._lock:
            now = self._now()
            for key in [k for k, expiry in self._entries.items() if expiry <= now]:
                del self._entries[key]
            key = nonce_key(nonce, agent_did)
            if key in self._entries:
                return False
            self._entries[key] = expires_at
            return True

    def has(self, nonce: str, agent_did: Optional[str]) -> bool:
        """Whether the pair is currently recorded (for tests and diagnostics)."""
        expiry = self._entries.get(nonce_key(nonce, agent_did))
        return expiry is not None and expiry > self._now()

    @property
    def size(self) -> int:
        return len(self._entries)


class RedisNonceStore:
    """Multi-instance store on Redis: ``SET key value PX ms NX`` is the atomic
    conditional insert, and Redis expires the key at ``expires_at``.
    ``client`` is anything with redis-py's ``set(name, value, px=, nx=)``:
    ``redis.Redis`` (sync) or ``redis.asyncio.Redis`` (then ``insert``
    answers with an awaitable)."""

    def __init__(self, client: Any, key_prefix: str = "kyaos:nonce:", now: Callable[[], float] = time.time) -> None:
        self._client = client
        self._prefix = key_prefix
        self._now = now

    def insert(self, nonce: str, agent_did: Optional[str], expires_at: float) -> Union[bool, Awaitable[bool]]:
        # An entry due to expire in the past still has to refuse a concurrent duplicate: keep it one tick.
        ttl_ms = max(1, math.ceil((expires_at - self._now()) * 1000))
        # The value is the expiry in milliseconds, as helix-sdk-js writes it.
        reply = self._client.set(f"{self._prefix}{nonce_key(nonce, agent_did)}", str(round(expires_at * 1000)), px=ttl_ms, nx=True)
        # redis-py answers True when set and None when NX refused it.
        return then(reply, lambda answer: answer is True or answer == "OK" or answer == b"OK")


def _conditional_check_failed(error: BaseException) -> bool:
    if type(error).__name__ == "ConditionalCheckFailedException":
        return True
    response = getattr(error, "response", None)
    code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
    return code == "ConditionalCheckFailedException"


class DynamoNonceStore:
    """Multi-instance store on DynamoDB: a ``put_item`` conditioned on the key's
    absence; the table's TTL setting (on ``ttl_attribute``) removes expired
    items. ``client`` is a boto3 (or aioboto3) DynamoDB *client*, whose
    ``put_item`` takes typed attribute values. The item has the attributes
    helix-sdk-js's store writes."""

    def __init__(self, client: Any, table_name: str, key_attribute: str = "pk", ttl_attribute: str = "expiresAt") -> None:
        self._client = client
        self._table = table_name
        self._key = key_attribute
        self._ttl = ttl_attribute

    def insert(self, nonce: str, agent_did: Optional[str], expires_at: float) -> Union[bool, Awaitable[bool]]:
        item: Dict[str, Any] = {self._key: {"S": nonce_key(nonce, agent_did)}, "nonce": {"S": nonce}}
        if agent_did is not None:
            item["agentDid"] = {"S": agent_did}
        # DynamoDB TTL is in seconds; round up so the item never leaves before expires_at.
        item[self._ttl] = {"N": str(math.ceil(expires_at))}
        request = {
            "TableName": self._table,
            "Item": item,
            "ConditionExpression": "attribute_not_exists(#pk)",
            "ExpressionAttributeNames": {"#pk": self._key},
        }
        try:
            reply = self._client.put_item(**request)
        except Exception as error:  # noqa: BLE001 - only the condition is a verdict
            if _conditional_check_failed(error):
                return False
            raise
        if hasattr(reply, "__await__"):

            async def later() -> bool:
                try:
                    await reply
                except Exception as error:  # noqa: BLE001
                    if _conditional_check_failed(error):
                        return False
                    raise
                return True

            return later()
        return True
