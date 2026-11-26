# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story C-E point 2: the last-seen DID document version shared on
Redis, and the local verifier's seam for it. Parity with helix-sdk-js
``mcp-middleware/tests/rotation-sequence-store.test.ts``."""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from helix_mcp_middleware import RAISE_TO_MAX_SCRIPT, ROTATION_SEQUENCE_KEY_PREFIX, RedisRotationSequenceStore
from helix_mcp_middleware.verify_locally import LocalVerifierOptions, create_local_verifier
from helix_sdk.verifier import RotationSequenceGuard, StaleDidDocumentError, create_did_resolver

DID = "did:web:agent.example:agents:01"


class FakeRedis:
    """Runs the raise script's semantics; returns bytes as redis-py does."""

    def __init__(self) -> None:
        self.data: Dict[str, str] = {}
        self.scripts: List[str] = []

    def get(self, key: str) -> Any:
        value = self.data.get(key)
        return value.encode() if value is not None else None

    def eval(self, script: str, numkeys: int, key: str, value: str) -> int:
        self.scripts.append(script)
        kept = self.data.get(key)
        if kept is None or int(kept) < int(value):
            self.data[key] = value
        return 1


def test_keeps_the_highest_sequence_per_did_under_its_prefix() -> None:
    redis = FakeRedis()
    store = RedisRotationSequenceStore(redis)
    assert store.get(DID) is None
    store.raise_to(DID, 3)
    store.raise_to(DID, 2)
    assert store.get(DID) == 3
    assert list(redis.data) == [f"{ROTATION_SEQUENCE_KEY_PREFIX}{DID}"]
    assert all(script == RAISE_TO_MAX_SCRIPT for script in redis.scripts)
    redis.data[f"custom:{DID}"] = "junk"
    assert RedisRotationSequenceStore(redis, key_prefix="custom:").get(DID) is None


def test_two_instances_sharing_it_refuse_the_same_replay() -> None:
    shared = RedisRotationSequenceStore(FakeRedis())
    first = create_did_resolver(lambda url: {"id": DID, "rotationSequence": 4}, sequence_guard=RotationSequenceGuard(shared))
    second = create_did_resolver(lambda url: {"id": DID, "rotationSequence": 3}, sequence_guard=RotationSequenceGuard(shared))
    first(DID)
    with pytest.raises(StaleDidDocumentError):
        second(DID)


def test_the_local_verifier_takes_the_store_for_its_default_resolver() -> None:
    store = RedisRotationSequenceStore(FakeRedis())
    store.raise_to(DID, 5)
    verifier = create_local_verifier(LocalVerifierOptions(service_did="did:web:orders.example", fetch=lambda url: {"id": DID, "rotationSequence": 4}, rotation_sequence_store=store))
    with pytest.raises(StaleDidDocumentError):
        verifier.seams.resolve_did(DID)
