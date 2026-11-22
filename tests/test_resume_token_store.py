# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story L3-E: the resume-token store (opaque, bound, single-use,
expiring), the same cases as helix-sdk-js's
mcp-middleware/tests/kyaos/resume-token-store.test.ts, plus the async client
path and a record written by the JS store."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple

import pytest

from helix_mcp_middleware.resume_token_store import (
    DEFAULT_RESUME_KEY_PREFIX,
    MemoryResumeTokenStore,
    RedisResumeTokenStore,
    ResumeTokenBinding,
    ResumeTokenRecord,
    generate_resume_token,
    is_resume_token,
    parse_record,
    serialize_record,
)

AGENT = "did:key:z6Mkagent"
NOW = 1_750_000_000.0
BINDING = ResumeTokenBinding(AGENT, "refund_order", ["orders:admin"])
TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class Clock:
    def __init__(self, start: float = NOW) -> None:
        self.current = start

    def now(self) -> float:
        return self.current


def counting_random(repeats: int = 0) -> Any:
    """A byte source that repeats its first value ``repeats`` times, then counts up: forces collisions on demand."""
    calls = [0]

    def random(size: int) -> bytes:
        n = 0 if calls[0] < repeats else calls[0] - repeats
        calls[0] += 1
        return bytes([n & 0xFF] + [7] * (size - 1))

    return random


class FakeRedis:
    """redis-py's SET NX PX and GETDEL, expiring by an injected clock, answering as redis-py does (True / None, bytes)."""

    def __init__(self, now: Any) -> None:
        self.entries: Dict[str, Tuple[bytes, float]] = {}
        self.commands: List[str] = []
        self.now = now

    def set(self, name: str, value: str, px: int, nx: bool) -> Optional[bool]:
        self.commands.append(f"SET {name} PX {px} NX {nx}")
        existing = self.entries.get(name)
        if existing is not None and existing[1] > self.now():
            return None
        self.entries[name] = (value.encode("utf-8"), self.now() + px / 1000)
        return True

    def getdel(self, name: str) -> Optional[bytes]:
        self.commands.append(f"GETDEL {name}")
        existing = self.entries.pop(name, None)
        return existing[0] if existing is not None and existing[1] > self.now() else None


class FakeAsyncRedis(FakeRedis):
    async def set(self, name: str, value: str, px: int, nx: bool) -> Optional[bool]:  # type: ignore[override]
        return FakeRedis.set(self, name, value, px, nx)

    async def getdel(self, name: str) -> Optional[bytes]:  # type: ignore[override]
        return FakeRedis.getdel(self, name)


class TestTokens:
    def test_are_32_random_bytes_as_base64url_and_only_such_strings_are_looked_up(self) -> None:
        token = generate_resume_token()
        assert TOKEN.match(token)
        assert generate_resume_token() != token
        assert is_resume_token(token)
        assert is_resume_token("k7Hy9mNpQrStUvWxYz01AB")
        assert not is_resume_token("short")
        assert not is_resume_token(token + "=")
        assert not is_resume_token(42)
        assert not is_resume_token(None)

    def test_records_serialise_as_the_js_store_writes_them(self) -> None:
        record = ResumeTokenRecord(AGENT, "refund_order", ["orders:admin"], NOW + 1)
        assert serialize_record(record) == '{"agentDid":"did:key:z6Mkagent","tool":"refund_order","scopes":["orders:admin"],"expiresAt":1750000001000}'
        assert parse_record(serialize_record(record)) == record
        # What helix-sdk-js's RedisResumeTokenStore writes (JSON.stringify, expiresAt in ms), as text or bytes.
        js = '{"agentDid":"did:key:z","tool":"t","scopes":["a",1,"b"],"expiresAt":5000}'
        assert parse_record(js) == ResumeTokenRecord("did:key:z", "t", ["a", "b"], 5.0)
        assert parse_record(js.encode()) == parse_record(js)
        for bad in ('{"agentDid":"x"}', '{"agentDid":"x","tool":"t","scopes":"a","expiresAt":1}', '{"agentDid":"x","tool":"t","scopes":[],"expiresAt":true}', "[]"):
            with pytest.raises(ValueError, match="malformed"):
                parse_record(bad)


class TestMemoryResumeTokenStore:
    def test_hands_a_record_back_exactly_once_and_never_after_it_expired(self) -> None:
        clock = Clock()
        store = MemoryResumeTokenStore(now=clock.now)
        token = store.issue(BINDING, NOW + 10)
        assert TOKEN.match(token)
        assert store.has(token) and len(store) == 1
        assert store.consume(token) == ResumeTokenRecord(AGENT, "refund_order", ["orders:admin"], NOW + 10)
        assert store.consume(token) is None
        assert not store.has(token)
        # The record is a copy: the caller's list is not shared.
        scopes = ["orders:read"]
        other = store.issue(ResumeTokenBinding(AGENT, "refund_order", scopes), NOW + 10)
        scopes.append("orders:admin")
        assert store.consume(other).scopes == ["orders:read"]  # type: ignore[union-attr]
        expiring = store.issue(BINDING, NOW + 1)
        clock.current += 0.999
        assert store.has(expiring)
        clock.current += 0.001
        assert not store.has(expiring)
        assert store.consume(expiring) is None
        assert len(store) == 0
        assert store.consume("not-a-token") is None

    def test_never_hands_out_a_token_twice_even_when_the_byte_source_repeats(self) -> None:
        store = MemoryResumeTokenStore(now=lambda: NOW, random=counting_random(1))
        first = store.issue(BINDING, NOW + 10)
        second = store.issue(BINDING, NOW + 10)
        assert first != second and len(store) == 2
        assert len(MemoryResumeTokenStore()) == 0


class TestRedisResumeTokenStore:
    def test_issues_with_set_nx_px_and_consumes_with_getdel_once(self) -> None:
        clock = Clock()
        redis = FakeRedis(clock.now)
        store = RedisResumeTokenStore(redis, now=clock.now)
        token = store.issue(BINDING, NOW + 10)
        assert redis.commands == [f"SET {DEFAULT_RESUME_KEY_PREFIX}{token} PX 10000 NX True"]
        assert store.consume(token) == ResumeTokenRecord(AGENT, "refund_order", ["orders:admin"], NOW + 10)
        assert redis.commands[1] == f"GETDEL kyaos:resume:{token}"
        assert store.consume(token) is None
        # Another instance on the same Redis sees the same single use.
        peer = RedisResumeTokenStore(redis, key_prefix="kyaos:resume:", now=clock.now)
        shared = store.issue(BINDING, NOW + 10)
        assert peer.consume(shared) is not None
        assert store.consume(shared) is None

    def test_refuses_a_record_past_its_promised_expiry_and_keeps_an_already_due_token_one_tick(self) -> None:
        clock = Clock()
        redis = FakeRedis(lambda: NOW)  # Redis's own clock stands still
        store = RedisResumeTokenStore(redis, key_prefix="r:", now=clock.now)
        token = store.issue(BINDING, NOW + 1)
        clock.current += 1
        assert store.consume(token) is None
        due = store.issue(BINDING, clock.current - 5)
        assert redis.commands[-1] == f"SET r:{due} PX 1 NX True"

    def test_retries_a_colliding_token_and_gives_up_after_three(self) -> None:
        redis = FakeRedis(lambda: NOW)
        store = RedisResumeTokenStore(redis, random=counting_random(1), now=lambda: NOW)
        first = store.issue(BINDING, NOW + 10)
        second = store.issue(BINDING, NOW + 10)
        assert first != second and len(redis.commands) == 3
        stuck = RedisResumeTokenStore(FakeRedis(lambda: NOW), random=counting_random(10), now=lambda: NOW)
        stuck.issue(BINDING, NOW + 10)
        with pytest.raises(RuntimeError, match="could not record a fresh resume token"):
            stuck.issue(BINDING, NOW + 10)

    def test_answers_awaitables_with_an_async_client(self) -> None:
        redis = FakeAsyncRedis(lambda: NOW)
        store = RedisResumeTokenStore(redis, random=counting_random(1), now=lambda: NOW)

        async def scenario() -> Any:
            first = await store.issue(BINDING, NOW + 10)  # type: ignore[misc]
            second = await store.issue(BINDING, NOW + 10)  # type: ignore[misc]  # one collision on the way
            record = await store.consume(first)  # type: ignore[misc]
            again = await store.consume(first)  # type: ignore[misc]
            return first, second, record, again

        first, second, record, again = asyncio.run(scenario())
        assert first != second and record == ResumeTokenRecord(AGENT, "refund_order", ["orders:admin"], NOW + 10) and again is None
        assert len(redis.commands) == 5
        stuck = RedisResumeTokenStore(FakeAsyncRedis(lambda: NOW), random=counting_random(10), now=lambda: NOW)

        async def exhaust() -> None:
            await stuck.issue(BINDING, NOW + 10)  # type: ignore[misc]
            await stuck.issue(BINDING, NOW + 10)  # type: ignore[misc]

        with pytest.raises(RuntimeError, match="could not record"):
            asyncio.run(exhaust())

    def test_reads_ok_replies_from_other_clients(self) -> None:
        class OkRedis(FakeRedis):
            def set(self, name: str, value: str, px: int, nx: bool) -> Any:
                return "OK" if FakeRedis.set(self, name, value, px, nx) else None

        store = RedisResumeTokenStore(OkRedis(lambda: NOW), now=lambda: NOW)
        assert store.consume(store.issue(BINDING, NOW + 10)) is not None  # type: ignore[arg-type]
