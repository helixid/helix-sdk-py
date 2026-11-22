# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story L3-E on L2-A's environment: the resume-token store follows
KYAOS_NONCE_STORE, the same cases as helix-sdk-js's
mcp-middleware/tests/kyaos/resume-token-store-env.test.ts."""

from __future__ import annotations

import asyncio
import logging
import time
import types
from typing import Any, Dict, List, Optional

import pytest

from helix_mcp_middleware import (
    MemoryResumeTokenStore,
    NeedsAuthorizationOptions,
    NonceStoreConfigError,
    RedisResumeTokenStore,
    ResumeTokenBinding,
    create_needs_authorization,
    describe_resume_token_store,
    read_nonce_store_config,
    resume_token_store_from_config,
    resume_token_store_from_env,
)
from helix_mcp_middleware.resume_token_store_env import _LoopBoundResumeRedis

AGENT = "did:key:z6Mkagent"
BINDING = ResumeTokenBinding(AGENT, "refund_order", ["orders:admin"])
REDIS = {"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "redis://user:secret@127.0.0.1:6380"}
LOGGER_NAME = "helix_mcp_middleware.kyaos"


class FakeAsyncRedis:
    """redis.asyncio.Redis with SET NX PX and GETDEL over one key space shared by every instance."""

    entries: Dict[str, str] = {}
    made: List[str] = []

    def __init__(self, url: str) -> None:
        self.url = url

    @classmethod
    def from_url(cls, url: str) -> "FakeAsyncRedis":
        cls.made.append(url)
        return cls(url)

    async def set(self, name: str, value: str, px: int, nx: bool) -> Optional[bool]:
        if name in self.entries:
            return None
        self.entries[name] = value
        return True

    async def getdel(self, name: str) -> Any:
        return self.entries.pop(name, None)


def fake_importer(module: str) -> Any:
    if module == "redis.asyncio":
        return types.SimpleNamespace(Redis=FakeAsyncRedis)
    raise ImportError(module, name=module)


def missing_redis(module: str) -> Any:
    raise ImportError(f"No module named {module!r}", name="redis")


@pytest.fixture(autouse=True)
def fresh_fake() -> None:
    FakeAsyncRedis.entries = {}
    FakeAsyncRedis.made = []


class TestDescribe:
    def test_names_the_store_without_secrets_with_the_js_text(self) -> None:
        assert describe_resume_token_store(read_nonce_store_config({})) == "KYA-OS resume-token store: memory (this process only)"
        assert describe_resume_token_store(read_nonce_store_config(REDIS)) == "KYA-OS resume-token store: redis redis://user:***@127.0.0.1:6380 (key prefix kyaos:resume:)"
        assert describe_resume_token_store(read_nonce_store_config(REDIS), "p:").endswith("(key prefix p:)")


class TestFromEnv:
    def test_memory_by_default_and_for_dynamo_with_a_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            store = resume_token_store_from_env({}, now=lambda: 1.0)
            dynamo = resume_token_store_from_env({"KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": "t"})
        assert isinstance(store, MemoryResumeTokenStore) and isinstance(dynamo, MemoryResumeTokenStore)
        messages = [(r.levelno, r.getMessage()) for r in caplog.records if r.name == LOGGER_NAME]
        assert messages[0] == (logging.INFO, "KYA-OS resume-token store: memory (this process only)")
        assert messages[-1][0] == logging.WARNING and "no DynamoDB resume-token store" in messages[-1][1]

    def test_reads_os_environ_by_default_and_logs_where_told(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("KYAOS_NONCE_STORE", "KYAOS_REDIS_URL", "KYAOS_RESUME_KEY_PREFIX"):
            monkeypatch.delenv(name, raising=False)
        logger = logging.getLogger("test.resume")
        seen: List[str] = []
        handler = logging.Handler()
        handler.emit = lambda record: seen.append(record.getMessage())  # type: ignore[method-assign]
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        try:
            assert isinstance(resume_token_store_from_env(logger=logger), MemoryResumeTokenStore)
        finally:
            logger.removeHandler(handler)
        assert seen == ["KYA-OS resume-token store: memory (this process only)"]

    def test_a_bad_replay_store_setting_fails_closed(self) -> None:
        for env in ({"KYAOS_NONCE_STORE": "postgres"}, {"KYAOS_NONCE_STORE": "redis"}, {"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "http://x"}):
            with pytest.raises(NonceStoreConfigError):
                resume_token_store_from_env(env)

    def test_redis_on_the_replay_store_url_single_use_across_instances_with_its_own_prefix(self, caplog: pytest.LogCaptureFixture) -> None:
        env = {**REDIS, "KYAOS_RESUME_KEY_PREFIX": "r:"}
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            store = resume_token_store_from_env(env, importer=fake_importer, now=time.time)
            peer = resume_token_store_from_env(env, importer=fake_importer)
        assert isinstance(store, RedisResumeTokenStore)
        assert [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME] == ["KYA-OS resume-token store: redis redis://user:***@127.0.0.1:6380 (key prefix r:)"] * 2
        assert "secret" not in caplog.text

        async def scenario() -> Any:
            token = await store.issue(BINDING, time.time() + 60)  # type: ignore[misc]
            keys = list(FakeAsyncRedis.entries)
            return keys, token, await peer.consume(token), await store.consume(token)  # type: ignore[misc]

        keys, token, first, second = asyncio.run(scenario())
        assert keys == [f"r:{token}"] and FakeAsyncRedis.made == ["redis://user:secret@127.0.0.1:6380"] * 2
        assert first is not None and first.agent_did == AGENT and second is None

    def test_a_missing_redis_package_fails_closed(self) -> None:
        with pytest.raises(NonceStoreConfigError, match=r"pip install 'helixid-sdk-py\[redis\]'"):
            resume_token_store_from_env(REDIS, importer=missing_redis)

    def test_from_config_builds_the_real_redis_client_lazily(self) -> None:
        pytest.importorskip("redis")
        assert isinstance(resume_token_store_from_config(read_nonce_store_config(REDIS)), RedisResumeTokenStore)
        assert isinstance(resume_token_store_from_config(read_nonce_store_config({})), MemoryResumeTokenStore)


class TestLoopBoundClient:
    def test_makes_one_client_per_event_loop_and_forwards_getdel(self) -> None:
        bound = _LoopBoundResumeRedis(lambda: FakeAsyncRedis.from_url("redis://h"))
        store = RedisResumeTokenStore(bound)

        async def scenario() -> Any:
            token = await store.issue(BINDING, time.time() + 60)  # type: ignore[misc]
            return await store.consume(token), await store.consume(token)  # type: ignore[misc]

        first, second = asyncio.run(scenario())
        assert first is not None and second is None
        asyncio.run(scenario())
        assert FakeAsyncRedis.made == ["redis://h", "redis://h"]


class TestLayerDefault:
    def test_the_layer_takes_its_store_from_the_environment_and_ready_resolves(self) -> None:
        layer = create_needs_authorization(NeedsAuthorizationOptions(authorization_url="https://consent.example", env={}))
        assert isinstance(layer.store, MemoryResumeTokenStore)
        assert asyncio.run(layer.ready()) is None
        explicit = MemoryResumeTokenStore()
        assert create_needs_authorization(NeedsAuthorizationOptions(authorization_url="https://consent.example", store=explicit)).store is explicit
        # A bad replay-store setting fails the layer at construction, as it fails create_kyaos.
        with pytest.raises(NonceStoreConfigError):
            create_needs_authorization(NeedsAuthorizationOptions(authorization_url="https://consent.example", env={"KYAOS_NONCE_STORE": "postgres"}))

    def test_the_layer_logs_through_its_logger(self, caplog: pytest.LogCaptureFixture) -> None:
        logger = logging.getLogger("test.layer")
        with caplog.at_level(logging.INFO, logger="test.layer"):
            create_needs_authorization(NeedsAuthorizationOptions(authorization_url="https://consent.example", env={}, logger=logger))
        assert [r.getMessage() for r in caplog.records if r.name == "test.layer"] == ["KYA-OS resume-token store: memory (this process only)"]

    def test_a_redis_store_works_behind_the_async_gate(self) -> None:
        pytest.importorskip("redis")
        layer = create_needs_authorization(NeedsAuthorizationOptions(authorization_url="https://consent.example", env=REDIS))
        assert isinstance(layer.store, RedisResumeTokenStore)
