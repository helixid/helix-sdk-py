# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story L2-A: the replay store chosen by environment variables
(KYAOS_NONCE_STORE and friends), the same cases as helix-sdk-js's
tests/kyaos/nonce-store-env.test.ts: every branch of the factory, the
secret-free startup line, a missing optional package, the runtime default,
and, when they are reachable, a real Redis (KYAOS_TEST_REDIS_URL, default
the e2e suite's redis://127.0.0.1:6380) and DynamoDB Local
(KYAOS_TEST_DYNAMO_ENDPOINT, default http://127.0.0.1:8001).
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import pytest

from helix_sdk import kyaos
from helix_sdk.keys import generate_key_pair
from helix_mcp_middleware import (
    DynamoNonceStore,
    KyaOsError,
    KyaOsOptions,
    MemoryNonceStore,
    NonceStoreConfig,
    NonceStoreConfigError,
    RedisNonceStore,
    create_kyaos,
    describe_nonce_store,
    nonce_store_from_config,
    nonce_store_from_env,
    read_nonce_store_config,
    redact_url,
)
from helix_mcp_middleware.kyaos import nonce_store_env

SERVER = "did:web:orders.example"
AGENT = "did:key:z6Mkagent"
NONCE = "k7Hy9mNpQrStUvWxYz01Aa"
KEYS = generate_key_pair()
SIGNER = kyaos.EnvSigner(SERVER, env_var="K", env={"K": KEYS.private_key})


class Recorder(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def lines(self, level: int) -> List[str]:
        return [r.getMessage() for r in self.records if r.levelno == level]


@pytest.fixture
def log() -> Any:
    logger = logging.getLogger(f"test.nonce_store_env.{uuid.uuid4()}")
    logger.setLevel(logging.DEBUG)
    recorder = Recorder()
    logger.addHandler(recorder)
    logger.propagate = False
    return logger, recorder


def fake_importer(missing: Optional[str] = None) -> Any:
    built: Dict[str, List[Any]] = {"redis": [], "boto3": []}

    class FakeRedis:
        @classmethod
        def from_url(cls, url: str) -> "FakeRedis":
            built["redis"].append(url)
            return cls()

        async def set(self, *args: Any, **kwargs: Any) -> bool:
            return True

    class FakeBoto3Client:
        def put_item(self, **request: Any) -> Dict[str, Any]:
            return {}

    class FakeBoto3:
        @staticmethod
        def client(service: str, **options: Any) -> FakeBoto3Client:
            built["boto3"].append((service, options))
            return FakeBoto3Client()

    modules = {"redis.asyncio": type("M", (), {"Redis": FakeRedis}), "boto3": FakeBoto3}

    def importer(name: str) -> Any:
        if name == missing:
            error = ModuleNotFoundError(f"No module named '{name.split('.')[0]}'")
            error.name = name.split(".")[0]
            raise error
        return modules[name]

    return importer, built


class TestReadConfig:
    def test_defaults_to_memory_case_and_space_insensitive(self) -> None:
        assert read_nonce_store_config({}) == NonceStoreConfig(kind="memory")
        assert read_nonce_store_config({"KYAOS_NONCE_STORE": ""}).kind == "memory"
        assert read_nonce_store_config({"KYAOS_NONCE_STORE": " Memory "}).kind == "memory"
        assert read_nonce_store_config({"KYAOS_NONCE_STORE": "REDIS", "KYAOS_REDIS_URL": "redis://h:6379"}).kind == "redis"

    def test_unknown_store_never_falls_back(self) -> None:
        with pytest.raises(NonceStoreConfigError, match="KYAOS_NONCE_STORE must be one of memory, redis, dynamo; got 'postgres'"):
            read_nonce_store_config({"KYAOS_NONCE_STORE": "postgres"})

    def test_redis(self) -> None:
        for env, message in (
            ({"KYAOS_NONCE_STORE": "redis"}, "KYAOS_NONCE_STORE=redis needs KYAOS_REDIS_URL"),
            ({"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "  "}, "needs KYAOS_REDIS_URL"),
            ({"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "not a url"}, "KYAOS_REDIS_URL is not a URL"),
            ({"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "http://h:6379"}, "must be a redis:// or rediss:// URL"),
        ):
            with pytest.raises(NonceStoreConfigError, match=message):
                read_nonce_store_config(env)
        assert read_nonce_store_config({"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "redis://h:6379"}) == NonceStoreConfig(
            kind="redis", url="redis://h:6379", key_prefix="kyaos:nonce:"
        )
        custom = read_nonce_store_config({"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "rediss://h", "KYAOS_NONCE_KEY_PREFIX": "app:"})
        assert (custom.url, custom.key_prefix) == ("rediss://h", "app:")

    def test_dynamo(self) -> None:
        with pytest.raises(NonceStoreConfigError, match="KYAOS_NONCE_STORE=dynamo needs KYAOS_DYNAMO_TABLE"):
            read_nonce_store_config({"KYAOS_NONCE_STORE": "dynamo"})
        assert read_nonce_store_config({"KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": "t"}) == NonceStoreConfig(
            kind="dynamo", table="t", key_attribute="pk", ttl_attribute="expiresAt"
        )
        full = read_nonce_store_config({
            "KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": "t", "KYAOS_DYNAMO_KEY_ATTRIBUTE": "id", "KYAOS_DYNAMO_TTL_ATTRIBUTE": "ttl",
            "KYAOS_DYNAMO_REGION": "eu-west-1", "KYAOS_DYNAMO_ENDPOINT": "http://127.0.0.1:8000",
        })
        assert full == NonceStoreConfig(kind="dynamo", table="t", key_attribute="id", ttl_attribute="ttl", region="eu-west-1", endpoint="http://127.0.0.1:8000")
        with pytest.raises(NonceStoreConfigError, match="KYAOS_DYNAMO_ENDPOINT is not a URL"):
            read_nonce_store_config({"KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": "t", "KYAOS_DYNAMO_ENDPOINT": "nope"})
        with pytest.raises(NonceStoreConfigError, match="must be a http:// or https:// URL"):
            read_nonce_store_config({"KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": "t", "KYAOS_DYNAMO_ENDPOINT": "ftp://x"})

    def test_reads_os_environ_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KYAOS_NONCE_STORE", "dynamo")
        monkeypatch.setenv("KYAOS_DYNAMO_TABLE", "from-environ")
        assert read_nonce_store_config().table == "from-environ"


class TestStartupLine:
    def test_names_the_store_and_never_a_secret(self) -> None:
        assert describe_nonce_store(NonceStoreConfig(kind="memory")) == "KYA-OS replay store: memory (this process only)"
        line = describe_nonce_store(NonceStoreConfig(kind="redis", url="redis://user:s3cr3t-pass@cache.internal:6379/2"))
        assert line == "KYA-OS replay store: redis redis://user:***@cache.internal:6379/2 (key prefix kyaos:nonce:)"
        assert "s3cr3t" not in line
        assert describe_nonce_store(NonceStoreConfig(kind="redis", url="redis://:only-pass@h", key_prefix="p:")) == "KYA-OS replay store: redis redis://:***@h (key prefix p:)"
        assert describe_nonce_store(NonceStoreConfig(kind="dynamo", table="t")) == "KYA-OS replay store: dynamo table t (key pk, ttl expiresAt)"
        dynamo = NonceStoreConfig(kind="dynamo", table="t", key_attribute="id", ttl_attribute="ttl", region="eu-west-1", endpoint="http://a:b@local:8000")
        assert describe_nonce_store(dynamo) == "KYA-OS replay store: dynamo table t (key id, ttl ttl, region eu-west-1, endpoint http://a:***@local:8000)"
        assert redact_url("redis://h:6379") == "redis://h:6379"
        assert redact_url("redis://u:p@[::1]:6379/0") == "redis://u:***@[::1]:6379/0"


class TestNonceStoreFromEnv:
    def test_memory_line_and_warnings(self, log: Any) -> None:
        logger, recorder = log
        assert isinstance(nonce_store_from_env({}, logger=logger), MemoryNonceStore)
        assert recorder.lines(logging.INFO) == ["KYA-OS replay store: memory (this process only)"]
        assert recorder.lines(logging.WARNING) == []
        for env in ({"ENV": "production"}, {"NODE_ENV": " Production "}):
            recorder.records.clear()
            nonce_store_from_env(env, logger=logger)
            assert len(recorder.lines(logging.WARNING)) == 1
            assert "memory in production covers this process only" in recorder.lines(logging.WARNING)[0]
        recorder.records.clear()
        nonce_store_from_env({"ENV": "development"}, logger=logger)
        assert recorder.lines(logging.WARNING) == []
        nonce_store_from_env({"KYAOS_REDIS_URL": "redis://u:secret@h", "KYAOS_DYNAMO_TABLE": "t"}, logger=logger)
        assert recorder.lines(logging.WARNING) == [
            "KYA-OS replay store: KYAOS_REDIS_URL is set but KYAOS_NONCE_STORE is memory; set KYAOS_NONCE_STORE to use it for replays",
            "KYA-OS replay store: KYAOS_DYNAMO_TABLE is set but KYAOS_NONCE_STORE is memory; set KYAOS_NONCE_STORE to use it for replays",
        ]
        assert "secret" not in " ".join(r.getMessage() for r in recorder.records)

    def test_redis_builds_an_asyncio_client_from_the_url(self, log: Any) -> None:
        logger, recorder = log
        importer, built = fake_importer()
        env = {"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "redis://u:pw@h:6379", "KYAOS_NONCE_KEY_PREFIX": "app:"}
        store = nonce_store_from_env(env, logger=logger, importer=importer)
        assert isinstance(store, RedisNonceStore)
        # The asyncio client is made on first use, inside the running loop, one per loop.
        assert built["redis"] == []
        assert recorder.lines(logging.INFO) == ["KYA-OS replay store: redis redis://u:***@h:6379 (key prefix app:)"]

        async def twice() -> List[bool]:
            return [await _settle(store.insert(NONCE, AGENT, time.time() + 1)), await _settle(store.insert(NONCE + "B", AGENT, time.time() + 1))]

        assert asyncio.run(twice()) == [True, True]
        assert built["redis"] == ["redis://u:pw@h:6379"]
        assert asyncio.run(twice()) == [True, True]
        assert built["redis"] == ["redis://u:pw@h:6379"] * 2

        async def close_unused() -> None:
            await store._client.aclose()  # type: ignore[attr-defined]  # nothing made on this loop: nothing to close

        asyncio.run(close_unused())

    def test_dynamo_builds_a_threaded_boto3_client_with_region_and_endpoint_only(self, log: Any) -> None:
        logger, recorder = log
        importer, built = fake_importer()
        env = {"KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": "nonces", "KYAOS_DYNAMO_REGION": "eu-west-1",
               "KYAOS_DYNAMO_ENDPOINT": "http://127.0.0.1:8000", "AWS_ACCESS_KEY_ID": "AKIA-never-logged"}
        store = nonce_store_from_env(env, logger=logger, importer=importer)
        assert isinstance(store, DynamoNonceStore)
        assert built["boto3"] == [("dynamodb", {"region_name": "eu-west-1", "endpoint_url": "http://127.0.0.1:8000"})]
        assert recorder.lines(logging.INFO) == ["KYA-OS replay store: dynamo table nonces (key pk, ttl expiresAt, region eu-west-1, endpoint http://127.0.0.1:8000)"]
        assert "AKIA" not in " ".join(recorder.lines(logging.INFO))
        # The boto3 call runs in a worker thread: the store answers with an awaitable.
        assert asyncio.run(_settle(store.insert(NONCE, AGENT, time.time() + 1))) is True
        bare_importer, bare = fake_importer()
        nonce_store_from_env({"KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": "nonces"}, logger=logger, importer=bare_importer)
        assert bare["boto3"] == [("dynamodb", {})]

    def test_a_missing_package_names_what_to_install(self, log: Any) -> None:
        logger, _ = log
        importer, _ = fake_importer(missing="redis.asyncio")
        with pytest.raises(NonceStoreConfigError, match=r"KYAOS_NONCE_STORE=redis needs the optional package redis: pip install 'helixid-sdk-py\[redis\]'"):
            nonce_store_from_env({"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "redis://h"}, logger=logger, importer=importer)
        importer, _ = fake_importer(missing="boto3")
        with pytest.raises(NonceStoreConfigError, match=r"needs the optional package boto3: pip install 'helixid-sdk-py\[dynamo\]'"):
            nonce_store_from_env({"KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": "t"}, logger=logger, importer=importer)

        def nameless(name: str) -> Any:
            raise ImportError("no name")

        with pytest.raises(NonceStoreConfigError):
            nonce_store_from_env({"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "redis://h"}, logger=logger, importer=nameless)

        def other_missing(name: str) -> Any:
            error = ModuleNotFoundError("No module named 'hiredis'")
            error.name = "hiredis"
            raise error

        # A dependency of the package missing is that package's own problem, not ours to rename.
        with pytest.raises(ModuleNotFoundError, match="hiredis"):
            nonce_store_from_env({"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": "redis://h"}, logger=logger, importer=other_missing)

    def test_dynamo_without_a_region_and_other_client_errors(self, log: Any) -> None:
        logger, _ = log

        class NoRegionError(Exception):
            pass

        def importer_raising(error: Exception) -> Any:
            return lambda name: type("B", (), {"client": staticmethod(lambda *a, **k: (_ for _ in ()).throw(error))})

        with pytest.raises(NonceStoreConfigError, match="set KYAOS_DYNAMO_REGION or AWS_REGION"):
            nonce_store_from_env({"KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": "t"}, logger=logger, importer=importer_raising(NoRegionError()))
        with pytest.raises(RuntimeError, match="other"):
            nonce_store_from_env({"KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": "t"}, logger=logger, importer=importer_raising(RuntimeError("other")))

    def test_bad_settings_raise_before_anything_is_imported(self) -> None:
        imported: List[str] = []
        with pytest.raises(NonceStoreConfigError):
            nonce_store_from_env({"KYAOS_NONCE_STORE": "redis"}, importer=imported.append)
        assert imported == []

    def test_real_packages_with_the_default_importer(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        pytest.importorskip("redis")
        pytest.importorskip("boto3")
        _isolate_aws(monkeypatch, tmp_path)
        redis_store = nonce_store_from_config(NonceStoreConfig(kind="redis", url="redis://127.0.0.1:1"))
        assert isinstance(redis_store, RedisNonceStore)
        dynamo_store = nonce_store_from_config(NonceStoreConfig(kind="dynamo", table="t", region="us-east-1", endpoint="http://127.0.0.1:1"))
        assert isinstance(dynamo_store, DynamoNonceStore)
        assert isinstance(nonce_store_from_config(NonceStoreConfig(kind="memory")), MemoryNonceStore)

    def test_default_logger_and_environ(self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
        monkeypatch.delenv("KYAOS_NONCE_STORE", raising=False)
        with caplog.at_level(logging.INFO, logger="helix_mcp_middleware.kyaos"):
            nonce_store_from_env()
        assert "KYA-OS replay store: memory (this process only)" in caplog.text


def _isolate_aws(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """boto3 resolves credentials when a client is built; keep the developer's
    own AWS config (an `aws login` profile, say) out of it. The credentials
    reach boto3 through its standard chain, as in production."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "local")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "local")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "aws-credentials"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)


async def _settle(value: Any) -> Any:
    return await value if asyncio.iscoroutine(value) else value


class TestRuntimeDefault:
    def test_uses_the_store_the_environment_names_and_an_explicit_store_wins(self, log: Any) -> None:
        logger, recorder = log
        runtime = create_kyaos(KyaOsOptions(signer=SIGNER, env={}, logger=logger))
        assert isinstance(runtime.nonce_store, MemoryNonceStore)
        assert asyncio.run(runtime.ready()) is None
        assert recorder.lines(logging.INFO) == ["KYA-OS replay store: memory (this process only)"]
        with pytest.raises(NonceStoreConfigError):
            create_kyaos(KyaOsOptions(signer=SIGNER, env={"KYAOS_NONCE_STORE": "bogus"}, logger=logger))
        with pytest.raises(NonceStoreConfigError, match="needs KYAOS_REDIS_URL"):
            create_kyaos(KyaOsOptions(signer=SIGNER, env={"KYAOS_NONCE_STORE": "redis"}, logger=logger))
        explicit = MemoryNonceStore()
        recorder.records.clear()
        chosen = create_kyaos(KyaOsOptions(signer=SIGNER, nonce_store=explicit, env={"KYAOS_NONCE_STORE": "bogus"}, logger=logger))
        assert chosen.nonce_store is explicit
        assert recorder.records == []
        assert nonce_store_env.NONCE_STORE_KINDS == ("memory", "redis", "dynamo")


# ── against real servers ─────────────────────────────────────────────────────

REDIS_URL = os.environ.get("KYAOS_TEST_REDIS_URL", "redis://127.0.0.1:6380")
DYNAMO_ENDPOINT = os.environ.get("KYAOS_TEST_DYNAMO_ENDPOINT", "http://127.0.0.1:8001")


def _reachable(url: str) -> bool:
    parts = urlsplit(url)
    try:
        with socket.create_connection((parts.hostname, parts.port), timeout=0.5):
            return True
    except OSError:
        return False


REDIS_UP = _reachable(REDIS_URL)
DYNAMO_UP = _reachable(DYNAMO_ENDPOINT)


def _handshake_args() -> Dict[str, Any]:
    return {"nonce": kyaos.generate_nonce(), "audience": SERVER, "timestamp": int(time.time()), "agentDid": AGENT}


async def _race(runtimes: List[Any], args: Dict[str, Any], attempts: int) -> List[str]:
    async def one(runtime: Any) -> str:
        try:
            await runtime.handshake(args)
            return "ok"
        except KyaOsError as error:
            return error.reason

    return list(await asyncio.gather(*[one(runtimes[i % 2]) for i in range(attempts)]))


@pytest.mark.skipif(not REDIS_UP, reason=f"no Redis at {REDIS_URL} (e2e-playwright: pnpm redis:up, or set KYAOS_TEST_REDIS_URL)")
def test_redis_two_runtimes_from_the_same_environment_refuse_each_others_replays() -> None:
    redis = pytest.importorskip("redis")
    prefix = f"l2a-test-py:{uuid.uuid4()}:"
    env = {"KYAOS_NONCE_STORE": "redis", "KYAOS_REDIS_URL": REDIS_URL, "KYAOS_NONCE_KEY_PREFIX": prefix}
    args = _handshake_args()

    async def scenario() -> List[str]:
        # redis.asyncio clients belong to the loop that uses them: build the runtimes inside it.
        runtimes = [create_kyaos(KyaOsOptions(signer=SIGNER, env=env)) for _ in range(2)]
        outcomes = await _race(runtimes, args, 40)
        for runtime in runtimes:
            await runtime.nonce_store._client.aclose()  # type: ignore[attr-defined]
        return outcomes

    outcomes = asyncio.run(scenario())
    assert outcomes.count("ok") == 1
    assert outcomes.count("nonce_replayed") == 39
    probe = redis.Redis.from_url(REDIS_URL)
    ttl = probe.pttl(f"{prefix}{AGENT}|{args['nonce']}")
    assert 115_000 < ttl <= 122_000
    # The value is the expiry in milliseconds, as helix-sdk-js writes it.
    assert int(probe.get(f"{prefix}{AGENT}|{args['nonce']}")) == (args["timestamp"] + 121) * 1000
    probe.close()


@pytest.mark.skipif(not DYNAMO_UP, reason=f"no DynamoDB Local at {DYNAMO_ENDPOINT} (docker run -p 8001:8000 amazon/dynamodb-local)")
def test_dynamo_two_runtimes_from_the_same_environment_refuse_each_others_replays(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    boto3 = pytest.importorskip("boto3")
    # DynamoDB Local takes any credentials; they reach boto3 through its standard chain (these variables).
    _isolate_aws(monkeypatch, tmp_path)
    table = f"kyaos-nonces-py-{uuid.uuid4().hex[:8]}"
    admin = boto3.client("dynamodb", region_name="us-east-1", endpoint_url=DYNAMO_ENDPOINT)
    admin.create_table(
        TableName=table, AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}], BillingMode="PAY_PER_REQUEST",
    )
    env = {"KYAOS_NONCE_STORE": "dynamo", "KYAOS_DYNAMO_TABLE": table, "KYAOS_DYNAMO_REGION": "us-east-1", "KYAOS_DYNAMO_ENDPOINT": DYNAMO_ENDPOINT}
    runtimes = [create_kyaos(KyaOsOptions(signer=SIGNER, env=env)) for _ in range(2)]
    args = _handshake_args()
    outcomes = asyncio.run(_race(runtimes, args, 20))
    assert outcomes.count("ok") == 1
    assert outcomes.count("nonce_replayed") == 19
    item = admin.get_item(TableName=table, Key={"pk": {"S": f"{AGENT}|{args['nonce']}"}})["Item"]
    assert item["expiresAt"] == {"N": str(args["timestamp"] + 121)}
    assert item["agentDid"] == {"S": AGENT}
