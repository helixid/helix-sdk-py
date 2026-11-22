# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story L2-A in helix_mcp_middleware: the replay store (L2.5) in memory,
on Redis and on DynamoDB; sessions (L2.7, L2.8, L2.10); the server's
response proof (L2.11, L2.12) with the self-custody invariant; what
/.well-known/mcp advertises; and the runtime around a tool call (L2.1 to
L2.15, L2.17). The same cases as helix-sdk-js's mcp-middleware/tests/kyaos.

Redis and DynamoDB are in-process fakes with the semantics the stores rely
on (``SET NX PX``; a conditional ``put_item``), in both the sync and the
async client shape. The e2e suite runs RedisNonceStore against a real Redis
shared by a JS and a Python instance.
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from helix_sdk import kyaos
from helix_sdk.did import build_did_document
from helix_sdk.errors import HelixError
from helix_sdk.keys import generate_key_pair
from helix_mcp_middleware import (
    HANDSHAKE_INPUT_SCHEMA,
    KYAOS_REJECTED,
    NO_SESSION_ID,
    RESPONSE_PROOF_META_KEY,
    AuthorizedCaller,
    AuthResult,
    DynamoNonceStore,
    KyaOsAllowed,
    KyaOsDenied,
    KyaOsError,
    KyaOsOptions,
    KyaOsSessionOptions,
    MCPMiddlewareOptions,
    MemoryNonceStore,
    MemorySessionStore,
    RedisNonceStore,
    async_helixid_mcp_middleware,
    attach_response_proof,
    build_response_proof,
    create_kyaos,
    describe_kyaos,
    helixid_mcp_middleware,
    nonce_key,
    to_http_error_response,
)

SERVER = "did:web:orders.example"
ORIGIN = "https://orders.example"
AGENT = "did:key:z6Mkagent"
NOW = 1_750_000_000.0
NONCE = "k7Hy9mNpQrStUvWxYz01Aa"
SKEW = 120
TS = int(NOW)
EXPIRY = TS + SKEW + 1
SESSION_ID = r"^kyaos_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"

KEYS = generate_key_pair()
SIGNER = kyaos.EnvSigner(SERVER, env_var="TEST_SERVICE_KEY", env={"TEST_SERVICE_KEY": KEYS.private_key})
DOCUMENT = build_did_document(SERVER, KEYS.public_key)


def resolve_did(did: str) -> Optional[Dict[str, Any]]:
    return DOCUMENT if did == SERVER else None


class Clock:
    def __init__(self, start: float = NOW) -> None:
        self.current = start

    def now(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def handshake_args(**overrides: Any) -> Dict[str, Any]:
    return {"nonce": kyaos.generate_nonce(), "audience": SERVER, "timestamp": TS, **overrides}


# ── fakes ────────────────────────────────────────────────────────────────────


class FakeRedis:
    """redis-py's ``set(name, value, px=, nx=)``: True when set, None when NX refused it. One key space, expiry by the clock."""

    def __init__(self, now: Callable[[], float]) -> None:
        self.entries: Dict[str, Tuple[str, float]] = {}
        self.commands: List[str] = []
        self.now = now

    def set(self, name: str, value: str, px: Optional[int] = None, nx: bool = False) -> Optional[bool]:
        self.commands.append(f"SET {name} {value} PX {px} NX {nx}")
        existing = self.entries.get(name)
        if nx and existing is not None and existing[1] > self.now():
            return None
        self.entries[name] = (value, self.now() + (px or 0) / 1000)
        return True


class FakeAsyncRedis(FakeRedis):
    """redis.asyncio's shape: the same answers, as coroutines."""

    async def set(self, name: str, value: str, px: Optional[int] = None, nx: bool = False) -> Optional[bool]:  # type: ignore[override]
        await asyncio.sleep(0)
        return FakeRedis.set(self, name, value, px, nx)


class ClientError(Exception):
    """botocore's ClientError shape: the error code is in ``response``."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "The conditional request failed"}}


class ConditionalCheckFailedException(Exception):
    """boto3's modeled exception class (client.exceptions.ConditionalCheckFailedException)."""


class FakeDynamo:
    """A boto3 DynamoDB client's ``put_item``: typed attribute values, ``attribute_not_exists(#pk)`` refuses a second item."""

    def __init__(self, modeled: bool = False) -> None:
        self.items: Dict[str, Dict[str, Any]] = {}
        self.puts: List[Dict[str, Any]] = []
        self.fail_with: Optional[BaseException] = None
        self.modeled = modeled

    def put_item(self, **request: Any) -> Dict[str, Any]:
        self.puts.append(request)
        if self.fail_with is not None:
            raise self.fail_with
        assert request["ConditionExpression"] == "attribute_not_exists(#pk)"
        key_attribute = request["ExpressionAttributeNames"]["#pk"]
        key = f"{request['TableName']}/{request['Item'][key_attribute]['S']}"
        if key in self.items:
            raise ConditionalCheckFailedException() if self.modeled else ClientError("ConditionalCheckFailedException")
        self.items[key] = request["Item"]
        return {}


class FakeAsyncDynamo(FakeDynamo):
    """aioboto3's shape: put_item is a coroutine, and so is its failure."""

    async def put_item(self, **request: Any) -> Dict[str, Any]:  # type: ignore[override]
        await asyncio.sleep(0)
        return FakeDynamo.put_item(self, **request)


async def settle(value: Any) -> Any:
    return await value if asyncio.iscoroutine(value) else value


# ── replay store ─────────────────────────────────────────────────────────────


class TestNonceKey:
    def test_one_key_per_pair(self) -> None:
        assert nonce_key(NONCE, AGENT) == f"{AGENT}|{NONCE}"
        assert nonce_key(NONCE, None) == f"|{NONCE}"
        assert nonce_key(NONCE, AGENT) != nonce_key(NONCE, "did:key:z6Mkother")


class TestMemoryNonceStore:
    def test_accepts_once_and_refuses_the_replay(self) -> None:
        store = MemoryNonceStore(now=Clock().now)
        assert store.insert(NONCE, AGENT, EXPIRY) is True
        assert store.insert(NONCE, AGENT, EXPIRY) is False
        assert store.has(NONCE, AGENT)
        assert store.size == 1

    def test_per_agent_tuples(self) -> None:
        store = MemoryNonceStore(now=Clock().now)
        assert store.insert(NONCE, AGENT, EXPIRY)
        assert store.insert(NONCE, "did:key:z6Mkother", EXPIRY)
        assert store.insert(NONCE, None, EXPIRY)
        assert not store.insert(NONCE, None, EXPIRY)
        assert store.size == 3

    def test_retained_until_ts_plus_skew_plus_one_and_never_evicted_early(self) -> None:
        clock = Clock()
        store = MemoryNonceStore(now=clock.now)
        assert store.insert(NONCE, AGENT, EXPIRY)
        clock.current = TS + SKEW  # the end of the acceptance window
        assert not store.insert(NONCE, AGENT, EXPIRY)
        clock.current = EXPIRY - 0.001
        assert not store.insert(NONCE, AGENT, EXPIRY)
        assert store.has(NONCE, AGENT)
        clock.current = EXPIRY
        assert not store.has(NONCE, AGENT)
        assert store.insert("AAAAAAAAAAAAAAAAAAAAAA", AGENT, EXPIRY + 10)  # sweeps the expired entry
        assert store.size == 1
        assert store.insert(NONCE, AGENT, EXPIRY + 10)

    def test_atomic_under_concurrent_threads(self) -> None:
        import threading

        store = MemoryNonceStore()
        results: List[bool] = []
        barrier = threading.Barrier(32)

        def attempt() -> None:
            barrier.wait()
            results.append(store.insert(NONCE, AGENT, time.time() + 60))

        threads = [threading.Thread(target=attempt) for _ in range(32)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert results.count(True) == 1

    def test_defaults_to_the_wall_clock(self) -> None:
        store = MemoryNonceStore()
        assert store.insert(NONCE, AGENT, time.time() - 1)
        assert not store.has(NONCE, AGENT)
        assert store.insert(NONCE, AGENT, time.time() + 1)


class TestRedisNonceStore:
    def test_set_nx_px_with_the_ttl_running_to_expires_at_under_the_prefix(self) -> None:
        clock = Clock()
        redis = FakeRedis(clock.now)
        store = RedisNonceStore(redis, now=clock.now)
        assert store.insert(NONCE, AGENT, EXPIRY) is True
        # The same key and value helix-sdk-js writes (expiry in ms), so JS and Python instances share one Redis.
        assert redis.commands == [f"SET kyaos:nonce:{AGENT}|{NONCE} {EXPIRY * 1000} PX {(EXPIRY - TS) * 1000} NX True"]
        assert store.insert(NONCE, AGENT, EXPIRY) is False
        custom = RedisNonceStore(redis, key_prefix="app:", now=clock.now)
        assert custom.insert(NONCE, AGENT, EXPIRY)
        assert redis.commands[2].startswith(f"SET app:{AGENT}|{NONCE} ")

    def test_refused_at_a_second_instance_sharing_the_store(self) -> None:
        clock = Clock()
        redis = FakeRedis(clock.now)
        first, second = RedisNonceStore(redis, now=clock.now), RedisNonceStore(redis, now=clock.now)
        attempts = [(first if i % 2 else second).insert(NONCE, AGENT, EXPIRY) for i in range(50)]
        assert attempts.count(True) == 1
        assert first.insert(NONCE, None, EXPIRY)

    def test_expires_at_expires_at_and_keeps_a_past_expiry_one_tick(self) -> None:
        clock = Clock()
        redis = FakeRedis(clock.now)
        store = RedisNonceStore(redis, now=clock.now)
        assert store.insert(NONCE, AGENT, EXPIRY)
        clock.current = EXPIRY - 0.001
        assert not store.insert(NONCE, AGENT, EXPIRY)
        clock.current = EXPIRY
        assert store.insert(NONCE, AGENT, EXPIRY + 1)
        assert store.insert("AAAAAAAAAAAAAAAAAAAAAA", AGENT, clock.now() - 5)
        assert redis.commands[-1].endswith("PX 1 NX True")

    def test_async_client_answers_with_an_awaitable(self) -> None:
        clock = Clock()
        redis = FakeAsyncRedis(clock.now)
        store = RedisNonceStore(redis, now=clock.now)

        async def scenario() -> List[bool]:
            return list(await asyncio.gather(*[settle(store.insert(NONCE, AGENT, EXPIRY)) for _ in range(20)]))

        assert run(scenario()).count(True) == 1

    def test_ok_replies_from_raw_clients_and_the_wall_clock(self) -> None:
        for reply in ("OK", b"OK"):
            client = type("C", (), {"set": lambda self, *a, **k: reply})()
            assert RedisNonceStore(client).insert(NONCE, AGENT, time.time() + 1) is True
        refusing = type("C", (), {"set": lambda self, *a, **k: None})()
        assert RedisNonceStore(refusing).insert(NONCE, AGENT, time.time() + 1) is False


class TestDynamoNonceStore:
    def test_conditional_put_with_the_expiry_in_seconds_for_the_table_ttl(self) -> None:
        dynamo = FakeDynamo()
        store = DynamoNonceStore(dynamo, "kyaos-nonces")
        assert store.insert(NONCE, AGENT, EXPIRY + 0.2) is True
        assert dynamo.puts[0] == {
            "TableName": "kyaos-nonces",
            "Item": {"pk": {"S": f"{AGENT}|{NONCE}"}, "nonce": {"S": NONCE}, "agentDid": {"S": AGENT}, "expiresAt": {"N": str(EXPIRY + 1)}},
            "ConditionExpression": "attribute_not_exists(#pk)",
            "ExpressionAttributeNames": {"#pk": "pk"},
        }
        assert store.insert(NONCE, AGENT, EXPIRY) is False
        assert store.insert(NONCE, None, EXPIRY) is True
        assert dynamo.puts[2]["Item"] == {"pk": {"S": f"|{NONCE}"}, "nonce": {"S": NONCE}, "expiresAt": {"N": str(EXPIRY)}}

    def test_custom_attributes_modeled_exception_and_shared_instances(self) -> None:
        dynamo = FakeDynamo(modeled=True)
        first = DynamoNonceStore(dynamo, "t", key_attribute="id", ttl_attribute="ttl")
        second = DynamoNonceStore(dynamo, "t", key_attribute="id", ttl_attribute="ttl")
        attempts = [(first if i % 2 else second).insert(NONCE, AGENT, EXPIRY) for i in range(20)]
        assert attempts.count(True) == 1
        assert dynamo.puts[0]["Item"]["id"] == {"S": f"{AGENT}|{NONCE}"}
        assert dynamo.puts[0]["Item"]["ttl"] == {"N": str(EXPIRY)}
        assert dynamo.puts[0]["ExpressionAttributeNames"] == {"#pk": "id"}

    def test_passes_any_other_failure_through(self) -> None:
        dynamo = FakeDynamo()
        store = DynamoNonceStore(dynamo, "t")
        dynamo.fail_with = ClientError("ProvisionedThroughputExceededException")
        with pytest.raises(ClientError):
            store.insert(NONCE, AGENT, EXPIRY)
        dynamo.fail_with = RuntimeError("no response")
        with pytest.raises(RuntimeError):
            store.insert(NONCE, AGENT, EXPIRY)

    def test_async_client(self) -> None:
        dynamo = FakeAsyncDynamo()
        store = DynamoNonceStore(dynamo, "t")

        async def scenario() -> Tuple[bool, bool]:
            return await settle(store.insert(NONCE, AGENT, EXPIRY)), await settle(store.insert(NONCE, AGENT, EXPIRY))

        assert run(scenario()) == (True, False)
        dynamo.fail_with = ClientError("InternalServerError")
        with pytest.raises(ClientError):
            run(settle(store.insert("AAAAAAAAAAAAAAAAAAAAAA", AGENT, EXPIRY)))


# ── sessions ─────────────────────────────────────────────────────────────────


SESSION_INPUT = {"agent_did": AGENT, "identity_state": "authenticated", "audience": SERVER, "nonce": NONCE, "now": NOW}


class TestMemorySessionStore:
    def test_creates_kyaos_uuid_sessions_with_a_30_minute_idle_ttl(self) -> None:
        import re

        store = MemorySessionStore()
        assert store.ttl_minutes == 30
        session = store.create(**SESSION_INPUT)
        assert re.match(SESSION_ID, session.id)
        assert (session.agent_did, session.identity_state, session.audience, session.nonce) == (AGENT, "authenticated", SERVER, NONCE)
        assert (session.created_at, session.last_activity, session.expires_at) == (NOW, NOW, NOW + 1800)
        assert store.create(**SESSION_INPUT).id != session.id
        assert store.size == 2
        anonymous = store.create(agent_did=None, identity_state="anonymous", audience=SERVER, nonce=NONCE, now=NOW)
        assert anonymous.agent_did is None and anonymous.identity_state == "anonymous"

    def test_sessions_are_immutable_snapshots(self) -> None:
        store = MemorySessionStore(generate_id=lambda: "kyaos_11111111-2222-4333-8444-555555555555")
        created = store.create(**SESSION_INPUT)
        with pytest.raises(Exception):
            created.last_activity = 0  # type: ignore[misc]
        assert store.get(created.id, NOW) == created

    def test_expires_an_idle_session_at_the_boundary(self) -> None:
        store = MemorySessionStore(ttl_minutes=1)
        session_id = store.create(**SESSION_INPUT).id
        assert store.get(session_id, NOW + 59.999) is not None
        assert store.get(session_id, NOW + 60) is None
        assert store.size == 0
        assert store.get(session_id, NOW) is None
        assert store.get("kyaos_unknown", NOW) is None

    def test_touch_moves_last_activity_and_the_expiry(self) -> None:
        store = MemorySessionStore(ttl_minutes=1)
        session_id = store.create(**SESSION_INPUT).id
        touched = store.touch(session_id, NOW + 30)
        assert touched is not None
        assert (touched.last_activity, touched.expires_at, touched.created_at) == (NOW + 30, NOW + 90, NOW)
        assert store.get(session_id, NOW + 89.999) is not None
        assert store.touch(session_id, NOW + 90) is None
        assert store.get(session_id, NOW + 90.001) is None
        assert store.touch("kyaos_unknown", NOW) is None

    def test_delete(self) -> None:
        store = MemorySessionStore()
        session_id = store.create(**SESSION_INPUT).id
        store.delete(session_id)
        assert store.get(session_id, NOW) is None
        store.delete(session_id)

    @pytest.mark.parametrize("ttl", [0, -1, math.nan, math.inf, True, "30"])
    def test_refuses_a_ttl_that_is_not_a_positive_number(self, ttl: Any) -> None:
        with pytest.raises(ValueError):
            MemorySessionStore(ttl_minutes=ttl)

    def test_fractional_ttl(self) -> None:
        assert MemorySessionStore(ttl_minutes=0.5).ttl_minutes == 0.5


# ── response proof ───────────────────────────────────────────────────────────


REQUEST = {"method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}}}
BODY = {"content": [{"type": "text", "text": "ok"}]}


def meta(outcome: str, **extra: Any) -> Dict[str, Any]:
    value: Dict[str, Any] = {
        "did": SERVER, "kid": f"{SERVER}#key-1", "ts": TS, "nonce": kyaos.generate_nonce(), "audience": SERVER,
        "sessionId": "kyaos_11111111-2222-4333-8444-555555555555", "requestHash": kyaos.hash_request(REQUEST),
    }
    if kyaos.outcome_has_response(outcome):
        value["responseHash"] = kyaos.hash_response(BODY, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE)
        value["prf"] = kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE
    value["outcome"] = outcome
    value.update(extra)
    return value


class TestBuildResponseProof:
    def test_signs_the_canonical_claims_and_the_sdk_verifies_it(self) -> None:
        proof = build_response_proof(meta("allowed", clientDid=AGENT), SIGNER)
        assert set(proof) == {"jws", "meta"}
        assert proof["meta"]["clientDid"] == AGENT
        import base64

        payload = proof["jws"].split(".")[1]
        assert base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode() == kyaos.proof_payload(proof["meta"])
        assert kyaos.read_jws_header(proof["jws"]) == {"alg": "EdDSA", "kid": f"{SERVER}#key-1"}
        verified = kyaos.verify_response_proof(attach_response_proof(BODY, proof), SERVER, resolve_did, request=REQUEST, now=NOW)
        assert verified.outcome == "allowed"

    def test_response_hash_presence_follows_the_outcome(self) -> None:
        for outcome in ("allowed", "needs_authorization"):
            proof = build_response_proof(meta(outcome), SIGNER)
            assert "responseHash" in proof["meta"]
            assert kyaos.verify_detached_proof(proof, resolve_did=resolve_did, now=NOW).outcome == outcome
            with pytest.raises(ValueError, match="must carry responseHash"):
                build_response_proof({k: v for k, v in meta(outcome).items() if k != "responseHash"}, SIGNER)
        for outcome in ("denied", "step_up_required"):
            proof = build_response_proof(meta(outcome, reason="insufficient scope"), SIGNER)
            assert "responseHash" not in proof["meta"]
            assert kyaos.verify_detached_proof(proof, resolve_did=resolve_did, now=NOW).outcome == outcome
            with pytest.raises(ValueError, match="no responseHash"):
                build_response_proof(meta(outcome, responseHash=kyaos.hash_response(BODY)), SIGNER)
        implicit = {k: v for k, v in meta("allowed").items() if k != "outcome"}
        assert "outcome" not in build_response_proof(implicit, SIGNER)["meta"]
        assert "clientDid" not in build_response_proof(meta("allowed", clientDid=None), SIGNER)["meta"]

    def test_refuses_meta_for_another_signer_or_malformed(self) -> None:
        with pytest.raises(ValueError, match="the signer is"):
            build_response_proof(meta("allowed", did="did:web:other.example"), SIGNER)
        with pytest.raises(ValueError, match="the signer is"):
            build_response_proof(meta("allowed", kid=f"{SERVER}#key-2"), SIGNER)
        with pytest.raises(kyaos.ResponseProofError) as caught:
            build_response_proof(meta("allowed", requestHash="nope"), SIGNER)
        assert caught.value.code == "RESPONSE_PROOF_INVALID"
        hash_kid = type("S", (), {"did": SERVER, "kid": "#key-1", "sign": lambda self, data: SIGNER.sign(data)})()
        assert build_response_proof(meta("allowed"), hash_kid)["meta"]["kid"] == f"{SERVER}#key-1"

    def test_self_custody_only_the_signing_input_reaches_the_signer(self) -> None:
        seen: List[bytes] = []

        class Spy:
            did, kid = SERVER, "key-1"

            def sign(self, data: bytes) -> bytes:
                seen.append(data)
                return SIGNER.sign(data)

        proof = build_response_proof(meta("allowed"), Spy())  # type: ignore[arg-type]
        assert len(seen) == 1
        assert seen[0].decode() == ".".join(proof["jws"].split(".")[:2])
        raw = bytes.fromhex(KEYS.private_key)
        import base64

        leaks = [KEYS.private_key, base64.urlsafe_b64encode(raw).decode().rstrip("="), base64.b64encode(raw).decode()]
        for leak in leaks:
            assert leak not in json.dumps(proof)
            assert leak not in repr(SIGNER)
            assert leak not in json.dumps(attach_response_proof(BODY, proof))
        assert set(vars(SIGNER)) & {"private_key", "key", "secret"} == set()


class TestAttachResponseProof:
    def test_puts_the_proof_at_the_kya_os_key_and_keeps_the_rest(self) -> None:
        proof = build_response_proof(meta("allowed"), SIGNER)
        assert RESPONSE_PROOF_META_KEY == "org.kya-os/response-proof"
        assert attach_response_proof(BODY, proof) == {**BODY, "_meta": {RESPONSE_PROOF_META_KEY: proof}}
        with_meta = {**BODY, "_meta": {"traceparent": "t", RESPONSE_PROOF_META_KEY: "stale"}}
        assert attach_response_proof(with_meta, proof)["_meta"] == {"traceparent": "t", RESPONSE_PROOF_META_KEY: proof}
        assert attach_response_proof({**BODY, "_meta": "not an object"}, proof)["_meta"] == {RESPONSE_PROOF_META_KEY: proof}


class TestDescribeKyaOs:
    def test_advertises_the_handshake_tool_the_skew_and_proofs(self) -> None:
        assert describe_kyaos() == {
            "endpoints": {"handshake": "/mcp#_kyaos_handshake"},
            "clockSkewSeconds": 120,
            "capabilities": {"proofs": True},
            "handshakeTool": "_kyaos_handshake",
        }
        described = describe_kyaos(clock_skew_seconds=300, tools_endpoint="https://mcp.example.com/mcp")
        assert described["endpoints"] == {"handshake": "https://mcp.example.com/mcp#_kyaos_handshake"}
        assert described["clockSkewSeconds"] == 300

    def test_no_handshake_endpoint_without_sessions_and_a_checked_skew(self) -> None:
        assert describe_kyaos(session_enabled=False)["endpoints"] == {}
        with pytest.raises(ValueError):
            describe_kyaos(clock_skew_seconds=10)


# ── runtime ──────────────────────────────────────────────────────────────────


def runtime(**overrides: Any) -> Tuple[Any, Clock]:
    clock = Clock()
    options = KyaOsOptions(signer=SIGNER, public_origin=ORIGIN, now=clock.now)
    for name, value in overrides.items():
        setattr(options, name, value)
    return create_kyaos(options), clock


def refusal(coroutine: Any) -> str:
    try:
        run(coroutine)
    except KyaOsError as error:
        return error.reason
    raise AssertionError("expected a refusal")


def tool_call(arguments: Optional[Dict[str, Any]] = None, meta_: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    call: Dict[str, Any] = {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"} if arguments is None else arguments}
    if meta_ is not None:
        call["_meta"] = meta_
    return call


RESULT = {"content": [{"type": "text", "text": '{"id":"ORD-1001"}'}], "structuredContent": {"id": "ORD-1001"}}


class TestCreateKyaOs:
    def test_derives_the_server_did_and_validates_the_config(self) -> None:
        kya, _ = runtime()
        assert kya.server_did == SERVER
        assert kya.clock_skew_seconds == 120
        assert kya.sessions_enabled is True
        assert kya.handshake_tool_name == "_kyaos_handshake"
        assert kya.is_handshake("_kyaos_handshake") and not kya.is_handshake("lookup_order") and not kya.is_handshake(None)
        assert isinstance(kya.nonce_store, MemoryNonceStore)
        assert isinstance(kya.session_store, MemorySessionStore)
        assert kya.describe() == describe_kyaos()
        assert create_kyaos(KyaOsOptions(signer=SIGNER, server_did=SERVER)).server_did == SERVER
        with pytest.raises(ValueError, match="is not the signer's DID"):
            create_kyaos(KyaOsOptions(signer=SIGNER, server_did="did:web:other.example"))
        orders = type("S", (), {"did": "orders", "kid": "key-1", "sign": lambda self, d: SIGNER.sign(d)})()
        with pytest.raises(ValueError, match="must be a DID"):
            create_kyaos(KyaOsOptions(signer=orders))
        with pytest.raises(ValueError):
            create_kyaos(KyaOsOptions(signer=SIGNER, clock_skew_seconds=29))
        quiet = create_kyaos(
            KyaOsOptions(signer=SIGNER, clock_skew_seconds=600, session=KyaOsSessionOptions(enabled=False, ttl_minutes=5), tools_endpoint="/api/mcp")
        )
        assert quiet.describe() == {"endpoints": {}, "clockSkewSeconds": 600, "capabilities": {"proofs": True}, "handshakeTool": "_kyaos_handshake"}
        assert quiet.session_store.ttl_minutes == 5
        assert create_kyaos(KyaOsOptions(signer=SIGNER, session=None)).sessions_enabled  # type: ignore[arg-type]
        assert HANDSHAKE_INPUT_SCHEMA["required"] == ["nonce", "audience", "timestamp"]
        assert HANDSHAKE_INPUT_SCHEMA["properties"]["nonce"]["minLength"] == 22


class TestHandshake:
    def test_creates_a_session_on_a_correct_handshake(self) -> None:
        import re

        kya, _ = runtime()
        args = handshake_args(agentDid=AGENT, clientInfo={"name": "e2e"}, clientProtocolVersion="1.0")
        response = run(kya.handshake(args))
        assert response == {
            "sessionId": response["sessionId"], "serverDid": SERVER, "protocolVersion": "1.0",
            "serverCapabilities": {"proofs": True, "delegation": False, "statusList": False}, "sessionTtl": 1800, "nonce": args["nonce"],
        }
        assert re.match(SESSION_ID, response["sessionId"])
        session = kya.session_store.get(response["sessionId"], NOW)
        assert (session.agent_did, session.identity_state, session.audience, session.nonce) == (AGENT, "anonymous", SERVER, args["nonce"])
        assert (session.created_at, session.last_activity, session.expires_at) == (NOW, NOW, NOW + 1800)
        anonymous = run(kya.handshake(handshake_args()))
        assert kya.session_store.get(anonymous["sessionId"], NOW).agent_did is None
        authenticated = run(kya.handshake(handshake_args(agentDid=AGENT), authenticated_agent_did=AGENT))
        assert kya.session_store.get(authenticated["sessionId"], NOW).identity_state == "authenticated"
        verified_only = run(kya.handshake(handshake_args(), authenticated_agent_did=AGENT))
        session = kya.session_store.get(verified_only["sessionId"], NOW)
        assert (session.agent_did, session.identity_state) == (AGENT, "authenticated")
        assert refusal(kya.handshake(handshake_args(agentDid="did:key:z6Mkother"), authenticated_agent_did=AGENT)) == "agent_did_mismatch"

    def test_audience_is_the_server_did_or_the_public_origin(self) -> None:
        kya, _ = runtime()
        assert run(kya.handshake(handshake_args(audience=ORIGIN)))["serverDid"] == SERVER
        assert refusal(kya.handshake(handshake_args(audience="did:web:other.example"))) == "audience_mismatch"
        assert refusal(kya.handshake(handshake_args(audience="https://other.example"))) == "audience_mismatch"
        no_origin = create_kyaos(KyaOsOptions(signer=SIGNER, now=lambda: NOW))
        assert refusal(no_origin.handshake(handshake_args(audience=ORIGIN))) == "audience_mismatch"

    def test_skew_is_enforced_inclusively_and_configurable(self) -> None:
        kya, _ = runtime()
        for ts in (TS - 120, TS + 120):
            assert run(kya.handshake(handshake_args(timestamp=ts)))["sessionId"]
        for ts in (TS - 121, TS + 121, TS - 10_000):
            assert refusal(kya.handshake(handshake_args(timestamp=ts))) == "timestamp_skew"
        tight = create_kyaos(KyaOsOptions(signer=SIGNER, clock_skew_seconds=30, now=lambda: NOW))
        assert run(tight.handshake(handshake_args(timestamp=TS - 30)))["sessionId"]
        assert refusal(tight.handshake(handshake_args(timestamp=TS - 31))) == "timestamp_skew"
        assert tight.clock_skew_seconds == 30

    def test_refuses_a_malformed_request_first(self) -> None:
        kya, _ = runtime()
        assert refusal(kya.handshake(handshake_args(nonce="k7Hy9mNpQrStUvWxYz01A"))) == "nonce_invalid"
        assert refusal(kya.handshake(handshake_args(nonce="k7Hy9mNpQrStUvWxYz01Aa=="))) == "nonce_invalid"
        assert refusal(kya.handshake(handshake_args(timestamp="now"))) == "timestamp_invalid"
        assert refusal(kya.handshake(handshake_args(audience=""))) == "audience_invalid"
        assert refusal(kya.handshake(handshake_args(agentDid="agent"))) == "agent_did_invalid"
        assert refusal(kya.handshake(handshake_args(extra=1))) == "unknown_member"
        assert refusal(kya.handshake("nope")) == "request_not_object"
        assert kya.session_store.size == 0

    def test_refuses_a_replay_retained_until_ts_plus_skew_plus_one(self) -> None:
        kya, clock = runtime()
        args = handshake_args(agentDid=AGENT)
        run(kya.handshake(args))
        assert refusal(kya.handshake(args)) == "nonce_replayed"
        assert run(kya.handshake({**args, "agentDid": "did:key:z6Mkother"}))["sessionId"]
        assert run(kya.handshake(handshake_args(nonce=args["nonce"])))["sessionId"]
        clock.current = NOW + 120
        assert refusal(kya.handshake(args)) == "nonce_replayed"
        clock.current = NOW + 121 - 0.001
        assert refusal(kya.handshake(args)) == "nonce_replayed"
        assert kya.nonce_store.has(args["nonce"], AGENT)
        clock.current = NOW + 121
        assert not kya.nonce_store.has(args["nonce"], AGENT)
        assert refusal(kya.handshake(args)) == "timestamp_skew"

    def test_refused_while_sessions_are_disabled(self) -> None:
        kya = create_kyaos(KyaOsOptions(signer=SIGNER, session=KyaOsSessionOptions(enabled=False), now=lambda: NOW))
        assert refusal(kya.handshake(handshake_args())) == "sessions_disabled"

    def test_handshake_tool_result(self) -> None:
        kya, _ = runtime()
        ok = run(kya.handshake_tool_result(handshake_args()))
        assert ok["structuredContent"]["serverDid"] == SERVER
        assert json.loads(ok["content"][0]["text"]) == ok["structuredContent"]
        assert "isError" not in ok
        bad = run(kya.handshake_tool_result(handshake_args(audience="did:web:other.example")))
        assert bad["isError"] is True
        assert bad["content"][0]["text"].startswith("audience_mismatch: ")
        assert bad["structuredContent"]["error"] == "audience_mismatch"
        assert "other.example" in bad["structuredContent"]["message"]

        class Down:
            def insert(self, *args: Any) -> bool:
                raise RuntimeError("store down")

        broken = create_kyaos(KyaOsOptions(signer=SIGNER, now=lambda: NOW, nonce_store=Down()))
        with pytest.raises(RuntimeError, match="store down"):
            run(broken.handshake_tool_result(handshake_args()))


class TestStartFinishCall:
    def test_allowed_call_strips_control_arguments_and_signs_a_proof_the_sdk_verifies(self) -> None:
        kya, _ = runtime()
        handshake = run(kya.handshake(handshake_args(agentDid=AGENT)))
        args = {"orderId": "ORD-1001", "_kyaos_session": handshake["sessionId"], "_kyaos_proof": {"jws": "x"}}
        noise = {"traceparent": "00-1-2-01", "io.modelcontextprotocol/trace": "x", "x-helix-vp": "ignored", "org.kya-os/request-proof": {"jws": "y", "meta": {}}}
        seen: List[Any] = []

        def handler(arguments: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
            seen.append((arguments, context))
            return RESULT

        outcome = run(kya.call(tool_call(args, noise), handler))
        assert isinstance(outcome, KyaOsAllowed) and outcome.outcome == "allowed"
        assert seen[0][0] == {"orderId": "ORD-1001"}
        assert seen[0][1]["session"].id == handshake["sessionId"] and seen[0][1]["client_did"] == AGENT
        assert outcome.arguments == {"orderId": "ORD-1001"}
        assert list(outcome.result["_meta"]) == [RESPONSE_PROOF_META_KEY]
        proof = outcome.result["_meta"][RESPONSE_PROOF_META_KEY]
        assert proof["meta"] == {
            "did": SERVER, "kid": f"{SERVER}#key-1", "ts": TS, "nonce": proof["meta"]["nonce"], "audience": SERVER,
            "sessionId": handshake["sessionId"],
            "requestHash": kyaos.hash_request({"method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}}}),
            "responseHash": kyaos.hash_response(RESULT, kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE),
            "outcome": "allowed", "clientDid": AGENT, "prf": kyaos.RESPONSE_PROOF_ENVELOPE_PROFILE,
        }
        assert kyaos.is_valid_nonce(proof["meta"]["nonce"])
        sent = {"method": "tools/call", "params": {"name": "lookup_order", "arguments": args, "_meta": noise}}
        verified = kyaos.verify_response_proof(outcome.result, SERVER, resolve_did, request=sent, now=NOW)
        assert verified.outcome == "allowed" and verified.response_hash == proof["meta"]["responseHash"]
        with pytest.raises(kyaos.ResponseProofError) as caught:
            kyaos.verify_response_proof({**outcome.result, "structuredContent": {"id": "ORD-9999"}}, SERVER, resolve_did, request=sent, now=NOW)
        assert caught.value.reason == "response_hash_mismatch"

    def test_without_a_session_the_call_is_authorised_from_its_credentials(self) -> None:
        kya, _ = runtime()
        started = run(kya.start(tool_call(), authorize=lambda: AuthorizedCaller(auth_method="kyaos", agent_did=AGENT)))
        assert isinstance(started, KyaOsAllowed)
        assert started.session is None and started.client_did == AGENT
        result = run(started.finish(RESULT))
        proof = result["_meta"][RESPONSE_PROOF_META_KEY]
        assert (proof["meta"]["sessionId"], proof["meta"]["audience"], proof["meta"]["clientDid"]) == (NO_SESSION_ID, SERVER, AGENT)
        assert kyaos.verify_response_proof(result, SERVER, resolve_did, request={"method": "tools/call", "params": tool_call()}, now=NOW).outcome == "allowed"
        anonymous = run(kya.start(tool_call()))
        assert "clientDid" not in run(anonymous.finish(RESULT))["_meta"][RESPONSE_PROOF_META_KEY]["meta"]
        assert run(kya.start(tool_call(), authorize=lambda: None)).client_did is None
        assert run(kya.start(tool_call(), authorize=lambda: {"agentDid": AGENT})).client_did == AGENT
        assert run(kya.start(tool_call(), authorize=lambda: {"agent_did": AGENT})).client_did == AGENT

        async def async_authorize() -> AuthorizedCaller:
            return AuthorizedCaller(auth_method="oauth", oauth_subject="s")

        assert run(kya.start(tool_call(), authorize=async_authorize)).client_did is None
        explicit = run(kya.start(tool_call(), authorize=lambda: {"agent_did": AGENT}, client_did="did:key:z6Mkexplicit"))
        assert explicit.client_did == "did:key:z6Mkexplicit"
        no_args = run(kya.start({"name": "lookup_order"}))
        assert no_args.arguments == {}
        assert no_args.request_hash == kyaos.hash_request({"method": "tools/call", "params": {"name": "lookup_order", "arguments": {}}})
        assert run(kya.start({"name": "lookup_order", "arguments": "x"})).arguments == {}

    def test_session_audience_and_last_activity_per_valid_call(self) -> None:
        kya, clock = runtime()
        handshake = run(kya.handshake(handshake_args(audience=ORIGIN)))
        clock.advance(10)
        first = run(kya.start(tool_call({"_kyaos_session": handshake["sessionId"]})))
        assert first.session.last_activity == NOW + 10 and first.session.expires_at == NOW + 10 + 1800
        proof = run(first.finish(RESULT))["_meta"][RESPONSE_PROOF_META_KEY]
        assert (proof["meta"]["audience"], proof["meta"]["sessionId"]) == (ORIGIN, handshake["sessionId"])
        clock.advance(20)
        assert run(kya.start(tool_call({"_kyaos_session": handshake["sessionId"]}))).session.last_activity == NOW + 30
        clock.advance(5)

        def deny() -> None:
            raise RuntimeError("no")

        run(kya.start(tool_call({"_kyaos_session": handshake["sessionId"]}), authorize=deny))
        assert kya.session_store.get(handshake["sessionId"], clock.now()).last_activity == NOW + 30

    def test_idle_ttl_expiry(self) -> None:
        kya, clock = runtime(session=KyaOsSessionOptions(ttl_minutes=1))
        handshake = run(kya.handshake(handshake_args()))
        assert handshake["sessionTtl"] == 60
        clock.advance(59)
        assert run(kya.start(tool_call({"_kyaos_session": handshake["sessionId"]}))).outcome == "allowed"
        clock.advance(59)  # the valid call moved the expiry out
        assert run(kya.start(tool_call({"_kyaos_session": handshake["sessionId"]}))).outcome == "allowed"
        clock.advance(60)
        denied = run(kya.start(tool_call({"_kyaos_session": handshake["sessionId"]})))
        assert isinstance(denied, KyaOsDenied) and denied.reason == "session_unknown"
        assert isinstance(denied.error, KyaOsError)

    def test_denies_with_a_signed_proof_without_response_hash(self) -> None:
        kya, _ = runtime()
        scope_error = HelixError("INSUFFICIENT_SCOPE", "Required scope: orders:admin", 403)

        def deny() -> None:
            raise scope_error

        denied = run(kya.start(tool_call(), authorize=deny, client_did=AGENT))
        assert isinstance(denied, KyaOsDenied)
        assert (denied.outcome, denied.reason, denied.error) == ("denied", "INSUFFICIENT_SCOPE", scope_error)
        assert denied.proof["meta"] == {
            "did": SERVER, "kid": f"{SERVER}#key-1", "ts": TS, "nonce": denied.proof["meta"]["nonce"], "audience": SERVER,
            "sessionId": NO_SESSION_ID, "requestHash": denied.request_hash, "outcome": "denied", "reason": "INSUFFICIENT_SCOPE", "clientDid": AGENT,
        }
        verified = kyaos.verify_response_proof({"error": "insufficient_scope"}, SERVER, resolve_did, request={"method": "tools/call", "params": tool_call()}, proof=denied.proof, now=NOW)
        assert verified.outcome == "denied" and verified.response_hash is None

        def raising(error: BaseException) -> Callable[[], None]:
            def authorize() -> None:
                raise error

            return authorize

        assert run(kya.start(tool_call(), authorize=raising(RuntimeError("token expired")))).reason == "token expired"
        assert run(kya.start(tool_call(), authorize=raising(RuntimeError()))).reason == "denied"
        empty_code = RuntimeError()
        empty_code.code = ""  # type: ignore[attr-defined]
        assert run(kya.start(tool_call(), authorize=raising(empty_code))).reason == "denied"
        assert run(kya.start(tool_call(), authorize=raising(KyaOsError("audience_mismatch", "x")))).reason == "audience_mismatch"
        assert run(kya.start(tool_call({"_kyaos_session": "sess_abc"}))).reason == "session_id_malformed"
        assert run(kya.start(tool_call({"_kyaos_session": "kyaos_11111111-2222-4333-8444-555555555555"}))).reason == "session_unknown"
        quiet = create_kyaos(KyaOsOptions(signer=SIGNER, session=KyaOsSessionOptions(enabled=False), now=lambda: NOW))
        assert run(quiet.start(tool_call({"_kyaos_session": "kyaos_11111111-2222-4333-8444-555555555555"}))).reason == "sessions_disabled"
        assert run(quiet.start(tool_call())).outcome == "allowed"

    def test_another_agents_session_is_refused(self) -> None:
        kya, _ = runtime()
        handshake = run(kya.handshake(handshake_args(agentDid=AGENT, audience=ORIGIN)))
        session_args = {"_kyaos_session": handshake["sessionId"]}
        denied = run(kya.start(tool_call(session_args), authorize=lambda: {"agent_did": "did:key:z6Mkother"}))
        assert denied.reason == "session_agent_mismatch"
        assert denied.session.id == handshake["sessionId"]
        assert (denied.proof["meta"]["sessionId"], denied.proof["meta"]["audience"], denied.proof["meta"]["clientDid"]) == (handshake["sessionId"], ORIGIN, "did:key:z6Mkother")
        assert run(kya.start(tool_call(session_args), authorize=lambda: {"agent_did": AGENT})).client_did == AGENT
        assert run(kya.start(tool_call(session_args))).client_did == AGENT
        open_session = run(kya.handshake(handshake_args()))
        assert run(kya.start(tool_call({"_kyaos_session": open_session["sessionId"]}), authorize=lambda: {"agent_did": AGENT})).outcome == "allowed"

    def test_call_returns_the_denial_without_running_and_awaits_async_handlers(self) -> None:
        kya, _ = runtime()
        ran: List[bool] = []

        def deny() -> None:
            raise RuntimeError("no")

        outcome = run(kya.call(tool_call(), lambda a, c: ran.append(True), authorize=deny))
        assert outcome.outcome == "denied" and ran == []

        async def handler(arguments: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
            return RESULT

        assert RESPONSE_PROOF_META_KEY in run(kya.call(tool_call(), handler)).result["_meta"]

    def test_every_proof_nonce_is_recorded_and_a_collision_retried(self) -> None:
        inserted: List[Tuple[str, Optional[str], float]] = []
        refuse = [2]

        class Store:
            def insert(self, nonce: str, agent_did: Optional[str], expires_at: float) -> bool:
                inserted.append((nonce, agent_did, expires_at))
                if refuse[0] > 0:
                    refuse[0] -= 1
                    return False
                return True

        kya = create_kyaos(KyaOsOptions(signer=SIGNER, nonce_store=Store(), now=lambda: NOW))
        result = run(run_finish(kya))
        proof = result["_meta"][RESPONSE_PROOF_META_KEY]
        assert len(inserted) == 3
        assert [did for _, did, _ in inserted] == [SERVER] * 3
        assert inserted[2][0] == proof["meta"]["nonce"]
        assert inserted[2][2] == proof["meta"]["ts"] + 120 + 1
        assert len({nonce for nonce, _, _ in inserted}) == 3
        refuse[0] = 3
        with pytest.raises(RuntimeError, match="fresh proof nonce"):
            run(run_finish(kya))

    def test_async_stores_are_awaited(self) -> None:
        clock = Clock()

        class AsyncSessions(MemorySessionStore):
            async def create(self, **kwargs: Any) -> Any:  # type: ignore[override]
                return MemorySessionStore.create(self, **kwargs)

            async def get(self, session_id: str, now: float) -> Any:  # type: ignore[override]
                return MemorySessionStore.get(self, session_id, now)

            async def touch(self, session_id: str, now: float) -> Any:  # type: ignore[override]
                return MemorySessionStore.touch(self, session_id, now)

        kya = create_kyaos(
            KyaOsOptions(
                signer=SIGNER, now=clock.now, nonce_store=RedisNonceStore(FakeAsyncRedis(clock.now), now=clock.now),
                session=KyaOsSessionOptions(store=AsyncSessions()),
            )
        )
        args = handshake_args(agentDid=AGENT)
        session_id = run(kya.handshake(args))["sessionId"]
        assert refusal(kya.handshake(args)) == "nonce_replayed"
        assert run(kya.start(tool_call({"_kyaos_session": session_id}))).session.id == session_id

    def test_cross_border_only_the_nonce_and_session_stores_are_touched(self) -> None:
        touched: List[str] = []

        class Store:
            def insert(self, nonce: str, agent_did: Optional[str], expires_at: float) -> bool:
                touched.append(f"nonce:{agent_did}:{expires_at - NOW}")
                return True

        kya = create_kyaos(KyaOsOptions(signer=SIGNER, nonce_store=Store(), now=lambda: NOW))
        handshake = run(kya.handshake(handshake_args(agentDid=AGENT)))
        run(kya.call(tool_call({"_kyaos_session": handshake["sessionId"]}), lambda a, c: RESULT))
        assert touched == [f"nonce:{AGENT}:121.0", f"nonce:{SERVER}:121.0"]
        assert kya.session_store.get(handshake["sessionId"], NOW) is not None


async def run_finish(kya: Any) -> Dict[str, Any]:
    started = await kya.start(tool_call())
    return await started.finish(RESULT)


# ── the gate and the HTTP refusal ────────────────────────────────────────────


class TestGateAuthorize:
    def _options(self) -> MCPMiddlewareOptions:
        def validate(token: str) -> AuthResult:
            if token != "ok":
                raise ValueError("no")
            return AuthResult(sub="agent-1", scopes=["orders:read"])

        return MCPMiddlewareOptions(validate_oauth_token=validate, tool_scopes={"lookup_order": ["orders:read"]})

    def test_sync_gate_resolves_the_identified_caller(self) -> None:
        gate = helixid_mcp_middleware(self._options())
        call = {"name": "lookup_order", "headers": {"authorization": "Bearer ok"}}
        assert gate.authorize(call) == AuthorizedCaller(auth_method="oauth", scopes=["orders:read"], oauth_subject="agent-1")  # type: ignore[attr-defined]
        assert gate(call) is call
        with pytest.raises(HelixError) as caught:
            gate.authorize({"name": "refund_order", "headers": {"authorization": "Bearer ok"}})  # type: ignore[attr-defined]
        assert caught.value.code == "TOOL_NOT_PERMITTED"

    def test_async_gate_resolves_the_identified_caller(self) -> None:
        gate = async_helixid_mcp_middleware(self._options())
        call = {"name": "lookup_order", "headers": {"authorization": "Bearer ok"}}
        assert run(gate.authorize(call)).oauth_subject == "agent-1"  # type: ignore[attr-defined]
        assert run(gate(call)) is call

    def test_a_kyaos_caller_carries_agent_did_level_assurance_and_freshness(self) -> None:
        from types import SimpleNamespace

        class Verifier:
            def verify_call(self, call: Dict[str, Any]) -> Any:
                return SimpleNamespace(ok=True, effective_scopes=["orders:read"], proof_did=AGENT, level="L2", proof_assurance="L3-minus", fresh=True, reasons=[])

        gate = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=Verifier(), tool_scopes={"lookup_order": ["orders:read"]}))
        caller = gate.authorize({"name": "lookup_order", "_meta": {"org.kya-os/request-proof": {"prf": "org.kya-os/proof.v1"}}})  # type: ignore[attr-defined]
        assert caller == AuthorizedCaller(auth_method="kyaos", scopes=["orders:read"], agent_did=AGENT, level="L2", proof_assurance="L3-minus", fresh=True)


class TestHttpRefusalWithProof:
    def test_carries_the_denied_proof_and_maps_a_session_refusal_to_400(self) -> None:
        kya, _ = runtime()
        denied = run(kya.start(tool_call({"_kyaos_session": "sess_x"})))
        assert isinstance(denied.error, KyaOsError)
        assert denied.error.code == KYAOS_REJECTED and denied.error.http_status == 400 and denied.error.details == {"reason": "session_id_malformed"}
        response = to_http_error_response(denied.error, "https://orders.example/.well-known/oauth-protected-resource/mcp", proof=denied.proof)
        assert response is not None and response.status == 400
        assert response.body["error"] == "invalid_request"
        assert "kyaos_<uuid-v4>" in response.body["error_description"]
        assert response.body["_meta"] == {"org.kya-os/response-proof": denied.proof}
        plain = to_http_error_response(denied.error, "x")
        assert plain is not None and set(plain.body) == {"error", "error_description"}
        scope = to_http_error_response(HelixError("INSUFFICIENT_SCOPE", "scope", 403), "x", proof=denied.proof)
        assert scope is not None and scope.body["_meta"] == {"org.kya-os/response-proof": denied.proof}


class TestExports:
    def test_the_package_exports_the_kyaos_layer(self) -> None:
        import helix_mcp_middleware as middleware

        for name in ("create_kyaos", "KyaOsRuntime", "KyaOsOptions", "KyaOsSessionOptions", "KyaOsError", "describe_kyaos",
                     "MemoryNonceStore", "RedisNonceStore", "DynamoNonceStore", "MemorySessionStore", "build_response_proof",
                     "attach_response_proof", "NO_SESSION_ID", "RESPONSE_PROOF_META_KEY", "AuthorizedCaller", "HANDSHAKE_INPUT_SCHEMA"):
            assert name in middleware.__all__, name
            assert hasattr(middleware, name), name
        assert middleware.NO_SESSION_ID == "none"
