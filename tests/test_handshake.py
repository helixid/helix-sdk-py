# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story L2-A: the session handshake, client side and shared format
rules (L2.2, L2.6, L2.7, L2.9, L2.14, L2.15), the same cases as helix-sdk-js's
tests/unit/kyaos/handshake.test.ts; and the helix_sdk.kyaos namespace."""

from __future__ import annotations

import re
import time
from typing import Any

import pytest

import helix_sdk
from helix_sdk import handshake as hs
from helix_sdk import kyaos
from helix_sdk import response_proof

AUDIENCE = "did:web:orders.example"
GOOD = {"nonce": "k7Hy9mNpQrStUvWxYz01Aa", "audience": AUDIENCE, "timestamp": 1_710_268_800}


class TestConstants:
    def test_names_and_defaults(self) -> None:
        assert hs.HANDSHAKE_TOOL_NAME == "_kyaos_handshake"
        assert hs.SESSION_CONTROL_ARGUMENT == "_kyaos_session"
        assert hs.SESSION_ID_PREFIX == "kyaos_"
        assert hs.PROTOCOL_VERSION == "1.0"
        assert hs.NONCE_MIN_LENGTH == 22
        assert hs.NONCE_BYTES == 16
        assert (hs.DEFAULT_CLOCK_SKEW_SECONDS, hs.MIN_CLOCK_SKEW_SECONDS, hs.MAX_CLOCK_SKEW_SECONDS) == (120, 30, 600)
        assert hs.DEFAULT_SESSION_TTL_MINUTES == 30


class TestNonces:
    def test_generates_22_char_base64url_unique(self) -> None:
        seen = set()
        for _ in range(200):
            nonce = hs.generate_nonce()
            assert re.fullmatch(r"[A-Za-z0-9_-]{22}", nonce)
            assert hs.is_valid_nonce(nonce)
            seen.add(nonce)
        assert len(seen) == 200
        assert hs.generate_nonce(lambda size: bytes(size)) == "AAAAAAAAAAAAAAAAAAAAAA"

    @pytest.mark.parametrize(
        "value",
        ["k7Hy9mNpQrStUvWxYz01A", "", "k7Hy9mNpQrStUvWxYz01Aa==", "k7Hy9mNpQrStUvWxYz01A+", "k7Hy9mNpQrStUvWxYz01 a",
         "k7Hy9mNpQrStUvWxYz01AaBBB", "k7Hy9mNpQrStUvWxYz01Aa\n", 42, None, ["k7Hy9mNpQrStUvWxYz01Aa"]],
    )
    def test_refuses_anything_but_strict_base64url_of_22_or_more(self, value: Any) -> None:
        assert hs.is_valid_nonce(value) is False

    def test_accepts_longer_nonces(self) -> None:
        assert hs.is_valid_nonce("k7Hy9mNpQrStUvWxYz01Aa")
        assert hs.is_valid_nonce("k7Hy9mNpQrStUvWxYz01AaBBBB")


class TestSessionIds:
    def test_kyaos_uuid_v4(self) -> None:
        session_id = hs.generate_session_id()
        assert re.fullmatch(r"kyaos_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", session_id)
        assert hs.is_session_id(session_id)
        assert hs.generate_session_id(lambda: "11111111-2222-4333-8444-555555555555") == "kyaos_11111111-2222-4333-8444-555555555555"
        assert hs.generate_session_id() != hs.generate_session_id()

    @pytest.mark.parametrize(
        "value", ["sess_abc", "kyaos_", "kyaos_not-a-uuid", "kyaos_11111111-2222-1333-8444-555555555555",
                  "kyaos_11111111-2222-4333-8444-555555555555\n", 7, None],
    )
    def test_refuses_other_ids(self, value: Any) -> None:
        assert hs.is_session_id(value) is False


class TestSkew:
    def test_default_and_range(self) -> None:
        assert hs.clock_skew_seconds() == 120
        assert hs.clock_skew_seconds(None) == 120
        assert hs.clock_skew_seconds(30) == 30
        assert hs.clock_skew_seconds(600) == 600
        for bad in (29, 601, 0, -120, 120.5, True, "120"):
            with pytest.raises(ValueError):
                hs.clock_skew_seconds(bad)  # type: ignore[arg-type]

    def test_within_skew_is_inclusive(self) -> None:
        assert hs.within_skew(1000, 1120, 120)
        assert hs.within_skew(1000, 880, 120)
        assert not hs.within_skew(1000, 1121, 120)
        assert not hs.within_skew(1000, 879, 120)
        assert hs.within_skew(1000, 1000, 0)


class TestCreateHandshakeRequest:
    def test_uses_the_current_timestamp_a_fresh_nonce_and_the_version(self) -> None:
        before = int(time.time())
        request = hs.create_handshake_request(audience=AUDIENCE)
        after = int(time.time())
        assert before <= request["timestamp"] <= after
        assert hs.is_valid_nonce(request["nonce"])
        assert request == {"nonce": request["nonce"], "audience": AUDIENCE, "timestamp": request["timestamp"], "clientProtocolVersion": "1.0"}
        assert hs.validate_handshake_format(request) == hs.HandshakeFormatResult(ok=True, request=request)

    def test_takes_a_fixed_clock_nonce_agent_client_info_and_capabilities(self) -> None:
        request = hs.create_handshake_request(
            audience=AUDIENCE, now=1_750_000_000.999, nonce="k7Hy9mNpQrStUvWxYz01Aa", agent_did="did:key:z6Mkagent",
            client_info={"name": "e2e", "version": "1"}, client_capabilities={"proofs": True},
        )
        assert request == {
            "nonce": "k7Hy9mNpQrStUvWxYz01Aa", "audience": AUDIENCE, "timestamp": 1_750_000_000, "agentDid": "did:key:z6Mkagent",
            "clientInfo": {"name": "e2e", "version": "1"}, "clientProtocolVersion": "1.0", "clientCapabilities": {"proofs": True},
        }
        assert hs.validate_handshake_format(request).ok


class TestValidateHandshakeFormat:
    def test_accepts_the_schema_example_and_the_minimal_request(self) -> None:
        assert hs.validate_handshake_format(GOOD) == hs.HandshakeFormatResult(ok=True, request=GOOD)
        example = {**GOOD, "agentDid": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "clientProtocolVersion": "1.0"}
        assert hs.validate_handshake_format(example).request == example
        assert hs.validate_handshake_format({**GOOD, "agentDid": "did:hedera:testnet:z6Mk_0.0.1"}).ok
        assert hs.validate_handshake_format({**GOOD, "timestamp": 0}).ok

    def test_a_whole_float_timestamp_is_the_same_value_as_in_js(self) -> None:
        result = hs.validate_handshake_format({**GOOD, "timestamp": 1_710_268_800.0})
        assert result.ok and result.request is not None and result.request["timestamp"] == 1_710_268_800
        assert isinstance(result.request["timestamp"], int)

    @pytest.mark.parametrize(
        "value,problem",
        [
            ("nonce", "request_not_object"),
            (None, "request_not_object"),
            ([GOOD], "request_not_object"),
            ({**GOOD, "extra": 1}, "unknown_member"),
            ({**GOOD, "nonce": "k7Hy9mNpQrStUvWxYz01A"}, "nonce_invalid"),
            ({**GOOD, "nonce": "k7Hy9mNpQrStUvWxYz01Aa=="}, "nonce_invalid"),
            ({"audience": AUDIENCE, "timestamp": 1}, "nonce_invalid"),
            ({**GOOD, "nonce": 12345678901234567890123}, "nonce_invalid"),
            ({**GOOD, "audience": ""}, "audience_invalid"),
            ({"nonce": GOOD["nonce"], "timestamp": 1}, "audience_invalid"),
            ({**GOOD, "audience": ["did:web:x"]}, "audience_invalid"),
            ({"nonce": GOOD["nonce"], "audience": AUDIENCE}, "timestamp_invalid"),
            ({**GOOD, "timestamp": "1710268800"}, "timestamp_invalid"),
            ({**GOOD, "timestamp": 1710268800.5}, "timestamp_invalid"),
            ({**GOOD, "timestamp": -1}, "timestamp_invalid"),
            ({**GOOD, "timestamp": True}, "timestamp_invalid"),
            ({**GOOD, "agentDid": "agent-1"}, "agent_did_invalid"),
            ({**GOOD, "agentDid": 7}, "agent_did_invalid"),
            ({**GOOD, "agentDid": "did:web:"}, "agent_did_invalid"),
            ({**GOOD, "agentDid": None}, "agent_did_invalid"),
            ({**GOOD, "agentDid": "did:web:x\n"}, "agent_did_invalid"),
            ({**GOOD, "clientInfo": "cli"}, "client_info_invalid"),
            ({**GOOD, "clientInfo": None}, "client_info_invalid"),
            ({**GOOD, "clientInfo": {"version": "1"}}, "client_info_invalid"),
            ({**GOOD, "clientInfo": {"name": "x", "extra": "y"}}, "client_info_invalid"),
            ({**GOOD, "clientInfo": {"name": "x", "version": 1}}, "client_info_invalid"),
            ({**GOOD, "clientProtocolVersion": "v1"}, "client_protocol_version_invalid"),
            ({**GOOD, "clientProtocolVersion": 1}, "client_protocol_version_invalid"),
            ({**GOOD, "clientProtocolVersion": None}, "client_protocol_version_invalid"),
            ({**GOOD, "clientCapabilities": []}, "client_capabilities_invalid"),
            ({**GOOD, "clientCapabilities": None}, "client_capabilities_invalid"),
        ],
    )
    def test_refuses(self, value: Any, problem: str) -> None:
        result = hs.validate_handshake_format(value)
        assert result.ok is False
        assert result.problem == problem
        assert result.message

    def test_is_did(self) -> None:
        assert hs.is_did("did:web:x")
        assert hs.is_did("did:key:z6Mk")
        assert hs.is_did("did:hedera:testnet:abc_0.0.1")
        assert not hs.is_did("did:WEB:x")
        assert not hs.is_did("http://x")
        assert not hs.is_did(1)


class TestNamespace:
    def test_helix_sdk_kyaos_carries_the_same_objects(self) -> None:
        assert helix_sdk.kyaos is kyaos
        assert kyaos.create_handshake_request is hs.create_handshake_request
        assert kyaos.verify_response_proof is response_proof.verify_response_proof
        assert kyaos.hash_request is response_proof.hash_request
        assert kyaos.ResponseProofError is helix_sdk.ResponseProofError
        assert all(hasattr(kyaos, name) for name in kyaos.__all__)
        # The JS kyaos namespace's names, in Python style.
        for name in ("canonicalize", "hash_json", "sign_jws", "verify_jws", "verify_jws_by_kid", "EnvSigner", "JwsReasons",
                     "generate_nonce", "validate_handshake_format", "verify_detached_proof", "ProofReasons", "proof_payload"):
            assert name in kyaos.__all__, name


class TestResolverObjects:
    """verify_response_proof takes a resolver function or, as helix-sdk-js takes
    an IDidResolver, an object with resolve(did)."""

    def _proof(self) -> Any:
        from helix_sdk.did import build_did_document
        from helix_sdk.keys import generate_key_pair

        keys = generate_key_pair()
        signer = kyaos.EnvSigner(AUDIENCE, env_var="K", env={"K": keys.private_key})
        request = {"method": "tools/call", "params": {"name": "echo", "arguments": {}}}
        meta = {"did": AUDIENCE, "kid": f"{AUDIENCE}#key-1", "ts": 1_750_000_000, "nonce": "b6VZmm9hXn-otOETBkvlvQ",
                "audience": AUDIENCE, "sessionId": "none", "requestHash": kyaos.hash_request(request), "outcome": "denied"}
        proof = {"jws": kyaos.sign_jws(kyaos.proof_payload(meta), signer), "meta": meta}
        return proof, request, build_did_document(AUDIENCE, keys.public_key)

    def test_resolution_results_and_plain_documents(self) -> None:
        proof, request, document = self._proof()

        class Result:
            def __init__(self, doc: Any) -> None:
                self.did_document = doc

        for answer in ({"didDocument": document}, {"did_document": document}, Result(document), document):
            resolver = type("R", (), {"resolve": lambda self, did, a=answer: a})()
            verified = kyaos.verify_response_proof({}, AUDIENCE, resolver, request=request, proof=proof, now=1_750_000_000)
            assert verified.outcome == "denied"
        nothing = type("R", (), {"resolve": lambda self, did: {"didDocument": None}})()
        with pytest.raises(kyaos.InvalidJWSError) as caught:
            kyaos.verify_response_proof({}, AUDIENCE, nothing, request=request, proof=proof, now=1_750_000_000)
        assert caught.value.reason == "jws_did_unresolved"
        with pytest.raises(TypeError):
            kyaos.verify_response_proof({}, AUDIENCE, object(), request=request, proof=proof, now=1_750_000_000)  # type: ignore[arg-type]
