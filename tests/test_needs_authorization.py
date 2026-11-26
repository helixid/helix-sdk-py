# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story L3-E: the client side of the signed needs_authorization
challenge and the resume retry, the same checks as helix-sdk-js's
core/kyaos/needs-authorization.ts, driven by the cross-language fixture
helix-sdk-js/fixtures/kya-os-helix/needs-authorization.json read from the
sibling checkout (or HELIX_SDK_JS_FIXTURES_DIR)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from helix_sdk import needs_authorization as na
from helix_sdk import response_proof as rp
from helix_sdk.crypto.jws import EnvSigner, sign_jws
from helix_sdk.did import build_did_document
from helix_sdk.errors import InvalidJWSError, NeedsAuthorizationError, ResponseProofError
from helix_sdk.keys import generate_key_pair

FIXTURES_DIR = Path(os.environ.get("HELIX_SDK_JS_FIXTURES_DIR") or Path(__file__).resolve().parents[2] / "helix-sdk-js" / "fixtures")
FIXTURE = FIXTURES_DIR / "kya-os-helix" / "needs-authorization.json"


def _fixture() -> Optional[Dict[str, Any]]:
    if not FIXTURE.is_file():
        return None
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)


FIXTURE_DATA = _fixture()
CASES: List[Dict[str, Any]] = FIXTURE_DATA["cases"] if FIXTURE_DATA else []

# ── a service of this test's own, for the cases the fixture does not cover ────

SERVER = "did:web:orders.example"
AGENT = "did:key:z6Mkagent"
NOW = 1_750_000_000
KEYS = generate_key_pair()
SIGNER = EnvSigner(SERVER, env_var="K", env={"K": KEYS.private_key})
DOCUMENT = build_did_document(SERVER, KEYS.public_key)
CALL = {"name": "refund_order", "arguments": {"orderId": "ORD-1001", "reason": "damaged"}}
REQUEST = {"method": "tools/call", "params": {**CALL, "_meta": {"traceparent": "t"}}}
CHALLENGE = {
    "error": "needs_authorization",
    "message": "refund_order requires delegation with scope: orders:admin",
    "authorizationUrl": "https://consent.example/authorize?tool=refund_order",
    "resumeToken": "uGb3QKq4D1yXj0r9ZaN2Pw8vLcE5tHsM6nRkF7oJiAw",
    "expiresAt": NOW + 600,
    "scopes": ["orders:admin"],
    "display": {"title": "Orders", "hint": ["link"]},
}
HOP = {"type": ["VerifiableCredential", "DelegationCredential"], "credentialSubject": {"invoker": AGENT, "invocationTarget": SERVER, "allowedAction": ["orders:admin"]}, "proof": {"type": "DataIntegrityProof"}}


def resolve_did(did: str) -> Optional[Dict[str, Any]]:
    return DOCUMENT if did == SERVER else None


def tool_result(challenge: Any) -> Dict[str, Any]:
    return {"isError": True, "content": [{"type": "text", "text": json.dumps(challenge, separators=(",", ":"))}], "structuredContent": challenge}


def signed(body: Dict[str, Any], outcome: str = "needs_authorization", request: Any = REQUEST, signer: EnvSigner = SIGNER) -> Dict[str, Any]:
    meta = {
        "did": SERVER,
        "kid": f"{SERVER}#key-1",
        "ts": NOW,
        "nonce": "b6VZmm9hXn-otOETBkvlvQ",
        "audience": SERVER,
        "sessionId": "none",
        "requestHash": rp.hash_request(request),
        "responseHash": rp.hash_response(body, rp.RESPONSE_PROOF_ENVELOPE_PROFILE),
        "outcome": outcome,
        "clientDid": AGENT,
        "prf": rp.RESPONSE_PROOF_ENVELOPE_PROFILE,
    }
    return {**body, "_meta": {rp.RESPONSE_PROOF_META_KEY: {"jws": sign_jws(rp.proof_payload(meta), signer), "meta": meta}}}


def reason_of(run: Any) -> str:
    try:
        run()
    except (ResponseProofError, InvalidJWSError, NeedsAuthorizationError) as error:
        return error.reason
    return "ok"


# ── the cross-language fixture ────────────────────────────────────────────────


class TestFixture:
    def test_fixture_present(self) -> None:
        if FIXTURE_DATA is None:
            pytest.skip(f"{FIXTURE} is missing: check out helix-sdk-js beside this repo or set HELIX_SDK_JS_FIXTURES_DIR")
        assert len(CASES) == 17
        assert FIXTURE_DATA["service"]["did"] == "did:web:orders.example"

    @pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
    def test_case(self, case: Dict[str, Any]) -> None:
        assert FIXTURE_DATA is not None
        service = FIXTURE_DATA["service"]
        documents = {service["did"]: service["didDocument"]}
        now = FIXTURE_DATA["now"] / 1000
        expected = case["expected"]
        try:
            handled = na.handle_needs_authorization(case["response"], service["did"], documents.get, request=FIXTURE_DATA["request"], now=now)
        except (ResponseProofError, InvalidJWSError, NeedsAuthorizationError) as error:
            assert expected == {"ok": False, "reason": error.reason}, case["name"]
            return
        assert expected["ok"] is True, case["name"]
        assert handled.challenge.to_dict() == expected["challenge"]
        assert handled.proof.outcome == "needs_authorization"
        assert handled.proof.response_hash == rp.hash_response(case["response"], rp.RESPONSE_PROOF_ENVELOPE_PROFILE)

    def test_retry_params(self) -> None:
        if FIXTURE_DATA is None:
            pytest.skip("fixture missing")
        retry = FIXTURE_DATA["retry"]
        assert na.with_resume(retry["call"], retry["resumeToken"], retry["hop"]) == retry["params"]


# ── handle_needs_authorization ────────────────────────────────────────────────


class TestHandle:
    def test_verifies_before_reading(self) -> None:
        valid = signed(tool_result(CHALLENGE))
        handled = na.handle_needs_authorization(valid, SERVER, resolve_did, request=REQUEST, now=NOW)
        assert handled.challenge.to_dict() == CHALLENGE
        assert handled.challenge.authorization_url == CHALLENGE["authorizationUrl"]
        assert handled.challenge.resume_token == CHALLENGE["resumeToken"]
        assert handled.proof.outcome == "needs_authorization"
        tampered = {**valid, "structuredContent": {**CHALLENGE, "authorizationUrl": "https://evil.example/authorize"}}
        with pytest.raises(ResponseProofError) as caught:
            na.handle_needs_authorization(tampered, SERVER, resolve_did, request=REQUEST, now=NOW)
        assert caught.value.reason == "response_hash_mismatch"
        assert reason_of(lambda: na.handle_needs_authorization(valid, "did:web:other.example", resolve_did, request=REQUEST, now=NOW)) == "proof_signer_mismatch"
        assert reason_of(lambda: na.handle_needs_authorization(valid, SERVER, lambda _did: None, request=REQUEST, now=NOW)) == "jws_did_unresolved"
        assert reason_of(lambda: na.handle_needs_authorization(valid, SERVER, resolve_did, request=REQUEST, now=NOW + 121)) == "proof_timestamp_skew"
        assert reason_of(lambda: na.handle_needs_authorization(valid, SERVER, resolve_did, request=REQUEST, now=NOW + 121, skew_seconds=600)) == "ok"
        assert reason_of(lambda: na.handle_needs_authorization(tool_result(CHALLENGE), SERVER, resolve_did, request=REQUEST, now=NOW)) == "proof_missing"

    def test_outcome_and_expiry(self) -> None:
        allowed = signed({"content": [{"type": "text", "text": "x"}]}, outcome="allowed")
        with pytest.raises(NeedsAuthorizationError) as caught:
            na.handle_needs_authorization(allowed, SERVER, resolve_did, request=REQUEST, now=NOW)
        assert caught.value.reason == na.ChallengeReasons.OUTCOME_MISMATCH
        assert caught.value.code == "NEEDS_AUTHORIZATION_INVALID"
        assert caught.value.details == {"reason": "challenge_outcome_mismatch"}
        assert NeedsAuthorizationError("x").message == "needs_authorization challenge is invalid"
        short = signed(tool_result({**CHALLENGE, "expiresAt": NOW + 1}))
        assert na.handle_needs_authorization(short, SERVER, resolve_did, request=REQUEST, now=NOW).challenge.expires_at == NOW + 1
        assert reason_of(lambda: na.handle_needs_authorization(short, SERVER, resolve_did, request=REQUEST, now=NOW + 1)) == "challenge_expired"
        # The challenge at the top level of the body is read too.
        top = signed(dict(CHALLENGE))
        assert na.handle_needs_authorization(top, SERVER, resolve_did, request=REQUEST, now=NOW).challenge.scopes == ["orders:admin"]


# ── read_challenge ────────────────────────────────────────────────────────────


class TestReadChallenge:
    def test_finds_the_challenge(self) -> None:
        assert na.find_challenge(CHALLENGE) is CHALLENGE
        assert na.find_challenge(tool_result(CHALLENGE)) is not None
        assert na.find_challenge({"content": []}) is None
        assert na.find_challenge({"structuredContent": "x"}) is None
        assert na.find_challenge("needs_authorization") is None
        assert na.is_needs_authorization(tool_result(CHALLENGE)) is True
        assert na.is_needs_authorization({"error": "denied"}) is False
        read = na.read_challenge(tool_result(CHALLENGE), now=NOW)
        assert read.to_dict() == CHALLENGE
        assert read.display == {"title": "Orders", "hint": ["link"]}
        assert na.read_challenge({**CHALLENGE, "display": None}, now=NOW).display is None
        assert "display" not in na.read_challenge({k: v for k, v in CHALLENGE.items() if k != "display"}, now=NOW).to_dict()
        full = na.read_challenge({**CHALLENGE, "display": {"title": "T", "authorizationCode": "ABCD", "qrUrl": "https://q", "hint": ["qr", "code"]}}, now=NOW)
        assert full.display == {"title": "T", "authorizationCode": "ABCD", "qrUrl": "https://q", "hint": ["qr", "code"]}
        assert na.read_challenge({**CHALLENGE, "display": {}}, now=NOW).display == {}
        assert na.read_challenge({**CHALLENGE, "authorizationUrl": "http://localhost:3700/authorize"}, now=NOW).authorization_url == "http://localhost:3700/authorize"
        assert na.read_challenge({**CHALLENGE, "expiresAt": 2_000_000_000}).scopes == ["orders:admin"]

    @pytest.mark.parametrize(
        "patch, reason",
        [
            ({"message": 1}, "challenge_malformed"),
            ({"authorizationUrl": ""}, "authorization_url_invalid"),
            ({"authorizationUrl": "not a url"}, "authorization_url_invalid"),
            ({"authorizationUrl": "/authorize"}, "authorization_url_invalid"),
            ({"authorizationUrl": "ftp://consent.example"}, "authorization_url_invalid"),
            ({"authorizationUrl": "javascript:alert(1)"}, "authorization_url_invalid"),
            ({"resumeToken": 5}, "challenge_malformed"),
            ({"resumeToken": ""}, "challenge_malformed"),
            ({"expiresAt": "2026-01-01T00:00:00Z"}, "challenge_malformed"),
            ({"expiresAt": 1.5}, "challenge_malformed"),
            ({"expiresAt": True}, "challenge_malformed"),
            ({"expiresAt": 0}, "challenge_malformed"),
            ({"scopes": "orders:admin"}, "challenge_malformed"),
            ({"scopes": ["orders:admin", 1]}, "challenge_malformed"),
            ({"display": "x"}, "challenge_malformed"),
            ({"display": {"title": 1}}, "challenge_malformed"),
            ({"display": {"qrUrl": 1}}, "challenge_malformed"),
            ({"display": {"hint": "link"}}, "challenge_malformed"),
            ({"display": {"hint": ["popup"]}}, "challenge_malformed"),
            ({"expiresAt": NOW}, "challenge_expired"),
        ],
    )
    def test_refuses_malformed(self, patch: Dict[str, Any], reason: str) -> None:
        assert reason_of(lambda: na.read_challenge({**CHALLENGE, **patch}, now=NOW)) == reason

    def test_missing(self) -> None:
        assert reason_of(lambda: na.read_challenge({"error": "denied"}, now=NOW)) == "challenge_missing"


# ── retry_with_resume ─────────────────────────────────────────────────────────


class TestRetry:
    def test_with_resume(self) -> None:
        token = CHALLENGE["resumeToken"]
        params = na.with_resume(CALL, token, HOP)
        assert params == {"name": "refund_order", "arguments": {"orderId": "ORD-1001", "reason": "damaged", "_kyaos_resume": token, "_kyaos_delegation": HOP}}
        assert na.with_resume({"name": "x"}, "t", HOP)["arguments"] == {"_kyaos_resume": "t", "_kyaos_delegation": HOP}
        assert na.with_resume({"name": "x", "_meta": {"k": 1}}, "t", HOP)["_meta"] == {"k": 1}
        with pytest.raises(TypeError):
            na.with_resume(CALL, "", HOP)
        with pytest.raises(TypeError):
            na.with_resume(CALL, token, None)

    def test_retry_sends_and_verifies(self) -> None:
        token = CHALLENGE["resumeToken"]
        params = na.with_resume(CALL, token, HOP)
        body = {"content": [{"type": "text", "text": '{"id":"ORD-1001","status":"refunded"}'}]}
        # The server signs over the covered request: control arguments are not part of it.
        answer = signed(body, outcome="allowed", request={"method": "tools/call", "params": CALL})
        sent: List[Dict[str, Any]] = []

        def send(p: Dict[str, Any]) -> Any:
            sent.append(p)
            return answer

        retried = na.retry_with_resume(token, HOP, call=CALL, send=send, service_did=SERVER, resolve_did=resolve_did, now=NOW)
        assert sent == [params]
        assert retried.params == params
        assert retried.response is answer
        assert retried.proof is not None and retried.proof.outcome == "allowed"
        assert retried.proof.request_hash == rp.hash_request({"method": "tools/call", "params": CALL})
        plain = na.retry_with_resume(token, HOP, call=CALL, send=lambda _p: body)
        assert plain.proof is None and plain.response is body and plain.params == params
        swapped = {**answer, "content": [{"type": "text", "text": "swapped"}]}
        with pytest.raises(ResponseProofError) as caught:
            na.retry_with_resume(token, HOP, call=CALL, send=lambda _p: swapped, service_did=SERVER, resolve_did=resolve_did, now=NOW, skew_seconds=120)
        assert caught.value.reason == "response_hash_mismatch"
        with pytest.raises(ResponseProofError) as missing:
            na.retry_with_resume(token, HOP, call=CALL, send=lambda _p: tool_result(CHALLENGE), service_did=SERVER, resolve_did=resolve_did, now=NOW)
        assert missing.value.reason == "proof_missing"
