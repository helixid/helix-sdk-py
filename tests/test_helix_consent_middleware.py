# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""KYA-OS story L3-H in the middleware (parity with helix-sdk-js's helix-consent tests): the challenge's
authorizationUrl is a consent request at Helix, and a retry's credential is verified in full by the local
verifier before it grants anything."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from helix_mcp_middleware import (
    ChallengeContext,
    ChallengeInput,
    ConsentUserUnknownError,
    MemoryResumeTokenStore,
    NeedsAuthorizationOptions,
    RetryAuthorizerInput,
    consent_retry_authorizer,
    create_helix_consent,
    create_needs_authorization,
)
from helix_mcp_middleware.resume_token_store import ResumeTokenRecord
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.errors import ConsentFlowError
from helix_sdk.keys import generate_key_pair

HELIX = "https://helix.example"
SERVICE = "did:web:shop.example:services:aa"
AGENT = "did:web:helix.example:agents:bb"
SIGNER = EnvSigner(did=SERVICE, env_var="K", env={"K": generate_key_pair().private_key})


class Response:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code = status
        self._body = body

    def json(self) -> Any:
        return self._body


class FakeHelix:
    def __init__(self, status: int = 201) -> None:
        self.status = status
        self.requests: List[str] = []

    def post(self, url: str, json: Any = None, timeout: float = 0) -> Response:
        self.requests.append(json["request"])
        if url.endswith("/withdrawals"):
            return Response(200, {"consentId": "c1", "withdrawn": ["c1"], "userDid": "did:key:z", "revoked": []})
        if self.status >= 300:
            return Response(self.status, {"error": {"code": "X"}})
        return Response(201, {"id": "abc", "authorizationUrl": f"{HELIX}/consent/abc", "resultUrl": "", "expiresAt": 1, "status": "pending"})


def claims(jws: str) -> Dict[str, Any]:
    part = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


CONTEXT = ChallengeContext(agent_did=AGENT, tool="list_orders", scopes=["orders:read"])


def details(**extra: Any) -> ChallengeInput:
    return ChallengeInput(agent_did=AGENT, tool="list_orders", scopes=["orders:read"], **extra)


def test_creates_a_consent_request_per_challenge_for_the_caller() -> None:
    helix = FakeHelix()
    now = [1_795_000_000.0]
    consent = create_helix_consent(HELIX, SERVICE, SIGNER, 3600, hop_lifetime_seconds=300, display={"serviceName": "Shop"}, return_url="https://shop.example/back", http=helix, now=lambda: now[0])
    assert consent.authorization_url(CONTEXT, details(oauth_subject="user-7")) == f"{HELIX}/consent/abc"
    body = claims(helix.requests[0])
    assert body["iss"] == SERVICE and body["serviceUserId"] == "user-7" and body["hopLifetimeSeconds"] == 300
    assert body["display"] == {"serviceName": "Shop"} and body["returnUrl"] == "https://shop.example/back"
    assert body["grant"]["credentialSubject"] == {"invoker": AGENT, "invocationTarget": SERVICE, "parentCapability": SERVICE, "allowedAction": ["orders:read"]}
    assert body["grant"]["validUntil"] == "2026-11-18T12:06:40.000Z"
    plain = create_helix_consent(HELIX, SERVICE, SIGNER, 60, service_user_of=lambda d: "u-9", http=helix)
    plain.authorization_url(CONTEXT, details())
    assert claims(helix.requests[1])["serviceUserId"] == "u-9" and "hopLifetimeSeconds" not in claims(helix.requests[1])
    assert plain.withdraw("c1")["consentId"] == "c1"
    assert claims(helix.requests[2])["consentId"] == "c1"


def test_refuses_nobody_a_wrong_signer_a_bad_window_and_relays_refusals() -> None:
    consent = create_helix_consent(HELIX, SERVICE, SIGNER, 60, http=FakeHelix())
    with pytest.raises(ConsentUserUnknownError):
        consent.authorization_url(CONTEXT, details())
    with pytest.raises(ValueError, match="signer"):
        create_helix_consent(HELIX, "did:web:other", SIGNER, 60)
    for window in (0, True, float("inf"), "60"):
        with pytest.raises(ValueError, match="window_seconds"):
            create_helix_consent(HELIX, SERVICE, SIGNER, window)  # type: ignore[arg-type]
    with pytest.raises(ConsentFlowError) as error:
        create_helix_consent(HELIX, SERVICE, SIGNER, 60, http=FakeHelix(403)).authorization_url(CONTEXT, details(oauth_subject="u"))
    assert error.value.reason == "consent_request_refused"


def test_puts_the_consent_page_in_the_signed_challenge() -> None:
    consent = create_helix_consent(HELIX, SERVICE, SIGNER, 60, http=FakeHelix())
    layer = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=consent.authorization_url, store=MemoryResumeTokenStore()))
    challenge = layer.challenge(agent_did=AGENT, tool="list_orders", scopes=["orders:read"], oauth_subject="user-1")
    assert challenge.challenge["authorizationUrl"] == f"{HELIX}/consent/abc"
    one_arg = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=lambda c: f"{HELIX}/static?agent={c.agent_did}", store=MemoryResumeTokenStore()))
    assert "agent=" in one_arg.challenge(agent_did=AGENT, tool="t", scopes=["a"]).challenge["authorizationUrl"]
    star = create_needs_authorization(NeedsAuthorizationOptions(authorization_url=lambda *args: f"{HELIX}/x?n={len(args)}", store=MemoryResumeTokenStore()))
    assert star.challenge(agent_did=AGENT, tool="t", scopes=["a"]).challenge["authorizationUrl"].endswith("n=2")

    class Odd:
        __signature__ = None

        def __call__(self, context: ChallengeContext) -> str:
            return f"{HELIX}/odd"

    odd = Odd()
    import inspect as _inspect

    original = _inspect.signature
    try:
        _inspect.signature = lambda f: (_ for _ in ()).throw(ValueError("no signature"))  # type: ignore[assignment]
        assert create_needs_authorization(NeedsAuthorizationOptions(authorization_url=odd, store=MemoryResumeTokenStore())).challenge(agent_did=AGENT, tool="t", scopes=["a"]).challenge["authorizationUrl"] == f"{HELIX}/odd"
    finally:
        _inspect.signature = original  # type: ignore[assignment]


TOKEN = ResumeTokenRecord(agent_did=AGENT, tool="list_orders", scopes=["orders:read"], expires_at=0)


def result(**overrides: Any) -> SimpleNamespace:
    return SimpleNamespace(**{"ok": True, "agent_did": AGENT, "effective_scopes": ["orders:read"], "reasons": [], **overrides})


def test_retry_authorizer_verifies_with_the_local_verifier() -> None:
    calls: List[Dict[str, Any]] = []

    class Verifier:
        def verify(self, proof: Any, **kwargs: Any) -> SimpleNamespace:
            calls.append({"proof": proof, **kwargs})
            return result()

    authorize = consent_retry_authorizer(Verifier())
    granted = authorize(RetryAuthorizerInput(credential={"id": "hop"}, token=TOKEN, agent_did=AGENT, tool="list_orders", scopes=["orders:read"]))
    assert granted.scopes == ["orders:read"]
    assert calls[0] == {"proof": None, "chain": [{"id": "hop"}], "require_proof": False, "live_status": True}
    authorize(RetryAuthorizerInput(credential=[{"id": "root"}, {"id": "leaf"}], token=TOKEN, agent_did=AGENT, tool="t", scopes=[]))
    assert calls[1]["chain"] == [{"id": "root"}, {"id": "leaf"}]


def test_retry_authorizer_refuses() -> None:
    class Refusing:
        def __init__(self, answer: SimpleNamespace) -> None:
            self.answer = answer

        def verify(self, proof: Any, **kwargs: Any) -> SimpleNamespace:
            return self.answer

    with pytest.raises(ValueError, match="status_revoked"):
        consent_retry_authorizer(Refusing(result(ok=False, reasons=["status_revoked"])))(RetryAuthorizerInput(credential={}, token=TOKEN, agent_did=AGENT, tool="t", scopes=[]))
    with pytest.raises(ValueError, match="not did:web"):
        consent_retry_authorizer(Refusing(result(agent_did="did:web:other")))(RetryAuthorizerInput(credential={}, token=TOKEN, agent_did=AGENT, tool="t", scopes=[]))
