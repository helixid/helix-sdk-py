# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""KYA-OS story L3-H, the SDK's side (parity with helix-sdk-js's kyaos.consent tests): consent requests and
withdrawals (service), the signed root hop and its renewal inside the window (agent), against a stand-in for
Helix's consent API that signs real hops with a did:key."""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

import pytest

from helix_sdk import kyaos
from helix_sdk.consent import (
    CONSENT_RENEWAL_TYP,
    CONSENT_REQUEST_TYP,
    CONSENT_WITHDRAWAL_TYP,
    ConsentHopKeeper,
    await_consent_hop,
    consent_result_url,
    create_consent_request,
    fetch_consent_result,
    helix_url_of,
    renew_before,
    renew_consent_hop,
    unsigned_root_grant,
    verify_consent_hop,
    withdraw_consent,
)
from helix_sdk.credential_store import CredentialStore, sign_attestation_document
from helix_sdk.crypto.jws import EnvSigner, read_jws_header, verify_jws_by_kid
from helix_sdk.errors import ConsentFlowError
from helix_sdk.keys import generate_key_pair, public_key_to_multibase
from helix_sdk.verifier.resolve import did_key_document

HELIX = "https://helix.example"
SERVICE = "did:web:shop.example:services:aa"
AGENT = "did:web:helix.example:agents:bb"


def did_key_signer() -> EnvSigner:
    keys = generate_key_pair()
    return EnvSigner(did=f"did:key:{public_key_to_multibase(keys.public_key)}", env_var="K", env={"K": keys.private_key})


USER = did_key_signer()
AGENT_SIGNER = EnvSigner(did=AGENT, env_var="K", env={"K": generate_key_pair().private_key})
SERVICE_SIGNER = EnvSigner(did=SERVICE, env_var="K", env={"K": generate_key_pair().private_key})
_counter = [0]


def iso(seconds_from_now: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def hop(issuer: EnvSigner = USER, invoker: str = AGENT, target: str = SERVICE, valid_for: float = 3600, parent: Optional[str] = None, allowed: Optional[List[str]] = None) -> Dict[str, Any]:
    _counter[0] += 1
    hop_id = f"urn:zcap:{_counter[0]}"
    return sign_attestation_document(
        {
            "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/zcap/v1", "https://kya-os.org/ns/delegation/v1"],
            "id": hop_id,
            "type": ["VerifiableCredential", "DelegationCredential"],
            "issuer": issuer.did,
            "validUntil": iso(valid_for),
            "credentialSubject": {"id": hop_id, "invoker": invoker, "parentCapability": parent or target, "invocationTarget": target, "allowedAction": allowed or ["orders:read"]},
            "credentialStatus": {"type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": "0", "statusListCredential": f"{HELIX}/v1/status-list/x"},
        },
        issuer,
        iso(0),
    )


class Response:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code = status
        self._body = body

    def json(self) -> Any:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeHelix:
    """``requests``-shaped: routes keyed by ``"<METHOD> <url>"``."""

    def __init__(self, routes: Dict[str, Callable[[Optional[Dict[str, Any]]], Response]]) -> None:
        self.routes = routes
        self.calls: List[Dict[str, Any]] = []

    def _answer(self, method: str, url: str, body: Optional[Dict[str, Any]]) -> Response:
        self.calls.append({"method": method, "url": url, "request": (body or {}).get("request")})
        route = self.routes.get(f"{method} {url}")
        return route(body) if route else Response(404, {"error": {"code": "NOT_FOUND", "message": url}})

    def get(self, url: str, timeout: float = 0) -> Response:
        return self._answer("GET", url, None)

    def post(self, url: str, json: Optional[Dict[str, Any]] = None, timeout: float = 0) -> Response:
        return self._answer("POST", url, json)


def claims_of(jws: str) -> Dict[str, Any]:
    part = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def test_kyaos_exposes_consent() -> None:
    assert kyaos.consent.create_consent_request is create_consent_request
    assert kyaos.ConsentFlowError is ConsentFlowError


def test_unsigned_root_grant() -> None:
    grant = unsigned_root_grant(AGENT, SERVICE, ["a", "b"], datetime(2027, 1, 1, tzinfo=timezone.utc), caveats=[{"type": "Expiry"}])
    assert grant == {
        "validUntil": "2027-01-01T00:00:00.000Z",
        "credentialSubject": {"invoker": AGENT, "invocationTarget": SERVICE, "parentCapability": SERVICE, "allowedAction": ["a", "b"], "caveats": [{"type": "Expiry"}]},
    }
    assert unsigned_root_grant(AGENT, SERVICE, ["a"], "2027-01-01T00:00:00Z")["validUntil"] == "2027-01-01T00:00:00Z"


def test_create_consent_request_signs_as_the_service() -> None:
    page = f"{HELIX}/consent/abc"
    helix = FakeHelix({f"POST {HELIX}/v1/consent/requests": lambda body: Response(201, {"id": "abc", "authorizationUrl": page, "resultUrl": "", "expiresAt": 1, "status": "pending"})})
    grant = unsigned_root_grant(AGENT, SERVICE, ["orders:read"], iso(86400))
    created = create_consent_request(f"{HELIX}/", SERVICE_SIGNER, "u1", grant, hop_lifetime_seconds=600, display={"serviceName": "Shop"}, return_url="https://shop.example/back", http=helix)
    assert created["authorizationUrl"] == page
    jws = helix.calls[0]["request"]
    assert read_jws_header(jws)["typ"] == CONSENT_REQUEST_TYP
    claims = claims_of(jws)
    assert claims["iss"] == SERVICE and claims["aud"] == f"{HELIX}/v1/consent/requests" and claims["serviceUserId"] == "u1"
    assert claims["grant"] == grant and claims["hopLifetimeSeconds"] == 600 and claims["returnUrl"] == "https://shop.example/back"
    assert claims["jti"].startswith("urn:uuid:")
    assert "privateKey" not in jws
    create_consent_request(HELIX, SERVICE_SIGNER, "u1", grant, http=helix, now=time.time())
    assert "hopLifetimeSeconds" not in claims_of(helix.calls[1]["request"])


def test_create_consent_request_refusals() -> None:
    grant = unsigned_root_grant(AGENT, SERVICE, ["x"], iso(10))
    refused = FakeHelix({f"POST {HELIX}/v1/consent/requests": lambda body: Response(403, {"error": {"code": "CONSENT_SERVICE_UNKNOWN", "message": "unknown"}})})
    with pytest.raises(ConsentFlowError) as error:
        create_consent_request(HELIX, SERVICE_SIGNER, "u", grant, http=refused)
    assert error.value.reason == "consent_request_refused" and error.value.http_status == 403 and "CONSENT_SERVICE_UNKNOWN" in str(error.value)
    assert error.value.helix_code == "CONSENT_SERVICE_UNKNOWN" and error.value.details == {"reason": "consent_request_refused", "helixCode": "CONSENT_SERVICE_UNKNOWN"}
    odd = FakeHelix({f"POST {HELIX}/v1/consent/requests": lambda body: Response(201, {})})
    with pytest.raises(ConsentFlowError) as error:
        create_consent_request(HELIX, SERVICE_SIGNER, "u", grant, http=odd)
    assert error.value.http_status == 502
    broken = FakeHelix({f"POST {HELIX}/v1/consent/requests": lambda body: Response(500, ValueError("not json"))})
    with pytest.raises(ConsentFlowError, match="500") as error:
        create_consent_request(HELIX, SERVICE_SIGNER, "u", grant, http=broken)
    assert error.value.helix_code is None

    class Down:
        def post(self, url: str, json: Any = None, timeout: float = 0) -> Response:
            raise ConnectionError("connection refused")

    # No answer at all: an outage (503, consent_unreachable), whatever the transport raised.
    with pytest.raises(ConsentFlowError) as error:
        create_consent_request(HELIX, SERVICE_SIGNER, "u", grant, http=Down())
    assert error.value.reason == "consent_unreachable" and error.value.http_status == 503
    assert str(error.value) == "Helix could not be reached: connection refused"


def test_withdraw_consent_signs_as_the_service() -> None:
    helix = FakeHelix({f"POST {HELIX}/v1/consent/withdrawals": lambda body: Response(200, {"consentId": "c1", "withdrawn": ["c1"], "userDid": USER.did, "revoked": ["urn:zcap:1"]})})
    assert withdraw_consent(HELIX, SERVICE_SIGNER, "c1", http=helix)["revoked"] == ["urn:zcap:1"]
    assert read_jws_header(helix.calls[0]["request"])["typ"] == CONSENT_WITHDRAWAL_TYP
    assert claims_of(helix.calls[0]["request"])["consentId"] == "c1"
    with pytest.raises(ConsentFlowError) as error:
        withdraw_consent(HELIX, SERVICE_SIGNER, "c1", http=FakeHelix({}), now=time.time())
    assert error.value.reason == "consent_withdrawal_refused"


def test_consent_result_url() -> None:
    assert consent_result_url(f"{HELIX}/consent/abc") == f"{HELIX}/v1/consent/requests/abc"
    assert consent_result_url("http://127.0.0.1:3000/base/consent/x_y") == "http://127.0.0.1:3000/base/v1/consent/requests/x_y"
    assert helix_url_of(f"{HELIX}/consent/abc") == HELIX
    for bad in ["not a url", f"{HELIX}/elsewhere/abc", "ftp://helix.example/consent/abc", "http://[::1/consent/x"]:
        with pytest.raises(ConsentFlowError):
            consent_result_url(bad)


def test_verify_consent_hop_from_the_did_key_alone() -> None:
    good = hop()
    assert verify_consent_hop(good, AGENT, SERVICE)["issuer"] == USER.did
    assert did_key_document(USER.did) is not None
    tampered = {**good, "credentialSubject": {**good["credentialSubject"], "allowedAction": ["orders:write"]}}
    cases = [
        ({"not": "a hop"}, "DelegationCredential"),
        (hop(issuer=SERVICE_SIGNER), "user did:key"),
        (hop(invoker="did:web:someone:else"), "delegates to"),
        (hop(target="did:web:other:service"), "targets"),
        (hop(parent="urn:zcap:parent"), "valid root"),
        (tampered, "signature"),
        (hop(valid_for=-5), "valid root|expired"),
    ]
    for value, message in cases:
        with pytest.raises(ConsentFlowError, match=message):
            verify_consent_hop(value, AGENT, SERVICE)
    soon = hop(valid_for=2)
    assert verify_consent_hop(soon, AGENT, SERVICE, now=time.time() + 1)
    with pytest.raises(ConsentFlowError, match="expired|valid root"):
        verify_consent_hop(soon, AGENT, SERVICE, now=time.time() + 400)


def test_await_consent_hop() -> None:
    signed = hop()
    polls = [0]

    def answer(body: Any) -> Response:
        polls[0] += 1
        if polls[0] < 3:
            return Response(200, {"id": "abc", "status": "pending", "expiresAt": 1})
        return Response(200, {"id": "abc", "status": "approved", "expiresAt": 1, "consentId": "c1", "hop": signed, "windowUntil": 2_000_000_000})

    sleeps: List[float] = []
    approved = await_consent_hop(f"{HELIX}/consent/abc", AGENT, SERVICE, http=FakeHelix({f"GET {HELIX}/v1/consent/requests/abc": answer}), sleep=sleeps.append, interval_seconds=0.01)
    assert approved["consentId"] == "c1" and approved["windowUntil"] == 2_000_000_000 and approved["helixUrl"] == HELIX
    assert approved["hop"]["id"] == signed["id"] and len(sleeps) == 2
    no_window = FakeHelix({f"GET {HELIX}/v1/consent/requests/abc": lambda body: Response(200, {"id": "abc", "status": "approved", "expiresAt": 1, "consentId": "c1", "hop": signed})})
    assert await_consent_hop(f"{HELIX}/consent/abc", AGENT, SERVICE, http=no_window)["windowUntil"] > 0


def test_await_consent_hop_gives_up() -> None:
    for status in ("denied", "expired"):
        helix = FakeHelix({f"GET {HELIX}/v1/consent/requests/abc": lambda body, s=status: Response(200, {"id": "abc", "status": s, "expiresAt": 1})})
        with pytest.raises(ConsentFlowError) as error:
            await_consent_hop(f"{HELIX}/consent/abc", AGENT, SERVICE, http=helix)
        assert error.value.reason == "consent_not_approved"
    with pytest.raises(ConsentFlowError) as error:
        fetch_consent_result(f"{HELIX}/consent/none", FakeHelix({}))
    assert error.value.http_status == 404
    pending = FakeHelix({f"GET {HELIX}/v1/consent/requests/abc": lambda body: Response(200, {"id": "abc", "status": "pending", "expiresAt": 1})})
    with pytest.raises(ConsentFlowError) as error:
        await_consent_hop(f"{HELIX}/consent/abc", AGENT, SERVICE, http=pending, timeout_seconds=0)
    assert error.value.reason == "consent_timeout"


def test_renew_consent_hop() -> None:
    renewed = hop()
    helix = FakeHelix({f"POST {HELIX}/v1/consent/renewals": lambda body: Response(200, {"consentId": "c1", "hop": renewed, "windowUntil": 2_000_000_000})})
    result = renew_consent_hop(HELIX, "c1", AGENT_SIGNER, SERVICE, allowed_action=["orders:read"], http=helix)
    assert result["windowUntil"] == 2_000_000_000
    assert read_jws_header(helix.calls[0]["request"])["typ"] == CONSENT_RENEWAL_TYP
    assert claims_of(helix.calls[0]["request"])["allowedAction"] == ["orders:read"]
    no_window = FakeHelix({f"POST {HELIX}/v1/consent/renewals": lambda body: Response(200, {"hop": renewed})})
    assert renew_consent_hop(HELIX, "c1", AGENT_SIGNER, SERVICE, http=no_window, now=time.time())["windowUntil"] > 0
    for code, reason in [("CONSENT_STEP_UP_REQUIRED", "step_up_required"), ("CONSENT_WINDOW_ENDED", "consent_window_ended"), ("CONSENT_WITHDRAWN", "consent_withdrawn"), ("OTHER", "consent_renewal_refused")]:
        refused = FakeHelix({f"POST {HELIX}/v1/consent/renewals": lambda body, c=code: Response(403, {"error": {"code": c}})})
        with pytest.raises(ConsentFlowError) as error:
            renew_consent_hop(HELIX, "c1", AGENT_SIGNER, SERVICE, http=refused)
        assert error.value.reason == reason


def test_renewals_verify_against_the_agent_did_document() -> None:
    agent_key = did_key_signer()
    own = hop(invoker=agent_key.did)
    helix = FakeHelix({f"POST {HELIX}/v1/consent/renewals": lambda body: Response(200, {"hop": own})})
    renew_consent_hop(HELIX, "c1", agent_key, SERVICE, http=helix)
    assert verify_jws_by_kid(helix.calls[0]["request"], did_key_document, expected_did=agent_key.did)
    stranger = FakeHelix({f"POST {HELIX}/v1/consent/renewals": lambda body: Response(200, {"hop": hop()})})
    with pytest.raises(ConsentFlowError, match="delegates to"):
        renew_consent_hop(HELIX, "c1", agent_key, SERVICE, http=stranger)


def test_renew_before() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    assert renew_before("2026-01-01T00:10:00Z", 60, start) == start + 540
    assert renew_before(datetime(2026, 1, 1, 0, 0, 30, tzinfo=timezone.utc), 60, start) == start
    assert renew_before(iso(120)) > time.time()
    with pytest.raises(ConsentFlowError):
        renew_before("soon")


def test_consent_hop_keeper_stores_and_renews_inside_the_window() -> None:
    now = [time.time()]
    first = hop(valid_for=120)
    second = hop(valid_for=240)
    helix = FakeHelix({f"POST {HELIX}/v1/consent/renewals": lambda body: Response(200, {"hop": second, "windowUntil": int(now[0] + 600)})})
    store = CredentialStore(identity={"id": "urn:id:1", "type": ["VerifiableCredential", "AgentIdentityCredential"], "issuer": "did:web:helix.example", "credentialSubject": {"id": AGENT, "name": "Bot", "responsibleParty": "did:web:helix.example:accounts:1"}})
    keeper = ConsentHopKeeper(store, AGENT_SIGNER, SERVICE, {"consentId": "c1", "hop": first, "windowUntil": int(now[0] + 600), "helixUrl": HELIX}, http=helix, clock=lambda: now[0])
    assert keeper.consent_id == "c1"
    assert [credential["id"] for credential in store.present_chain(invocation_target=SERVICE)["hops"]] == [first["id"]]
    assert [credential["id"] for credential in keeper.chain()] == [first["id"]]
    now[0] += 61
    assert keeper.current()["id"] == second["id"]
    assert [credential["id"] for credential in store.hops] == [second["id"]] and keeper.hop["id"] == second["id"]
    now[0] += 600
    assert keeper.current()["id"] == second["id"]
    narrower = FakeHelix({f"POST {HELIX}/v1/consent/renewals": lambda body: Response(200, {"hop": second})})
    narrow = ConsentHopKeeper(CredentialStore(), AGENT_SIGNER, SERVICE, {"consentId": "c2", "hop": first, "windowUntil": 2_000_000_000, "helixUrl": HELIX}, http=narrower)
    narrow.renew(["orders:read"])
    assert claims_of(narrower.calls[0]["request"])["allowedAction"] == ["orders:read"]


def test_default_http_is_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    seen: Dict[str, Any] = {}

    def fake_get(url: str, timeout: float = 0) -> Response:
        seen["url"] = url
        return Response(200, {"id": "abc", "status": "pending", "expiresAt": 1})

    monkeypatch.setattr(requests, "get", fake_get)
    assert fetch_consent_result(f"{HELIX}/consent/abc")["status"] == "pending"
    assert seen["url"] == f"{HELIX}/v1/consent/requests/abc"
