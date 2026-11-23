# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
HelixClient tests against a stubbed HTTP layer.

With agent self-custody retired, onboard_agent() is the custodial
agent-side surface: the server holds the key, and the client only shapes
requests and unwraps responses. sign_vp()/verify_vp() are gone with the
Helix VP (KYA-OS story C-C), delegate_authority() with F-1's follow-up. These pin
the routes, auth headers, and bodies for both core (admin key) and
enterprise (account API key) modes, plus how API errors surface. No network
access or running helix-api instance needed.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest
import requests

from helix_sdk import HelixClient
from helix_sdk.errors import (
    HelixError,
    InternalError,
    MaxDelegationDepthExceededError,
    ScopeEscalationDeniedError,
    SDKOnlyModeNoAPIError,
)

BASE_URL = "http://helix.test"
AGENT_DID = "did:web:helix.test:agents:a1"


class FakeResponse:
    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no body")
        return self._payload


class RecordedCall:
    def __init__(self, method: str, url: str, json: Any, headers: Dict[str, str]) -> None:
        self.method = method
        self.url = url
        self.json = json
        self.headers = headers


@pytest.fixture
def http(monkeypatch: pytest.MonkeyPatch):
    """Stubs requests.request (HttpAdapter) and requests.post (enterprise
    custodial routes). Queue responses with http.respond(); inspect calls via
    http.calls."""

    class Stub:
        def __init__(self) -> None:
            self.calls: List[RecordedCall] = []
            self.responses: List[FakeResponse] = []

        def respond(self, status_code: int, payload: Any = None) -> None:
            self.responses.append(FakeResponse(status_code, payload))

        def _next(self, method: str, url: str, json: Any, headers: Optional[Dict[str, str]]) -> FakeResponse:
            self.calls.append(RecordedCall(method, url, json, headers or {}))
            return self.responses.pop(0)

    stub = Stub()
    monkeypatch.setattr(
        requests,
        "request",
        lambda method, url, json=None, headers=None, timeout=None: stub._next(method, url, json, headers),
    )
    monkeypatch.setattr(
        requests,
        "post",
        lambda url, json=None, headers=None, timeout=None: stub._next("POST", url, json, headers),
    )
    return stub


class TestSdkOnlyMode:
    @pytest.mark.parametrize(
        "call",
        [
            lambda c: c.onboard_agent("token"),
            lambda c: c.list_vcs(),
        ],
    )
    def test_api_calls_raise_without_a_base_url(self, call) -> None:
        with pytest.raises(SDKOnlyModeNoAPIError):
            call(HelixClient())


class TestCoreMode:
    def test_onboard_agent_posts_token_and_domains(self, http) -> None:
        http.respond(201, {"agentDid": AGENT_DID, "vcId": "vc-1"})
        client = HelixClient(BASE_URL + "/", admin_api_key="admin")

        result = client.onboard_agent("enroll-token", ["https://agent.example.com"])

        assert result == {"agentDid": AGENT_DID, "vcId": "vc-1"}
        call = http.calls[0]
        assert (call.method, call.url) == ("POST", f"{BASE_URL}/v1/onboard")
        assert call.json == {"enrollmentToken": "enroll-token", "domains": ["https://agent.example.com"]}
        assert call.headers["x-admin-api-key"] == "admin"

    def test_the_helix_vp_methods_are_gone(self) -> None:
        client = HelixClient(BASE_URL, admin_api_key="admin")
        assert not hasattr(client, "sign_vp") and not hasattr(client, "verify_vp")

    def test_create_service_posts_to_v1_services(self, http) -> None:
        http.respond(201, {"serviceDid": "did:web:helix.test:services:s1", "serviceName": "orders"})
        client = HelixClient(BASE_URL, admin_api_key="admin")

        result = client.create_service("orders", "Orders", "https://orders.example")

        assert result["serviceDid"] == "did:web:helix.test:services:s1"
        call = http.calls[0]
        assert (call.method, call.url) == ("POST", f"{BASE_URL}/v1/services")
        assert call.json == {"serviceName": "orders", "displayName": "Orders", "verifiedDomain": "https://orders.example"}

    @pytest.mark.parametrize(
        "code, error_type",
        [
            ("MAX_DELEGATION_DEPTH_EXCEEDED", MaxDelegationDepthExceededError),
            ("SCOPE_ESCALATION_DENIED", ScopeEscalationDeniedError),
        ],
    )
    def test_delegation_refusals_map_to_typed_errors(self, http, code, error_type) -> None:
        http.respond(400, {"error": {"code": code, "message": "refused"}})
        with pytest.raises(error_type):
            HelixClient(BASE_URL, admin_api_key="admin").get_vc("vc-1")

    def test_unknown_error_code_keeps_code_and_status(self, http) -> None:
        http.respond(418, {"error": {"code": "SOMETHING_NEW", "message": "teapot"}})
        with pytest.raises(HelixError) as excinfo:
            HelixClient(BASE_URL, admin_api_key="admin").get_vc("vc-1")
        assert excinfo.value.code == "SOMETHING_NEW"

    def test_error_without_a_json_body_is_internal(self, http) -> None:
        http.respond(502)
        with pytest.raises(InternalError):
            HelixClient(BASE_URL, admin_api_key="admin").get_vc("vc-1")

    def test_no_content_response_is_an_empty_dict(self, http) -> None:
        http.respond(204)
        assert HelixClient(BASE_URL, admin_api_key="admin").revoke_vc("vc-1") == {}

    def test_list_vcs_sends_only_set_filters(self, http) -> None:
        http.respond(200, [{"vcId": "vc-1"}])
        http.respond(200, [])
        client = HelixClient(BASE_URL, admin_api_key="admin")

        assert client.list_vcs(subject_did=AGENT_DID, status="active") == [{"vcId": "vc-1"}]
        client.list_vcs()

        assert http.calls[0].url == f"{BASE_URL}/v1/vcs?subjectDid=did%3Aweb%3Ahelix.test%3Aagents%3Aa1&status=active"
        assert http.calls[1].url == f"{BASE_URL}/v1/vcs"

    def test_register_vc_uses_the_admin_header(self, http) -> None:
        http.respond(200, {"vcId": "vc-grant", "alreadyRegistered": True})
        HelixClient(BASE_URL, admin_api_key="admin").register_vc({"id": "vc-grant"})
        call = http.calls[0]
        assert call.url == f"{BASE_URL}/v1/vcs/register"
        assert call.headers["x-admin-api-key"] == "admin"
        assert "authorization" not in call.headers

    def test_renew_vc_sends_only_given_overrides(self, http) -> None:
        http.respond(200, {"vcId": "vc-2"})
        HelixClient(BASE_URL, admin_api_key="admin").renew_vc("vc-1", expires_in_seconds=60)
        assert http.calls[0].url == f"{BASE_URL}/v1/vcs/vc-1/renew"
        assert http.calls[0].json == {"expiresInSeconds": 60}


class TestEnterpriseMode:
    def test_api_key_alone_defaults_to_the_hosted_api(self, http) -> None:
        http.respond(200, [])
        HelixClient(api_key="hak_test").list_vcs(subject_did=AGENT_DID)
        assert http.calls[0].url.startswith("https://api.helixid.dev/v1/")

    def test_every_call_carries_the_bearer_token_not_an_admin_header(self, http) -> None:
        # The VC lifecycle routes used to go out with no credential at all in
        # enterprise mode (only the custodial routes set the bearer token), so
        # enterprise answered 403.
        http.respond(200, {"vcId": "vc-grant", "revoked": True})
        client = HelixClient(BASE_URL, api_key="hak_test")

        client.revoke_vc("vc-grant")

        call = http.calls[0]
        assert call.url.startswith(f"{BASE_URL}/v1/vcs/")
        assert call.headers["authorization"] == "Bearer hak_test"
        assert "x-admin-api-key" not in call.headers

    def test_register_vc_posts_the_signed_credential(self, http) -> None:
        http.respond(201, {"vcId": "vc-grant", "alreadyRegistered": False})
        client = HelixClient(BASE_URL, api_key="hak_test")

        result = client.register_vc({"id": "vc-grant", "proof": {}})

        assert result == {"vcId": "vc-grant", "alreadyRegistered": False}
        call = http.calls[0]
        assert call.url == f"{BASE_URL}/v1/vcs/register"
        assert call.json == {"vc": {"id": "vc-grant", "proof": {}}}
        assert call.headers["authorization"] == "Bearer hak_test"

    def test_renew_vc_carries_the_bearer_token(self, http) -> None:
        http.respond(201, {"vcId": "vc-2", "previousVcId": "vc-1"})
        HelixClient(BASE_URL, api_key="hak_test").renew_vc("vc-1")
        assert http.calls[0].headers["authorization"] == "Bearer hak_test"

    @pytest.mark.parametrize(
        "method",
        [
            lambda c: c.list_vcs(subject_did=AGENT_DID),
        ],
    )
    def test_custodial_route_errors_are_mapped(self, http, method) -> None:
        http.respond(403, {"error": {"code": "SCOPE_ESCALATION_DENIED", "message": "no"}})
        with pytest.raises(ScopeEscalationDeniedError):
            method(HelixClient(BASE_URL, api_key="hak_test"))

    @pytest.mark.parametrize(
        "method",
        [
            lambda c: c.list_vcs(subject_did=AGENT_DID),
        ],
    )
    def test_custodial_route_error_without_json_is_internal(self, http, method) -> None:
        http.respond(500)
        with pytest.raises(InternalError):
            method(HelixClient(BASE_URL, api_key="hak_test"))


class TestAuditLog:
    def test_get_audit_log_returns_one_page_and_passes_filters_and_cursor(self, http) -> None:
        page = {"items": [{"id": "1", "recordedAt": "t", "eventDigest": "sha256:" + "0" * 64, "event": {"eventType": "consent.approved"}}], "nextCursor": "abc_-1"}
        http.respond(200, page)
        client = HelixClient(BASE_URL, api_key="hak")
        assert client.get_audit_log(event_type="consent.approved", since="2026-01-01", limit=5, family="consent", cursor="prev") == page
        assert http.calls[0].url == BASE_URL + "/v1/audit-log?eventType=consent.approved&family=consent&since=2026-01-01&cursor=prev&limit=5"
        http.respond(200, {"items": [], "nextCursor": None})
        assert client.get_audit_log() == {"items": [], "nextCursor": None} and http.calls[1].url == BASE_URL + "/v1/audit-log"

    def test_record_audit_event_posts_the_event_and_lets_a_refusal_propagate(self, http) -> None:
        event = {"eventType": "consent.approved", "schema": "x"}
        http.respond(201, {"recorded": True})
        HelixClient(BASE_URL, api_key="hak").record_audit_event(event)
        assert (http.calls[0].method, http.calls[0].url, http.calls[0].json) == ("POST", BASE_URL + "/v1/audit-log/events", event)
        assert http.calls[0].headers["authorization"] == "Bearer hak"
        # A refusal propagates (as in the JS client): a producer that must not fail catches it.
        http.respond(400, {"error": {"code": "AUDIT_EVENT_INVALID", "message": "bad"}})
        with pytest.raises(HelixError) as refused:
            HelixClient(BASE_URL, admin_api_key="admin").record_audit_event(event)
        assert refused.value.code == "AUDIT_EVENT_INVALID"
        assert len(http.calls) == 2
        # Without a key (or without an API) it is a no-op.
        HelixClient(BASE_URL).record_audit_event(event)
        HelixClient().record_audit_event(event)
        assert len(http.calls) == 2

    def test_audit_sink_reports_each_entry_through_record_audit_event(self, http) -> None:
        from helix_sdk.audit import AuditTrail, pairwise_did

        http.respond(201, {"recorded": True})
        trail = AuditTrail(sink=HelixClient(BASE_URL, api_key="hak").audit_sink(), source_id="s", producer=pairwise_did("did:key:zA"), tenant_ref=pairwise_did("did:key:zA"))
        entry = trail.record({"eventType": "session.established", "action": {"category": "session"}, "outcome": "succeeded", "details": {"family": "session", "phase": "established"}})
        assert (http.calls[0].url, http.calls[0].json) == (BASE_URL + "/v1/audit-log/events", entry.event)

