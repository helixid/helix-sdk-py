# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
HelixClient tests against a stubbed HTTP layer.

With agent self-custody retired, onboard_agent()/sign_vp()/
delegate_authority() are the whole agent-side surface: the server holds the
key, and the client only shapes requests and unwraps responses. These pin
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
            lambda c: c.sign_vp(AGENT_DID, "orders"),
            lambda c: c.delegate_authority(AGENT_DID, "did:key:z6Mkchild", ["read:orders"], 3600),
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

    def test_sign_vp_hits_the_admin_route_with_optional_fields(self, http) -> None:
        http.respond(200, {"signedVP": {"id": "vp-1"}})
        client = HelixClient(BASE_URL, admin_api_key="admin")
        grant = {"id": "grant-1"}

        vp = client.sign_vp(AGENT_DID, "orders", user_did="did:web:user", grant_vc=grant, vc_id="vc-2")

        assert vp == {"id": "vp-1"}
        call = http.calls[0]
        assert call.url == f"{BASE_URL}/v1/agents/did%3Aweb%3Ahelix.test%3Aagents%3Aa1/vp"
        assert call.json == {"targetService": "orders", "userDid": "did:web:user", "grantVC": grant, "vcId": "vc-2"}

    def test_sign_vp_omits_unset_optional_fields(self, http) -> None:
        http.respond(200, {"signedVP": {"id": "vp-1"}})
        HelixClient(BASE_URL, admin_api_key="admin").sign_vp(AGENT_DID, "orders")
        assert http.calls[0].json == {"targetService": "orders"}

    def test_delegate_authority_returns_the_delegated_vc(self, http) -> None:
        http.respond(200, {"delegatedVC": {"id": "vc-child"}})
        client = HelixClient(BASE_URL, admin_api_key="admin")

        vc = client.delegate_authority(AGENT_DID, "did:key:z6Mkchild", ["read:orders"], 3600, vc_id="vc-1")

        assert vc == {"id": "vc-child"}
        call = http.calls[0]
        assert call.url == f"{BASE_URL}/v1/agents/did%3Aweb%3Ahelix.test%3Aagents%3Aa1/delegate"
        assert call.json == {"to": "did:key:z6Mkchild", "scopes": ["read:orders"], "expiresIn": 3600, "vcId": "vc-1"}

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
            HelixClient(BASE_URL, admin_api_key="admin").delegate_authority(
                AGENT_DID, "did:key:z6Mkchild", ["read:orders"], 3600
            )

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

    def test_renew_vc_sends_only_given_overrides(self, http) -> None:
        http.respond(200, {"vcId": "vc-2"})
        HelixClient(BASE_URL, admin_api_key="admin").renew_vc("vc-1", expires_in_seconds=60)
        assert http.calls[0].url == f"{BASE_URL}/v1/vcs/vc-1/renew"
        assert http.calls[0].json == {"expiresInSeconds": 60}


class TestEnterpriseMode:
    def test_api_key_alone_defaults_to_the_hosted_api(self, http) -> None:
        http.respond(200, {"signedVP": {"id": "vp-1"}})
        HelixClient(api_key="hak_test").sign_vp(AGENT_DID, "orders")
        assert http.calls[0].url.startswith("https://api.helixid.dev/v1/custodial-agents/")

    def test_sign_vp_uses_the_custodial_route_and_bearer_token(self, http) -> None:
        http.respond(200, {"signedVP": {"id": "vp-1"}})
        client = HelixClient(BASE_URL, api_key="hak_test")

        vp = client.sign_vp(AGENT_DID, "orders", vc_id="vc-2")

        assert vp == {"id": "vp-1"}
        call = http.calls[0]
        assert call.url == f"{BASE_URL}/v1/custodial-agents/did%3Aweb%3Ahelix.test%3Aagents%3Aa1/vp"
        assert call.headers["authorization"] == "Bearer hak_test"
        assert call.json == {"targetService": "orders", "vcId": "vc-2"}

    def test_delegate_authority_uses_the_custodial_route(self, http) -> None:
        http.respond(200, {"delegatedVC": {"id": "vc-child"}})
        client = HelixClient(BASE_URL, api_key="hak_test")

        vc = client.delegate_authority(AGENT_DID, "did:key:z6Mkchild", ["read:orders"], 3600)

        assert vc == {"id": "vc-child"}
        call = http.calls[0]
        assert call.url == f"{BASE_URL}/v1/custodial-agents/did%3Aweb%3Ahelix.test%3Aagents%3Aa1/delegate"
        assert call.headers["authorization"] == "Bearer hak_test"

    @pytest.mark.parametrize(
        "method",
        [
            lambda c: c.sign_vp(AGENT_DID, "orders"),
            lambda c: c.delegate_authority(AGENT_DID, "did:key:z6Mkchild", ["read:orders"], 3600),
        ],
    )
    def test_custodial_route_errors_are_mapped(self, http, method) -> None:
        http.respond(403, {"error": {"code": "SCOPE_ESCALATION_DENIED", "message": "no"}})
        with pytest.raises(ScopeEscalationDeniedError):
            method(HelixClient(BASE_URL, api_key="hak_test"))

    @pytest.mark.parametrize(
        "method",
        [
            lambda c: c.sign_vp(AGENT_DID, "orders"),
            lambda c: c.delegate_authority(AGENT_DID, "did:key:z6Mkchild", ["read:orders"], 3600),
        ],
    )
    def test_custodial_route_error_without_json_is_internal(self, http, method) -> None:
        http.respond(500)
        with pytest.raises(InternalError):
            method(HelixClient(BASE_URL, api_key="hak_test"))
