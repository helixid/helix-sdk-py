# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""A consent request Helix refuses or cannot take never becomes a 500 (parity with helix-sdk-js's
consent-failure tests): the caller's refusal is a 403 insufficient_scope, audited as a denial; Helix's
outage an AuthorizationServerUnavailableError (a 503 at the host); anything else stays a server error."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from helix_mcp_middleware import (
    MCPMiddlewareOptions,
    MemoryResumeTokenStore,
    NeedsAuthorizationOptions,
    create_helix_consent,
    create_needs_authorization,
    helixid_mcp_middleware,
)
from helix_mcp_middleware.errors import AuthorizationServerUnavailableError, ToolScopeError
from helix_mcp_middleware.metadata import to_http_error_response
from helix_mcp_middleware.needs_authorization_guard import consent_failure_of
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.errors import ConsentFlowError
from helix_sdk.keys import generate_key_pair

HELIX = "https://helix.example"
SERVICE = "did:web:shop.example:services:aa"
SIGNER = EnvSigner(did=SERVICE, env_var="K", env={"K": generate_key_pair().private_key})
CALL = {"name": "refund_order", "input": {"orderId": "ORD-1"}, "headers": {"authorization": "Bearer t"}}


class Answering:
    """``requests``-shaped Helix answering every POST with one status and body, or raising."""

    def __init__(self, status: int = 0, body: Any = None, raises: Exception | None = None) -> None:
        self.status, self.body, self.raises = status, body, raises

    def post(self, url: str, json: Any = None, timeout: float = 0) -> Any:
        if self.raises is not None:
            raise self.raises
        return SimpleNamespace(status_code=self.status, json=lambda: self.body)


def gate_with(http: Any) -> Any:
    events: List[Dict[str, Any]] = []
    consent = create_helix_consent(HELIX, SERVICE, SIGNER, 60, http=http)
    gate = helixid_mcp_middleware(
        MCPMiddlewareOptions(
            validate_oauth_token=lambda token: {"sub": "user-1", "scopes": ["orders:read"]},
            tool_scopes={"refund_order": ["orders:admin"]},
            needs_authorization=create_needs_authorization(NeedsAuthorizationOptions(authorization_url=consent.authorization_url, store=MemoryResumeTokenStore())),
            audit_sink=events.append,
        )
    )
    return gate, events


def test_a_caller_refusal_is_a_403_insufficient_scope_with_the_reason_audited_as_a_denial() -> None:
    gate, events = gate_with(Answering(403, {"error": {"code": "CONSENT_GRANT_SCOPE_NOT_ALLOWED", "message": "the agent is not attested for: orders:admin"}}))
    with pytest.raises(ToolScopeError) as caught:
        gate(CALL)
    assert str(caught.value) == "Required scope: orders:admin. Helix refused the consent request: CONSENT_GRANT_SCOPE_NOT_ALLOWED the agent is not attested for: orders:admin"
    http = to_http_error_response(caught.value, "https://shop.example/.well-known/oauth-protected-resource")
    assert http is not None and http.status == 403 and http.body["error"] == "insufficient_scope"
    assert 'scope="orders:admin"' in http.headers["WWW-Authenticate"]
    assert [(e["event"], e["requiredScope"], e["reason"], e["oauthSubject"]) for e in events] == [
        ("AUTHZ_DENIED", "orders:admin", "consent_refused: CONSENT_GRANT_SCOPE_NOT_ALLOWED", "user-1")
    ]


def test_an_agent_helix_does_not_know_is_the_callers_refusal_too() -> None:
    gate, _ = gate_with(Answering(404, {"error": {"code": "DID_NOT_FOUND", "message": "Delegatee is not a known agent"}}))
    with pytest.raises(ToolScopeError):
        gate(CALL)


@pytest.mark.parametrize("http", [Answering(503, {"error": {"code": "SERVICE_UNAVAILABLE"}}), Answering(raises=ConnectionError("connection refused"))])
def test_helix_failing_or_unreachable_is_an_outage_never_a_401_or_403(http: Any) -> None:
    gate, events = gate_with(http)
    with pytest.raises(AuthorizationServerUnavailableError, match=r"^Helix's consent service is unavailable: ") as caught:
        gate(CALL)
    assert to_http_error_response(caught.value, "https://x") is None
    assert events == []


def test_a_refusal_that_is_the_services_own_doing_stays_a_server_error() -> None:
    gate, _ = gate_with(Answering(403, {"error": {"code": "CONSENT_SERVICE_UNKNOWN", "message": "not a service of a hosted account"}}))
    with pytest.raises(ConsentFlowError) as caught:
        gate(CALL)
    assert caught.value.helix_code == "CONSENT_SERVICE_UNKNOWN"
    assert to_http_error_response(caught.value, "https://x") is None


def test_consent_failure_of_sorts_consent_errors() -> None:
    def flow(reason: str, status: int, helix_code: str | None = None) -> ConsentFlowError:
        return ConsentFlowError(reason, "m", status, helix_code)

    assert consent_failure_of(flow("consent_request_refused", 403, "CONSENT_NO_GRANTABLE_SCOPES")) == {"kind": "refused", "helixCode": "CONSENT_NO_GRANTABLE_SCOPES", "message": "m"}
    assert consent_failure_of(flow("consent_unreachable", 503)) == {"kind": "unavailable", "message": "m"}
    for status in (502, 408, 429):
        assert consent_failure_of(flow("consent_request_refused", status)) == {"kind": "unavailable", "message": "m"}
    assert consent_failure_of(SimpleNamespace(code="CONSENT_FLOW_FAILED", reason="consent_unreachable")) == {"kind": "unavailable", "message": "consent flow failed"}  # type: ignore[arg-type]
    assert consent_failure_of(SimpleNamespace(code="CONSENT_FLOW_FAILED")) is None  # type: ignore[arg-type]
    assert consent_failure_of(flow("consent_request_refused", 403)) is None
    assert consent_failure_of(flow("consent_hop_invalid", 400, "CONSENT_GRANT_SCOPE_NOT_ALLOWED")) is None
    assert consent_failure_of(ValueError("x")) is None
