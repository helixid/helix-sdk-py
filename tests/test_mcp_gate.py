# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""Gap 1: the gate decides which JSON-RPC methods need a caller (all but ``open_methods``); resources and
prompts have their own deny-by-default scope maps. Gap 2: every refusal is audited, including those of a
caller the gate could not identify (anonymous, with what it claimed marked unverified). Parity with
helix-sdk-js's gate.test.ts."""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List

import pytest

from helix_sdk.audit import MemoryAuditSink
from helix_sdk.request_proof import with_request_proof
from helix_mcp_middleware import (
    DEFAULT_OPEN_METHODS,
    MCPMiddlewareOptions,
    create_local_verifier,
    create_mcp_audit_trail,
    helixid_mcp_middleware,
)
from helix_mcp_middleware.errors import AuthorizationServerUnavailableError
from helix_mcp_middleware.gate import claimed_issuer_of, header_of, method_of, refusal_code_of, target_of
from helix_mcp_middleware.metadata import to_http_error_response

from mcp_proof_helpers import NOW_MS, fixture_verifier_options, make_agent

SERVICE = "did:web:orders.helix.test"
READER = {"authorization": "Bearer reader"}


def validate(token: str) -> Dict[str, Any]:
    if token == "reader":
        return {"sub": "user-1", "scopes": ["docs:read"]}
    raise ValueError("unknown token")


def gate(**extra: Any) -> Any:
    events: List[Dict[str, Any]] = []
    options: Dict[str, Any] = {
        "validate_oauth_token": validate,
        "tool_scopes": {"lookup": []},
        "resource_scopes": {"file:///docs/a.md": ["docs:read"], "file:///docs/secret.md": ["docs:admin"]},
        "prompt_scopes": {"summarize": ["docs:read"]},
        "audit_sink": events.append,
        "service_did": SERVICE,
        **extra,
    }
    return helixid_mcp_middleware(MCPMiddlewareOptions(**options)), events


def jwt(claims: Dict[str, Any]) -> str:
    enc = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


def refused(fn: Any) -> Any:
    with pytest.raises(Exception) as caught:  # noqa: PT011
        fn()
    return caught.value


def test_lets_the_default_open_methods_through_unchecked_and_unaudited() -> None:
    mw, events = gate()
    assert DEFAULT_OPEN_METHODS == ("initialize", "notifications/initialized", "tools/list")
    for method in DEFAULT_OPEN_METHODS:
        assert mw.authorize({"method": method}).auth_method == "none"
    assert mw.authorize({"request": {"method": "tools/list", "params": {}}}).scopes == []
    assert events == []


def test_refuses_every_other_method_without_a_credential_and_audits_each_with_its_method() -> None:
    mw, events = gate()
    for method in ("resources/list", "resources/read", "prompts/list", "prompts/get", "ping", "tools/call"):
        error = refused(lambda: mw.authorize({"method": method, "name": "x"}))
        assert to_http_error_response(error, "https://x").status == 401
    assert [(e["method"], e["authMethod"], e["reasonCode"]) for e in events] == [
        ("resources/list", "none", "proof_missing"),
        ("resources/read", "none", "proof_missing"),
        ("prompts/list", "none", "proof_missing"),
        ("prompts/get", "none", "proof_missing"),
        ("ping", "none", "proof_missing"),
        ("tools/call", "none", "proof_missing"),
    ]
    assert events[1]["resourceUri"] == "x" and events[3]["promptName"] == "x" and events[5]["toolName"] == "x"


def test_the_operator_sets_the_open_list() -> None:
    closed, _ = gate(open_methods=[])
    assert refused(lambda: closed.authorize({"method": "initialize"})).code == "PROOF_MISSING"
    opened, _ = gate(open_methods=["resources/list"])
    assert opened.authorize({"method": "resources/list"}).auth_method == "none"
    assert refused(lambda: opened.authorize({"method": "tools/list"})).code == "PROOF_MISSING"


def test_a_verified_caller_may_list_and_resources_and_prompts_are_deny_by_default() -> None:
    mw, events = gate()
    assert mw.authorize({"method": "resources/list", "headers": READER}).oauth_subject == "user-1"
    assert mw.authorize({"method": "prompts/list", "headers": READER}).auth_method == "oauth"
    mw.authorize({"request": {"method": "resources/read", "params": {"uri": "file:///docs/a.md"}}, "headers": READER})
    mw.authorize({"request": {"method": "prompts/get", "params": {"name": "summarize"}}, "headers": READER})
    assert refused(lambda: mw.authorize({"method": "resources/read", "name": "file:///docs/secret.md", "headers": READER})).code == "INSUFFICIENT_SCOPE"
    unlisted = refused(lambda: mw.authorize({"method": "resources/read", "name": "file:///etc/passwd", "headers": READER}))
    assert (unlisted.code, str(unlisted)) == ("RESOURCE_NOT_PERMITTED", "This resource is not permitted")
    http = to_http_error_response(unlisted, "https://x")
    assert http.status == 403 and http.body["error"] == "insufficient_scope"
    assert refused(lambda: mw.authorize({"method": "prompts/get", "name": "other", "headers": READER})).code == "PROMPT_NOT_PERMITTED"
    assert refused(lambda: mw.authorize({"method": "resources/read", "headers": READER})).code == "RESOURCE_NOT_PERMITTED"
    assert [(e["method"], e["result"], e.get("resourceUri") or e.get("promptName"), e.get("reasonCode") or e.get("reason")) for e in events] == [
        ("resources/list", "allowed", None, None),
        ("prompts/list", "allowed", None, None),
        ("resources/read", "allowed", "file:///docs/a.md", None),
        ("prompts/get", "allowed", "summarize", None),
        ("resources/read", "denied", "file:///docs/secret.md", "insufficient scope"),
        ("resources/read", "denied", "file:///etc/passwd", "resource_not_permitted"),
        ("prompts/get", "denied", "other", "prompt_not_permitted"),
        ("resources/read", "denied", None, "resource_not_permitted"),
    ]
    bare = helixid_mcp_middleware(MCPMiddlewareOptions(validate_oauth_token=lambda token: {"sub": "u", "scopes": []}))
    assert refused(lambda: bare.authorize({"method": "resources/read", "name": "file:///a", "headers": READER})).code == "RESOURCE_NOT_PERMITTED"
    assert refused(lambda: bare.authorize({"method": "prompts/get", "name": "p", "headers": READER})).code == "PROMPT_NOT_PERMITTED"


def test_a_kyaos_proof_for_another_method_binds_that_request_received_or_rebuilt() -> None:
    agent = make_agent()
    verifier = create_local_verifier(fixture_verifier_options(SERVICE, documents={agent["did"]: agent["document"]}))
    mw = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier, minimum_level="L1", resource_scopes={"file:///a": []}))
    signed = with_request_proof({"method": "resources/read", "params": {"uri": "file:///a"}}, agent["signer"], audience=SERVICE, now_ms=NOW_MS)
    assert mw.authorize({"method": "resources/read", "request": signed, "_meta": signed["params"]["_meta"]}).agent_did == agent["did"]
    again = with_request_proof({"method": "resources/read", "params": {"uri": "file:///a"}}, agent["signer"], audience=SERVICE, now_ms=NOW_MS)
    caller = mw.authorize({"method": "resources/read", "name": "file:///a", "input": {"uri": "file:///a"}, "_meta": again["params"]["_meta"]})
    assert caller.agent_did == agent["did"]


def test_records_method_target_address_user_agent_and_the_unverified_issuer_of_a_refused_bearer() -> None:
    mw, events = gate()
    token = jwt({"iss": "https://login.example", "sub": "x"})
    refused(lambda: mw.authorize({"method": "tools/call", "name": "lookup", "clientIp": "203.0.113.7", "headers": {"authorization": f"Bearer {token}", "user-agent": "claude-code/2.0"}}))
    assert len(events) == 1
    event = events[0]
    assert {k: event[k] for k in ("event", "result", "authMethod", "method", "toolName", "reasonCode", "clientIp", "userAgent", "oauthIssuer", "claimedVerified", "serviceDid", "effectiveScopes")} == {
        "event": "AUTHZ_DENIED", "result": "denied", "authMethod": "none", "method": "tools/call", "toolName": "lookup", "reasonCode": "oauth_token_invalid",
        "clientIp": "203.0.113.7", "userAgent": "claude-code/2.0", "oauthIssuer": "https://login.example", "claimedVerified": False, "serviceDid": SERVICE, "effectiveScopes": [],
    }
    assert "oauthSubject" not in event


def test_records_conflicts_and_a_bearer_with_no_validator_and_nothing_for_a_server_fault() -> None:
    mw, events = gate()
    refused(lambda: mw.authorize({"name": "lookup", "headers": {"authorization": ["Bearer a", "Bearer b"]}}))
    no_oauth = helixid_mcp_middleware(MCPMiddlewareOptions(audit_sink=events.append))
    refused(lambda: no_oauth.authorize({"name": "lookup", "headers": {"authorization": "Bearer opaque"}}))
    assert [e["reasonCode"] for e in events] == ["credential_conflict", "oauth_token_invalid"]
    assert "oauthIssuer" not in events[1]

    def down(token: str) -> Any:
        raise AuthorizationServerUnavailableError("down")

    unavailable = helixid_mcp_middleware(MCPMiddlewareOptions(validate_oauth_token=down, audit_sink=events.append))
    assert isinstance(refused(lambda: unavailable.authorize({"name": "lookup", "headers": READER})), AuthorizationServerUnavailableError)
    assert len(events) == 2


def test_reaches_the_typed_trail_as_authorization_denied_with_the_reason_and_no_actor() -> None:
    sink = MemoryAuditSink()
    trail = create_mcp_audit_trail(reporter=sink, service_did=SERVICE)
    mw = helixid_mcp_middleware(MCPMiddlewareOptions(audit_sink=trail.tool_audit_sink(), service_did=SERVICE, resource_scopes={}))
    refused(lambda: mw.authorize({"method": "resources/list"}))
    assert sink.event_types == ["authorization.denied"]
    assert sink.events[0]["reason"] == {"code": "proof_missing"} and "actor" not in sink.events[0]
    trail.tool_audit_sink()({"event": "AUTHZ_DENIED", "result": "denied", "timestamp": "2026-11-24T00:00:00.000Z", "authMethod": "none", "effectiveScopes": []})
    assert sink.events[1]["reason"] == {"code": "unidentified"}
    named = create_mcp_audit_trail(reporter=sink, service_did=SERVICE, include_tool_names=True)
    oauth = helixid_mcp_middleware(MCPMiddlewareOptions(audit_sink=named.tool_audit_sink(), validate_oauth_token=lambda token: {"sub": "u", "scopes": []}, resource_scopes={}))
    refused(lambda: oauth.authorize({"method": "tools/call", "name": "lookup"}))
    refused(lambda: oauth.authorize({"method": "resources/read", "name": "file:///x", "headers": READER}))
    assert [(e["eventType"], e["reason"]["code"], e["action"].get("name")) for e in sink.events[2:]] == [
        ("authorization.denied", "proof_missing", "lookup"),
        ("authorization.denied", "resource_not_permitted", None),
    ]


def test_gate_helpers() -> None:
    assert method_of({}) == "tools/call"
    assert method_of({"method": "", "request": {"method": "ping"}}) == "ping"
    assert method_of({"request": {"method": ""}}) == "tools/call"
    assert target_of("resources/read", {"request": {"method": "resources/read", "params": {"uri": 7}}}) is None
    assert target_of("prompts/get", {"request": {"method": "prompts/get"}}) is None
    assert header_of(None, "user-agent") is None
    assert header_of({"User-Agent": ["first", "second"]}, "user-agent") == "first"
    assert claimed_issuer_of({"authorization": f"Bearer {jwt({'sub': 'no-iss'})}"}) is None
    assert claimed_issuer_of({"authorization": "Bearer aaa.%%%.c"}) is None
    assert claimed_issuer_of({"authorization": "Bearer only-one-part"}) is None
    assert claimed_issuer_of({"authorization": "Basic abc"}) is None
    assert refusal_code_of(type("E", (Exception,), {"code": "PROOF_INVALID", "reasons": ("status_revoked",)})()) == "status_revoked"
    assert refusal_code_of(type("E", (Exception,), {"code": "PROOF_INVALID", "reasons": ()})()) == "proof_invalid"
    assert refusal_code_of(type("E", (Exception,), {"code": "TOOL_NOT_PERMITTED"})()) is None
    assert refusal_code_of(ValueError("x")) is None
