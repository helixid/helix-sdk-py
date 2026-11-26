# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story L1-D, client side: reading /.well-known/mcp (Core L1.10) and the
skew window it advertises. The same cases as helix-sdk-js's
tests/unit/kyaos/discovery.test.ts.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

import pytest

from helix_sdk import kyaos
from helix_sdk.discovery import (
    WELL_KNOWN_MCP_INVALID,
    WELL_KNOWN_MCP_PATH,
    WellKnownMcpError,
    WellKnownMcpProblems,
    fetch_well_known_mcp,
    read_well_known_mcp,
    well_known_mcp_url,
)

ORIGIN = "https://api.example.com"
SERVER = "did:web:api.example.com"
DOCUMENT: Dict[str, Any] = {
    "version": "1.0",
    "serverDid": SERVER,
    "endpoints": {"tools": f"{ORIGIN}/mcp", "handshake": f"{ORIGIN}/mcp#_kyaos_handshake"},
    "clockSkewSeconds": 300,
    "capabilities": {"proofs": True, "delegation": False, "statusList": False, "crisp": False},
    "statusListCredential": f"{ORIGIN}/credentials/status/1",
    "supportedDidMethods": ["did:web", "did:key"],
    "proofAlgorithms": ["EdDSA"],
}


def reason(value: Any, origin: Optional[str] = None) -> str:
    with pytest.raises(WellKnownMcpError) as raised:
        read_well_known_mcp(value, origin=origin)
    return raised.value.reason


def test_well_known_mcp_url_is_at_the_origin_whatever_path_the_caller_holds() -> None:
    assert WELL_KNOWN_MCP_PATH == "/.well-known/mcp"
    assert well_known_mcp_url(ORIGIN) == f"{ORIGIN}/.well-known/mcp"
    assert well_known_mcp_url(f"{ORIGIN}/orders/mcp?x=1") == f"{ORIGIN}/.well-known/mcp"
    assert well_known_mcp_url("http://127.0.0.1:3700/mcp") == "http://127.0.0.1:3700/.well-known/mcp"
    assert well_known_mcp_url("HTTPS://API.example.com:443/x") == f"{ORIGIN}/.well-known/mcp"
    with pytest.raises(ValueError):
        well_known_mcp_url("/relative")


def test_returns_the_document_with_its_skew_and_keeps_members_the_schema_does_not_name() -> None:
    read = read_well_known_mcp({**DOCUMENT, "contact": {"name": "ops"}})
    assert read == {**DOCUMENT, "contact": {"name": "ops"}}
    assert read["clockSkewSeconds"] == 300
    assert read["endpoints"]["handshake"] == f"{ORIGIN}/mcp#_kyaos_handshake"


def test_fills_clock_skew_seconds_with_120_when_absent_and_accepts_a_minimal_document() -> None:
    minimal = read_well_known_mcp({"version": "1.0.0", "serverDid": "did:key:z6Mkserver", "endpoints": {}})
    assert minimal == {"version": "1.0.0", "serverDid": "did:key:z6Mkserver", "endpoints": {}, "clockSkewSeconds": kyaos.DEFAULT_CLOCK_SKEW_SECONDS, "capabilities": {}}
    assert "handshake" not in minimal["endpoints"]


def test_resolves_relative_endpoint_references_against_the_origin_the_document_came_from() -> None:
    read = read_well_known_mcp(
        {"version": "1.0", "serverDid": SERVER, "endpoints": {"tools": "/orders/mcp", "handshake": "/orders/mcp#_kyaos_handshake", "delegation": "delegations"}},
        origin=f"{ORIGIN}/.well-known/mcp",
    )
    assert read["endpoints"] == {"tools": f"{ORIGIN}/orders/mcp", "handshake": f"{ORIGIN}/orders/mcp#_kyaos_handshake", "delegation": f"{ORIGIN}/delegations"}
    # Without an origin they are returned as written.
    assert read_well_known_mcp({"version": "1.0", "serverDid": SERVER, "endpoints": {"tools": "/mcp"}})["endpoints"]["tools"] == "/mcp"


def test_refuses_what_the_schema_refuses_naming_the_member() -> None:
    assert reason(None) == reason([]) == WellKnownMcpProblems.DOCUMENT_NOT_OBJECT == "document_not_object"
    assert reason({**DOCUMENT, "version": "one"}) == "version_invalid"
    assert reason({**DOCUMENT, "version": "1.0\n"}) == "version_invalid"
    assert reason({k: v for k, v in DOCUMENT.items() if k != "version"}) == "version_invalid"
    assert reason({**DOCUMENT, "serverDid": "did:hedera:testnet:0.0.1"}) == "server_did_invalid"
    assert reason({**DOCUMENT, "endpoints": "x"}) == "endpoints_invalid"
    assert reason({**DOCUMENT, "endpoints": {"tools": 1}}) == "endpoints_invalid"
    assert reason({**DOCUMENT, "endpoints": {"tools": "http://[bad"}}, origin=ORIGIN) == "endpoints_invalid"
    assert reason({**DOCUMENT, "clockSkewSeconds": 29}) == "clock_skew_invalid"
    assert reason({**DOCUMENT, "clockSkewSeconds": 601}) == "clock_skew_invalid"
    assert reason({**DOCUMENT, "clockSkewSeconds": "120"}) == "clock_skew_invalid"
    assert reason({**DOCUMENT, "clockSkewSeconds": True}) == "clock_skew_invalid"
    assert reason({**DOCUMENT, "clockSkewSeconds": float("nan")}) == "clock_skew_invalid"
    assert reason({**DOCUMENT, "capabilities": []}) == "capabilities_invalid"
    assert reason({**DOCUMENT, "capabilities": {"proofs": "yes"}}) == "capabilities_invalid"
    assert reason({**DOCUMENT, "statusListCredential": 7}) == "status_list_credential_invalid"
    assert reason({**DOCUMENT, "statusListCredential": "/credentials/status/1"}) == "status_list_credential_invalid"
    assert reason({**DOCUMENT, "supportedDidMethods": "did:web"}) == "advisory_list_invalid"
    assert reason({**DOCUMENT, "proofAlgorithms": [1]}) == "advisory_list_invalid"
    with pytest.raises(WellKnownMcpError, match="version must look like 1.0"):
        read_well_known_mcp({**DOCUMENT, "version": "one"})
    with pytest.raises(WellKnownMcpError) as raised:
        read_well_known_mcp({})
    assert raised.value.code == WELL_KNOWN_MCP_INVALID == "WELL_KNOWN_MCP_INVALID"
    assert raised.value.reason == "version_invalid"
    assert isinstance(raised.value, ValueError)
    # A fractional skew inside the range is a number, as the schema says.
    assert read_well_known_mcp({**DOCUMENT, "clockSkewSeconds": 90.5})["clockSkewSeconds"] == 90.5


def test_is_what_the_client_hands_to_its_handshake_timing() -> None:
    read = read_well_known_mcp(DOCUMENT)
    now = 1_750_000_000
    skew = read["clockSkewSeconds"]
    assert kyaos.within_skew(now - skew, now, skew) is True
    assert kyaos.within_skew(now - skew - 1, now, skew) is False
    request = kyaos.create_handshake_request(audience=read["serverDid"], now=now)
    assert request["audience"] == SERVER and request["timestamp"] == now


class Response:
    def __init__(self, status_code: int, body: Any = None, text: Optional[str] = None) -> None:
        self.status_code = status_code
        self._body = body
        self._text = text

    def json(self) -> Any:
        if self._text is not None:
            raise ValueError("not json")
        return self._body


def recorder(response: Callable[[], Any]) -> Any:
    calls: List[Dict[str, Any]] = []

    def get(url: str, **kwargs: Any) -> Any:
        calls.append({"url": url, **kwargs})
        return response()

    get.calls = calls  # type: ignore[attr-defined]
    return get


def test_fetch_gets_the_document_and_resolves_relative_endpoints_against_the_origin() -> None:
    get = recorder(lambda: Response(200, {**DOCUMENT, "endpoints": {"tools": "/mcp"}}))
    read = fetch_well_known_mcp(f"{ORIGIN}/mcp", get=get)
    assert get.calls == [{"url": f"{ORIGIN}/.well-known/mcp", "headers": {"accept": "application/json"}, "timeout": 5.0}]
    assert read["endpoints"]["tools"] == f"{ORIGIN}/mcp"
    assert read["clockSkewSeconds"] == 300
    fetch_well_known_mcp(ORIGIN, get=get, timeout=1.5)
    assert get.calls[1]["timeout"] == 1.5


def test_fetch_refuses_a_non_200_answer_a_non_json_body_and_a_network_failure() -> None:
    with pytest.raises(WellKnownMcpError, match=f"GET {ORIGIN}/.well-known/mcp answered 404") as raised:
        fetch_well_known_mcp(ORIGIN, get=lambda url, **kw: Response(404, {"error": "not_found"}))
    assert raised.value.reason == "fetch_failed"
    with pytest.raises(WellKnownMcpError) as raised:
        fetch_well_known_mcp(ORIGIN, get=lambda url, **kw: Response(200, text="<html>"))
    assert raised.value.reason == "not_json"

    def down(url: str, **kw: Any) -> Any:
        raise ConnectionError("ECONNREFUSED")

    with pytest.raises(WellKnownMcpError, match="ECONNREFUSED") as raised:
        fetch_well_known_mcp(ORIGIN, get=down)
    assert raised.value.reason == "fetch_failed"
    with pytest.raises(WellKnownMcpError) as raised:
        fetch_well_known_mcp(ORIGIN, get=lambda url, **kw: Response(200, {"version": "1.0"}))
    assert raised.value.reason == "server_did_invalid"


def test_fetch_defaults_to_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    seen: List[str] = []

    def fake_get(url: str, **kwargs: Any) -> Any:
        seen.append(url)
        return Response(200, DOCUMENT)

    monkeypatch.setattr(requests, "get", fake_get)
    assert fetch_well_known_mcp(ORIGIN)["serverDid"] == SERVER
    assert seen == [f"{ORIGIN}/.well-known/mcp"]


def test_is_exported_on_the_kyaos_namespace() -> None:
    assert kyaos.fetch_well_known_mcp is fetch_well_known_mcp
    assert kyaos.read_well_known_mcp is read_well_known_mcp
    assert kyaos.well_known_mcp_url is well_known_mcp_url
    assert kyaos.WellKnownMcpError is WellKnownMcpError
    assert kyaos.WellKnownMcpProblems is WellKnownMcpProblems
    for name in ("fetch_well_known_mcp", "read_well_known_mcp", "well_known_mcp_url", "WellKnownMcpError", "WELL_KNOWN_MCP_PATH"):
        assert name in kyaos.__all__
