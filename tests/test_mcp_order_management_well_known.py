# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story L1-D in examples/mcp_order_management: the sample serves the
discovery document at /.well-known/mcp, and WELL_KNOWN_MCP /
STATUS_LIST_CREDENTIAL in its environment. The same cases as the JS sample's
tests/well-known.test.ts. Needs the `mcp` extra, so Python 3.10+.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest

pytest.importorskip("mcp")
pytest.importorskip("starlette")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from starlette.testclient import TestClient  # noqa: E402

from helix_sdk import kyaos  # noqa: E402
from helix_sdk.keys import generate_key_pair  # noqa: E402
from helix_mcp_middleware import (  # noqa: E402
    KyaOsOptions,
    KyaOsRuntime,
    KyaOsSessionOptions,
    MCPMiddlewareOptions,
    WellKnownMcp,
    create_kyaos,
    create_well_known_mcp,
    validate_well_known_mcp,
)
from mcp_order_management import __main__ as entry  # noqa: E402
from mcp_order_management.app import create_order_app  # noqa: E402

SERVICE = "did:web:orders.example"
PUBLIC_ORIGIN = "https://orders.example"
BIND = "http://127.0.0.1:3700"
KEYS = generate_key_pair()
SIGNER = kyaos.EnvSigner(SERVICE, env_var="SAMPLE_SERVICE_KEY", env={"SAMPLE_SERVICE_KEY": KEYS.private_key})


def client(kyaos_runtime: Optional[KyaOsRuntime] = None, well_known: Optional[WellKnownMcp] = None) -> TestClient:
    options = MCPMiddlewareOptions(client=MagicMock(), service_did=SERVICE, validate_oauth_token=lambda token: {"sub": "x", "scopes": []})
    return TestClient(create_order_app(f"{BIND}/orders/mcp", options, kyaos=kyaos_runtime, well_known=well_known), base_url=BIND)


def test_returns_the_document_which_validates_and_carries_the_public_urls_not_the_bind_address() -> None:
    runtime = create_kyaos(KyaOsOptions(signer=SIGNER, public_origin=PUBLIC_ORIGIN, clock_skew_seconds=60, tools_endpoint=f"{BIND}/orders/mcp"))
    well_known = create_well_known_mcp(public_origin=PUBLIC_ORIGIN, server_did=SERVICE, tools_endpoint="/orders/mcp", kyaos=runtime.describe())
    http = client(runtime, well_known)
    res = http.get("/.well-known/mcp")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/json"
    raw = res.json()
    assert validate_well_known_mcp(raw).ok
    # A client reads it (every endpoint is absolute already, so nothing changes) and takes the skew the handshake enforces.
    document = kyaos.read_well_known_mcp(raw, origin=BIND)
    assert document == {
        "version": "1.0",
        "serverDid": SERVICE,
        "endpoints": {"tools": f"{PUBLIC_ORIGIN}/orders/mcp", "handshake": f"{PUBLIC_ORIGIN}/orders/mcp#_kyaos_handshake"},
        "clockSkewSeconds": 60,
        "capabilities": {"proofs": True, "delegation": False, "statusList": False, "crisp": False},
        "supportedDidMethods": ["did:web", "did:key"],
        "proofAlgorithms": ["EdDSA"],
    }
    assert "127.0.0.1" not in res.text
    assert document["clockSkewSeconds"] == runtime.clock_skew_seconds
    # The bytes are JSON.stringify's, as the JS sample serves them.
    assert res.content == json.dumps(raw, separators=(",", ":")).encode()
    assert http.head("/.well-known/mcp").status_code == 200
    # The rest of the sample is untouched.
    assert http.get("/.well-known/oauth-protected-resource/orders/mcp").status_code == 200
    assert http.get("/elsewhere").status_code == 404


def test_shows_no_proofs_and_no_handshake_without_the_kyaos_layer_and_no_handshake_while_sessions_are_off() -> None:
    http = client(well_known=create_well_known_mcp(public_origin=PUBLIC_ORIGIN, server_did=SERVICE, tools_endpoint="/orders/mcp"))
    document = kyaos.read_well_known_mcp(http.get("/.well-known/mcp").json())
    assert document["capabilities"]["proofs"] is False
    assert document["endpoints"] == {"tools": f"{PUBLIC_ORIGIN}/orders/mcp"}
    assert document["clockSkewSeconds"] == 120

    no_sessions = create_kyaos(KyaOsOptions(signer=SIGNER, session=KyaOsSessionOptions(enabled=False)))
    without_handshake = create_well_known_mcp(public_origin=PUBLIC_ORIGIN, server_did=SERVICE, kyaos=no_sessions.describe())
    assert without_handshake.document is not None
    assert without_handshake.document["capabilities"]["proofs"] is True
    assert without_handshake.document["endpoints"] == {"tools": f"{PUBLIC_ORIGIN}/mcp"}


def test_answers_404_when_the_route_is_disabled_and_when_the_sample_is_started_without_it() -> None:
    res = client(well_known=create_well_known_mcp(enabled=False)).get("/.well-known/mcp")
    assert res.status_code == 404
    assert res.json() == {"error": "not_found"}
    assert client().get("/.well-known/mcp").status_code == 404


class TestWellKnownFromEnv:
    RESOURCE = f"{BIND}/orders/mcp"

    def test_builds_the_document_from_the_environment_and_the_kyaos_runtime(self) -> None:
        runtime = entry.kyaos_from_env({"SERVICE_SIGNING_KEY": KEYS.private_key, "KYAOS_CLOCK_SKEW_SECONDS": "45"}, self.RESOURCE, SERVICE)
        well_known, off = entry.well_known_from_env(
            {"KYAOS_PUBLIC_ORIGIN": PUBLIC_ORIGIN, "STATUS_LIST_CREDENTIAL": f"{PUBLIC_ORIGIN}/status/1"}, self.RESOURCE, SERVICE, runtime
        )
        assert off is None and well_known is not None
        assert well_known.document == {
            "version": "1.0",
            "serverDid": SERVICE,
            "endpoints": {"tools": f"{PUBLIC_ORIGIN}/orders/mcp", "handshake": f"{PUBLIC_ORIGIN}/orders/mcp#_kyaos_handshake"},
            "clockSkewSeconds": 45,
            "capabilities": {"proofs": True, "delegation": False, "statusList": False, "crisp": False},
            "statusListCredential": f"{PUBLIC_ORIGIN}/status/1",
            "supportedDidMethods": ["did:web", "did:key"],
            "proofAlgorithms": ["EdDSA"],
        }
        assert entry.describe_well_known(well_known, off) == (
            f"{PUBLIC_ORIGIN}/.well-known/mcp, serverDid {SERVICE}, skew 45 s, handshake advertised "
            "(route the path at that origin to this server: see helix-sdk-js mcp-middleware/docs/well-known.md)"
        )

    def test_defaults_to_the_origin_of_mcp_resource_without_kyaos(self) -> None:
        well_known, off = entry.well_known_from_env({}, self.RESOURCE, "did:key:z6Mkservice", None)
        assert off is None and well_known is not None and well_known.document is not None
        assert well_known.document["endpoints"] == {"tools": f"{BIND}/orders/mcp"}
        assert well_known.document["capabilities"]["proofs"] is False
        assert "handshake absent" in entry.describe_well_known(well_known, off)

    @pytest.mark.parametrize(
        "env, service_did, expected",
        [
            ({}, None, "off (set SERVICE_DID)"),
            ({}, "", "off (set SERVICE_DID)"),
            ({}, "did:hedera:testnet:0.0.1", "is not a did:web or did:key"),
        ],
    )
    def test_stays_off_with_the_reason(self, env: Dict[str, str], service_did: Optional[str], expected: str) -> None:
        well_known, off = entry.well_known_from_env(env, self.RESOURCE, service_did, None)
        assert well_known is None and off is not None and expected in off
        assert expected in entry.describe_well_known(well_known, off)

    def test_well_known_mcp_0_serves_404(self) -> None:
        well_known, off = entry.well_known_from_env({"WELL_KNOWN_MCP": "0"}, self.RESOURCE, SERVICE, None)
        assert well_known is not None and well_known.enabled is False and well_known.respond().status == 404
        assert off == "off (WELL_KNOWN_MCP=0): 404"
        assert entry.describe_well_known(well_known, off) == off
        assert entry.describe_well_known(None, None) == "off"

    @pytest.mark.parametrize(
        "env, service_did, message",
        [
            ({"WELL_KNOWN_MCP": "1"}, "did:hedera:testnet:0.0.1", "server_did must be a did:web or did:key"),
            ({"KYAOS_PUBLIC_ORIGIN": "https://orders.example/mcp"}, SERVICE, "put the MCP path in tools_endpoint"),
            ({"STATUS_LIST_CREDENTIAL": "status/1"}, SERVICE, 'statusListCredential must match format "uri"'),
        ],
    )
    def test_refuses_a_document_that_would_not_validate(self, env: Dict[str, str], service_did: str, message: str, capsys: Any) -> None:
        with pytest.raises(SystemExit):
            entry.well_known_from_env(env, self.RESOURCE, service_did, None)
        err = capsys.readouterr().err
        assert "order-management: /.well-known/mcp:" in err and message in err
