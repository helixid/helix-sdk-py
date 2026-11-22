# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story L1-D: the /.well-known/mcp discovery document, built from config
and validated against well-known-mcpi.json. The same cases as helix-sdk-js's
mcp-middleware/tests/well-known.test.ts. The vendored schema is compared byte
for byte with helix-core's copy, read from the sibling checkout
(``../helix-core/fixtures``) or HELIX_CORE_FIXTURES_DIR; that case skips when
neither exists.
"""

from __future__ import annotations

import asyncio
import json
import os
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

import helix_mcp_middleware as middleware
from helix_mcp_middleware import (
    DEFAULT_PROOF_ALGORITHMS,
    DEFAULT_SUPPORTED_DID_METHODS,
    WELL_KNOWN_MCP_INVALID,
    WELL_KNOWN_MCP_PATH,
    WellKnownMcpConfig,
    WellKnownMcpError,
    WellKnownMcpResponse,
    assert_well_known_mcp,
    build_well_known_mcp,
    create_well_known_mcp,
    describe_kyaos,
    validate_well_known_mcp,
)
from helix_mcp_middleware.well_known import _ecma_pattern, _is_email, _is_uri, _is_uri_reference

ORIGIN = "https://api.example.com"
SERVER = "did:web:api.example.com"
BASE = {"public_origin": ORIGIN, "server_did": SERVER}

SCHEMA_BYTES = resources.files("helix_mcp_middleware").joinpath("schemas/well-known-mcpi.json").read_bytes()
SCHEMA = json.loads(SCHEMA_BYTES)
CORE_FIXTURES = Path(os.environ.get("HELIX_CORE_FIXTURES_DIR") or Path(__file__).resolve().parents[2] / "helix-core" / "fixtures")
VENDORED_SCHEMA = CORE_FIXTURES / "kya-os" / "schemas" / "well-known-mcpi.json"


def build(**kwargs: Any) -> Dict[str, Any]:
    return build_well_known_mcp(**{**BASE, **kwargs})


def problems_of(**kwargs: Any) -> Tuple[str, ...]:
    with pytest.raises(WellKnownMcpError) as raised:
        build(**kwargs)
    return raised.value.problems


# -- validate_well_known_mcp ------------------------------------------------------------------------


def test_accepts_the_schemas_own_example_and_refuses_a_document_missing_its_required_members() -> None:
    assert validate_well_known_mcp(SCHEMA["examples"][0]).ok is True
    result = validate_well_known_mcp({"version": "one"})
    assert result.ok is False
    assert set(result.problems) == {
        "/ must have required property 'serverDid'",
        "/ must have required property 'endpoints'",
        '/version must match pattern "^\\d+\\.\\d+(\\.\\d+)?$"',
    }
    with pytest.raises(WellKnownMcpError):
        assert_well_known_mcp({"version": "1.0", "serverDid": "did:hedera:x", "endpoints": {}})
    with pytest.raises(WellKnownMcpError, match="clockSkewSeconds must be >= 30"):
        assert_well_known_mcp({"version": "1.0", "serverDid": SERVER, "endpoints": {}, "clockSkewSeconds": 10})
    with pytest.raises(WellKnownMcpError, match='endpoints/tools must match format "uri-reference"'):
        assert_well_known_mcp({"version": "1.0", "serverDid": SERVER, "endpoints": {"tools": "not a uri reference "}})
    with pytest.raises(WellKnownMcpError, match='statusListCredential must match format "uri"'):
        assert_well_known_mcp({"version": "1.0", "serverDid": SERVER, "endpoints": {}, "statusListCredential": "/relative"})
    assert_well_known_mcp(SCHEMA["examples"][0])


def test_reports_problems_the_way_ajv_does_so_both_languages_agree() -> None:
    result = validate_well_known_mcp({
        "version": "1.0", "serverDid": SERVER, "endpoints": [], "clockSkewSeconds": 601,
        "capabilities": {"proofs": "yes", "audit": {"profile": "AAP-9"}},
        "publicKeys": [{"id": "k", "type": "t", "publicKeyJwk": {"kty": "RSA", "crv": "Ed25519"}}],
        "contact": {"email": "nope"},
    })
    assert set(result.problems) == {
        "/endpoints must be object",
        "/clockSkewSeconds must be <= 600",
        "/capabilities/proofs must be boolean",
        "/capabilities/audit must have required property 'recorderTopology'",
        "/capabilities/audit must have required property 'delivery'",
        "/capabilities/audit must have required property 'journalDurability'",
        "/capabilities/audit must have required property 'atomicAppend'",
        "/capabilities/audit must have required property 'sourceHighWater'",
        "/capabilities/audit must have required property 'merkleCheckpoints'",
        "/capabilities/audit must have required property 'independentObservation'",
        "/capabilities/audit must have required property 'supportingAnchors'",
        "/capabilities/audit must have required property 'evidenceRetention'",
        "/capabilities/audit/profile must be equal to one of the allowed values",
        "/publicKeys/0/publicKeyJwk must have required property 'x'",
        "/publicKeys/0/publicKeyJwk/kty must be equal to constant",
        '/contact/email must match format "email"',
    }
    # The one closed object in the schema is capabilities.audit.
    audit = {
        "profile": "AAP-1", "recorderTopology": "none", "delivery": "buffered", "journalDurability": "none", "atomicAppend": False,
        "sourceHighWater": False, "merkleCheckpoints": False, "independentObservation": False, "supportingAnchors": [],
        "evidenceRetention": "none",
    }
    assert validate_well_known_mcp({"version": "1.0", "serverDid": SERVER, "endpoints": {}, "capabilities": {"audit": audit}}).ok
    extra = validate_well_known_mcp({"version": "1.0", "serverDid": SERVER, "endpoints": {}, "capabilities": {"audit": {**audit, "extra": 1}}})
    assert extra.problems == ("/capabilities/audit must NOT have additional properties",)
    # A JSON pointer escapes "~" and "/" in member names.
    weird = validate_well_known_mcp({"version": "1.0", "serverDid": SERVER, "endpoints": {"a/b~c": "not a uri reference "}})
    assert weird.problems == ('/endpoints/a~1b~0c must match format "uri-reference"',)
    # Anything else falls back to jsonschema's own message.
    unique = validate_well_known_mcp({"version": "1.0", "serverDid": SERVER, "endpoints": {}, "capabilities": {"audit": {
        "profile": "AAP-1", "recorderTopology": "none", "delivery": "buffered", "journalDurability": "none", "atomicAppend": False,
        "sourceHighWater": False, "merkleCheckpoints": False, "independentObservation": False, "supportingAnchors": ["worm", "worm"],
        "evidenceRetention": "none",
    }}})
    assert unique.ok is False and unique.problems[0].startswith("/capabilities/audit/supportingAnchors ")


def test_reads_patterns_and_formats_the_ecma_way() -> None:
    # "$" is the end of the input, not "before a final newline".
    assert _ecma_pattern(r"^did:(key|web):.+$").search("did:web:x\n") is None
    assert _ecma_pattern(r"^a\$").search("a$") is not None
    assert validate_well_known_mcp({"version": "1.0\n", "serverDid": SERVER, "endpoints": {}}).problems == ('/version must match pattern "^\\d+\\.\\d+(\\.\\d+)?$"',)
    # \d is ASCII.
    assert validate_well_known_mcp({"version": "١.٠", "serverDid": SERVER, "endpoints": {}}).ok is False
    # ajv-formats' "uri" needs a scheme and a ":" or "/", "uri-reference" takes relative references too.
    assert _is_uri("https://a.example/x?y#z") and _is_uri("urn:uuid:1") and _is_uri("HTTPS://A.EXAMPLE/X")
    assert not _is_uri("/relative") and not _is_uri("https://a b") and not _is_uri("plain")
    assert _is_uri_reference("/mcp#_kyaos_handshake") and _is_uri_reference("//host/p") and _is_uri_reference("http://[::1]:80/p")
    assert not _is_uri_reference("not a uri reference ") and not _is_uri_reference("%zz")
    assert _is_email("ops@example.com") and not _is_email("nope")
    # Formats apply to strings only; the type keyword reports the rest.
    assert validate_well_known_mcp({"version": "1.0", "serverDid": SERVER, "endpoints": {"tools": 5}}).problems == ("/endpoints/tools must be string",)


def test_has_no_vectors_in_the_vendored_suite() -> None:
    """L1.10 and L1.11 are implementation-specific (CONFORMANCE.md), so the schema and its example are the
    upstream fixtures. Recorded here so the absence of a vector test is a decision, not an omission."""
    assert len(SCHEMA["examples"]) == 1


@pytest.mark.skipif(not VENDORED_SCHEMA.exists(), reason=f"helix-core fixtures not found at {CORE_FIXTURES}: check out helix-core beside helix-sdk-py or set HELIX_CORE_FIXTURES_DIR")
def test_the_packaged_schema_is_byte_for_byte_the_vendored_one() -> None:
    assert SCHEMA_BYTES == VENDORED_SCHEMA.read_bytes()


# -- build_well_known_mcp ---------------------------------------------------------------------------


def test_fills_every_field_from_config_and_validates_the_result() -> None:
    kyaos = describe_kyaos(clock_skew_seconds=300, tools_endpoint=f"{ORIGIN}/mcp")
    document = build(
        kyaos=kyaos,
        status_list_credential=f"{ORIGIN}/credentials/status/1",
        capabilities={"delegation": True, "statusList": True},
    )
    assert document == {
        "version": "1.0",
        "serverDid": SERVER,
        "endpoints": {"tools": f"{ORIGIN}/mcp", "handshake": f"{ORIGIN}/mcp#_kyaos_handshake"},
        "clockSkewSeconds": 300,
        "capabilities": {"proofs": True, "delegation": True, "statusList": True, "crisp": False},
        "statusListCredential": f"{ORIGIN}/credentials/status/1",
        "supportedDidMethods": ["did:web", "did:key"],
        "proofAlgorithms": ["EdDSA"],
    }
    # Members in the JS middleware's order, so the served bytes are the same.
    assert list(document) == ["version", "serverDid", "endpoints", "clockSkewSeconds", "capabilities", "statusListCredential", "supportedDidMethods", "proofAlgorithms"]
    assert validate_well_known_mcp(document).ok
    assert document["supportedDidMethods"] == list(DEFAULT_SUPPORTED_DID_METHODS)
    assert document["proofAlgorithms"] == list(DEFAULT_PROOF_ALGORITHMS)
    # A config object works as well as keywords; the advisory lists can be overridden.
    custom = build_well_known_mcp(WellKnownMcpConfig(**BASE, supported_did_methods=["did:web"], proof_algorithms=["EdDSA", "ES256"]))
    assert custom["supportedDidMethods"] == ["did:web"] and custom["proofAlgorithms"] == ["EdDSA", "ES256"]


def test_sets_each_capability_true_only_while_that_feature_is_enabled() -> None:
    bare = build()
    assert bare["capabilities"] == {"proofs": False, "delegation": False, "statusList": False, "crisp": False}
    assert "statusListCredential" not in bare
    assert bare["endpoints"] == {"tools": f"{ORIGIN}/mcp"}
    assert build(kyaos=describe_kyaos())["capabilities"]["proofs"] is True
    assert build(capabilities={"crisp": True, "delegation": False})["capabilities"] == {"proofs": False, "delegation": False, "statusList": False, "crisp": True}
    # Only a real True turns a flag on.
    assert build(capabilities={"crisp": "yes"})["capabilities"]["crisp"] is False


def test_advertises_endpoints_handshake_only_while_l2a_sessions_are_enabled() -> None:
    assert build(kyaos=describe_kyaos(session_enabled=True))["endpoints"]["handshake"] == f"{ORIGIN}/mcp#_kyaos_handshake"
    assert build(kyaos=describe_kyaos(session_enabled=False))["endpoints"] == {"tools": f"{ORIGIN}/mcp"}
    assert "handshake" not in build()["endpoints"]


def test_builds_endpoints_from_public_origin_never_the_bind_address_behind_a_sub_path_proxy() -> None:
    kyaos = describe_kyaos(tools_endpoint="http://127.0.0.1:3700/mcp")
    document = build(kyaos=kyaos, tools_endpoint="/orders/mcp")
    assert document["endpoints"] == {"tools": f"{ORIGIN}/orders/mcp", "handshake": f"{ORIGIN}/orders/mcp#_kyaos_handshake"}
    assert "127.0.0.1" not in json.dumps(document)
    assert build(tools_endpoint=f"{ORIGIN}/orders/mcp")["endpoints"]["tools"] == f"{ORIGIN}/orders/mcp"
    assert build(tools_endpoint="mcp")["endpoints"]["tools"] == f"{ORIGIN}/mcp"
    # The origin is normalised the WHATWG way: lower-case host, default port dropped.
    assert build_well_known_mcp(public_origin="HTTPS://API.Example.com:443/", server_did=SERVER)["endpoints"]["tools"] == f"{ORIGIN}/mcp"
    assert build_well_known_mcp(public_origin="http://[::1]:3700", server_did=SERVER)["endpoints"]["tools"] == "http://[::1]:3700/mcp"
    with pytest.raises(WellKnownMcpError, match="is not at public_origin"):
        build(tools_endpoint="http://127.0.0.1:3700/mcp")
    with pytest.raises(WellKnownMcpError, match="tools_endpoint must be a path or an absolute URL"):
        build(tools_endpoint="http://[bad")


def test_takes_the_skew_from_config_or_the_runtime_and_refuses_a_mismatch_or_a_value_outside_30_to_600() -> None:
    assert build()["clockSkewSeconds"] == 120
    assert build(clock_skew_seconds=60)["clockSkewSeconds"] == 60
    assert build(kyaos=describe_kyaos(clock_skew_seconds=45))["clockSkewSeconds"] == 45
    assert build(kyaos=describe_kyaos(clock_skew_seconds=45), clock_skew_seconds=45)["clockSkewSeconds"] == 45
    with pytest.raises(WellKnownMcpError, match="differs from the KYA-OS runtime's 45"):
        build(kyaos=describe_kyaos(clock_skew_seconds=45), clock_skew_seconds=60)
    for bad in (29, 601, 120.5, float("nan"), True):
        with pytest.raises(WellKnownMcpError, match="clock_skew_seconds must be an integer from 30 to 600"):
            build(clock_skew_seconds=bad)


def test_fails_fast_with_the_reason_on_a_configuration_that_cannot_make_a_valid_document() -> None:
    with pytest.raises(WellKnownMcpError, match="public_origin is required"):
        build_well_known_mcp(server_did=SERVER)
    with pytest.raises(WellKnownMcpError, match="public_origin is required"):
        build_well_known_mcp(public_origin="", server_did=SERVER)
    with pytest.raises(WellKnownMcpError, match="public_origin must be an absolute URL"):
        build_well_known_mcp(public_origin="api.example.com", server_did=SERVER)
    with pytest.raises(WellKnownMcpError, match="public_origin must be an absolute URL"):
        build_well_known_mcp(public_origin="https://api.example.com:99999", server_did=SERVER)
    with pytest.raises(WellKnownMcpError, match=r"public_origin must be http\(s\)"):
        build_well_known_mcp(public_origin="ftp://api.example.com", server_did=SERVER)
    with pytest.raises(WellKnownMcpError, match="put the MCP path in tools_endpoint"):
        build_well_known_mcp(public_origin=f"{ORIGIN}/mcp", server_did=SERVER)
    with pytest.raises(WellKnownMcpError, match="server_did is required"):
        build_well_known_mcp(public_origin=ORIGIN)
    with pytest.raises(WellKnownMcpError, match="server_did must be a did:web or did:key"):
        build_well_known_mcp(public_origin=ORIGIN, server_did="did:hedera:testnet:0.0.1")
    with pytest.raises(WellKnownMcpError, match="server_did must be a did:web or did:key"):
        build_well_known_mcp(public_origin=ORIGIN, server_did="did:web:x\n")
    # What the schema catches rather than the config checks.
    with pytest.raises(WellKnownMcpError) as raised:
        build(version="one")
    error = raised.value
    assert error.code == WELL_KNOWN_MCP_INVALID == "WELL_KNOWN_MCP_INVALID"
    assert error.problems == ('/version must match pattern "^\\d+\\.\\d+(\\.\\d+)?$"',)
    assert "does not validate against well-known-mcpi.json: /version" in str(error)
    assert isinstance(error, ValueError)
    assert problems_of(status_list_credential="credentials/status/1") == ('/statusListCredential must match format "uri"',)
    build(version="2.1.3")


# -- create_well_known_mcp: the ASGI route --------------------------------------------------------


def serve(route: Any, method: str = "GET", path: str = WELL_KNOWN_MCP_PATH, kind: str = "http") -> Tuple[bool, List[Dict[str, Any]]]:
    sent: List[Dict[str, Any]] = []

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    handled = asyncio.run(route.handle({"type": kind, "method": method, "path": path}, None, send))
    return handled, sent


def headers_of(sent: List[Dict[str, Any]]) -> Dict[str, str]:
    return {k.decode(): v.decode() for k, v in sent[0]["headers"]}


def test_is_on_by_default_and_serves_the_validated_document_on_get_and_head() -> None:
    route = create_well_known_mcp(**BASE, kyaos=describe_kyaos())
    assert route.enabled is True and route.path == "/.well-known/mcp" == WELL_KNOWN_MCP_PATH
    body = json.dumps(route.document, separators=(",", ":")).encode()
    assert route.respond() == WellKnownMcpResponse(status=200, headers={"content-type": "application/json", "cache-control": "public, max-age=300"}, body=body)

    handled, sent = serve(route)
    assert handled is True
    assert sent[0]["status"] == 200
    assert headers_of(sent) == {"content-type": "application/json", "cache-control": "public, max-age=300", "content-length": str(len(body))}
    assert json.loads(sent[1]["body"]) == route.document
    handled, sent = serve(route, method="HEAD")
    assert handled is True and sent[0]["status"] == 200 and headers_of(sent)["content-length"] == str(len(body)) and sent[1]["body"] == b""
    # Everything else is left to the host.
    for method, path, kind in (("POST", WELL_KNOWN_MCP_PATH, "http"), ("GET", "/.well-known/other", "http"), ("GET", "/mcp", "http"), ("GET", WELL_KNOWN_MCP_PATH, "websocket")):
        assert serve(route, method, path, kind) == (False, [])


def test_serves_non_ascii_as_utf8_like_json_stringify() -> None:
    route = create_well_known_mcp(**BASE, supported_did_methods=["did:wéb"])
    assert '"did:wéb"'.encode("utf-8") in route.respond().body


def test_answers_404_when_disabled_and_then_needs_no_configuration() -> None:
    route = create_well_known_mcp(enabled=False)
    assert route.enabled is False and route.document is None
    assert route.respond() == WellKnownMcpResponse(status=404, headers={"content-type": "application/json", "cache-control": "no-store"}, body=b'{"error":"not_found"}')
    handled, sent = serve(route)
    assert handled is True and sent[0]["status"] == 404 and json.loads(sent[1]["body"]) == {"error": "not_found"}
    assert serve(route, path="/mcp") == (False, [])
    # Disabled with a bad configuration is still fine: nothing is built.
    create_well_known_mcp(WellKnownMcpConfig(enabled=False, public_origin="nope"))
    with pytest.raises(WellKnownMcpError):
        create_well_known_mcp(enabled=True, public_origin="nope", server_did=SERVER)
    with pytest.raises(WellKnownMcpError, match="public_origin is required"):
        create_well_known_mcp()


def test_is_exported_from_the_package() -> None:
    for name in (
        "create_well_known_mcp", "build_well_known_mcp", "validate_well_known_mcp", "assert_well_known_mcp", "WellKnownMcpError",
        "WellKnownMcp", "WellKnownMcpConfig", "WellKnownMcpResponse", "WellKnownMcpValidation",
    ):
        assert name in middleware.__all__ and hasattr(middleware, name)
    assert middleware.WELL_KNOWN_MCP_PATH == "/.well-known/mcp"
    assert middleware.DEFAULT_WELL_KNOWN_VERSION == "1.0"
    assert middleware.DEFAULT_SUPPORTED_DID_METHODS == ("did:web", "did:key")
    assert middleware.DEFAULT_PROOF_ALGORITHMS == ("EdDSA",)
