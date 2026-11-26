# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story C-A in helix_mcp_middleware: serve_identity serves the service's
own did.json and card.json from its origin and projects a claim-minimal
summary into server.json _meta["org.kya-os/card"] with a cardRef;
resolve_server_card dereferences it and falls back to the canonical card when
the projection was stripped. The same cases as helix-sdk-js's
mcp-middleware/tests/identity.test.ts, plus parity with the entities of
helix-core's fixtures/kya-os-helix/entity-card.json (sibling checkout or
HELIX_CORE_FIXTURES_DIR). No `mcp` extra needed: runs on Python 3.9.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List

import pytest

import helix_sdk
from helix_sdk import codes
from helix_sdk.entity_card import EntityCardError, create_safe_fetch, validate_entity_card
from helix_mcp_middleware import ServedIdentity, ServeIdentityOptions, resolve_server_card, serve_identity

FIXTURES_DIR = Path(os.environ.get("HELIX_CORE_FIXTURES_DIR") or Path(__file__).resolve().parents[2] / "helix-core" / "fixtures")
JWK = {"kty": "OKP", "crv": "Ed25519", "x": "JUO5L_EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0"}
CONTEXTS = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]


def _serving(served: Dict[str, Any]):
    calls: List[str] = []

    def fetch_json(url: str) -> Any:
        calls.append(url)
        if url not in served:
            raise EntityCardError("unavailable", f"{url} answered HTTP 404")
        return served[url]

    fetch_json.calls = calls  # type: ignore[attr-defined]
    return fetch_json


def test_builds_both_documents_from_the_public_origin_and_path_and_anchors_the_card():
    identity = serve_identity(ServeIdentityOptions(
        public_origin="https://mcp.example.com",
        path="/mcp",
        card={"name": "Orders", "kid": "key-1", "publicKeyJwk": JWK, "capabilities": ["tools/list", "tools/call"], "responsibleParty": "did:web:example.com:org:acme"},
        also_known_as=["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"],
        service=[{"id": "#home", "type": "LinkedDomains", "serviceEndpoint": "https://example.com"}],
    ))
    did = "did:web:mcp.example.com:mcp"
    assert identity.did == did
    assert identity.paths == {"did_document": "/mcp/did.json", "card": "/mcp/card.json"}
    assert identity.did_document_url == "https://mcp.example.com/mcp/did.json"
    assert identity.card_url == "https://mcp.example.com/mcp/card.json"
    assert identity.did_document == {
        "@context": CONTEXTS,
        "id": did,
        "alsoKnownAs": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"],
        "verificationMethod": [{"id": f"{did}#key-1", "type": "Ed25519VerificationKey2020", "controller": did, "publicKeyJwk": JWK}],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
        "service": [
            {"id": "#home", "type": "LinkedDomains", "serviceEndpoint": "https://example.com"},
            {"id": "#kya-os-card", "type": "KyaOsEntityCard", "serviceEndpoint": "https://mcp.example.com/mcp/card.json"},
        ],
    }
    assert validate_entity_card(identity.card) == []
    assert identity.card == {
        "id": did,
        "entityType": "mcp",
        "name": "Orders",
        "kid": f"{did}#key-1",
        "publicKeyJwk": {**JWK, "kid": f"{did}#key-1"},
        "capabilities": ["tools/list", "tools/call"],
        "responsibleParty": "did:web:example.com:org:acme",
        "didDocument": "https://mcp.example.com/mcp/did.json",
        "proofProfile": "org.kya-os/proof.v1",
    }
    summary = {"id": did, "entityType": "mcp", "name": "Orders", "capabilities": ["tools/list", "tools/call"],
               "responsibleParty": "did:web:example.com:org:acme", "proofProfile": "org.kya-os/proof.v1",
               "org.kya-os/cardRef": "https://mcp.example.com/mcp/card.json"}
    assert identity.server_meta() == {"org.kya-os/card": summary}
    assert identity.server_meta(by_ref=True) == {"org.kya-os/card": {"org.kya-os/cardRef": "https://mcp.example.com/mcp/card.json"}}
    assert identity.project_server_json({"name": "orders", "_meta": {"modelcontextprotocol/mcp": {"x": 1}}}) == {
        "name": "orders", "_meta": {"modelcontextprotocol/mcp": {"x": 1}, "org.kya-os/card": summary}}
    assert identity.project_server_json({"name": "orders"})["_meta"] == identity.server_meta()
    assert identity.project_server_json({"name": "orders", "_meta": "junk"})["_meta"] == identity.server_meta()


def test_root_origin_is_a_bare_did_web_at_the_well_known_paths_and_path_defaults_to_the_origin():
    root = serve_identity(public_origin="https://mcp.example.com/", card={"name": "Root"})
    assert root.did == "did:web:mcp.example.com"
    assert root.paths == {"did_document": "/.well-known/did.json", "card": "/.well-known/kya-os-card.json"}
    assert root.card_url == "https://mcp.example.com/.well-known/kya-os-card.json"
    assert root.did_document["verificationMethod"] == [] and root.did_document["authentication"] == [] and root.did_document["assertionMethod"] == []
    assert "alsoKnownAs" not in root.did_document
    under = serve_identity(public_origin="https://mcp.example.com/api/v2")
    assert under.did == "did:web:mcp.example.com:api:v2"
    assert under.card["name"] == "did:web:mcp.example.com:api:v2"
    # A default port is dropped from the origin, as URL.origin drops it.
    assert serve_identity(public_origin="https://MCP.example.com:443/x").did == "did:web:mcp.example.com:x"


def test_behind_a_local_http_origin_the_documents_name_the_origin_they_are_reachable_at():
    local = serve_identity(public_origin="http://127.0.0.1:3794", path="/mcp", card={"name": "Local"})
    assert local.did == "did:web:127.0.0.1%3A3794:mcp"
    assert local.did_document_url == "http://127.0.0.1:3794/mcp/did.json"
    assert local.card_url == "http://127.0.0.1:3794/mcp/card.json"
    assert local.card["didDocument"] == "http://127.0.0.1:3794/mcp/did.json"
    assert local.did_document["service"] == [{"id": "#kya-os-card", "type": "KyaOsEntityCard", "serviceEndpoint": "http://127.0.0.1:3794/mcp/card.json"}]
    named = serve_identity(public_origin="https://proxy.example.com", path="/mcp", did="did:web:orders.example", card={"name": "Named"})
    assert named.did == "did:web:orders.example"
    assert named.paths == {"did_document": "/.well-known/did.json", "card": "/.well-known/kya-os-card.json"}
    assert named.card_url == "https://proxy.example.com/.well-known/kya-os-card.json"
    ipv6 = serve_identity(public_origin="http://[::1]:8080", card={"name": "v6"})
    assert ipv6.card_url == "http://[::1]:8080/.well-known/kya-os-card.json"


def test_serves_documents_helix_init_wrote_and_refuses_ones_for_another_did_or_an_invalid_card():
    did_document = {"id": "did:web:mcp.example.com:mcp", "verificationMethod": [], "service": [{"id": "#kya-os-card", "type": "KyaOsEntityCard", "serviceEndpoint": "https://mcp.example.com/mcp/card.json"}]}
    card = {"id": "did:web:mcp.example.com:mcp", "entityType": "mcp", "name": "Written", "proofProfile": "org.kya-os/proof.v1"}
    identity = serve_identity(public_origin="https://mcp.example.com", path="/mcp", documents={"didDocument": did_document, "card": card})
    assert identity.did_document == did_document
    assert identity.card == card
    with pytest.raises(ValueError, match="DID document is for did:web:other"):
        serve_identity(public_origin="https://mcp.example.com", path="/mcp", documents={"didDocument": {**did_document, "id": "did:web:other"}, "card": card})
    with pytest.raises(ValueError, match="DID document is for None"):
        serve_identity(public_origin="https://mcp.example.com", path="/mcp", documents={"didDocument": "nope", "card": card})
    with pytest.raises(ValueError, match="card is for"):
        serve_identity(public_origin="https://mcp.example.com", path="/mcp", documents={"didDocument": did_document, "card": {**card, "id": "did:web:other"}})
    with pytest.raises(EntityCardError, match="bogusField"):
        serve_identity(public_origin="https://mcp.example.com", path="/mcp", documents={"didDocument": did_document, "card": {**card, "bogusField": 1}})
    with pytest.raises(ValueError, match="absolute URL"):
        serve_identity(public_origin="not a url")
    with pytest.raises(ValueError, match="absolute URL"):
        serve_identity(public_origin=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=r"http\(s\) origin"):
        serve_identity(public_origin="ftp://mcp.example.com")
    with pytest.raises(ValueError, match="did:web"):
        serve_identity(public_origin="https://mcp.example.com", did="did:key:z6Mk")
    with pytest.raises(ValueError, match="unencoded port"):
        serve_identity(public_origin="http://localhost:3000", did="did:web:localhost:3000:mcp")
    assert serve_identity(public_origin="http://localhost:3000", path="/mcp").did == "did:web:localhost%3A3000:mcp"
    with pytest.raises(EntityCardError, match="proof") as refused:
        serve_identity(public_origin="https://mcp.example.com", card={"name": "X", "proof": {}})
    assert refused.value.code == codes.ENTITY_CARD_INVALID == "ENTITY_CARD_INVALID"


def _asgi(identity: ServedIdentity, method: str, path: str, scope_type: str = "http"):
    sent: List[Dict[str, Any]] = []

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    handled = asyncio.run(identity.handle({"type": scope_type, "method": method, "path": path}, receive, send))
    return handled, sent


def test_handle_answers_the_two_paths_over_asgi_with_the_js_bytes_and_nothing_else():
    identity = serve_identity(public_origin="https://mcp.example.com", path="/mcp", card={"name": "Orders – é"})
    handled, sent = _asgi(identity, "GET", "/mcp/did.json")
    assert handled
    start, body = sent
    assert start["status"] == 200
    headers = dict(start["headers"])
    assert headers[b"content-type"] == b"application/json"
    assert headers[b"cache-control"] == b"public, max-age=300"
    assert json.loads(body["body"]) == identity.did_document
    # JSON.stringify's bytes: no spaces, raw UTF-8, member order kept.
    _, sent = _asgi(identity, "GET", "/mcp/card.json")
    assert sent[1]["body"] == json.dumps(identity.card, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert "Orders – é".encode("utf-8") in sent[1]["body"]
    assert int(dict(sent[0]["headers"])[b"content-length"]) == len(sent[1]["body"])
    for method, path, kind in (("GET", "/mcp/other.json", "http"), ("GET", "/.well-known/did.json", "http"), ("POST", "/mcp/did.json", "http"), ("GET", "/mcp/did.json", "websocket")):
        assert _asgi(identity, method, path, kind) == (False, []), (method, path, kind)
    assert identity.body_for("/mcp/card.json") == sent[1]["body"]
    assert identity.body_for("/nope") is None


def test_resolve_server_card_dereferences_the_projection_and_a_stripped_one_falls_back_to_the_did():
    identity = serve_identity(public_origin="https://mcp.example.com", path="/mcp", card={"name": "Orders", "capabilities": ["tools/call"]})
    served = {identity.did_document_url: identity.did_document, identity.card_url: identity.card}
    projected = identity.project_server_json({"name": "orders"})
    via_meta = resolve_server_card(projected, fetch_json=_serving(served))
    assert via_meta.card == identity.card and via_meta.card_url == identity.card_url
    fetch_json = _serving(served)
    stripped = resolve_server_card({"name": "orders", "_meta": {"modelcontextprotocol/mcp": {}}}, did=identity.did, fetch_json=fetch_json)
    assert stripped.card == identity.card
    assert fetch_json.calls == [identity.did_document_url, identity.card_url]
    assert resolve_server_card(None, did=identity.did, fetch_json=_serving(served)).card == identity.card
    with pytest.raises(EntityCardError) as refused:
        resolve_server_card({"name": "orders"}, fetch_json=_serving(served))
    assert refused.value.reason == "no_projection"


def test_a_served_identity_resolves_in_two_steps_over_http_through_the_development_safe_fetch():
    """The served bytes, over a real socket, through the SDK's SafeFetch (development mode: loopback http)."""
    holder: Dict[str, ServedIdentity] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:  # noqa: D102
            pass

        def do_GET(self) -> None:  # noqa: N802
            body = holder["identity"].body_for(self.path)
            self.send_response(200 if body is not None else 404)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body or b"")))
            self.end_headers()
            self.wfile.write(body or b"")

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        identity = serve_identity(public_origin=f"http://127.0.0.1:{server.server_port}", path="/mcp", card={"name": "Over HTTP", "kid": "key-1", "publicKeyJwk": JWK})
        holder["identity"] = identity
        dev = create_safe_fetch(development=True)
        resolved = helix_sdk.resolve_entity_card(identity.did, fetch_json=lambda url: dev(url).json())
        assert resolved.card == identity.card
        assert resolved.card_url == identity.card_url
        assert resolve_server_card(identity.project_server_json({"name": "x"}), fetch_json=lambda url: dev(url).json()).card == identity.card
    finally:
        server.shutdown()
        server.server_close()


def _fixture() -> Dict[str, Any]:
    path = FIXTURES_DIR / "kya-os-helix" / "entity-card.json"
    if not path.is_file():
        pytest.skip(f"{path} not found: check out helix-core beside this repo or set HELIX_CORE_FIXTURES_DIR")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("kind", ["service", "agent", "org", "org_root"])
def test_parity_with_helix_core_fixture_entities(kind: str):
    """serve_identity, given what helix-core's card says, builds the same card, card URL and projection."""
    f = _fixture()
    entity = f["entities"][kind]
    card = entity["card"]
    host, path = f["host"], entity["did"][len(f"did:web:{f['host']}"):].replace(":", "/")
    given = {k: v for k, v in card.items() if k not in ("id", "didDocument", "kid", "publicKeyJwk")}
    given.update({"kid": "key-1", "publicKeyJwk": entity["public_key_jwk"]})
    identity = serve_identity(public_origin=f"https://{host}", path=path, card=given, also_known_as=[entity["did_key"], entity["did_hedera"]])
    assert identity.did == entity["did"]
    assert identity.card == card
    assert identity.card_url == entity["card_url"]
    assert identity.did_document_url == entity["did_document_url"]
    assert identity.server_meta() == entity["server_meta"]
    assert identity.did_document["alsoKnownAs"] == entity["did_document"]["alsoKnownAs"]
    assert identity.did_document["service"] == entity["did_document"]["service"]
    assert identity.did_document["verificationMethod"][0]["id"] == entity["did_document"]["verificationMethod"][0]["id"]
    assert identity.did_document["verificationMethod"][0]["publicKeyJwk"] == entity["did_document"]["verificationMethod"][0]["publicKeyJwk"]
    resolved = resolve_server_card({"_meta": entity["server_meta"]}, fetch_json=_serving(f["served"]))
    assert resolved.card == card


def test_the_middleware_and_sdk_export_what_helix_sdk_js_exports():
    import helix_mcp_middleware

    for name in ("serve_identity", "resolve_server_card", "ServeIdentityOptions", "ServedIdentity"):
        assert name in helix_mcp_middleware.__all__ and hasattr(helix_mcp_middleware, name)
    # helix-sdk-js's index, C-A block, in Python style (fetchTransport is requests_transport here).
    js_names = [
        "resolve_entity_card", "resolve_entity_card_from_server_meta", "fetch_entity_card", "parse_entity_card", "validate_entity_card",
        "build_entity_card", "entity_card_summary", "server_card_meta", "capability_name", "create_safe_fetch", "default_outbound_fetch",
        "requests_transport", "node_transport", "is_public_unicast_address", "parse_did_web", "did_web_for", "is_raw_did_web_host", "own_did_web_problem", "did_web_document_url",
        "did_web_card_url", "is_loopback_host", "normalize_did", "same_did", "card_endpoint_of", "kya_os_card_service_entry",
        "EntityCardError", "SafeFetchRefusedError", "ENTITY_TYPES", "KYA_OS_CARD_SERVICE_TYPE", "KYA_OS_CARD_SERVICE_ID",
        "KYA_OS_CARD_META_KEY", "KYA_OS_CARD_REF_KEY", "KYA_OS_CARD_WELL_KNOWN_PATH", "PROOF_PROFILE_V1", "SAFE_FETCH_MAX_BYTES",
        "SAFE_FETCH_TIMEOUT_SECONDS", "SAFE_FETCH_MAX_REDIRECTS", "ResolvedEntityCard", "SafeFetchResponse",
    ]
    for name in js_names:
        assert name in helix_sdk.__all__ and hasattr(helix_sdk, name), name
    assert codes.SAFE_FETCH_REFUSED == "SAFE_FETCH_REFUSED"
