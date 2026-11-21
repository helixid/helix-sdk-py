# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story C-A in Python: resolve_entity_card (two-step, bare-host fallback,
service entry wins, did:key refused), the strict card schema, the server.json
projection, and SafeFetch, asserted against helix-core's
fixtures/kya-os-helix/entity-card.json (sibling checkout or
HELIX_CORE_FIXTURES_DIR, as test_jws.py reads it) and the vendored
entity-card vectors.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List

import pytest

from helix_sdk.entity_card import (
    EntityCardError,
    SafeFetchRefusedError,
    build_entity_card,
    card_endpoint_of,
    create_safe_fetch,
    default_outbound_fetch,
    did_web_card_url,
    did_web_document_url,
    did_web_for,
    entity_card_summary,
    fetch_entity_card,
    is_public_unicast_address,
    kya_os_card_service_entry,
    normalize_did,
    parse_did_web,
    parse_entity_card,
    resolve_entity_card,
    resolve_entity_card_from_server_meta,
    same_did,
    server_card_meta,
    validate_entity_card,
)

FIXTURES_DIR = Path(os.environ.get("HELIX_CORE_FIXTURES_DIR") or Path(__file__).resolve().parents[2] / "helix-core" / "fixtures")
FIXTURE = FIXTURES_DIR / "kya-os-helix" / "entity-card.json"
JWK = {"kty": "OKP", "crv": "Ed25519", "x": "JUO5L_EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0"}
AGENT = "did:web:helix.test:acme:ledger-agent"


def _load(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        pytest.skip(f"{path} not found: check out helix-core beside this repo or set HELIX_CORE_FIXTURES_DIR")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _serving(served: Dict[str, Any]):
    calls: List[str] = []

    def fetch_json(url: str) -> Any:
        calls.append(url)
        if url not in served:
            raise EntityCardError("unavailable", f"{url} answered HTTP 404")
        return served[url]

    fetch_json.calls = calls  # type: ignore[attr-defined]
    return fetch_json


def _reason(run) -> str:
    try:
        run()
    except (EntityCardError, SafeFetchRefusedError) as err:
        return err.reason
    return "ok"


# ── did:web helpers ───────────────────────────────────────────────────────────

def test_did_web_helpers():
    assert did_web_for("Helix.Test", ["acme", "a b"]) == "did:web:helix.test:acme:a%20b"
    assert parse_did_web("did:web:localhost%3A3000:acme:a%20b") == ("localhost:3000", ["acme", "a b"])
    assert parse_did_web("did:web:helix.test") == ("helix.test", [])
    for bad in ("did:key:z6Mk", "did:web:", "did:web:helix.test::x", "did:web:helix.test:acme:agent#key-1", "did:web:helix.test:%E0%A4%A", "did:web:helix.test:a%2Fb", 42):
        assert parse_did_web(bad) is None, bad
    assert did_web_document_url(AGENT) == "https://helix.test/acme/ledger-agent/did.json"
    assert did_web_card_url(AGENT) == "https://helix.test/acme/ledger-agent/card.json"
    assert did_web_document_url("did:web:helix.test") == "https://helix.test/.well-known/did.json"
    assert did_web_card_url("did:web:helix.test") == "https://helix.test/.well-known/kya-os-card.json"
    assert did_web_card_url("did:web:localhost%3A3000:acme") == "http://localhost:3000/acme/card.json"
    assert did_web_document_url("did:web:127.0.0.1%3A3580") == "http://127.0.0.1:3580/.well-known/did.json"
    with pytest.raises(EntityCardError):
        did_web_card_url("did:key:z6Mk")
    assert normalize_did("did:web:HELIX.test:a%3ab") == "did:web:helix.test:a%3Ab"
    assert normalize_did("did:key:abc") == "did:key:abc"
    assert same_did("did:web:HELIX.test", "did:web:helix.test")
    assert not same_did("did:web:helix.test:users:alice%3Aagent", "did:web:helix.test:users:alice:agent")
    assert not same_did("did:web:helix.test:%E0%A4%A", "did:web:helix.test:%E0%A4%A")
    assert card_endpoint_of({"service": [{"type": "LinkedDomains", "serviceEndpoint": "https://x"}, kya_os_card_service_entry("https://h/card.json")]}) == "https://h/card.json"
    assert card_endpoint_of({"service": "none"}) is None
    assert card_endpoint_of(None) is None


# ── The strict schema ─────────────────────────────────────────────────────────

def test_schema_admits_vendored_examples_and_refuses_unknown_fields():
    schema = _load(FIXTURES_DIR / "kya-os" / "schemas" / "kya-os-card.schema.json")
    for example in schema["examples"]:
        assert validate_entity_card(example) == []
        assert validate_entity_card({**example, "bogusField": True}) == ["/bogusField: must NOT have additional properties"]


def test_schema_refuses_each_malformed_member():
    base = {"id": AGENT, "entityType": "agent", "name": "A"}

    def first(value: Any) -> str:
        issues = validate_entity_card(value)
        return issues[0] if issues else "ok"

    assert first("card") == ": must be of type object"
    assert first({"id": AGENT}) == ": must have required property 'entityType'"
    assert first({**base, "id": "did:hedera:x"}) == "/id: must be a did:key or did:web DID"
    assert first({**base, "entityType": "tool"}).startswith("/entityType: must be one of")
    assert first({**base, "name": ""}) == "/name: must be a non-empty string"
    assert first({**base, "kid": 1}) == "/kid: must be of type string"
    assert first({**base, "publicKeyJwk": {**JWK, "d": "x"}}) == "/publicKeyJwk/d: must NOT have additional properties"
    assert first({**base, "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": 1, "kid": 2}}) == '/publicKeyJwk/kty: must equal "OKP"'
    assert validate_entity_card({**base, "publicKeyJwk": "jwk"}) == ["/publicKeyJwk: must be of type object"]
    assert first({**base, "createdAt": "yesterday"}) == "/createdAt: must be an RFC 3339 date-time"
    assert first({**base, "capabilities": "x"}) == "/capabilities: must be of type array"
    assert first({**base, "capabilities": [""]}).startswith("/capabilities/0")
    assert first({**base, "capabilities": [{"name": "x", "attestations": []}]}).startswith("/capabilities/0")
    assert first({**base, "capabilities": [{"name": "x", "attestations": [{"vc": "jwt"}], "extra": 1}]}).startswith("/capabilities/0")
    assert first({**base, "capabilities": ["x", {"name": "y", "attestations": [{"vc": {"id": "v"}, "note": 1}]}]}) == "ok"
    assert first({**base, "conformanceLevel": "L4"}).startswith("/conformanceLevel")
    assert first({**base, "responsibleParty": "acme"}) == "/responsibleParty: must be a did:key or did:web DID"
    assert first({**base, "principal": "did:hedera:x"}) == "/principal: must be a did:key or did:web DID"
    assert first({**base, "attestations": "x"}) == "/attestations: must be of type array"
    assert first({**base, "attestations": [{"type": "KYC", "vc": "x"}]}).startswith("/attestations/0/type")
    assert first({**base, "attestations": [{"type": "IdentityVerification", "vc": 1}]}).startswith("/attestations/0/vc")
    assert first({**base, "attestations": [{"type": "IdentityVerification", "vc": "x", "issuer": "nope"}]}).startswith("/attestations/0/issuer")
    assert first({**base, "attestations": ["x"]}) == "/attestations/0: must be of type object"
    assert first({**base, "didDocument": "not a uri"}) == "/didDocument: must be a URI"
    assert first({**base, "didDocument": 7}) == "/didDocument: must be a URI"
    assert first({**base, "proofProfile": "v2"}).startswith("/proofProfile")
    assert first({**base, "cimd": {"clientId": "x"}}) == "/cimd/jwksUri: must be a non-empty string"
    assert first({**base, "revocation": {"statusListCredential": "x", "statusListIndex": "0x7"}}) == "/revocation/statusListIndex: must match ^[0-9]+$"
    assert first({**base, "revocation": {"statusListCredential": "", "statusListIndex": "7"}}) == "/revocation/statusListCredential: must be a non-empty string"
    assert first({**base, "revocation": {"statusListCredential": "x", "statusListIndex": "7", "statusSize": 0}}) == "/revocation/statusSize: must be an integer of at least 1"
    assert first({**base, "revocation": {"statusListCredential": "x", "statusListIndex": "7", "statusSize": True}}) == "/revocation/statusSize: must be an integer of at least 1"
    assert first({**base, "revocation": {"statusListCredential": "x", "statusListIndex": "7", "statusMessage": "m"}}) == "/revocation/statusMessage: must be an array"
    assert first({**base, "revocation": {"statusListCredential": "x", "statusListIndex": "7", "statusMessage": [{"status": "0x1"}]}}).startswith("/revocation/statusMessage/0")
    assert first({**base, "revocation": {"statusListCredential": "x", "statusListIndex": "7", "statusSize": 1, "statusMessage": [{"status": "0x1", "message": "r"}]}}) == "ok"
    assert first({**base, "revocation": "r"}) == "/revocation: must be of type object"
    with pytest.raises(EntityCardError, match="bogusField"):
        parse_entity_card({**base, "bogusField": True})
    assert parse_entity_card(base) == base


def test_build_entity_card():
    card = build_entity_card({"id": AGENT, "entityType": "agent", "name": "Ledger", "kid": "key-1", "publicKeyJwk": JWK, "capabilities": ["handshake"], "conformanceLevel": "L3"})
    assert card == {
        "id": AGENT, "entityType": "agent", "name": "Ledger", "kid": f"{AGENT}#key-1",
        "publicKeyJwk": {**JWK, "kid": f"{AGENT}#key-1"}, "capabilities": ["handshake"],
        "didDocument": "https://helix.test/acme/ledger-agent/did.json", "proofProfile": "org.kya-os/proof.v1",
    }
    assert "conformanceLevel" not in card
    full = build_entity_card({"id": AGENT, "entityType": "mcp", "name": "S", "kid": f"{AGENT}#k2", "proofProfile": "org.kya-os/proof@1",
                              "didDocument": "https://cdn.example/did.json", "createdAt": "2026-11-21T00:00:00Z",
                              "responsibleParty": "did:web:helix.test:acme", "principal": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                              "delegationRef": "r>d", "attestations": [{"type": "IdentityVerification", "vc": "jwt"}],
                              "cimd": {"clientId": "https://x", "jwksUri": "https://x/jwks"}, "revocation": {"statusListCredential": "https://s", "statusListIndex": "1"}})
    assert list(full) == ["id", "entityType", "name", "kid", "createdAt", "responsibleParty", "principal", "delegationRef", "attestations", "didDocument", "proofProfile", "cimd", "revocation"]
    key_card = build_entity_card({"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "entityType": "human", "name": "Alice", "publicKeyJwk": JWK})
    assert key_card == {"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "entityType": "human", "name": "Alice", "publicKeyJwk": JWK, "proofProfile": "org.kya-os/proof.v1"}
    for bad, pattern in (
        ({"id": AGENT, "entityType": "agent", "name": "L", "proof": {}}, "unknown members"),
        ({"id": AGENT, "entityType": "agent", "name": "L", "publicKeyJwk": {**JWK, "d": "x"}}, "private material"),
        ({"id": AGENT, "entityType": "agent", "name": "L", "publicKeyJwk": {**JWK, "use": "sig"}}, "unexpected members"),
        ({"id": AGENT, "entityType": "agent", "name": "L", "publicKeyJwk": "jwk"}, "private material"),
        ({"id": AGENT, "entityType": "agent", "name": "L", "kid": "did:web:other#k"}, "does not name"),
        ({"id": AGENT, "entityType": "agent", "name": "L", "kid": "#"}, "does not name"),
        ({"id": AGENT, "entityType": "agent", "name": ""}, "Entity Card is invalid"),
        ("nope", "input mapping"),
    ):
        with pytest.raises(EntityCardError, match=pattern):
            build_entity_card(bad)  # type: ignore[arg-type]


def test_server_card_meta():
    card = build_entity_card({"id": AGENT, "entityType": "agent", "name": "Ledger", "capabilities": ["handshake", {"name": "ledger.post", "attestations": [{"vc": "jwt"}]}],
                              "responsibleParty": "did:web:helix.test:acme", "delegationRef": "r>d", "revocation": {"statusListCredential": "https://helix.test/s", "statusListIndex": "1"}})
    assert server_card_meta(card) == {"org.kya-os/card": {
        "id": AGENT, "entityType": "agent", "name": "Ledger", "capabilities": ["handshake", "ledger.post"], "responsibleParty": "did:web:helix.test:acme",
        "delegationRef": "r>d", "proofProfile": "org.kya-os/proof.v1", "revocation": {"statusListCredential": "https://helix.test/s", "statusListIndex": "1"},
        "org.kya-os/cardRef": "https://helix.test/acme/ledger-agent/card.json"}}
    assert server_card_meta(card, card_url="https://cdn.example/card.json", by_ref=True) == {"org.kya-os/card": {"org.kya-os/cardRef": "https://cdn.example/card.json"}}
    key_card = build_entity_card({"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "entityType": "human", "name": "Alice"})
    assert entity_card_summary(key_card) == {"id": key_card["id"], "entityType": "human", "name": "Alice", "proofProfile": "org.kya-os/proof.v1"}
    with pytest.raises(EntityCardError, match="did:key"):
        server_card_meta(key_card)


# ── helix-core fixture ────────────────────────────────────────────────────────

def test_fixture_entities_validate_and_project():
    f = _load(FIXTURE)
    for e in f["entities"].values():
        assert validate_entity_card(e["card"]) == []
        assert entity_card_summary(e["card"]) == e["summary"]
        assert server_card_meta(e["card"]) == e["server_meta"]
        assert did_web_card_url(e["did"]) == e["card_url"]
        assert did_web_document_url(e["did"]) == e["did_document_url"]
        assert card_endpoint_of(e["did_document"]) == e["card_url"]
    assert f["entities"]["agent"]["card"]["responsibleParty"] == f["entities"]["org"]["did"]
    assert f["entities"]["agent"]["card"]["principal"] == f["user_did_key"]


def test_fixture_resolution_two_steps_and_projection():
    f = _load(FIXTURE)
    for step in f["resolution"]:
        fetch_json = _serving(f["served"])
        resolved = resolve_entity_card(step["did"], fetch_json=fetch_json)
        assert fetch_json.calls == step["steps"], step["did"]
        assert resolved.card["id"] == step["card_id"]
        assert resolved.did_document == f["served"][step["steps"][0]]
        via_meta = resolve_entity_card_from_server_meta(server_card_meta(resolved.card), fetch_json=_serving(f["served"]))
        assert via_meta.card == resolved.card
        stripped = resolve_entity_card_from_server_meta({}, did=step["did"], fetch_json=_serving(f["served"]))
        assert stripped.card == resolved.card


def test_fixture_refusals():
    f = _load(FIXTURE)
    for refusal in f["refusals"]:
        if "card" in refusal:
            got = "additionalProperties" if any("additional properties" in i for i in validate_entity_card(refusal["card"])) else "accepted"
        else:
            got = _reason(lambda: resolve_entity_card(refusal["did"], fetch_json=_serving(refusal.get("served", f["served"]))))
        assert got == refusal["reason"], refusal["name"]


def test_fixture_build_cases():
    f = _load(FIXTURE)
    for build in f["build_cases"]:
        if build["expected"] == "card":
            card = build_entity_card(build["input"])
            assert card == build["card"], build["name"]
            for member in build.get("absent", []):
                assert member not in card
        else:
            with pytest.raises(EntityCardError):
                build_entity_card(build["input"])


def test_fixture_safe_fetch_refusals_and_addresses():
    f = _load(FIXTURE)
    safe_fetch = create_safe_fetch(lookup=lambda _h: ["93.184.216.34"], transport=lambda *_a: (200, {}, b"{}"))
    for case in f["safe_fetch_refusals"]:
        assert _reason(lambda: safe_fetch(case["url"])) == case["reason"], case["url"]
    for address in f["public_addresses"]:
        assert is_public_unicast_address(address), address
    for address in f["non_public_addresses"]:
        assert not is_public_unicast_address(address), address
    assert not is_public_unicast_address("helix.test")


def test_vendored_entity_card_vectors_parse():
    vectors = _load(FIXTURES_DIR / "kya-os" / "conformance" / "vectors" / "entity-card.json")["vectors"]
    assert len(vectors) == 8
    for vector in vectors:
        if vector["id"] == "entity-card/malformed-unknown-field":
            with pytest.raises(EntityCardError, match="bogusField"):
                parse_entity_card(vector["input"]["card"])
        else:
            assert validate_entity_card(vector["input"]["card"]) == [], vector["id"]


# ── Resolution ────────────────────────────────────────────────────────────────

AGENT_CARD = build_entity_card({"id": AGENT, "entityType": "agent", "name": "Ledger", "publicKeyJwk": JWK, "kid": "key-1"})
AGENT_DOCUMENT = {"id": AGENT, "service": [kya_os_card_service_entry("https://helix.test/acme/ledger-agent/card.json")]}
ORG_CARD = build_entity_card({"id": "did:web:helix.test", "entityType": "verifier", "name": "Helix"})


def test_resolve_entity_card_paths():
    resolved = resolve_entity_card(AGENT, fetch_json=_serving({"https://helix.test/acme/ledger-agent/did.json": AGENT_DOCUMENT, "https://helix.test/acme/ledger-agent/card.json": AGENT_CARD}))
    assert (resolved.did, resolved.card, resolved.card_url, resolved.did_document) == (AGENT, AGENT_CARD, "https://helix.test/acme/ledger-agent/card.json", AGENT_DOCUMENT)
    fallback = resolve_entity_card("did:web:helix.test", fetch_json=_serving({"https://helix.test/.well-known/did.json": {"id": "did:web:helix.test"}, "https://helix.test/.well-known/kya-os-card.json": ORG_CARD}))
    assert fallback.card_url == "https://helix.test/.well-known/kya-os-card.json"
    both = _serving({"https://helix.test/.well-known/did.json": {"id": "did:web:helix.test", "service": [kya_os_card_service_entry("https://helix.test/cards/org.json")]},
                     "https://helix.test/cards/org.json": ORG_CARD, "https://helix.test/.well-known/kya-os-card.json": {**ORG_CARD, "name": "stale"}})
    assert resolve_entity_card("did:web:helix.test", fetch_json=both).card["name"] == "Helix"
    assert len(both.calls) == 2


def test_resolve_entity_card_refusals():
    none = _serving({})
    assert _reason(lambda: resolve_entity_card("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", fetch_json=none)) == "did_key_not_resolvable"
    assert _reason(lambda: resolve_entity_card(f"{AGENT}#key-1", fetch_json=none)) == "malformed_did"
    assert _reason(lambda: resolve_entity_card(5, fetch_json=none)) == "malformed_did"  # type: ignore[arg-type]
    assert none.calls == []
    assert _reason(lambda: resolve_entity_card(AGENT, fetch_json=none)) == "did_document_unavailable"
    assert _reason(lambda: resolve_entity_card(AGENT, fetch_json=_serving({"https://helix.test/acme/ledger-agent/did.json": {"id": "did:web:other"}}))) == "did_document_mismatch"
    assert _reason(lambda: resolve_entity_card(AGENT, fetch_json=_serving({"https://helix.test/acme/ledger-agent/did.json": "text"}))) == "did_document_mismatch"
    assert _reason(lambda: resolve_entity_card(AGENT, fetch_json=_serving({"https://helix.test/acme/ledger-agent/did.json": {"id": AGENT}}))) == "no_card_service"
    assert _reason(lambda: resolve_entity_card(AGENT, fetch_json=_serving({"https://helix.test/acme/ledger-agent/did.json": AGENT_DOCUMENT}))) == "card_unavailable"
    assert _reason(lambda: resolve_entity_card(AGENT, fetch_json=_serving({"https://helix.test/acme/ledger-agent/did.json": AGENT_DOCUMENT, "https://helix.test/acme/ledger-agent/card.json": ORG_CARD}))) == "card_mismatch"
    assert _reason(lambda: resolve_entity_card(AGENT, fetch_json=_serving({"https://helix.test/acme/ledger-agent/did.json": AGENT_DOCUMENT, "https://helix.test/acme/ledger-agent/card.json": {**AGENT_CARD, "bogus": 1}}))) == "card_invalid"

    def broken(_url: str) -> Any:
        raise RuntimeError("refused by SafeFetch")

    assert _reason(lambda: resolve_entity_card(AGENT, fetch_json=broken)) == "did_document_unavailable"
    assert _reason(lambda: fetch_entity_card("https://helix.test/x", fetch_json=broken)) == "card_unavailable"


def test_resolve_from_server_meta():
    served = {"https://helix.test/acme/ledger-agent/did.json": AGENT_DOCUMENT, "https://helix.test/acme/ledger-agent/card.json": AGENT_CARD, "https://cdn.example/card.json": AGENT_CARD}
    assert resolve_entity_card_from_server_meta({"org.kya-os/card": {"org.kya-os/cardRef": "https://cdn.example/card.json"}}, fetch_json=_serving(served)).card_url == "https://cdn.example/card.json"
    assert resolve_entity_card_from_server_meta({"org.kya-os/card": entity_card_summary(AGENT_CARD)}, fetch_json=_serving(served)).card_url == "https://helix.test/acme/ledger-agent/card.json"
    key_card = build_entity_card({"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "entityType": "human", "name": "Alice"})
    assert resolve_entity_card_from_server_meta({"org.kya-os/card": entity_card_summary(key_card)}, fetch_json=_serving(served)).card == entity_card_summary(key_card)
    assert resolve_entity_card_from_server_meta(None, did=AGENT, fetch_json=_serving(served)).card == AGENT_CARD
    assert _reason(lambda: resolve_entity_card_from_server_meta({}, fetch_json=_serving(served))) == "no_projection"
    assert _reason(lambda: resolve_entity_card_from_server_meta({"org.kya-os/card": {"name": "x"}}, fetch_json=_serving(served))) == "no_projection"
    assert _reason(lambda: resolve_entity_card_from_server_meta({"org.kya-os/card": {"id": "did:web:helix.test", "org.kya-os/cardRef": "https://cdn.example/card.json"}}, fetch_json=_serving(served))) == "card_mismatch"
    assert _reason(lambda: resolve_entity_card_from_server_meta({"org.kya-os/card": {"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "bogus": 1}}, fetch_json=_serving(served))) == "card_invalid"


# ── SafeFetch ─────────────────────────────────────────────────────────────────

PUBLIC = "93.184.216.34"


def _harness(routes: Dict[str, Any], addresses: Dict[str, List[str]] | None = None):
    addresses = addresses if addresses is not None else {"helix.test": [PUBLIC]}
    requests: List[Any] = []

    def lookup(hostname: str) -> List[str]:
        if hostname not in addresses:
            raise socket.gaierror(f"ENOTFOUND {hostname}")
        return addresses[hostname]

    def transport(url: str, headers: Any, address: Any, timeout: float, max_bytes: int):
        requests.append((url, dict(headers), address, max_bytes))
        served = routes.get(url, {"status": 404})
        return served["status"], served.get("headers", {}), served.get("body", b"")

    return requests, lookup, transport


def test_safe_fetch_policy():
    requests, lookup, transport = _harness({
        "https://helix.test/card.json": {"status": 200, "headers": {"content-type": "application/json"}, "body": b'{"ok":1}'},
        "https://helix.test/old": {"status": 301, "headers": {"location": "/card.json"}},
        "https://helix.test/cross": {"status": 302, "headers": {"location": "https://other.test/"}},
        "https://helix.test/port": {"status": 302, "headers": {"location": "https://helix.test:8443/"}},
        "https://helix.test/down": {"status": 307, "headers": {"location": "http://helix.test/"}},
        "https://helix.test/blank": {"status": 308},
        "https://helix.test/bad": {"status": 302, "headers": {"location": "http://"}},
        "https://helix.test/loop": {"status": 302, "headers": {"location": "/loop"}},
    })
    safe_fetch = create_safe_fetch(lookup=lookup, transport=transport)
    response = safe_fetch("https://helix.test/card.json", headers={"accept": "application/did+json"})
    assert (response.ok, response.status, response.url, response.json(), response.text()) == (True, 200, "https://helix.test/card.json", {"ok": 1}, '{"ok":1}')
    assert requests[0][1]["accept"] == "application/did+json" and requests[0][2] == PUBLIC and requests[0][3] == 1024 * 1024
    assert safe_fetch("https://helix.test/old").url == "https://helix.test/card.json"
    assert not safe_fetch("https://helix.test/missing").ok
    assert _reason(lambda: safe_fetch("https://helix.test/cross")) == "cross_origin_redirect"
    assert _reason(lambda: safe_fetch("https://helix.test/port")) == "cross_origin_redirect"
    assert _reason(lambda: safe_fetch("https://helix.test/down")) == "scheme_refused"
    assert _reason(lambda: safe_fetch("https://helix.test/blank")) == "unavailable"
    assert _reason(lambda: safe_fetch("https://helix.test/bad")) == "invalid_url"
    assert _reason(lambda: safe_fetch("https://helix.test/loop")) == "too_many_redirects"
    assert _reason(lambda: safe_fetch("https://unknown.test/")) == "unresolved"
    assert _reason(lambda: safe_fetch("https://user:pw@helix.test/")) == "host_refused"
    assert _reason(lambda: safe_fetch("not a url")) == "invalid_url"
    assert _reason(lambda: create_safe_fetch(lookup=lambda _h: [], transport=transport)("https://helix.test/")) == "unresolved"
    assert _reason(lambda: create_safe_fetch(lookup=lambda _h: ["10.0.0.1"], transport=transport)("https://helix.test/")) == "host_refused"
    assert _reason(lambda: create_safe_fetch(lookup=lambda _h: [PUBLIC, "169.254.169.254"], transport=transport)("https://helix.test/")) == "host_refused"

    def reset(*_a: Any):
        raise ConnectionResetError("ECONNRESET")

    assert _reason(lambda: create_safe_fetch(lookup=lookup, transport=reset)("https://helix.test/")) == "unavailable"

    def slow(*_a: Any):
        raise socket.timeout("timed out")

    assert _reason(lambda: create_safe_fetch(lookup=lookup, transport=slow)("https://helix.test/")) == "deadline_exceeded"
    assert _reason(lambda: create_safe_fetch(lookup=lookup, transport=transport, timeout=0)("https://helix.test/")) == "deadline_exceeded"
    assert create_safe_fetch(lookup=lookup, transport=transport)(f"https://{PUBLIC}/card.json").status == 404
    assert requests[-1][2] is None


def test_safe_fetch_development_mode():
    requests, lookup, transport = _harness({"http://localhost:3000/did.json": {"status": 200, "body": b"{}"}, "http://localhost:3000/cross": {"status": 302, "headers": {"location": "http://10.0.0.1/"}}})
    dev = create_safe_fetch(lookup=lookup, transport=transport, development=True)
    assert dev("http://localhost:3000/did.json").ok
    assert requests[0][2] == "127.0.0.1"
    assert _reason(lambda: dev("http://localhost:3000/cross")) == "cross_origin_redirect"
    assert create_safe_fetch(lookup=lambda _h: ["10.0.0.1"], transport=transport, development=True)("https://internal.test/").status == 404
    assert default_outbound_fetch() is default_outbound_fetch()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # noqa: D102
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/big":
            body = b"A" * (2 * 1024 * 1024)
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/declared":
            self.send_response(200)
            self.send_header("content-length", str(2 * 1024 * 1024))
            self.end_headers()
            self.wfile.write(b"a")
        elif self.path == "/slow":
            import time as _time

            _time.sleep(0.5)
            self.send_response(200)
            self.send_header("content-length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("location", "/card.json")
            self.end_headers()
        else:
            body = json.dumps({"path": self.path, "host": self.headers.get("host")}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


@pytest.fixture()
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server.server_port
    finally:
        server.shutdown()
        server.server_close()


def test_node_transport_over_local_server(local_server):
    origin, port = local_server
    safe_fetch = create_safe_fetch(development=True, timeout=5)
    assert safe_fetch(f"{origin}/card.json").json()["path"] == "/card.json"
    assert safe_fetch(f"{origin}/redirect").json()["path"] == "/card.json"
    assert _reason(lambda: safe_fetch(f"{origin}/big")) == "too_large"
    assert _reason(lambda: safe_fetch(f"{origin}/declared")) == "too_large"
    pinned = create_safe_fetch(development=True, lookup=lambda _h: ["127.0.0.1"])
    assert pinned(f"http://pinned.test:{port}/card.json").json() == {"path": "/card.json", "host": f"pinned.test:{port}"}
    assert _reason(lambda: create_safe_fetch(lookup=lambda _h: ["127.0.0.1"])(f"https://pinned.test:{port}/")) == "host_refused"
    assert _reason(lambda: create_safe_fetch(development=True, timeout=0.1)(f"{origin}/slow")) == "deadline_exceeded"
