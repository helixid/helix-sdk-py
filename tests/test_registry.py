# Copyright 2026 DgVerse LLP
"""Registry v3: kyaos.registry (parity with sdk-js tests/unit/kyaos/registry.test.ts)."""

import base64
import json
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from helix_sdk import kyaos
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.agent_key import generate_agent_key
from helix_sdk.registry import (
    HELIX_REGISTRY_ORIGIN,
    RegistryError,
    create_registry_client,
    helix_origin_of_did,
    helix_registry_origin,
    publish,
)

HELIX = "http://127.0.0.1:3880"
AIR_DID = "did:web:127.0.0.1%3A3880:services:air"
GHOST_DID = "did:web:127.0.0.1%3A4540:services:ghost"
TEST_ONLY = "HELIX_TEST_ONLY_REGISTRY_ORIGIN"
AGENT_D = {
    "agentDid": "did:web:127.0.0.1%3A3880:agents:d", "name": "Agent D", "status": "active",
    "owner": {"did": None, "name": "Client D"}, "publishedAt": "2026-11-24T10:00:00.000Z", "deployment": HELIX,
}


@pytest.fixture(autouse=True)
def helix_here(monkeypatch):
    monkeypatch.setenv(TEST_ONLY, HELIX)


class Response:
    def __init__(self, status=200, body=None, not_json=False):
        self.status_code = status
        self._body = body
        self._not_json = not_json

    def json(self):
        if self._not_json:
            raise ValueError("not JSON")
        return self._body


class World:
    """The Helix registry, two services' /.well-known/mcp, and the DID documents Helix serves."""

    def __init__(self, overrides=None):
        self.overrides = overrides or {}
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append(url)
        for prefix, answer in self.overrides.items():
            if url.startswith(prefix):
                return answer()
        if url == "http://127.0.0.1:4530/.well-known/mcp":
            return Response(body={"version": "1.0", "serverDid": AIR_DID, "endpoints": {"tools": "/mcp"}})
        if url == "http://127.0.0.1:4540/.well-known/mcp":
            return Response(body={"version": "1.0", "serverDid": GHOST_DID, "endpoints": {"tools": "/mcp"}})
        if url == "http://127.0.0.1:9000/.well-known/mcp":
            return Response(body={"version": "1.0", "serverDid": AIR_DID, "endpoints": {}})
        parts = urlsplit(url)
        if f"{parts.scheme}://{parts.netloc}" == HELIX and parts.path == "/agent/registry":
            q = parse_qs(parts.query).get("q", [""])[0].lower()
            return Response(body={"agents": [a for a in [AGENT_D, {"name": "no DID"}] if q in str(a["name"]).lower()], "nextCursor": None})
        if url == f"{HELIX}/agent/registry/{quote(AGENT_D['agentDid'], safe='')}":
            return Response(body={"agent": AGENT_D})
        return Response(status=404, body={})


def documents(did):
    """What resolving a DID gives: Air's document is served, the ghost's is not."""
    return {"id": AIR_DID, "verificationMethod": []} if did == AIR_DID else None


def test_the_helix_registry_is_fixed_with_a_test_only_override(monkeypatch):
    assert helix_registry_origin() == HELIX
    assert create_registry_client().registry == HELIX
    monkeypatch.delenv(TEST_ONLY)
    assert helix_registry_origin() == HELIX_REGISTRY_ORIGIN == "https://api.helixid.dev"
    assert not hasattr(kyaos.registry, "create_account_check")
    assert not hasattr(create_registry_client(), "find_services")


def test_reads_the_deployment_of_a_did_web():
    assert helix_origin_of_did("did:web:127.0.0.1%3A3880:agents:a") == HELIX
    assert helix_origin_of_did("did:web:helix.example.com:agents:a") == "https://helix.example.com"
    assert helix_origin_of_did("did:web:%5B%3A%3A1%5D%3A3000:a") == "http://[::1]:3000"
    assert helix_origin_of_did("did:key:z6Mk") is None
    assert helix_origin_of_did("did:web:bad%20host") is None


def test_find_agents_and_lookup_read_the_helix_registry():
    world = World()
    client = create_registry_client(get=world.get)
    assert client.find_agents("agent") == [AGENT_D]
    assert world.calls[0] == f"{HELIX}/agent/registry?q=agent"
    assert client.lookup(AGENT_D["agentDid"]) == AGENT_D
    assert client.lookup("did:web:127.0.0.1%3A3200:agents:hidden") is None


def test_refuses_a_registry_that_answers_something_else():
    odd = create_registry_client(get=World({f"{HELIX}/agent/registry": lambda: Response(body={"agents": "x"})}).get)
    with pytest.raises(RegistryError) as error:
        odd.find_agents("x")
    assert error.value.reason == "registry_error" and error.value.code == "REGISTRY_ERROR"
    assert odd.lookup("did:web:x") is None
    missing = create_registry_client(get=World({f"{HELIX}/agent/registry": lambda: Response(status=404, body={})}).get)
    with pytest.raises(RegistryError, match="did not answer an agents list"):
        missing.find_agents("x")
    with pytest.raises(RegistryError, match="answered 500"):
        create_registry_client(get=World({f"{HELIX}/agent/registry": lambda: Response(status=500)}).get).find_agents("x")
    with pytest.raises(RegistryError, match="did not answer with JSON"):
        create_registry_client(get=World({f"{HELIX}/agent/registry": lambda: Response(not_json=True)}).get).find_agents("x")

    def down(*_a, **_k):
        raise ConnectionError("ECONNREFUSED")

    with pytest.raises(RegistryError) as error:
        create_registry_client(get=down).lookup("did:web:x")
    assert error.value.reason == "fetch_failed"


def test_resolve_reads_well_known_mcp_and_fetches_the_did_document():
    client = create_registry_client(get=World().get, resolve_did=documents)
    resolved = client.resolve("http://127.0.0.1:4530/anything")
    assert resolved == {"serviceDid": AIR_DID, "toolsUrl": "http://127.0.0.1:4530/mcp", "url": "http://127.0.0.1:4530", "didDocument": {"id": AIR_DID, "verificationMethod": []}}
    assert client.resolve("http://127.0.0.1:4530", expected_did=AIR_DID)["serviceDid"] == AIR_DID


def test_resolve_refuses_an_unresolvable_did_another_did_no_tools_or_no_url():
    client = create_registry_client(get=World().get, resolve_did=documents)
    with pytest.raises(RegistryError) as error:
        client.resolve("http://127.0.0.1:4540")
    assert error.value.reason == "did_unresolvable" and GHOST_DID in str(error.value)
    with pytest.raises(RegistryError) as error:
        client.resolve("http://127.0.0.1:4530", expected_did="did:web:other")
    assert error.value.reason == "did_mismatch"
    with pytest.raises(RegistryError) as error:
        client.resolve("http://127.0.0.1:9000")
    assert error.value.reason == "no_url" and "no tools endpoint" in str(error.value)
    with pytest.raises(RegistryError) as error:
        client.resolve("not a url")
    assert error.value.reason == "no_url"

    def stale(_did):
        raise ValueError("stale")

    with pytest.raises(RegistryError) as error:
        create_registry_client(get=World().get, resolve_did=stale).resolve("http://127.0.0.1:4530")
    assert error.value.reason == "did_unresolvable" and "stale" in str(error.value)


def test_defaults_use_requests_and_the_sdk_resolver(monkeypatch):
    import requests

    world = World()
    monkeypatch.setattr(requests, "get", world.get)
    assert create_registry_client().find_agents("agent") == [AGENT_D]
    # The default resolver fetches https only: a loopback did:web document is not fetched, so it does not resolve.
    with pytest.raises(RegistryError) as error:
        create_registry_client().resolve("http://127.0.0.1:4540")
    assert error.value.reason == "did_unresolvable"


AGENT_DID = "did:web:127.0.0.1%3A3200:agents:a"


def signer(did=AGENT_DID):
    return EnvSigner(did, env={"HELIX_SIGNING_KEY": generate_agent_key().private_key_hex})


def decode(part):
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def test_publish_signs_with_its_own_key_and_sends_to_the_helix_registry():
    sent = []

    def post(url, json=None, headers=None, timeout=None):
        sent.append((url, json))
        return Response(status=201, body={"agent": {**AGENT_D, "agentDid": AGENT_DID, "name": "Agent A"}})

    listed = publish(signer(), post=post, now=1795521600)
    assert listed["name"] == "Agent A"
    url, body = sent[0]
    assert url == f"{HELIX}/agent/registry"
    header, payload = [decode(part) for part in body["registration"].split(".")[:2]]
    assert header["typ"] == "helix-registration+jwt" and header["kid"] == f"{AGENT_DID}#key-1"
    assert payload["iss"] == AGENT_DID and payload["aud"] == HELIX and payload["deployment"] == "http://127.0.0.1:3200"
    assert payload["exp"] - payload["iat"] == 300 and "kind" not in payload
    via_url = []
    publish(signer(), helix_url="http://127.0.0.1:3200/v1", post=lambda url, json=None, **k: via_url.append(json) or Response(status=201, body={"agent": {"agentDid": "x"}}))
    assert decode(via_url[0]["registration"].split(".")[1])["deployment"] == "http://127.0.0.1:3200"


def test_publish_reports_refusals_and_failures_and_needs_a_deployment(monkeypatch):
    with pytest.raises(RegistryError) as error:
        publish(signer(), post=lambda *a, **k: Response(status=403, body={"error": {"message": "not listed as discoverable"}}))
    assert error.value.reason == "publish_refused" and "not listed as discoverable" in str(error.value)
    with pytest.raises(RegistryError) as error:
        publish(signer(), post=lambda *a, **k: Response(status=502, not_json=True))
    assert "answered 502" in str(error.value)

    def down(*_a, **_k):
        raise ConnectionError("down")

    with pytest.raises(RegistryError) as error:
        publish(signer(), post=down)
    assert error.value.reason == "fetch_failed"
    with pytest.raises(RegistryError) as error:
        publish(signer("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), post=down)
    assert error.value.reason == "no_helix_link"
    import requests

    monkeypatch.setattr(requests, "post", lambda *a, **k: Response(status=201, body={"agent": {"agentDid": AGENT_DID}}))
    assert publish(signer())["agentDid"] == AGENT_DID


def test_on_the_kyaos_namespace():
    assert kyaos.registry.publish is publish
    assert kyaos.registry.create_registry_client is create_registry_client
