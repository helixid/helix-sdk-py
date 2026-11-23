"""KYA-OS story L3-D in the Python sample, the twin of the JS sample's
tests/downstream.test.ts: the agent calls service A's forward_lookup_order
with its request proof and chain; A's tool calls service B's lookup_order
through with_delegation; B verifies the forwarded chain and A's delegation
proof with its own verifier. Two apps, the helix-core fixture world, no
secret shared."""

from __future__ import annotations

import asyncio
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

pytest.importorskip("mcp")
pytest.importorskip("starlette")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))

from starlette.testclient import TestClient  # noqa: E402

from helix_sdk.audit import MemoryAuditSink  # noqa: E402
from helix_sdk.credentials import sign_data_integrity  # noqa: E402
from helix_sdk.did import build_did_document  # noqa: E402
from helix_sdk.keys import derive_public_key  # noqa: E402
from helix_mcp_middleware import InboundDelegationSettings, MCPMiddlewareOptions, create_local_verifier, create_mcp_audit_trail  # noqa: E402

from mcp_order_management.app import create_order_app  # noqa: E402
from mcp_order_management.downstream import DownstreamOptions  # noqa: E402
from mcp_proof_helpers import NOW_MS, fixture_signer, fixture_verifier_options, have_verifier_fixtures, load_environment, proof_meta  # noqa: E402

pytestmark = pytest.mark.skipif(not have_verifier_fixtures(), reason="helix-core verifier fixtures not found")

JSON_HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
B_DID = "did:web:b.helix.test:services:0b"


def _sign(env: Dict[str, Any], label: str, doc: Dict[str, Any]) -> Dict[str, Any]:
    return sign_data_integrity(doc, fixture_signer(env, label), created="2026-01-01T00:00:00Z")


def _world() -> Dict[str, Any]:
    env = copy.deepcopy(load_environment())
    did = lambda label: env["keys"][label]["did"]  # noqa: E731
    # The account (the fixture's owner) roots one hop to the agent at service A, in the sample's scope names.
    chain = [
        _sign(
            env,
            "owner",
            {
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/zcap/v1", "https://kya-os.org/ns/delegation/v1"],
                "id": "urn:zcap:00000000-0000-4000-8000-0000000d3e01",
                "type": ["VerifiableCredential", "DelegationCredential"],
                "issuer": did("owner"),
                "validFrom": "2026-01-01T00:00:00Z",
                "validUntil": "2026-11-01T00:00:00Z",
                "credentialSubject": {
                    "id": "urn:zcap:00000000-0000-4000-8000-0000000d3e01",
                    "invoker": did("agent"),
                    "parentCapability": did("service"),
                    "invocationTarget": did("service"),
                    "allowedAction": ["orders:read"],
                },
                "credentialStatus": {
                    "id": "https://owner.example/status/1#3",
                    "type": "BitstringStatusListEntry",
                    "statusPurpose": "revocation",
                    "statusListIndex": "3",
                    "statusListCredential": "https://owner.example/status/1",
                },
            },
        )
    ]
    card = copy.deepcopy(env["cards"]["attested"])
    card["responsibleParty"] = did("owner")
    card["capabilities"] = [
        {
            "name": "orders:read",
            "attestations": [
                {
                    "vc": _sign(
                        env,
                        "helix",
                        {
                            "@context": ["https://www.w3.org/ns/credentials/v2", "https://helixid.io/contexts/v1"],
                            "id": "urn:uuid:00000000-0000-4000-8000-0000000d3000",
                            "type": ["VerifiableCredential", "CapabilityAttestationCredential"],
                            "issuer": did("helix"),
                            "validFrom": "2026-01-01T00:00:00Z",
                            "validUntil": "2026-12-31T00:00:00Z",
                            "credentialSubject": {"id": did("agent"), "capability": "orders:read"},
                            "credentialStatus": {
                                "id": "https://helix.example/status/1#5",
                                "type": "BitstringStatusListEntry",
                                "statusPurpose": "revocation",
                                "statusListIndex": "5",
                                "statusListCredential": "https://helix.example/status/1",
                            },
                        },
                    )
                }
            ],
        }
    ]
    return {"env": env, "chain": chain, "cards": {did("agent"): card}, "A": did("service")}


def _forward(world: Dict[str, Any], forwarders: Optional[List[str]] = None) -> Any:
    env, A = world["env"], world["A"]
    b_doc = build_did_document(B_DID, derive_public_key("11" * 32))
    b_options = MCPMiddlewareOptions(
        service_did=B_DID,
        verifier=create_local_verifier(fixture_verifier_options(B_DID, env, {B_DID: b_doc}, cards=world["cards"])),
        tools={"lookup_order": {"minimum_level": "L2"}},
        inbound_delegation=InboundDelegationSettings(forwarders=forwarders),
    )
    sink = MemoryAuditSink()
    trail = create_mcp_audit_trail(sink, service_did=A)
    with TestClient(create_order_app("http://b.helix.test/mcp", b_options), base_url="http://b.helix.test") as b:

        async def request(method: str, url: str, headers: Any = None, content: Any = None) -> Any:
            return await asyncio.to_thread(b.request, method, url, headers=headers, content=content)

        a_options = MCPMiddlewareOptions(
            service_did=A,
            verifier=create_local_verifier(fixture_verifier_options(A, env, cards=world["cards"])),
            tools={"forward_lookup_order": {"minimum_level": "L2"}},
        )
        downstream = DownstreamOptions(
            url="http://b.helix.test/mcp", signer=fixture_signer(env, "service"), advisory_headers=True, audit=trail.outbound_audit(), request=request, clock=lambda: NOW_MS
        )
        with TestClient(create_order_app("http://a.helix.test/mcp", a_options, downstream=downstream), base_url="http://a.helix.test") as a:
            meta = proof_meta(fixture_signer(env, "agent"), A, "forward_lookup_order", {"orderId": "ORD-1001"}, chain=world["chain"])
            response = a.post(
                "/mcp",
                headers=JSON_HEADERS,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "forward_lookup_order", "arguments": {"orderId": "ORD-1001"}, "_meta": meta}},
            )
    return response, sink


def test_b_answers_the_agents_lookup_and_a_audits_the_attachment() -> None:
    world = _world()
    response, sink = _forward(world, [world["A"]])
    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert not result.get("isError")
    answer = json.loads(result["content"][0]["text"])
    assert answer["downstreamStatus"] == 200
    assert json.loads(answer["downstream"]["result"]["content"][0]["text"])["customer"] == "Asha Rao"
    attached = next(event for event in sink.events if event["eventType"] == "delegation.outbound_attached")
    assert attached["resource"] == {"kind": "public_did", "did": "did:web:b.helix.test"}
    assert attached["actor"] == {"kind": "pairwise_did", "did": world["env"]["keys"]["agent"]["did"]}
    assert world["chain"][0]["id"] in attached["action"]["name"]


def test_by_default_b_accepts_the_forward_of_any_service() -> None:
    response, _ = _forward(_world())
    result = response.json()["result"]
    assert not result.get("isError")
    assert json.loads(result["content"][0]["text"])["downstreamStatus"] == 200


def test_b_refuses_when_it_does_not_accept_as_forwards() -> None:
    world = _world()
    response, _ = _forward(world, [])
    result = response.json()["result"]
    assert result["isError"] is True
    assert json.loads(result["content"][0]["text"])["downstreamStatus"] == 401
