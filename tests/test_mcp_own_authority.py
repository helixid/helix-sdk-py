# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""Own authority (four-clients) on the gated methods (MCP gate fixes): with ``allow_own_authority``, an
agent's attested capabilities count as far as the service offers them, across its tools, resources and
prompts. ``require_delegation`` keeps a tool out of own authority. The verifier is a stub that grants the
agent's attested capabilities within the catalog the gate hands it. Parity with helix-sdk-js's
own-authority.test.ts."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from helix_mcp_middleware import MCPMiddlewareOptions, helixid_mcp_middleware

SERVICE = "did:web:orders.helix.test"
AGENT = "did:web:agents.helix.test:reader"
META = {"org.kya-os/request-proof": "stub.proof.jws"}


class StubVerifier:
    def __init__(self, attested: List[str], allow_own_authority: bool = True) -> None:
        self.attested = attested
        self.allow_own_authority = allow_own_authority
        self.service_did = SERVICE
        self.calls: List[Dict[str, Any]] = []

    def verify_call(self, call: Dict[str, Any]) -> Any:
        self.calls.append(call)
        catalog: Optional[List[str]] = call.get("own_authority_catalog")
        scopes = [scope for scope in self.attested if catalog is not None and scope in catalog]
        return SimpleNamespace(
            ok=True, reasons=[], warnings=[], agent_did=AGENT, effective_scopes=scopes, level="L3",
            proof_assurance=None, fresh=True, proof_floor=False, proof_did=AGENT,
        )


def gate(verifier: StubVerifier, **extra: Any) -> Any:
    return helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier, service_did=SERVICE, inbound_delegation=False, **extra))


def code_of(error: BaseException) -> Optional[str]:
    return getattr(error, "code", None)


def test_hands_the_verifier_every_scope_the_service_offers_once_each() -> None:
    verifier = StubVerifier(["orders:read"])
    mw = gate(
        verifier,
        tool_scopes={"lookup_order": ["orders:read"]},
        resource_scopes={"orders://ledger": ["ledger:read"], "orders://a": ["orders:read"]},
        prompt_scopes={"summarize": ["prompts:use"]},
    )
    mw.authorize({"method": "tools/call", "name": "lookup_order", "_meta": META})
    assert verifier.calls[0]["own_authority_catalog"] == ["orders:read", "ledger:read", "prompts:use"]


def test_resource_and_prompt_on_attested_capabilities_alone() -> None:
    verifier = StubVerifier(["ledger:read", "prompts:use"])
    mw = gate(
        verifier,
        tool_scopes={"lookup_order": ["orders:read"]},
        resource_scopes={"orders://ledger": ["ledger:read"]},
        prompt_scopes={"summarize": ["prompts:use"]},
    )
    resource = mw.authorize({"method": "resources/read", "name": "orders://ledger", "_meta": META})
    assert list(resource.scopes) == ["ledger:read", "prompts:use"]
    prompt = mw.authorize({"method": "prompts/get", "name": "summarize", "_meta": META})
    assert prompt.agent_did == AGENT
    # A tool scope the agent is not attested for still refuses.
    with pytest.raises(Exception) as refused:
        mw.authorize({"method": "tools/call", "name": "lookup_order", "_meta": META})
    assert code_of(refused.value) == "INSUFFICIENT_SCOPE"


def test_resources_only_and_no_catalog_without_any_scope_map() -> None:
    only_resources = StubVerifier(["ledger:read"])
    gate(only_resources, resource_scopes={"orders://ledger": ["ledger:read"]}).authorize(
        {"method": "resources/read", "name": "orders://ledger", "_meta": META}
    )
    assert only_resources.calls[0]["own_authority_catalog"] == ["ledger:read"]
    none = StubVerifier([])
    gate(none).authorize({"method": "ping", "_meta": META})
    assert "own_authority_catalog" not in none.calls[0]


def test_no_catalog_when_the_service_did_not_opt_in() -> None:
    verifier = StubVerifier(["orders:read"], allow_own_authority=False)
    mw = gate(verifier, tool_scopes={"lookup_order": ["orders:read"]})
    with pytest.raises(Exception) as refused:
        mw.authorize({"method": "tools/call", "name": "lookup_order", "_meta": META})
    assert code_of(refused.value) == "INSUFFICIENT_SCOPE"
    assert "own_authority_catalog" not in verifier.calls[0]


def test_require_delegation_tool_stays_out_of_own_authority() -> None:
    verifier = StubVerifier(["orders:read", "orders:admin"])
    mw = gate(
        verifier,
        tool_scopes={"lookup_order": ["orders:read"], "refund_order": ["orders:admin"]},
        tools={"refund_order": {"require_delegation": True}},
    )
    assert "orders:read" in mw.authorize({"method": "tools/call", "name": "lookup_order", "_meta": META}).scopes
    with pytest.raises(Exception) as refused:
        mw.authorize({"method": "tools/call", "name": "refund_order", "_meta": META})
    assert code_of(refused.value) == "INSUFFICIENT_SCOPE"
