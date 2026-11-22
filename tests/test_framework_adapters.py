# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Functional tests for the three framework-adapter packages
(helix_mcp_middleware, helix_langchain, helix_crewai) against real
langchain-core / crewai tool base classes -- not mocks of those
frameworks, the actual installed packages, so a real interface drift
(e.g. a BaseTool signature change) would fail these tests instead of
silently passing against a stale assumption.

Agent self-custody has been retired: signing and scope lookups are
server-side calls now (client.sign_vp() / client.list_vcs()), not reads
from a local wallet file -- these tests use a fake HelixClient instead of
a real AgentWallet fixture.
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def fake_client_and_did():
    did = "did:key:zTestAgent"
    fake_signed_vp = {"id": "vp:helix:test-1", "holder": did, "proof": {}}
    client = MagicMock()
    client.sign_vp.return_value = fake_signed_vp
    client.list_vcs.return_value = [{"vcId": "vc:1", "subjectDid": did, "scopes": ["read:orders"]}]
    return client, did


class _Verifier:
    """Stands in for the local verifier (story F-2): every proof verifies with ``scopes``."""

    def __init__(self, scopes: Any) -> None:
        self.scopes = list(scopes)
        self.calls: list = []

    def verify_call(self, call: Dict[str, Any]) -> Any:
        from types import SimpleNamespace

        self.calls.append(call)
        return SimpleNamespace(ok=True, effective_scopes=self.scopes, proof_did="did:key:zTestAgent", level="L1", fresh=True, reasons=[], proof_assurance="L3-minus")


PROOF_META = {"org.kya-os/request-proof": {"prf": "org.kya-os/proof.v1"}}


class TestMCP:
    def test_middleware_rejects_a_call_without_a_proof(self) -> None:
        from helix_mcp_middleware import MCPMiddlewareOptions, ProofError, helixid_mcp_middleware

        middleware = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=_Verifier([])))
        with pytest.raises(ProofError) as excinfo:
            middleware({"name": "get_orders", "input": {}})
        assert excinfo.value.code == "PROOF_MISSING"

    def test_middleware_ignores_a_proof_in_tool_arguments(self) -> None:
        from helix_mcp_middleware import MCPMiddlewareOptions, ProofError, helixid_mcp_middleware

        verifier = _Verifier([])
        middleware = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier))
        with pytest.raises(ProofError):
            middleware({"name": "get_orders", "input": {"org.kya-os/request-proof": {"prf": "x"}}})
        assert verifier.calls == []

    def test_middleware_no_longer_reads_a_helix_vp(self) -> None:
        from helix_mcp_middleware import MCPMiddlewareOptions, ProofError, helixid_mcp_middleware

        verifier = _Verifier(["read:orders"])
        middleware = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier))
        for call in ({"_meta": {"x-helix-vp": "e30"}}, {"headers": {"x-helix-vp": "e30"}}, {"headers": {"authorization": "HelixVP e30"}}):
            with pytest.raises(ProofError):
                middleware({"name": "get_orders", **call})
        assert verifier.calls == []

    def test_middleware_verifies_and_checks_scope(self) -> None:
        from helix_mcp_middleware import MCPMiddlewareOptions, helixid_mcp_middleware
        from helix_sdk.errors import InsufficientScopeError

        verifier = _Verifier(["read:orders"])
        allowed = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier, required_scopes=["read:orders"]))
        call = {"name": "get_orders", "_meta": PROOF_META}
        assert allowed(call) is call
        refused = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier, required_scopes=["write:orders"]))
        with pytest.raises(InsufficientScopeError):
            refused(call)
        assert len(verifier.calls) == 2


class TestLangChain:
    def test_tool_wrapper_exposes_vp_header_and_delegates(self, fake_client_and_did) -> None:
        pytest.importorskip("langchain_core", reason="langchain-core requires Python >= 3.10")
        from langchain_core.tools import BaseTool
        from pydantic import BaseModel, Field
        from helix_langchain import helix_id_tool_wrapper, current_helix_vp_headers
        from helix_sdk import decode_helix_vp

        client, did = fake_client_and_did

        class Args(BaseModel):
            order_id: str = Field(description="order id")

        captured: Dict[str, Any] = {}

        class RealTool(BaseTool):
            name: str = "get_orders"
            description: str = "gets orders"
            args_schema: type = Args

            def _run(self, *args: Any, **kwargs: Any) -> Any:
                captured.update(kwargs)
                captured["headers"] = current_helix_vp_headers()
                return "ok"

        wrapped = helix_id_tool_wrapper(RealTool(), client, did, target_service="https://svc.example.invalid")
        result = wrapped.run({"order_id": "123"})
        assert result == "ok"
        assert captured["order_id"] == "123"
        assert "_helixVP" not in captured
        assert decode_helix_vp(captured["headers"]["X-Helix-VP"])["holder"] == did
        assert current_helix_vp_headers() == {}

    def test_filter_tools_by_scope(self, fake_client_and_did) -> None:
        pytest.importorskip("langchain_core", reason="langchain-core requires Python >= 3.10")
        from helix_langchain import filter_tools_by_scope

        client, did = fake_client_and_did

        class FakeTool:
            def __init__(self, name: str, required_scope: str = None) -> None:
                self.name = name
                if required_scope:
                    self.metadata = {"requiredScope": required_scope}

        allowed_tool = FakeTool("get_orders", "read:orders")
        denied_tool = FakeTool("write_orders", "write:orders")
        unscoped_tool = FakeTool("misc")

        result = filter_tools_by_scope([allowed_tool, denied_tool, unscoped_tool], client, did)
        assert {t.name for t in result} == {"get_orders", "misc"}


class TestCrewAI:
    def test_crewai_tool_wrapper_exposes_vp_header_and_delegates(self, fake_client_and_did) -> None:
        pytest.importorskip("crewai", reason="crewai requires Python >= 3.10")
        from crewai.tools import BaseTool
        from pydantic import BaseModel, Field
        from helix_crewai import helix_id_crewai_tool, current_helix_vp_headers
        from helix_sdk import decode_helix_vp

        client, did = fake_client_and_did

        class Args(BaseModel):
            order_id: str = Field(description="order id")

        captured: Dict[str, Any] = {}

        class RealTool(BaseTool):
            name: str = "get_orders"
            description: str = "gets orders"
            args_schema: type = Args

            def _run(self, *args: Any, **kwargs: Any) -> Any:
                captured.update(kwargs)
                captured["headers"] = current_helix_vp_headers()
                return "ok"

        wrapped = helix_id_crewai_tool(RealTool(), client, did, target_service="https://svc.example.invalid")
        result = wrapped.run(order_id="123")
        assert result == "ok"
        assert captured["order_id"] == "123"
        assert "_helixVP" not in captured
        assert decode_helix_vp(captured["headers"]["X-Helix-VP"])["holder"] == did
        assert current_helix_vp_headers() == {}

    def test_filter_crewai_tools_by_scope(self, fake_client_and_did) -> None:
        pytest.importorskip("crewai", reason="crewai requires Python >= 3.10")
        from helix_crewai import filter_crewai_tools_by_scope

        client, did = fake_client_and_did

        class FakeTool:
            def __init__(self, name: str, required_scope: str = None) -> None:
                self.name = name
                self.required_scope = required_scope

        allowed_tool = FakeTool("get_orders", "read:orders")
        denied_tool = FakeTool("write_orders", "write:orders")

        result = filter_crewai_tools_by_scope([allowed_tool, denied_tool], client, did)
        assert [t.name for t in result] == ["get_orders"]
