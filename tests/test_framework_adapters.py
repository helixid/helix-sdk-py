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


class TestMCP:
    def test_attach_helix_vp_adds_vp_to_input(self, fake_client_and_did) -> None:
        from helix_mcp_middleware import attach_helix_vp, AttachHelixVPOptions

        client, did = fake_client_and_did
        tool_call = {"name": "get_orders", "input": {"orderId": "123"}}
        result = attach_helix_vp(
            tool_call,
            AttachHelixVPOptions(client=client, agent_did=did, target_service="https://svc.example.invalid"),
        )
        assert result["input"]["orderId"] == "123"
        assert result["input"]["_helixVP"]["holder"] == did
        client.sign_vp.assert_called_once_with(did, "https://svc.example.invalid", user_did=None)
        # Original tool_call must be untouched (shallow-copy semantics,
        # matching the JS spread-based implementation).
        assert "_helixVP" not in tool_call["input"]

    def test_middleware_rejects_missing_vp(self) -> None:
        from helix_mcp_middleware import helixid_mcp_middleware, MCPMiddlewareOptions
        from helix_sdk.errors import VPMissingError

        fake_client = MagicMock()
        middleware = helixid_mcp_middleware(MCPMiddlewareOptions(client=fake_client))
        with pytest.raises(VPMissingError):
            middleware({"name": "get_orders", "input": {}})

    def test_middleware_verifies_and_checks_scope(self) -> None:
        from helix_mcp_middleware import helixid_mcp_middleware, MCPMiddlewareOptions
        from helix_sdk.errors import InsufficientScopeError

        fake_client = MagicMock()
        fake_client.verify_vp.return_value = {"valid": True, "effectiveScopes": ["read:orders"]}
        middleware = helixid_mcp_middleware(
            MCPMiddlewareOptions(client=fake_client, required_scopes=["write:orders"])
        )
        with pytest.raises(InsufficientScopeError):
            middleware({"name": "get_orders", "input": {"_helixVP": {"id": "vp:1"}}})

        fake_client.verify_vp.assert_called_once()


class TestLangChain:
    def test_tool_wrapper_injects_vp_and_delegates(self, fake_client_and_did) -> None:
        pytest.importorskip("langchain_core", reason="langchain-core requires Python >= 3.10")
        from langchain_core.tools import BaseTool
        from pydantic import BaseModel, Field
        from helix_langchain import helix_id_tool_wrapper

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
                return "ok"

        wrapped = helix_id_tool_wrapper(RealTool(), client, did, target_service="https://svc.example.invalid")
        result = wrapped.run({"order_id": "123"})
        assert result == "ok"
        assert captured["order_id"] == "123"
        assert captured["_helixVP"]["holder"] == did

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
    def test_crewai_tool_wrapper_injects_vp_and_delegates(self, fake_client_and_did) -> None:
        pytest.importorskip("crewai", reason="crewai requires Python >= 3.10")
        from crewai.tools import BaseTool
        from pydantic import BaseModel, Field
        from helix_crewai import helix_id_crewai_tool

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
                return "ok"

        wrapped = helix_id_crewai_tool(RealTool(), client, did, target_service="https://svc.example.invalid")
        result = wrapped.run(order_id="123")
        assert result == "ok"
        assert captured["order_id"] == "123"
        assert captured["_helixVP"]["holder"] == did

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
