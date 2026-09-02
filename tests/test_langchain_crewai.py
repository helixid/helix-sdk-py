# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Functional tests for the three framework-adapter packages
(helix_mcp, helix_langchain, helix_crewai) against real AgentWallet files
and real langchain-core / crewai tool base classes -- not mocks of those
frameworks, the actual installed packages, so a real interface drift
(e.g. a BaseTool signature change) would fail these tests instead of
silently passing against a stale assumption.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

from helix_sdk import AgentWallet, generate_key_pair, public_key_to_multibase
from helix_sdk.self_signed import self_issue_vc, SelfIssueOptions


@pytest.fixture()
def wallet_with_credential():
    with tempfile.TemporaryDirectory() as d:
        key_pair = generate_key_pair()
        did = f"did:key:{public_key_to_multibase(key_pair.public_key)}"
        path = os.path.join(d, "wallet.json")
        wallet = AgentWallet(private_key_hex=key_pair.private_key, did_value=did, passphrase="test-pass")
        wallet.save(path)
        vc = self_issue_vc(SelfIssueOptions(scopes=["read:orders"]), did, key_pair.private_key)
        wallet.add_credential(vc)
        yield path, "test-pass", did


class TestMCP:
    def test_attach_helix_vp_adds_vp_to_input(self, wallet_with_credential) -> None:
        from helix_mcp import attach_helix_vp, AttachHelixVPOptions

        wallet_path, passphrase, did = wallet_with_credential
        tool_call = {"name": "get_orders", "input": {"orderId": "123"}}
        result = attach_helix_vp(
            tool_call,
            AttachHelixVPOptions(
                wallet_passphrase=passphrase,
                wallet_file_path=wallet_path,
                target_service="https://svc.example.invalid",
            ),
        )
        assert result["input"]["orderId"] == "123"
        assert result["input"]["_helixVP"]["holder"] == did
        # Original tool_call must be untouched (shallow-copy semantics,
        # matching the JS spread-based implementation).
        assert "_helixVP" not in tool_call["input"]

    def test_middleware_rejects_missing_vp(self) -> None:
        from helix_mcp import helixid_mcp_middleware, MCPMiddlewareOptions
        from helix_sdk.errors import VPMissingError

        fake_client = MagicMock()
        middleware = helixid_mcp_middleware(MCPMiddlewareOptions(client=fake_client))
        with pytest.raises(VPMissingError):
            middleware({"name": "get_orders", "input": {}})

    def test_middleware_verifies_and_checks_scope(self) -> None:
        from helix_mcp import helixid_mcp_middleware, MCPMiddlewareOptions
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
    def test_tool_wrapper_injects_vp_and_delegates(self, wallet_with_credential) -> None:
        pytest.importorskip("langchain_core", reason="langchain-core requires Python >= 3.10")
        from langchain_core.tools import BaseTool
        from pydantic import BaseModel, Field
        from helix_langchain import helix_id_tool_wrapper

        wallet_path, passphrase, did = wallet_with_credential

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

        wrapped = helix_id_tool_wrapper(
            RealTool(), wallet_path, passphrase, target_service="https://svc.example.invalid"
        )
        result = wrapped.run({"order_id": "123"})
        assert result == "ok"
        assert captured["order_id"] == "123"
        assert captured["_helixVP"]["holder"] == did

    def test_filter_tools_by_scope(self, wallet_with_credential) -> None:
        pytest.importorskip("langchain_core", reason="langchain-core requires Python >= 3.10")
        from helix_langchain import filter_tools_by_scope

        wallet_path, passphrase, _did = wallet_with_credential

        class FakeTool:
            def __init__(self, name: str, required_scope: str = None) -> None:
                self.name = name
                if required_scope:
                    self.metadata = {"requiredScope": required_scope}

        allowed_tool = FakeTool("get_orders", "read:orders")
        denied_tool = FakeTool("write_orders", "write:orders")
        unscoped_tool = FakeTool("misc")

        result = filter_tools_by_scope([allowed_tool, denied_tool, unscoped_tool], wallet_path, passphrase)
        assert {t.name for t in result} == {"get_orders", "misc"}


class TestCrewAI:
    def test_crewai_tool_wrapper_injects_vp_and_delegates(self, wallet_with_credential) -> None:
        pytest.importorskip("crewai", reason="crewai requires Python >= 3.10")
        from crewai.tools import BaseTool
        from pydantic import BaseModel, Field
        from helix_crewai import helix_id_crewai_tool

        wallet_path, passphrase, did = wallet_with_credential

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

        wrapped = helix_id_crewai_tool(
            RealTool(), wallet_path, passphrase, target_service="https://svc.example.invalid"
        )
        result = wrapped.run(order_id="123")
        assert result == "ok"
        assert captured["order_id"] == "123"
        assert captured["_helixVP"]["holder"] == did

    def test_filter_crewai_tools_by_scope(self, wallet_with_credential) -> None:
        pytest.importorskip("crewai", reason="crewai requires Python >= 3.10")
        from helix_crewai import filter_crewai_tools_by_scope

        wallet_path, passphrase, _did = wallet_with_credential

        class FakeTool:
            def __init__(self, name: str, required_scope: str = None) -> None:
                self.name = name
                self.required_scope = required_scope

        allowed_tool = FakeTool("get_orders", "read:orders")
        denied_tool = FakeTool("write_orders", "write:orders")

        result = filter_crewai_tools_by_scope([allowed_tool, denied_tool], wallet_path, passphrase)
        assert [t.name for t in result] == ["get_orders"]
