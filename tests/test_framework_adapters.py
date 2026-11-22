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

KYA-OS story C-C: a wrapped tool signs each MCP request it sends with a
request proof by the agent's own Signer (``sign_current_request``); the
Helix VP and its X-Helix-VP header are gone. Scope lookups are server-side
(client.list_vcs()), so the tool filters use a fake HelixClient.
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from helix_sdk.agent_key import generate_agent_key, to_did_key
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.verifier import (
    DELEGATION_CHAIN_META_KEY,
    REQUEST_PROOF_META_KEY,
    MemoryNonceStore,
    RequestProofOptions,
    RequestProofSeams,
    did_key_document,
    ed25519_keys_of,
    verify_request_proof,
)

SERVICE = "did:web:orders.example.com"
HOP = {"proof": {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "proofPurpose": "assertionMethod"}}


@pytest.fixture()
def agent_signer():
    key = generate_agent_key()
    did = to_did_key(key.public_key_hex)
    return EnvSigner(did, kid=did.split(":")[-1], env_var="AGENT_KEY", env={"AGENT_KEY": key.private_key_hex}), key.private_key_hex


def verifies(request: Dict[str, Any]) -> bool:
    seams = RequestProofSeams(
        resolve_did=did_key_document,
        resolve_did_keys=lambda did: ed25519_keys_of(did_key_document(did) or {}),
        nonce_store=MemoryNonceStore(),
        clock=lambda: int(__import__("time").time() * 1000),
    )
    proof = request["params"]["_meta"][REQUEST_PROOF_META_KEY]
    return verify_request_proof(proof, request, seams, RequestProofOptions(expected_audience=SERVICE)).ok


@pytest.fixture()
def fake_client_and_did():
    did = "did:key:zTestAgent"
    client = MagicMock()
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
        return SimpleNamespace(
            ok=True, effective_scopes=self.scopes, proof_did="did:key:zTestAgent", agent_did="did:key:zTestAgent", level="L1",
            fresh=True, reasons=[], proof_assurance="L3-minus", proof_floor=True, warnings=[],
        )


PROOF_META = {"org.kya-os/request-proof": {"prf": "org.kya-os/proof.v1"}}


class TestMCP:
    def test_middleware_rejects_a_call_without_a_proof(self) -> None:
        from helix_mcp_middleware import MCPMiddlewareOptions, ProofError, helixid_mcp_middleware

        middleware = helixid_mcp_middleware(MCPMiddlewareOptions(minimum_level="L1", verifier=_Verifier([])))
        with pytest.raises(ProofError) as excinfo:
            middleware({"name": "get_orders", "input": {}})
        assert excinfo.value.code == "PROOF_MISSING"

    def test_middleware_ignores_a_proof_in_tool_arguments(self) -> None:
        from helix_mcp_middleware import MCPMiddlewareOptions, ProofError, helixid_mcp_middleware

        verifier = _Verifier([])
        middleware = helixid_mcp_middleware(MCPMiddlewareOptions(minimum_level="L1", verifier=verifier))
        with pytest.raises(ProofError):
            middleware({"name": "get_orders", "input": {"org.kya-os/request-proof": {"prf": "x"}}})
        assert verifier.calls == []

    def test_middleware_no_longer_reads_a_helix_vp(self) -> None:
        from helix_mcp_middleware import MCPMiddlewareOptions, ProofError, helixid_mcp_middleware

        verifier = _Verifier(["read:orders"])
        middleware = helixid_mcp_middleware(MCPMiddlewareOptions(minimum_level="L1", verifier=verifier))
        for call in ({"_meta": {"x-helix-vp": "e30"}}, {"headers": {"x-helix-vp": "e30"}}, {"headers": {"authorization": "HelixVP e30"}}):
            with pytest.raises(ProofError):
                middleware({"name": "get_orders", **call})
        assert verifier.calls == []

    def test_middleware_verifies_and_checks_scope(self) -> None:
        from helix_mcp_middleware import MCPMiddlewareOptions, helixid_mcp_middleware
        from helix_sdk.errors import InsufficientScopeError

        verifier = _Verifier(["read:orders"])
        allowed = helixid_mcp_middleware(MCPMiddlewareOptions(minimum_level="L1", verifier=verifier, required_scopes=["read:orders"]))
        call = {"name": "get_orders", "_meta": PROOF_META}
        assert allowed(call) is call
        refused = helixid_mcp_middleware(MCPMiddlewareOptions(minimum_level="L1", verifier=verifier, required_scopes=["write:orders"]))
        with pytest.raises(InsufficientScopeError):
            refused(call)
        assert len(verifier.calls) == 2


class TestLangChain:
    def test_tool_wrapper_signs_each_request_and_delegates(self, agent_signer) -> None:
        pytest.importorskip("langchain_core", reason="langchain-core requires Python >= 3.10")
        from langchain_core.tools import BaseTool
        from pydantic import BaseModel, Field
        from helix_langchain import helix_id_tool_wrapper, sign_current_request

        signer, private_key_hex = agent_signer

        class Args(BaseModel):
            order_id: str = Field(description="order id")

        captured: Dict[str, Any] = {}
        sent: List[Dict[str, Any]] = []

        class RealTool(BaseTool):
            name: str = "get_orders"
            description: str = "gets orders"
            args_schema: type = Args

            def _run(self, *args: Any, **kwargs: Any) -> Any:
                captured.update(kwargs)
                for _ in range(2):
                    sent.append(sign_current_request({"name": "lookup_order", "arguments": {"orderId": kwargs["order_id"]}}))
                return "ok"

        wrapped = helix_id_tool_wrapper(RealTool(), signer=signer, audience=SERVICE, chain=lambda: [HOP])
        assert wrapped.run({"order_id": "123"}) == "ok"
        assert captured == {"order_id": "123"}
        assert sent[0]["params"]["arguments"] == {"orderId": "123"} and sent[0]["params"]["_meta"][DELEGATION_CHAIN_META_KEY] == [HOP]
        proofs = [request["params"]["_meta"][REQUEST_PROOF_META_KEY] for request in sent]
        assert proofs[0]["nonce"] != proofs[1]["nonce"] and proofs[0]["did"] == signer.did
        assert all(verifies(request) for request in sent)
        assert private_key_hex not in str(sent)  # rule 7: no request carries the key
        with pytest.raises(RuntimeError, match="not inside a Helix-wrapped tool call"):
            sign_current_request({"name": "lookup_order"})

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
    def test_crewai_tool_wrapper_signs_each_request_and_delegates(self, agent_signer) -> None:
        pytest.importorskip("crewai", reason="crewai requires Python >= 3.10")
        from crewai.tools import BaseTool
        from pydantic import BaseModel, Field
        from helix_crewai import helix_id_crewai_tool, sign_current_request

        signer, _ = agent_signer

        class Args(BaseModel):
            order_id: str = Field(description="order id")

        captured: Dict[str, Any] = {}

        class RealTool(BaseTool):
            name: str = "get_orders"
            description: str = "gets orders"
            args_schema: type = Args

            def _run(self, *args: Any, **kwargs: Any) -> Any:
                captured.update(kwargs)
                captured["request"] = sign_current_request({"name": "lookup_order", "arguments": {"orderId": kwargs["order_id"]}})
                return "ok"

        wrapped = helix_id_crewai_tool(RealTool(), signer=signer, audience=SERVICE, chain=[HOP])
        assert wrapped.run(order_id="123") == "ok"
        assert captured["order_id"] == "123"
        assert captured["request"]["params"]["_meta"][DELEGATION_CHAIN_META_KEY] == [HOP]
        assert verifies(captured["request"])
        with pytest.raises(RuntimeError):
            sign_current_request({"name": "lookup_order"})

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


class TestAgentScopes:
    def test_scopes_come_from_the_active_credential_and_none_is_an_error(self) -> None:
        from helix_sdk.agent_scopes import get_agent_scopes

        client = MagicMock()
        client.list_vcs.return_value = [{"scopes": ["read:orders"]}]
        assert get_agent_scopes(client, "did:key:zA") == ["read:orders"]
        client.list_vcs.assert_called_with(subject_did="did:key:zA", status="active")
        client.list_vcs.return_value = []
        with pytest.raises(RuntimeError, match="No active credential"):
            get_agent_scopes(client, "did:key:zA")

    def test_the_langchain_callback_handler_signs_nothing(self) -> None:
        pytest.importorskip("langchain_core", reason="langchain-core requires Python >= 3.10")
        from helix_langchain import HelixIDCallbackHandler

        handler = HelixIDCallbackHandler("did:key:zA", "did:web:orders.example.com")
        assert (handler.agent_did, handler.audience) == ("did:key:zA", "did:web:orders.example.com")
        assert handler.on_tool_start({}, "input") is None
