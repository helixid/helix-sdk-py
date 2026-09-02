# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_crewai -- CrewAI integration for HelixID.

There is no CrewAI counterpart in helix-sdk-js -- CrewAI is Python-only.
This package follows the same pattern as helix_langchain's tool wrapper
(itself ported from helix-sdk-js's langchain package), adapted to CrewAI's
actual `crewai.tools.BaseTool` interface -- verified directly against the
installed `crewai` package (see tests/test_langchain_crewai.py), not
assumed by analogy. CrewAI's `BaseTool._run(*args, **kwargs)` has the
same shape as LangChain Python's, so `helix_id_crewai_tool()` mirrors
`helix_id_tool_wrapper()` almost exactly.

Usage:

    from helix_crewai import helix_id_crewai_tool

    protected_tool = helix_id_crewai_tool(
        my_orders_tool,
        wallet_file_path="agent-wallet.json",
        wallet_passphrase=os.environ["HELIX_WALLET_PASSPHRASE"],
        target_service="https://api.example.com/v1/tools/orders",
    )
    crew = Crew(agents=[...], tasks=[...], tools=[protected_tool])
"""

from __future__ import annotations

from typing import Any, List, Optional, TypeVar

from pydantic import PrivateAttr

from helix_sdk import AgentWallet
from helix_sdk.errors import NoCredentialInWalletError
from helix_sdk.tool_vp import build_signed_vp

try:
    from crewai.tools import BaseTool
except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
    raise ImportError(
        "helix_crewai requires the 'crewai' package. Install it with: "
        "pip install helixid-sdk-py[crewai]"
    ) from exc

T = TypeVar("T", bound=BaseTool)


def helix_id_crewai_tool(
    tool: T,
    wallet_file_path: str,
    wallet_passphrase: str,
    target_service: str,
    user_did: Optional[str] = None,
) -> BaseTool:
    """Wraps `tool` so every invocation has a freshly signed VP injected
    into its kwargs as `_helixVP`, before delegating to the original
    tool's `_run`."""

    class _HelixIDWrappedCrewAITool(BaseTool):
        _wrapped: Any = PrivateAttr()
        _wallet_file_path: str = PrivateAttr()
        _wallet_passphrase: str = PrivateAttr()
        _target_service: str = PrivateAttr()
        _user_did: Optional[str] = PrivateAttr()

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            vp = build_signed_vp(
                self._wallet_file_path, self._wallet_passphrase, self._target_service, self._user_did
            )
            kwargs["_helixVP"] = vp
            return self._wrapped._run(*args, **kwargs)

    wrapped = _HelixIDWrappedCrewAITool(
        name=tool.name, description=tool.description, args_schema=tool.args_schema
    )
    object.__setattr__(wrapped, "_wrapped", tool)
    object.__setattr__(wrapped, "_wallet_file_path", wallet_file_path)
    object.__setattr__(wrapped, "_wallet_passphrase", wallet_passphrase)
    object.__setattr__(wrapped, "_target_service", target_service)
    object.__setattr__(wrapped, "_user_did", user_did)
    return wrapped


def filter_crewai_tools_by_scope(
    tools: List[T], wallet_file_path: str, wallet_passphrase: str
) -> List[T]:
    """CrewAI counterpart of helix_langchain.filter_tools_by_scope(). CrewAI's
    BaseTool has no built-in metadata/required-scope field, so this checks
    a plain `required_scope` attribute if the tool defines one (e.g. a
    custom BaseTool subclass with `required_scope: str = "read:orders"`),
    defaulting to allow when absent -- same default-allow rule as the
    LangChain and JS versions."""
    wallet = AgentWallet.load(wallet_file_path, wallet_passphrase)
    vcs = wallet.credentials
    if not vcs:
        raise NoCredentialInWalletError("No credential in wallet. Run enrollment first.")
    scopes = vcs[0].get("credentialSubject", {}).get("privilegeScopes", [])

    def allowed(tool: T) -> bool:
        required_scope = getattr(tool, "required_scope", None)
        if not required_scope:
            return True
        return required_scope in scopes or getattr(tool, "name", None) in scopes

    return [tool for tool in tools if allowed(tool)]
