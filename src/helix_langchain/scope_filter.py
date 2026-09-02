# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
filter_tools_by_scope(), ported from helix-sdk-js's
langchain/src/scope-filter.ts.
"""

from __future__ import annotations

from typing import Any, List, Protocol, runtime_checkable

from helix_sdk import AgentWallet
from helix_sdk.errors import NoCredentialInWalletError


@runtime_checkable
class StructuredTool(Protocol):
    name: str


def filter_tools_by_scope(
    tools: List[Any], wallet_file_path: str, wallet_passphrase: str
) -> List[Any]:
    wallet = AgentWallet.load(wallet_file_path, wallet_passphrase)
    vcs = wallet.credentials
    if not vcs:
        raise NoCredentialInWalletError("No credential in wallet. Run enrollment first.")
    vc = vcs[0]

    scopes = vc.get("credentialSubject", {}).get("privilegeScopes", [])

    def allowed(tool: Any) -> bool:
        # LangChain tools carry required-scope metadata inconsistently
        # across versions; check the two conventions this SDK supports --
        # a `metadata` dict (matching helix-sdk-js's tool.metadata.requiredScope)
        # or a plain `required_scope` attribute -- and default to allow when
        # neither is present, exactly like the JS version.
        required_scope = None
        metadata = getattr(tool, "metadata", None)
        if isinstance(metadata, dict):
            required_scope = metadata.get("requiredScope") or metadata.get("required_scope")
        if required_scope is None:
            required_scope = getattr(tool, "required_scope", None)
        if not required_scope:
            return True
        return required_scope in scopes or getattr(tool, "name", None) in scopes

    return [tool for tool in tools if allowed(tool)]
