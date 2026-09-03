# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_crewai.scope_filter -- CrewAI counterpart of
helix_langchain.scope_filter.filter_tools_by_scope(). CrewAI's BaseTool
has no built-in metadata/required-scope field, so this checks a plain
`required_scope` attribute if the tool defines one (e.g. a custom
BaseTool subclass with `required_scope: str = "read:orders"`), defaulting
to allow when absent -- same default-allow rule as the LangChain and JS
versions.
"""

from __future__ import annotations

from typing import List, TypeVar

from helix_sdk import AgentWallet
from helix_sdk.errors import NoCredentialInWalletError

try:
    from crewai.tools import BaseTool
except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
    raise ImportError(
        "helix_crewai requires the 'crewai' package. Install it with: "
        "pip install helixid-sdk-py[crewai]"
    ) from exc

T = TypeVar("T", bound=BaseTool)


def filter_crewai_tools_by_scope(
    tools: List[T], wallet_file_path: str, wallet_passphrase: str
) -> List[T]:
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
