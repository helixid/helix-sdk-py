# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
filter_tools_by_scope(), ported from helix-sdk-js's
langchain/src/scope-filter.ts.

Agent self-custody has been retired -- there is no local wallet file to
read credentialSubject.privilegeScopes from anymore. list_vcs() already
returns scopes directly on each summary, so this is one API call.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol, runtime_checkable

from helix_sdk.tool_vp import get_agent_scopes

if TYPE_CHECKING:
    from helix_sdk import HelixClient


@runtime_checkable
class StructuredTool(Protocol):
    name: str


def filter_tools_by_scope(tools: List[Any], client: "HelixClient", agent_did: str) -> List[Any]:
    scopes = get_agent_scopes(client, agent_did)

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
