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

Agent self-custody has been retired -- there is no local wallet file to
read credentialSubject.privilegeScopes from anymore. list_vcs() already
returns scopes directly on each summary, so this is one API call.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, TypeVar

from helix_sdk.tool_vp import get_agent_scopes

if TYPE_CHECKING:
    from helix_sdk import HelixClient

try:
    from crewai.tools import BaseTool
except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
    raise ImportError(
        "helix_crewai requires the 'crewai' package. Install it with: "
        "pip install helixid-sdk-py[crewai]"
    ) from exc

T = TypeVar("T", bound=BaseTool)


def filter_crewai_tools_by_scope(tools: List[T], client: "HelixClient", agent_did: str) -> List[T]:
    scopes = get_agent_scopes(client, agent_did)

    def allowed(tool: T) -> bool:
        required_scope = getattr(tool, "required_scope", None)
        if not required_scope:
            return True
        return required_scope in scopes or getattr(tool, "name", None) in scopes

    return [tool for tool in tools if allowed(tool)]
