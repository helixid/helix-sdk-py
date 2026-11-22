# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_crewai.middleware -- tool-wrapping half of the CrewAI integration
(KYA-OS story C-C).

Verified against the installed `crewai` package's `crewai.tools.BaseTool`
interface (see tests/test_framework_adapters.py). CrewAI's
`BaseTool._run(*args, **kwargs)` has the same shape as LangChain Python's, so
`helix_id_crewai_tool()` mirrors `helix_langchain.helix_id_tool_wrapper()`:
inside a wrapped tool, `sign_current_request(request)` signs the MCP request
the tool sends with a fresh request proof by the agent's own Signer. The Helix
VP and its X-Helix-VP header are gone.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from pydantic import PrivateAttr

from helix_sdk.crypto.jws import Signer
from helix_sdk.tool_signing import ChainSource, request_signer, signing_context

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
    *,
    signer: Signer,
    audience: str,
    chain: ChainSource = None,
    cnf_jkt: Optional[str] = None,
) -> BaseTool:
    """Wraps `tool` so the requests it sends while running can be signed with
    `sign_current_request(request)`: a fresh request proof per request, by the
    agent's own `signer`, for the service `audience`, with `chain` attached
    and `cnf_jkt` carried. The tool input is passed through unchanged."""
    sign = request_signer(signer, audience, chain, cnf_jkt)

    class _HelixIDWrappedCrewAITool(BaseTool):
        _wrapped: Any = PrivateAttr()

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            with signing_context(sign):
                return self._wrapped._run(*args, **kwargs)

    wrapped = _HelixIDWrappedCrewAITool(name=tool.name, description=tool.description, args_schema=tool.args_schema)
    object.__setattr__(wrapped, "_wrapped", tool)
    return wrapped
