# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
LangChain integration, ported from helix-sdk-js's langchain/src/middleware.ts
(KYA-OS story C-C).

helix-sdk-js's version targets LangChain.js's `_call(input)` tool interface.
This port targets LangChain Python's `langchain_core.tools.BaseTool`
(`_run(*args, **kwargs)`), verified against the installed `langchain-core`
package (see tests/test_framework_adapters.py). `helix_id_tool_wrapper()` is
the equivalent of the JS `HelixIDToolWrapper`, and `sign_current_request()`
of the JS `signCurrentRequest()`: inside a wrapped tool it signs the MCP
request the tool sends with a fresh request proof, by the agent's own Signer,
with the delegation chain attached. The Helix VP and its X-Helix-VP header are
gone.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from pydantic import PrivateAttr

from helix_sdk.crypto.jws import Signer
from helix_sdk.tool_signing import ChainSource, request_signer, sign_current_request, signing_context

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.tools import BaseTool
except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
    raise ImportError(
        "helix_langchain requires the 'langchain-core' package. Install it with: "
        "pip install helixid-sdk-py[langchain]"
    ) from exc

T = TypeVar("T", bound=BaseTool)

__all__ = ["HelixIDCallbackHandler", "helix_id_tool_wrapper", "sign_current_request"]


def helix_id_tool_wrapper(
    tool: T,
    *,
    signer: Signer,
    audience: str,
    chain: ChainSource = None,
    cnf_jkt: Optional[str] = None,
) -> BaseTool:
    """Wraps `tool` so the requests it sends while running can be signed with
    `sign_current_request(request)`: a fresh KYA-OS request proof per request,
    signed by the agent's own `signer` (its key stays wherever the signer keeps
    it), for the service `audience` (its DID, from its Entity Card), with the
    delegation `chain` (root to leaf, or a function returning the current one)
    attached and `cnf_jkt` carried for the section 8.6 fusion. The tool input
    is passed through unchanged."""
    sign = request_signer(signer, audience, chain, cnf_jkt)

    class _HelixIDWrappedTool(BaseTool):
        _wrapped: Any = PrivateAttr()

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            with signing_context(sign):
                return self._wrapped._run(*args, **kwargs)

    wrapped = _HelixIDWrappedTool(name=tool.name, description=tool.description, args_schema=tool.args_schema)
    object.__setattr__(wrapped, "_wrapped", tool)
    return wrapped


class HelixIDCallbackHandler(BaseCallbackHandler):
    """A LangChain-native callback handler, kept for observability/logging use
    cases only. It signs nothing: a callback cannot hand a proof to the tool,
    so that happens in helix_id_tool_wrapper() above."""

    def __init__(self, agent_did: str, audience: str) -> None:
        super().__init__()
        self.agent_did = agent_did
        self.audience = audience

    def on_tool_start(self, serialized: Any, input_str: str, **kwargs: Any) -> None:
        pass
