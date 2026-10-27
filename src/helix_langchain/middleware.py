# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
LangChain integration, ported from helix-sdk-js's langchain/src/middleware.ts.

helix-sdk-js's version targets LangChain.js's `_call(input)` tool
interface. This port targets LangChain Python's actual `langchain_core.tools.BaseTool`
(`_run(*args, **kwargs)`) instead -- verified directly against the
installed `langchain-core` package (see tests/test_langchain_crewai.py)
rather than assumed from the JS source, since the two SDKs' tool
interfaces genuinely differ. `helix_id_tool_wrapper()` is the practical
equivalent of the JS `HelixIDToolWrapper`, and `current_helix_vp_headers()`
of the JS `currentHelixVPHeaders()`.

Agent self-custody has been retired: signing is a server-side call
(client.sign_vp()) now, not a local wallet load + VPBuilder.sign().
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional, TypeVar

from pydantic import PrivateAttr

from helix_sdk.tool_vp import build_signed_vp, helix_vp_context, encode_base64url_json

if TYPE_CHECKING:
    from helix_sdk import HelixClient

try:
    from langchain_core.tools import BaseTool
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
    raise ImportError(
        "helix_langchain requires the 'langchain-core' package. Install it with: "
        "pip install helixid-sdk-py[langchain]"
    ) from exc

T = TypeVar("T", bound=BaseTool)


def helix_id_tool_wrapper(
    tool: T,
    client: "HelixClient",
    agent_did: str,
    target_service: str,
    user_did: Optional[str] = None,
) -> BaseTool:
    """Wraps `tool` so every invocation signs a fresh VP, then delegates to
    the original tool's `_run` with its arguments unchanged. The tool reads
    the VP with `current_helix_vp_headers()` and sends it as the X-Helix-VP
    header. Equivalent to helix-sdk-js's HelixIDToolWrapper()."""

    class _HelixIDWrappedTool(BaseTool):
        _wrapped: Any = PrivateAttr()
        _client: Any = PrivateAttr()
        _agent_did: str = PrivateAttr()
        _target_service: str = PrivateAttr()
        _user_did: Optional[str] = PrivateAttr()

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            vp = build_signed_vp(self._client, self._agent_did, self._target_service, self._user_did)
            with helix_vp_context(vp):
                return self._wrapped._run(*args, **kwargs)

    wrapped = _HelixIDWrappedTool(name=tool.name, description=tool.description, args_schema=tool.args_schema)
    object.__setattr__(wrapped, "_wrapped", tool)
    object.__setattr__(wrapped, "_client", client)
    object.__setattr__(wrapped, "_agent_did", agent_did)
    object.__setattr__(wrapped, "_target_service", target_service)
    object.__setattr__(wrapped, "_user_did", user_did)
    return wrapped


class HelixIDCallbackHandler(BaseCallbackHandler):
    """A LangChain-native callback handler, kept for observability/logging
    use cases only. It attaches no VP: a callback cannot hand one to the
    tool, so that happens in helix_id_tool_wrapper() above."""

    def __init__(
        self,
        client: "HelixClient",
        agent_did: str,
        target_service: str,
        user_did: Optional[str] = None,
    ) -> None:
        super().__init__()
        self._client = client
        self._agent_did = agent_did
        self._target_service = target_service
        self._user_did = user_did

    def on_tool_start(self, serialized: Any, input_str: str, **kwargs: Any) -> None:
        pass


def encode_base64url_json_public(value: Any) -> str:
    """Re-exported for parity with the JS package's exported
    encodeBase64UrlJson() helper."""
    return encode_base64url_json(value)
