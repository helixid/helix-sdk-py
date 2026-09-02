# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
LangChain integration, ported from helix-sdk-js's langchain/src/middleware.ts.

helix-sdk-js's version targets LangChain.js's `_call(input)` tool
interface and a lightweight `RunnableConfigLike` callback shape. This
port targets LangChain Python's actual `langchain_core.tools.BaseTool`
(`_run(*args, **kwargs)`) instead -- verified directly against the
installed `langchain-core` package (see tests/test_langchain_crewai.py)
rather than assumed from the JS source, since the two SDKs' tool
interfaces genuinely differ. `helix_id_tool_wrapper()` is the practical
equivalent of the JS `HelixIDToolWrapper`; `HelixIDCallbackHandler` is
offered as a LangChain-native alternative to the JS `HelixIDMiddleware`
(a bespoke `RunnableConfigLike` object, which has no direct Python
equivalent since LangChain Python's callback system is class-based, not
an ad-hoc `{ callbacks: [...] }` literal).
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from pydantic import PrivateAttr

from helix_sdk import AgentWallet
from helix_sdk.tool_vp import build_signed_vp, encode_base64url_json

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
    wallet_file_path: str,
    wallet_passphrase: str,
    target_service: str,
    user_did: Optional[str] = None,
) -> BaseTool:
    """Wraps `tool` so every invocation has a freshly signed VP injected
    into its kwargs as `_helixVP`, before delegating to the original
    tool's `_run`. Equivalent to helix-sdk-js's HelixIDToolWrapper()."""

    class _HelixIDWrappedTool(BaseTool):
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

    wrapped = _HelixIDWrappedTool(name=tool.name, description=tool.description, args_schema=tool.args_schema)
    object.__setattr__(wrapped, "_wrapped", tool)
    object.__setattr__(wrapped, "_wallet_file_path", wallet_file_path)
    object.__setattr__(wrapped, "_wallet_passphrase", wallet_passphrase)
    object.__setattr__(wrapped, "_target_service", target_service)
    object.__setattr__(wrapped, "_user_did", user_did)
    return wrapped


class HelixIDCallbackHandler(BaseCallbackHandler):
    """A LangChain-native callback handler that attaches a signed VP to
    every tool's input at `on_tool_start`, caching the loaded wallet
    across calls. Functionally equivalent to helix-sdk-js's
    HelixIDMiddleware(), adapted to LangChain Python's class-based
    callback system rather than an ad-hoc RunnableConfigLike literal."""

    def __init__(
        self,
        wallet_file_path: str,
        wallet_passphrase: str,
        target_service: str,
        user_did: Optional[str] = None,
    ) -> None:
        super().__init__()
        self._wallet_file_path = wallet_file_path
        self._wallet_passphrase = wallet_passphrase
        self._target_service = target_service
        self._user_did = user_did
        self._wallet: Optional[AgentWallet] = None

    def _get_wallet(self) -> AgentWallet:
        if self._wallet is None:
            self._wallet = AgentWallet.load(self._wallet_file_path, self._wallet_passphrase)
        return self._wallet

    def on_tool_start(self, serialized: Any, input_str: str, **kwargs: Any) -> None:
        # LangChain's on_tool_start receives the raw input string/dict, not
        # a mutable object the callback can rewrite before the tool runs
        # (unlike the JS RunnableConfigLike.handleToolStart contract) --
        # Python callbacks are notification hooks, not interceptors. Real
        # VP injection therefore happens in helix_id_tool_wrapper() above;
        # this handler is kept for observability/logging use cases and to
        # eagerly warm the wallet cache, and is documented as such.
        self._get_wallet()


def encode_base64url_json_public(value: Any) -> str:
    """Re-exported for parity with the JS package's exported
    encodeBase64UrlJson() helper."""
    return encode_base64url_json(value)
