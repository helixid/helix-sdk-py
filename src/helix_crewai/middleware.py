# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_crewai.middleware -- tool-wrapping half of the CrewAI integration.

Verified directly against the installed `crewai` package's actual
`crewai.tools.BaseTool` interface (see tests/test_langchain_crewai.py),
not assumed by analogy. CrewAI's `BaseTool._run(*args, **kwargs)` has the
same shape as LangChain Python's, so `helix_id_crewai_tool()` mirrors
`helix_langchain.middleware.helix_id_tool_wrapper()` almost exactly.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from pydantic import PrivateAttr

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
