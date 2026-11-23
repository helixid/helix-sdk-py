# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The minimum Card level a tool demands (KYA-OS story C-C point 7,
SPEC-ENTITY-CARD.md section 9), ported from helix-sdk-js's
mcp-middleware/src/level.ts. Scopes say whether the agent may do the action,
from its chain; the level says how sure the verifier is that the caller is
that agent right now. Under KYA-OS a request proof is optional per request,
so the minimum is explicit: ``L3`` for every tool by default (what Helix
always demanded: a fresh signature on every call), lowered per tool.

The verifier derives the level (``derive_conformance_level``, section 9.4) and
never reads the card's own ``conformanceLevel``. A proof without a token
``cnf`` to fuse with is L3-minus (section 8.6); whether L3-minus satisfies an
L3 tool is ``l3_minus_satisfies_l3``, default True, as section 9.4 lets the
proof floor hold.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

from helix_sdk.credentials import derive_conformance_level

MINIMUM_LEVELS = ("L1", "L2", "L3")
DEFAULT_MINIMUM_LEVEL = "L3"
DERIVED_LEVELS = ("L1", "L2", "L3-minus", "L3")
"""The level a call came to: ``L3-minus`` is an L3 without the token ``cnf`` fusion."""

_RANK = {"L1": 1, "L2": 2, "L3": 3}


@dataclass
class LevelPolicy:
    minimum_level: Optional[str] = None
    """Every tool's minimum; default ``L3``."""
    tools: Optional[Mapping[str, Any]] = None
    """Per-tool overrides: ``{"lookup_order": {"minimum_level": "L2"}}`` (``minimumLevel`` is read too)."""
    l3_minus_satisfies_l3: Optional[bool] = None
    """Whether L3-minus (a proof with no token ``cnf`` to fuse) satisfies an ``L3`` minimum; default True."""


def _tool_minimum(tool: Any) -> Optional[str]:
    if isinstance(tool, Mapping):
        value = tool.get("minimum_level", tool.get("minimumLevel"))
    else:
        value = getattr(tool, "minimum_level", None)
    return value  # type: ignore[no-any-return]


def assert_level_policy(policy: LevelPolicy) -> None:
    """Raises on a policy that names a level that does not exist, so a typo never lowers a tool's bar."""

    def check(where: str, level: Any) -> None:
        if level is not None and level not in MINIMUM_LEVELS:
            raise ValueError(f"helixid_mcp_middleware: {where} must be one of {', '.join(MINIMUM_LEVELS)}")

    check("minimum_level", policy.minimum_level)
    for name, tool in (policy.tools or {}).items():
        check(f"tools.{name}.minimum_level", _tool_minimum(tool))


def minimum_level_for(policy: LevelPolicy, tool_name: Optional[str]) -> str:
    """The minimum a tool demands: its override, else the policy's, else ``L3``."""
    tools = policy.tools or {}
    own = _tool_minimum(tools[tool_name]) if tool_name is not None and tool_name in tools else None
    return own or policy.minimum_level or DEFAULT_MINIMUM_LEVEL


def derived_level_of(level: str, proof_assurance: Optional[str]) -> str:
    """The level a verified call came to: the verifier's level, ``L3-minus`` when its L3 rests on an unfused proof."""
    return "L3-minus" if level == "L3" and proof_assurance == "L3-minus" else level


def meets_minimum_level(derived: str, minimum: str, l3_minus_satisfies_l3: bool = True) -> bool:
    """Whether ``derived`` meets ``minimum`` under the policy's L3-minus setting."""
    if derived == "L3-minus":
        return minimum != "L3" or l3_minus_satisfies_l3
    return _RANK[derived] >= _RANK[minimum]


__all__ = [
    "DEFAULT_MINIMUM_LEVEL",
    "DERIVED_LEVELS",
    "MINIMUM_LEVELS",
    "LevelPolicy",
    "assert_level_policy",
    "derive_conformance_level",
    "derived_level_of",
    "meets_minimum_level",
    "minimum_level_for",
]
