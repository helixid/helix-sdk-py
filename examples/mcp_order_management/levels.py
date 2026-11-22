# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The minimum Card level settings of story C-C from the environment, the same
variables as the JS sample's src/levels.ts."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Sequence

from helix_mcp_middleware import MINIMUM_LEVELS

LEVEL_VARIABLES = ("KYAOS_MINIMUM_LEVEL", "KYAOS_TOOL_LEVELS", "KYAOS_L3_MINUS_SATISFIES_L3")
"""The variables read_level_settings reads; set without SERVICE_DID they are a configuration error."""


def _level_of(name: str, raw: Optional[str]) -> Optional[str]:
    value = (raw or "").strip()
    if not value:
        return None
    if value not in MINIMUM_LEVELS:
        raise ValueError(f"{name}: {value} is not one of {', '.join(MINIMUM_LEVELS)}")
    return value


def read_level_settings(env: Mapping[str, str], tool_names: Sequence[str]) -> Dict[str, Any]:
    """``KYAOS_MINIMUM_LEVEL`` (L1, L2 or L3; default L3), ``KYAOS_TOOL_LEVELS``
    (``tool=level,...``, tools of this server only) and ``KYAOS_L3_MINUS_SATISFIES_L3``
    (``0`` or ``1``; default 1), as MCPMiddlewareOptions fields. Raises on anything
    else, so a typo never lowers a tool's bar."""
    settings: Dict[str, Any] = {}
    minimum = _level_of("KYAOS_MINIMUM_LEVEL", env.get("KYAOS_MINIMUM_LEVEL"))
    if minimum is not None:
        settings["minimum_level"] = minimum
    tool_levels = (env.get("KYAOS_TOOL_LEVELS") or "").strip()
    if tool_levels:
        tools: Dict[str, Dict[str, str]] = {}
        for entry in (item.strip() for item in tool_levels.split(",")):
            if not entry:
                continue
            parts = [part.strip() for part in entry.split("=")]
            level = _level_of("KYAOS_TOOL_LEVELS", parts[1] if len(parts) > 1 else None)
            if len(parts) != 2 or not parts[0] or level is None or parts[0] not in tool_names:
                raise ValueError(f"KYAOS_TOOL_LEVELS: {entry} is not tool=level for a tool of this server")
            tools[parts[0]] = {"minimum_level": level}
        settings["tools"] = tools
    l3_minus = (env.get("KYAOS_L3_MINUS_SATISFIES_L3") or "").strip()
    if l3_minus:
        if l3_minus not in ("0", "1"):
            raise ValueError("KYAOS_L3_MINUS_SATISFIES_L3 must be 0 or 1")
        settings["l3_minus_satisfies_l3"] = l3_minus == "1"
    return settings


def describe_level_settings(settings: Mapping[str, Any]) -> str:
    """One line for the startup log: the default minimum and the per-tool ones."""
    tools = [f"{tool} {setting['minimum_level']}" for tool, setting in (settings.get("tools") or {}).items()]
    return (
        f"minimum level {settings.get('minimum_level') or 'L3'}"
        + (f" ({', '.join(tools)})" if tools else "")
        + (", L3-minus refused for L3" if settings.get("l3_minus_satisfies_l3") is False else "")
    )
