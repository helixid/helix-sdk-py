# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""examples/mcp_order_management: the minimum Card level settings of story C-C
from the environment, the same variables and refusals as the JS sample's
tests/levels.test.ts."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from mcp_order_management.levels import LEVEL_VARIABLES, describe_level_settings, read_level_settings  # noqa: E402

TOOLS = ["lookup_order", "refund_order", "delete_order"]


def test_nothing_set_is_the_default() -> None:
    assert read_level_settings({}, TOOLS) == {}
    assert describe_level_settings({}) == "minimum level L3"
    assert LEVEL_VARIABLES == ("KYAOS_MINIMUM_LEVEL", "KYAOS_TOOL_LEVELS", "KYAOS_L3_MINUS_SATISFIES_L3")


def test_every_setting() -> None:
    settings = read_level_settings(
        {"KYAOS_MINIMUM_LEVEL": " L2 ", "KYAOS_TOOL_LEVELS": "lookup_order=L1, refund_order = L3,", "KYAOS_L3_MINUS_SATISFIES_L3": "0"},
        TOOLS,
    )
    assert settings == {
        "minimum_level": "L2",
        "tools": {"lookup_order": {"minimum_level": "L1"}, "refund_order": {"minimum_level": "L3"}},
        "l3_minus_satisfies_l3": False,
    }
    assert describe_level_settings(settings) == "minimum level L2 (lookup_order L1, refund_order L3), L3-minus refused for L3"
    assert read_level_settings({"KYAOS_L3_MINUS_SATISFIES_L3": "1"}, TOOLS) == {"l3_minus_satisfies_l3": True}


@pytest.mark.parametrize(
    "env",
    [
        {"KYAOS_MINIMUM_LEVEL": "L4"},
        {"KYAOS_MINIMUM_LEVEL": "l3"},
        {"KYAOS_TOOL_LEVELS": "lookup_order"},
        {"KYAOS_TOOL_LEVELS": "lookup_order=L0"},
        {"KYAOS_TOOL_LEVELS": "lookup_order=L1=L2"},
        {"KYAOS_TOOL_LEVELS": "=L1"},
        {"KYAOS_TOOL_LEVELS": "unknown_tool=L1"},
        {"KYAOS_L3_MINUS_SATISFIES_L3": "yes"},
    ],
)
def test_a_typo_is_refused_never_a_lower_bar(env: dict) -> None:
    with pytest.raises(ValueError):
        read_level_settings(env, TOOLS)
