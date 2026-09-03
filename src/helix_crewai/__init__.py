# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_crewai -- CrewAI integration for HelixID.

There is no CrewAI counterpart in helix-sdk-js -- CrewAI is Python-only.
This package follows the same pattern as helix_langchain (itself ported
from helix-sdk-js's langchain package), adapted to CrewAI's actual
`crewai.tools.BaseTool` interface -- verified directly against the
installed `crewai` package (see tests/test_langchain_crewai.py), not
assumed by analogy.

Usage:

    from helix_crewai import helix_id_crewai_tool

    protected_tool = helix_id_crewai_tool(
        my_orders_tool,
        wallet_file_path="agent-wallet.json",
        wallet_passphrase=os.environ["HELIX_WALLET_PASSPHRASE"],
        target_service="https://api.example.com/v1/tools/orders",
    )
    crew = Crew(agents=[...], tasks=[...], tools=[protected_tool])
"""

from __future__ import annotations

from .middleware import helix_id_crewai_tool
from .scope_filter import filter_crewai_tools_by_scope

__all__ = [
    "helix_id_crewai_tool",
    "filter_crewai_tools_by_scope",
]
