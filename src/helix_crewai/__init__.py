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

    from helix_sdk import kyaos
    from helix_crewai import helix_id_crewai_tool, sign_current_request

    signer = kyaos.EnvSigner(did="did:web:agent.example.com")   # the agent's own key, from HELIX_SIGNING_KEY
    protected_tool = helix_id_crewai_tool(my_orders_tool, signer=signer, audience="did:web:orders.example.com", chain=hops)
    crew = Crew(agents=[...], tasks=[...], tools=[protected_tool])

    # inside my_orders_tool._run: the MCP request it sends, signed for this one call
    request = sign_current_request({"name": "lookup_order", "arguments": {"orderId": order_id}})
"""

from __future__ import annotations

from .middleware import helix_id_crewai_tool
from .scope_filter import filter_crewai_tools_by_scope
from helix_sdk.tool_signing import RequestSigner, sign_current_request

__all__ = [
    "helix_id_crewai_tool",
    "sign_current_request",
    "RequestSigner",
    "filter_crewai_tools_by_scope",
]
