# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The agent's own scopes, for the framework adapters' tool filters
(helix_langchain, helix_crewai)."""

from __future__ import annotations

from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from .client import HelixClient


def get_agent_scopes(client: "HelixClient", agent_did: str) -> List[str]:
    """Scopes for the agent's one active HelixAgentCredential: list_vcs() returns them directly."""
    active_vcs = client.list_vcs(subject_did=agent_did, status="active")
    if not active_vcs:
        raise RuntimeError("No active credential for this agent. Run onboarding first.")
    return list(active_vcs[0].get("scopes", []))
