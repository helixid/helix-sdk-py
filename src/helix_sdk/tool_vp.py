# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Shared helpers used by all three of this repo's framework adapters
(helix_mcp_middleware, helix_langchain, helix_crewai), factored out so the
logic stays in exactly one place.

Agent self-custody has been retired: there is no wallet file to load and
no local key to sign with, so attaching a VP to an outbound tool call is
now a server-side call (client.sign_vp()) instead of loading a wallet and
signing locally with VPBuilder. Credential selection (which VC to sign
with) happens server-side too.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from .client import HelixClient


def build_signed_vp(
    client: "HelixClient",
    agent_did: str,
    target_service: str,
    user_did: Optional[str] = None,
) -> Dict[str, Any]:
    return client.sign_vp(agent_did, target_service, user_did=user_did)


def get_agent_scopes(client: "HelixClient", agent_did: str) -> List[str]:
    """Scopes for the agent's one active HelixAgentCredential --
    list_vcs() already returns them directly, so no separate VC fetch or
    wallet read is needed."""
    active_vcs = client.list_vcs(subject_did=agent_did, status="active")
    if not active_vcs:
        raise RuntimeError("No active credential for this agent. Run onboarding first.")
    return active_vcs[0].get("scopes", [])


def encode_base64url_json(value: Any) -> str:
    """Matches helix-sdk-js's encodeBase64UrlJson() (langchain/src/middleware.ts):
    Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')."""
    return base64.urlsafe_b64encode(json.dumps(value).encode("utf-8")).rstrip(b"=").decode("ascii")
