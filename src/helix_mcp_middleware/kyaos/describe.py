# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
What the KYA-OS layer advertises (story L2-A point 7), mirroring
helix-sdk-js's describeKyaOs(). Story L1-D serves ``/.well-known/mcp`` and
reads these values from here: ``endpoints.handshake`` only while sessions are
enabled, ``clockSkewSeconds`` as configured, and ``capabilities.proofs`` true
because every tool call is answered with a response proof. The keys are the
document's own (camelCase).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from helix_sdk.handshake import HANDSHAKE_TOOL_NAME, clock_skew_seconds as checked_skew


def describe_kyaos(
    clock_skew_seconds: Optional[int] = None,
    session_enabled: bool = True,
    tools_endpoint: Optional[str] = None,
) -> Dict[str, Any]:
    """``tools_endpoint`` is the MCP endpoint the handshake tool is called on,
    as a URI reference (``/mcp`` by default, or an absolute URL)."""
    tools = tools_endpoint if tools_endpoint is not None else "/mcp"
    return {
        "endpoints": {"handshake": f"{tools}#{HANDSHAKE_TOOL_NAME}"} if session_enabled else {},
        "clockSkewSeconds": checked_skew(clock_skew_seconds),
        "capabilities": {"proofs": True},
        "handshakeTool": HANDSHAKE_TOOL_NAME,
    }
