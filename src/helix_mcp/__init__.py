# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_mcp -- MCP (Model Context Protocol) integration for HelixID,
mirroring helix-sdk-js's mcp package.

- helixid_mcp_middleware(): server-side, requires and verifies a signed VP
  on every incoming tool call.
- attach_helix_vp(): client-side, attaches a signed VP to an outgoing tool
  call from an agent's wallet.
"""

from __future__ import annotations

from .middleware import helixid_mcp_middleware
from .attach import attach_helix_vp
from .types import MCPMiddlewareOptions, AttachHelixVPOptions, MCPToolCall

__all__ = [
    "helixid_mcp_middleware",
    "attach_helix_vp",
    "MCPMiddlewareOptions",
    "AttachHelixVPOptions",
    "MCPToolCall",
]
