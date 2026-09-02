# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Client-side helper that attaches a signed VP to an outgoing MCP tool call,
ported from helix-sdk-js's mcp/src/attach.ts.
"""

from __future__ import annotations

from helix_sdk.tool_vp import build_signed_vp

from .types import AttachHelixVPOptions, MCPToolCall


def attach_helix_vp(tool_call: MCPToolCall, options: AttachHelixVPOptions) -> MCPToolCall:
    vp = build_signed_vp(
        options.wallet_file_path, options.wallet_passphrase, options.target_service, options.user_did
    )
    result = dict(tool_call)
    result["input"] = {**(tool_call.get("input") or {}), "_helixVP": vp}
    return result
