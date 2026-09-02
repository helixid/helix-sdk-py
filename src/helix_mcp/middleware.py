# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Server-side MCP tool-call verification middleware, ported from
helix-sdk-js's mcp/src/middleware.ts.

Wrap an MCP tool handler with this to require every incoming tool call to
carry a valid, API-verified `_helixVP` -- and optionally to require
specific privilege scopes.
"""

from __future__ import annotations

from typing import Callable

from helix_sdk import require_scope, verify_vp
from helix_sdk.errors import VPMissingError, VPVerificationFailedError

from .types import MCPMiddlewareOptions, MCPToolCall


def helixid_mcp_middleware(options: MCPMiddlewareOptions) -> Callable[[MCPToolCall], MCPToolCall]:
    def middleware(tool_call: MCPToolCall) -> MCPToolCall:
        vp = (tool_call.get("input") or {}).get("_helixVP")
        if not vp:
            raise VPMissingError()

        result = verify_vp(vp, options.client, allow_self_signed=options.allow_self_signed)

        if not result.get("valid"):
            error_message = result.get("error")
            raise VPVerificationFailedError(error_message) if error_message else VPVerificationFailedError()

        for scope in options.required_scopes:
            require_scope(result, scope)

        return tool_call

    return middleware
