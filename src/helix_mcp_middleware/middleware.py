# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Server-side MCP tool-call verification middleware, ported from
helix-sdk-js's mcp/src/middleware.ts.

Wrap an MCP tool handler with this to require every incoming tool call to
carry a valid, API-verified VP in `_meta["x-helix-vp"]` or the X-Helix-VP
header -- and optionally to require specific privilege scopes. Tool
arguments are never consulted.
"""

from __future__ import annotations

from typing import Callable

from helix_sdk import require_scope, verify_vp
from helix_sdk.errors import VPMissingError, VPVerificationFailedError
from helix_sdk.vp_transport import read_helix_vp_header, read_helix_vp_meta

from .types import MCPMiddlewareOptions, MCPToolCall


def helixid_mcp_middleware(options: MCPMiddlewareOptions) -> Callable[[MCPToolCall], MCPToolCall]:
    def middleware(tool_call: MCPToolCall) -> MCPToolCall:
        vp = read_helix_vp_meta(tool_call.get("_meta")) or read_helix_vp_header(tool_call.get("headers"))
        if not vp:
            raise VPMissingError()

        result = verify_vp(
            vp,
            options.client,
            expected_target_service=options.expected_target_service,
            allow_self_signed=options.allow_self_signed,
        )

        if not result.get("valid"):
            error_message = result.get("error")
            raise VPVerificationFailedError(error_message) if error_message else VPVerificationFailedError()

        for scope in options.required_scopes:
            require_scope(result, scope)

        return tool_call

    return middleware
