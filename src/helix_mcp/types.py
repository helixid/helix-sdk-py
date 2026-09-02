# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Types, ported from helix-sdk-js's mcp/src/types.ts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from helix_sdk import HelixClient

MCPToolCall = Dict[str, Any]
"""A dict with at least 'name' and 'input' keys, matching the JS
MCPToolCall interface's structural typing (input is an untyped
Record<string, unknown> on both sides)."""


@dataclass
class MCPMiddlewareOptions:
    """Required now that verification calls the API (see
    docs/proposal-sdk-api-only.md) rather than verifying locally."""

    client: HelixClient
    required_scopes: List[str] = field(default_factory=list)
    allow_self_signed: bool = False


@dataclass
class AttachHelixVPOptions:
    wallet_passphrase: str
    wallet_file_path: str
    target_service: str
    user_did: Optional[str] = None
