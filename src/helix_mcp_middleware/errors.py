# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Errors raised by the middleware itself, ported from helix-sdk-js's
mcp-middleware/src/errors.ts. Missing/invalid VPs and insufficient scope
still use the helix_sdk errors (VP_MISSING, VP_VERIFICATION_FAILED,
INSUFFICIENT_SCOPE) so existing handlers keep working."""

from __future__ import annotations

from typing import Optional, Sequence

from helix_sdk.errors import HelixError, InsufficientScopeError

CREDENTIAL_CONFLICT = "CREDENTIAL_CONFLICT"
OAUTH_TOKEN_INVALID = "OAUTH_TOKEN_INVALID"
TOOL_NOT_PERMITTED = "TOOL_NOT_PERMITTED"

_STATUS = {CREDENTIAL_CONFLICT: 400, OAUTH_TOKEN_INVALID: 401, TOOL_NOT_PERMITTED: 403}


class MCPAuthError(HelixError):
    """A caller-side auth failure the sdk's own error codes do not cover."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, _STATUS[code])


class ToolScopeError(InsufficientScopeError):
    """INSUFFICIENT_SCOPE with the scopes as fields, so the 403 challenge can
    carry them as the RFC 6750 `scope` attribute. `required_scope` is the
    first one the caller lacked (what the audit row records);
    `required_scopes` is everything the tool requires."""

    def __init__(self, required_scope: str, required_scopes: Optional[Sequence[str]] = None) -> None:
        super().__init__(required_scope)
        self.required_scope = required_scope
        self.required_scopes = list(required_scopes) if required_scopes is not None else [required_scope]


class AuthorizationServerUnavailableError(Exception):
    """The authorization server could not be reached or gave an unusable
    answer (metadata, JWKS or introspection). A fault on the server side, not
    a bad credential: to_http_error_response() leaves it unmapped so the host
    answers 5xx, never 401."""
