# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Errors raised by the middleware itself, ported from helix-sdk-js's
mcp-middleware/src/errors.ts. Insufficient scope still uses the helix_sdk
error (INSUFFICIENT_SCOPE) so existing handlers keep working."""

from __future__ import annotations

from typing import Optional, Sequence, Tuple

from helix_sdk.errors import HelixError, InsufficientScopeError

CREDENTIAL_CONFLICT = "CREDENTIAL_CONFLICT"
OAUTH_TOKEN_INVALID = "OAUTH_TOKEN_INVALID"
TOOL_NOT_PERMITTED = "TOOL_NOT_PERMITTED"

_STATUS = {CREDENTIAL_CONFLICT: 400, OAUTH_TOKEN_INVALID: 401, TOOL_NOT_PERMITTED: 403}


class MCPAuthError(HelixError):
    """A caller-side auth failure the sdk's own error codes do not cover."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, _STATUS[code])


PROOF_MISSING = "PROOF_MISSING"
PROOF_INVALID = "PROOF_INVALID"
PROOF_LEVEL_INSUFFICIENT = "PROOF_LEVEL_INSUFFICIENT"


class ProofError(HelixError):
    """A KYA-OS request proof that is absent (PROOF_MISSING), or that the local
    verifier refused (PROOF_INVALID), story F-2. ``reasons`` carries the
    verifier's reason codes (``nonce_replayed``, ``audience_mismatch``,
    ``attenuation_violation``, ...), so a host can answer or log the refusal
    without parsing the message. Always HTTP 401."""

    def __init__(self, code: str, message: str, reasons: Sequence[str] = ()) -> None:
        if code not in (PROOF_MISSING, PROOF_INVALID, PROOF_LEVEL_INSUFFICIENT):
            raise ValueError(f"ProofError code must be {PROOF_MISSING}, {PROOF_INVALID} or {PROOF_LEVEL_INSUFFICIENT}")
        super().__init__(code, message, 401)
        self.reasons: Tuple[str, ...] = tuple(reasons)


class LevelError(ProofError):
    """A verified call below the Card level its tool demands (story C-C):
    PROOF_LEVEL_INSUFFICIENT, HTTP 401 ``insufficient_user_authentication``.
    ``derived_level`` is the level the call came to (``L1``, ``L2``,
    ``L3-minus``, ``L3``), ``required_level`` the tool's minimum."""

    def __init__(self, derived_level: str, required_level: str) -> None:
        super().__init__(
            PROOF_LEVEL_INSUFFICIENT,
            f"This tool needs Card level {required_level}; the call came to {derived_level}",
            ["proof_level_insufficient"],
        )
        self.derived_level = derived_level
        self.required_level = required_level


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
