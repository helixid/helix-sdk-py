# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Refusals by the KYA-OS session, replay or proof layer (story L2-A),
mirroring helix-sdk-js's mcp-middleware/src/kyaos/errors.ts."""

from __future__ import annotations

from helix_sdk.errors import HelixError

KYAOS_REJECTED = "KYAOS_REJECTED"


class KyaOsReasons:
    """``KyaOsError.reason`` values: the handshake format problems of
    helix_sdk.handshake.HandshakeFormatProblems, plus these. The same strings
    as helix-sdk-js."""

    SESSIONS_DISABLED = "sessions_disabled"
    AUDIENCE_MISMATCH = "audience_mismatch"
    TIMESTAMP_SKEW = "timestamp_skew"
    NONCE_REPLAYED = "nonce_replayed"
    AGENT_DID_MISMATCH = "agent_did_mismatch"
    SESSION_ID_MALFORMED = "session_id_malformed"
    SESSION_UNKNOWN = "session_unknown"
    SESSION_AGENT_MISMATCH = "session_agent_mismatch"


class KyaOsError(HelixError):
    """A refusal by the session, replay or proof layer. ``reason`` is the
    machine code (also the ``reason`` of the denied proof), the message says
    why in words. Handshake refusals are answered as the handshake tool's
    error result; call refusals become a ``denied`` proof, and
    to_http_error_response() answers them 400 invalid_request."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(KYAOS_REJECTED, message, 400, {"reason": reason})
        self.reason = reason
