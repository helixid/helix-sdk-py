# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS session, replay store and server response proof (story L2-A), the
Python twin of helix-sdk-js's mcp-middleware/src/kyaos."""

from .describe import describe_kyaos
from .errors import KYAOS_REJECTED, KyaOsError, KyaOsReasons
from .nonce_store import DynamoNonceStore, MemoryNonceStore, NonceStore, RedisNonceStore, nonce_key
from .response_proof import attach_response_proof, build_response_proof
from .runtime import (
    HANDSHAKE_INPUT_SCHEMA,
    NO_SESSION_ID,
    Authorize,
    KyaOsAllowed,
    KyaOsDenied,
    KyaOsOptions,
    KyaOsRuntime,
    KyaOsSessionOptions,
    KyaOsStarted,
    create_kyaos,
)
from .session_store import IDENTITY_ANONYMOUS, IDENTITY_AUTHENTICATED, KyaOsSession, MemorySessionStore, SessionStore
from helix_sdk.response_proof import RESPONSE_PROOF_META_KEY

__all__ = [
    "create_kyaos",
    "KyaOsRuntime",
    "KyaOsOptions",
    "KyaOsSessionOptions",
    "KyaOsAllowed",
    "KyaOsDenied",
    "KyaOsStarted",
    "Authorize",
    "HANDSHAKE_INPUT_SCHEMA",
    "NO_SESSION_ID",
    "describe_kyaos",
    "KyaOsError",
    "KyaOsReasons",
    "KYAOS_REJECTED",
    "NonceStore",
    "MemoryNonceStore",
    "RedisNonceStore",
    "DynamoNonceStore",
    "nonce_key",
    "SessionStore",
    "MemorySessionStore",
    "KyaOsSession",
    "IDENTITY_ANONYMOUS",
    "IDENTITY_AUTHENTICATED",
    "build_response_proof",
    "attach_response_proof",
    "RESPONSE_PROOF_META_KEY",
]
