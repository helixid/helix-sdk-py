# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS sessions (story L2-A; conformance L2.7, L2.8, L2.10), mirroring
helix-sdk-js's mcp-middleware/src/kyaos/session-store.ts. A session is
created by a valid handshake, named ``kyaos_<uuid-v4>``, and lives while
calls keep coming: every valid call moves ``last_activity`` and the expiry
out by the idle TTL (default 30 minutes). Sessions are optional: a call that
names none is still authorised from its credentials alone.

Times are Unix seconds.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, replace
from typing import Awaitable, Callable, Dict, Optional, Union

try:
    from typing import Protocol
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol  # type: ignore[assignment]

from helix_sdk.handshake import DEFAULT_SESSION_TTL_MINUTES, generate_session_id

IDENTITY_ANONYMOUS = "anonymous"
IDENTITY_AUTHENTICATED = "authenticated"


@dataclass(frozen=True)
class KyaOsSession:
    id: str
    #: ``authenticated`` only when the host verified the agent at the handshake.
    identity_state: str
    #: What the handshake was addressed to: the server DID or its public origin.
    audience: str
    #: The handshake nonce.
    nonce: str
    created_at: float
    last_activity: float
    expires_at: float
    #: The DID the session is for: verified by the host at the handshake, or claimed in it.
    agent_did: Optional[str] = None


class SessionStore(Protocol):
    """Where sessions live. Methods may answer with an awaitable."""

    @property
    def ttl_minutes(self) -> float:  # pragma: no cover
        ...

    def create(
        self, *, agent_did: Optional[str], identity_state: str, audience: str, nonce: str, now: float
    ) -> Union[KyaOsSession, Awaitable[KyaOsSession]]:
        ...  # pragma: no cover

    def get(self, session_id: str, now: float) -> Union[Optional[KyaOsSession], Awaitable[Optional[KyaOsSession]]]:
        """The live session ``session_id`` names at ``now``, or None when there is none or it has expired."""
        ...  # pragma: no cover

    def touch(self, session_id: str, now: float) -> Union[Optional[KyaOsSession], Awaitable[Optional[KyaOsSession]]]:
        """Records activity at ``now`` on a live session and answers it, or None when there is none."""
        ...  # pragma: no cover

    def delete(self, session_id: str) -> Union[None, Awaitable[None]]:
        ...  # pragma: no cover


class MemorySessionStore:
    """Single-process store; expired sessions are dropped when looked up. Thread-safe."""

    def __init__(self, ttl_minutes: Optional[float] = None, generate_id: Callable[[], str] = generate_session_id) -> None:
        ttl = DEFAULT_SESSION_TTL_MINUTES if ttl_minutes is None else ttl_minutes
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("session ttl_minutes must be a positive number")
        self._ttl_minutes = ttl
        self._sessions: Dict[str, KyaOsSession] = {}
        self._generate_id = generate_id
        self._lock = threading.Lock()

    @property
    def ttl_minutes(self) -> float:
        return self._ttl_minutes

    @property
    def _ttl_seconds(self) -> float:
        return self._ttl_minutes * 60

    def create(self, *, agent_did: Optional[str], identity_state: str, audience: str, nonce: str, now: float) -> KyaOsSession:
        session = KyaOsSession(
            id=self._generate_id(),
            agent_did=agent_did,
            identity_state=identity_state,
            audience=audience,
            nonce=nonce,
            created_at=now,
            last_activity=now,
            expires_at=now + self._ttl_seconds,
        )
        with self._lock:
            self._sessions[session.id] = session
        return session

    def get(self, session_id: str, now: float) -> Optional[KyaOsSession]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.expires_at <= now:
                del self._sessions[session_id]
                return None
            return session

    def touch(self, session_id: str, now: float) -> Optional[KyaOsSession]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.expires_at <= now:
                self._sessions.pop(session_id, None)
                return None
            touched = replace(session, last_activity=now, expires_at=now + self._ttl_seconds)
            self._sessions[session_id] = touched
            return touched

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    @property
    def size(self) -> int:
        return len(self._sessions)
