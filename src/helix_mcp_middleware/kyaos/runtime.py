# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The KYA-OS session, replay and response-proof layer of the middleware (story
L2-A), mirroring helix-sdk-js's createKyaOs(). One runtime per server:

- ``handshake(args)`` answers the ``_kyaos_handshake`` tool: nonce format,
  timestamp within the skew, audience the server DID or public origin, nonce
  never seen before (the replay store), then a session.
- ``start(call)`` runs before a tool handler: it hashes the covered request,
  looks up the session the ``_kyaos_session`` control argument names, runs
  the host's authorization and strips the control arguments. A refusal comes
  back as a signed ``denied`` proof; an allowed call comes back with
  ``finish(result)``, which hashes the result and signs the proof into
  ``_meta["org.kya-os/response-proof"]``.
- ``call(call, run)`` is ``start`` then the handler then ``finish``.

The runtime is async, like the JS one; stores, ``authorize`` and ``run`` may
be sync or async. Only KYA-OS ``_meta`` keys are ever read; everything else in
``_meta`` is ignored (L2.17). The VP path is not extended: nothing here reads
``x-helix-vp``. Times are Unix seconds (``now`` defaults to ``time.time``).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Set, Union

from helix_sdk.crypto.jws import Signer
from helix_sdk.handshake import (
    HANDSHAKE_TOOL_NAME,
    NONCE_MIN_LENGTH,
    PROTOCOL_VERSION,
    SESSION_CONTROL_ARGUMENT,
    clock_skew_seconds,
    generate_nonce,
    is_did,
    is_session_id,
    validate_handshake_format,
    within_skew,
)
from helix_sdk.response_proof import RESPONSE_PROOF_ENVELOPE_PROFILE, hash_request, hash_response, strip_control_arguments

from ._util import resolve
from .describe import describe_kyaos
from .errors import KyaOsError, KyaOsReasons
from .nonce_store import MemoryNonceStore, NonceStore
from .response_proof import attach_response_proof, build_response_proof
from .session_store import IDENTITY_ANONYMOUS, IDENTITY_AUTHENTICATED, KyaOsSession, MemorySessionStore, SessionStore

NO_SESSION_ID = "none"
"""The ``sessionId`` a proof carries for a call that named no session."""

HANDSHAKE_INPUT_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["nonce", "audience", "timestamp"],
    "properties": {
        "nonce": {"type": "string", "minLength": NONCE_MIN_LENGTH},
        "audience": {"type": "string"},
        "timestamp": {"type": "integer", "minimum": 0},
        "agentDid": {"type": "string", "pattern": "^did:[a-z0-9]+:.+$"},
        "clientInfo": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}},
        "clientProtocolVersion": {"type": "string", "pattern": "^\\d+\\.\\d+$"},
        "clientCapabilities": {"type": "object"},
    },
    "additionalProperties": False,
}
"""The handshake tool's input, as ``handshake-request.json`` defines it, for hosts that register tools with JSON schema."""


@dataclass
class KyaOsSessionOptions:
    #: When False the handshake tool is refused and ``_kyaos_session`` is not looked up.
    enabled: bool = True
    #: Idle TTL; default 30.
    ttl_minutes: Optional[float] = None
    #: Default MemorySessionStore.
    store: Optional[SessionStore] = None


@dataclass
class KyaOsOptions:
    #: The service's Signer: signs every response proof. Its DID is the server DID.
    signer: Signer
    #: This server's DID; default ``signer.did``, and must equal it.
    server_did: Optional[str] = None
    #: The origin agents connect to; accepted as a handshake audience next to the server DID.
    public_origin: Optional[str] = None
    #: Default 120; 30 to 600.
    clock_skew_seconds: Optional[int] = None
    #: Default MemoryNonceStore (one process). Share a RedisNonceStore or DynamoNonceStore across instances.
    nonce_store: Optional[NonceStore] = None
    session: KyaOsSessionOptions = field(default_factory=KyaOsSessionOptions)
    #: The MCP endpoint, for describe().
    tools_endpoint: Optional[str] = None
    #: Unix seconds; default ``time.time``. Injectable for tests.
    now: Optional[Callable[[], float]] = None


Authorize = Callable[[], Any]
"""The host's authorization of a call (the helixid_mcp_middleware gate's
``authorize``, say): raise to deny; answer (or resolve to) a caller whose
``agent_did`` names the client in the proof, or None. May be async."""


@dataclass
class KyaOsDenied:
    reason: str
    #: What ``authorize`` raised, or the KyaOsError of the session layer.
    error: BaseException
    proof: Dict[str, Any]
    request_hash: str
    session: Optional[KyaOsSession] = None
    outcome: str = "denied"


@dataclass
class KyaOsAllowed:
    #: The tool's arguments with every ``_kyaos*`` member removed: what the handler sees.
    arguments: Dict[str, Any]
    request_hash: str
    _finish: Callable[[Mapping[str, Any]], Awaitable[Dict[str, Any]]] = field(repr=False)
    session: Optional[KyaOsSession] = None
    client_did: Optional[str] = None
    #: Set by ``call()``: the handler's result with the proof in ``_meta``.
    result: Optional[Dict[str, Any]] = None
    outcome: str = "allowed"

    async def finish(self, result: Mapping[str, Any]) -> Dict[str, Any]:
        """Signs the proof over ``result`` and returns ``result`` with it in ``_meta``."""
        return await self._finish(result)


KyaOsStarted = Union[KyaOsDenied, KyaOsAllowed]


def _reason_of(error: BaseException) -> str:
    if isinstance(error, KyaOsError):
        return error.reason
    code = getattr(error, "code", None)
    if isinstance(code, str) and code:
        return code
    message = str(error)
    return message if message else "denied"


def _agent_did_of(caller: Any) -> Optional[str]:
    if caller is None:
        return None
    if isinstance(caller, Mapping):
        value = caller.get("agent_did", caller.get("agentDid"))
    else:
        value = getattr(caller, "agent_did", None)
    return value if isinstance(value, str) else None


class KyaOsRuntime:
    """Built by create_kyaos(); see the module docstring."""

    def __init__(self, options: KyaOsOptions) -> None:
        signer = options.signer
        server_did = options.server_did if options.server_did is not None else signer.did
        if server_did != signer.did:
            raise ValueError(f"create_kyaos: server_did {server_did} is not the signer's DID {signer.did}")
        if not is_did(server_did):
            raise ValueError("create_kyaos: server_did must be a DID")
        self._signer = signer
        self.server_did: str = server_did
        self.clock_skew_seconds: int = clock_skew_seconds(options.clock_skew_seconds)
        session = options.session if options.session is not None else KyaOsSessionOptions()
        self.sessions_enabled: bool = session.enabled
        self._now: Callable[[], float] = options.now if options.now is not None else time.time
        self.nonce_store: NonceStore = options.nonce_store if options.nonce_store is not None else MemoryNonceStore(now=self._now)
        self.session_store: SessionStore = session.store if session.store is not None else MemorySessionStore(ttl_minutes=session.ttl_minutes)
        self.handshake_tool_name: str = HANDSHAKE_TOOL_NAME
        self._audiences: Set[str] = {server_did} | ({options.public_origin} if options.public_origin is not None else set())
        fragment = signer.kid[1:] if signer.kid.startswith("#") else signer.kid
        self._kid = f"{server_did}#{fragment}"
        self._tools_endpoint = options.tools_endpoint

    # ── description ──────────────────────────────────────────────────────────

    def describe(self) -> Dict[str, Any]:
        return describe_kyaos(self.clock_skew_seconds, self.sessions_enabled, self._tools_endpoint)

    def is_handshake(self, name: Optional[str]) -> bool:
        """Whether ``name`` is the handshake tool, which the host answers with handshake() and never passes to its own tools."""
        return name == HANDSHAKE_TOOL_NAME

    # ── nonces and signing ───────────────────────────────────────────────────

    def _retain_until(self, ts_seconds: float) -> float:
        """Retention of a nonce whose timestamp is ``ts_seconds``: until ts + skew + 1 s, never less."""
        return ts_seconds + self.clock_skew_seconds + 1

    async def _proof_nonce(self, ts_seconds: int) -> str:
        """A fresh nonce for a proof, recorded in the same store the handshake uses, so no proof nonce is ever reused."""
        for _ in range(3):
            nonce = generate_nonce()
            if await resolve(self.nonce_store.insert(nonce, self.server_did, self._retain_until(ts_seconds))):
                return nonce
        raise RuntimeError("create_kyaos: could not record a fresh proof nonce")

    async def _sign(self, *, session_id: str, audience: Optional[str], request_hash: str, **rest: Any) -> Dict[str, Any]:
        ts = int(self._now())
        nonce = await self._proof_nonce(ts)
        meta: Dict[str, Any] = {
            "did": self.server_did,
            "kid": self._kid,
            "ts": ts,
            "nonce": nonce,
            "audience": audience if audience is not None else self.server_did,
            "sessionId": session_id,
            "requestHash": request_hash,
            **rest,
        }
        return build_response_proof(meta, self._signer)

    # ── handshake ────────────────────────────────────────────────────────────

    async def handshake(self, args: Any, authenticated_agent_did: Optional[str] = None) -> Dict[str, Any]:
        """Answers a handshake request; raises KyaOsError on refusal.
        ``authenticated_agent_did`` is the agent the host verified on the
        handshake call (its credentials), making the session authenticated."""
        checked = validate_handshake_format(args)
        if not checked.ok:
            raise KyaOsError(checked.problem or "request_not_object", checked.message or "")
        request = checked.request or {}
        if not self.sessions_enabled:
            raise KyaOsError(KyaOsReasons.SESSIONS_DISABLED, "this server does not open KYA-OS sessions")
        if request["audience"] not in self._audiences:
            raise KyaOsError(
                KyaOsReasons.AUDIENCE_MISMATCH,
                f"audience {request['audience']} is not this server ({' or '.join(sorted(self._audiences))})",
            )
        now = self._now()
        now_seconds = int(now)
        if not within_skew(request["timestamp"], now_seconds, self.clock_skew_seconds):
            raise KyaOsError(
                KyaOsReasons.TIMESTAMP_SKEW,
                f"timestamp {request['timestamp']} is more than {self.clock_skew_seconds} s from the server time {now_seconds}",
            )
        claimed = request.get("agentDid")
        if authenticated_agent_did is not None and claimed is not None and authenticated_agent_did != claimed:
            raise KyaOsError(KyaOsReasons.AGENT_DID_MISMATCH, f"agentDid {claimed} is not the authenticated agent {authenticated_agent_did}")
        agent_did = authenticated_agent_did if authenticated_agent_did is not None else claimed
        if not await resolve(self.nonce_store.insert(request["nonce"], agent_did, self._retain_until(request["timestamp"]))):
            raise KyaOsError(KyaOsReasons.NONCE_REPLAYED, "nonce was already used")
        session = await resolve(
            self.session_store.create(
                agent_did=agent_did,
                identity_state=IDENTITY_AUTHENTICATED if authenticated_agent_did is not None else IDENTITY_ANONYMOUS,
                audience=request["audience"],
                nonce=request["nonce"],
                now=now,
            )
        )
        return {
            "sessionId": session.id,
            "serverDid": self.server_did,
            "protocolVersion": PROTOCOL_VERSION,
            "serverCapabilities": {"proofs": True, "delegation": False, "statusList": False},
            "sessionTtl": round(self.session_store.ttl_minutes * 60),
            "nonce": request["nonce"],
        }

    async def handshake_tool_result(self, args: Any, authenticated_agent_did: Optional[str] = None) -> Dict[str, Any]:
        """handshake() as a tool result: the response as ``structuredContent``
        (and text), or an ``isError`` result naming the reason."""
        try:
            response = await self.handshake(args, authenticated_agent_did)
        except KyaOsError as error:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"{error.reason}: {error.message}"}],
                "structuredContent": {"error": error.reason, "message": error.message},
            }
        return {"content": [{"type": "text", "text": json.dumps(response, separators=(",", ":"))}], "structuredContent": response}

    # ── calls ────────────────────────────────────────────────────────────────

    async def _session_of(self, args: Mapping[str, Any], now: float) -> Optional[KyaOsSession]:
        """The session a call names, or a KyaOsError when it names one that is not live."""
        if SESSION_CONTROL_ARGUMENT not in args:
            return None
        session_id = args[SESSION_CONTROL_ARGUMENT]
        if not self.sessions_enabled:
            raise KyaOsError(KyaOsReasons.SESSIONS_DISABLED, "this server does not open KYA-OS sessions")
        if not is_session_id(session_id):
            raise KyaOsError(KyaOsReasons.SESSION_ID_MALFORMED, f"{SESSION_CONTROL_ARGUMENT} must be kyaos_<uuid-v4>")
        session = await resolve(self.session_store.get(session_id, now))
        if session is None:
            raise KyaOsError(KyaOsReasons.SESSION_UNKNOWN, f"session {session_id} is unknown or has expired")
        return session

    async def start(
        self,
        call: Mapping[str, Any],
        authorize: Optional[Authorize] = None,
        client_did: Optional[str] = None,
    ) -> KyaOsStarted:
        """``call`` is ``{"name", "arguments", "_meta"}`` (the request's
        params); only KYA-OS ``_meta`` keys would be read, and none is yet."""
        raw_args = call.get("arguments")
        args: Dict[str, Any] = dict(raw_args) if isinstance(raw_args, Mapping) else {}
        name = call.get("name")
        request_hash = hash_request({"method": "tools/call", "params": {"name": name, "arguments": args}})
        stripped = strip_control_arguments(args)
        session: Optional[KyaOsSession] = None
        caller_did = client_did
        try:
            session = await self._session_of(args, self._now())
            caller = await resolve(authorize()) if authorize is not None else None
            if caller_did is None:
                caller_did = _agent_did_of(caller)
            if caller_did is None and session is not None:
                caller_did = session.agent_did
            if session is not None and session.agent_did is not None and caller_did is not None and session.agent_did != caller_did:
                raise KyaOsError(
                    KyaOsReasons.SESSION_AGENT_MISMATCH, f"session {session.id} belongs to {session.agent_did}, not {caller_did}"
                )
        except Exception as error:  # noqa: BLE001 - every refusal becomes a signed denied proof
            reason = _reason_of(error)
            proof = await self._sign(
                session_id=session.id if session is not None else NO_SESSION_ID,
                audience=session.audience if session is not None else None,
                request_hash=request_hash,
                outcome="denied",
                reason=reason,
                clientDid=caller_did,
            )
            return KyaOsDenied(reason=reason, error=error, proof=proof, request_hash=request_hash, session=session)
        if session is not None:
            session = await resolve(self.session_store.touch(session.id, self._now()))
        session_id = session.id if session is not None else NO_SESSION_ID
        audience = session.audience if session is not None else None
        final_client = caller_did

        async def finish(result: Mapping[str, Any]) -> Dict[str, Any]:
            proof = await self._sign(
                session_id=session_id,
                audience=audience,
                request_hash=request_hash,
                responseHash=hash_response(result, RESPONSE_PROOF_ENVELOPE_PROFILE),
                outcome="allowed",
                clientDid=final_client,
                prf=RESPONSE_PROOF_ENVELOPE_PROFILE,
            )
            return attach_response_proof(result, proof)

        return KyaOsAllowed(arguments=stripped, request_hash=request_hash, _finish=finish, session=session, client_did=caller_did)

    async def call(
        self,
        call: Mapping[str, Any],
        run: Callable[[Dict[str, Any], Dict[str, Any]], Any],
        authorize: Optional[Authorize] = None,
        client_did: Optional[str] = None,
    ) -> KyaOsStarted:
        """start(), then ``run(arguments, {"session", "client_did"})`` on the
        stripped arguments (sync or async), then finish(); a denial is
        returned instead of running."""
        started = await self.start(call, authorize, client_did)
        if isinstance(started, KyaOsDenied):
            return started
        result = await resolve(run(started.arguments, {"session": started.session, "client_did": started.client_did}))
        started.result = await started.finish(result)
        return started


def create_kyaos(options: KyaOsOptions) -> KyaOsRuntime:
    """The KYA-OS layer for one server; see KyaOsRuntime."""
    return KyaOsRuntime(options)


__all__: List[str] = [
    "NO_SESSION_ID",
    "HANDSHAKE_INPUT_SCHEMA",
    "KyaOsSessionOptions",
    "KyaOsOptions",
    "KyaOsDenied",
    "KyaOsAllowed",
    "KyaOsStarted",
    "KyaOsRuntime",
    "Authorize",
    "create_kyaos",
]
