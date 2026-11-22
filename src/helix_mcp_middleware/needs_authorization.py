# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The signed ``needs_authorization`` challenge and the resume flow (KYA-OS
story L3-E; SPEC §9.2, §9.3; conformance L3.25, L3.26), mirroring
helix-sdk-js's mcp-middleware/src/needs-authorization.ts.

When a call's delegation is missing or does not cover the tool's scopes the
gate raises a NeedsAuthorizationError built here instead of the plain 403:
``{"error": "needs_authorization", "message", "authorizationUrl",
"resumeToken", "expiresAt", "scopes", "display"?}``. The KYA-OS runtime
(L2-A) turns it into a tool result signed with ``outcome:
needs_authorization`` and a ``responseHash`` over the whole result, so
``authorizationUrl`` is covered by the service signature and a proxy cannot
redirect the user to a consent page of its own.

``resumeToken`` is opaque, bound to the agent DID, the tool and the scopes
asked for, single-use and expiring at ``expiresAt`` (ResumeTokenStore). A
retry carries it as the ``_kyaos_resume`` control argument and the new
DelegationCredential as ``_kyaos_delegation`` (SPEC §7.3's ``_kyaos*``
channel; both are stripped before the handler and never hashed).
``authorize_retry`` consumes the token, checks the binding, then hands the
credential to the injected RetryAuthorizer: the seam story F-2 (chain
verification) and L3-H (the user-signed root hop) implement. The default
authorizer refuses, so until they land a retry never succeeds on a token
alone: completing consent never authorises the call by itself.

Every challenge issued is audited through the audit sink as an
``AUTHZ_DENIED`` event with ``reason: "needs_authorization"`` (L3.26); the
signed proof on the challenge is the tamper-evident record of it.

The layer is synchronous, like helixid_mcp_middleware(): its store,
authorizer and audit sink answer values. With no store given it takes the
one the environment names (resume_token_store_from_env, following L2-A's
KYAOS_NONCE_STORE); a Redis one is async (redis.asyncio). async_helixid_mcp_middleware()
runs it in a worker thread and bridges each of them onto the request's event
loop (``bridged()``), so there they may be async (redis.asyncio, say).

Cross-border rule: the only state is the resume-token store, local like the
nonce store; nothing here asks a Helix database anything.
"""

from __future__ import annotations

import inspect
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Union
from urllib.parse import urlsplit, urlunsplit

from helix_sdk.errors import HelixError

from .resume_token_store import (
    ResumeTokenBinding,
    ResumeTokenRecord,
    ResumeTokenStore,
    is_resume_token,
)
from .resume_token_store_env import resume_token_store_from_env

NEEDS_AUTHORIZATION = "needs_authorization"
#: Control argument carrying the resume token on a retry.
RESUME_CONTROL_ARGUMENT = "_kyaos_resume"
#: Control argument carrying the new DelegationCredential on a retry.
DELEGATION_CONTROL_ARGUMENT = "_kyaos_delegation"
#: Default lifetime of a resume token, in seconds.
DEFAULT_RESUME_TTL_SECONDS = 600

NEEDS_AUTHORIZATION_CODE = "NEEDS_AUTHORIZATION"
RESUME_REFUSED = "RESUME_REFUSED"


class NeedsAuthorizationError(HelixError):
    """The gate's refusal when authority is missing: carries the challenge
    (a dict in its wire shape). The KYA-OS runtime answers it as a signed
    tool result; a host without the runtime answers it through
    to_http_error_response() as a 403 whose body is the challenge (unsigned,
    since there is no signer)."""

    def __init__(self, challenge: Mapping[str, Any]) -> None:
        super().__init__(NEEDS_AUTHORIZATION_CODE, str(challenge.get("message", "")), 403)
        self.challenge: Dict[str, Any] = dict(challenge)


def is_needs_authorization_error(error: Any) -> bool:
    return isinstance(error, NeedsAuthorizationError) or getattr(error, "code", None) == NEEDS_AUTHORIZATION_CODE


class ResumeRefusalReasons:
    """Why a retry was refused; the ``reason`` of the denied proof's error. The same strings as helix-sdk-js."""

    MALFORMED = "resume_token_malformed"
    UNKNOWN = "resume_token_unknown"
    AGENT_MISMATCH = "resume_token_agent_mismatch"
    TOOL_MISMATCH = "resume_token_tool_mismatch"
    SCOPE_MISMATCH = "resume_token_scope_mismatch"
    DELEGATION_MISSING = "delegation_missing"
    DELEGATION_REFUSED = "delegation_refused"
    AUTHORIZER_MISSING = "retry_authorizer_missing"


class ResumeRefusedError(HelixError):
    """A retry refused: the token was replayed, expired, bound to another
    agent or tool, or the credential did not verify. to_http_error_response()
    answers it 403 insufficient_scope."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(RESUME_REFUSED, message, 403, {"reason": reason})
        self.reason = reason


@dataclass(frozen=True)
class ChallengeContext:
    agent_did: str
    tool: str
    #: The scopes the tool requires.
    scopes: List[str]


@dataclass(frozen=True)
class RetryAuthorizerInput:
    #: The DelegationCredential the retry carried, as received.
    credential: Any
    #: The consumed token's binding.
    token: ResumeTokenRecord
    #: The agent retrying, as the gate identified it.
    agent_did: str
    tool: str
    #: The scopes the tool requires.
    scopes: List[str]


@dataclass(frozen=True)
class RetryAuthorization:
    #: The scopes the credential grants this agent at this service.
    scopes: List[str] = field(default_factory=list)


RetryAuthorizer = Callable[[RetryAuthorizerInput], Any]
"""Verifies the credential a retry carries and says what it grants: answers a
RetryAuthorization (or a dict with ``scopes``); raise to refuse (any
exception becomes ``delegation_refused``). Story F-2 supplies the chain
verifier and L3-H the user-signed root hop; until then the default refuses
every retry. May be async with async_helixid_mcp_middleware()."""


@dataclass(frozen=True)
class ResumeRetry:
    resume_token: Any
    credential: Any


@dataclass
class NeedsAuthorizationOptions:
    #: The consent page: a URL, or a function of the challenge's ChallengeContext. Always covered by the proof.
    authorization_url: Union[str, Callable[[ChallengeContext], str]]
    #: Default: the store KYAOS_NONCE_STORE leads to (resume_token_store_from_env: Redis on KYAOS_REDIS_URL
    #: when the replay store is Redis, memory otherwise). An explicit store wins.
    store: Optional[ResumeTokenStore] = None
    #: Where the default store reads its settings; default ``os.environ``.
    env: Optional[Mapping[str, str]] = None
    #: Where the default store logs its startup line and warnings; default the ``helix_mcp_middleware.kyaos`` logger.
    logger: Optional[logging.Logger] = None
    #: Resume-token lifetime; default 600.
    ttl_seconds: Optional[float] = None
    #: Verifies the credential a retry carries (F-2, L3-H). Default: refuses.
    authorizer: Optional[RetryAuthorizer] = None
    #: Receives one AUTHZ_DENIED event with reason "needs_authorization" per challenge issued.
    audit_sink: Optional[Callable[[Dict[str, Any]], Any]] = None
    on_audit_error: Optional[Callable[[BaseException], Any]] = None
    #: This server's DID, for the audit event.
    service_did: Optional[str] = None
    #: Default message; a challenge may override it.
    message: Optional[Callable[[ChallengeContext], str]] = None
    display: Optional[Dict[str, Any]] = None
    #: Unix seconds; default ``time.time``. Injectable for tests.
    now: Optional[Callable[[], float]] = None


def challenge_tool_result(challenge: Mapping[str, Any]) -> Dict[str, Any]:
    """The challenge as an MCP tool result: ``isError``, the challenge as text and as ``structuredContent``."""
    body = dict(challenge)
    return {"isError": True, "content": [{"type": "text", "text": json.dumps(body, separators=(",", ":"))}], "structuredContent": body}


def read_resume_retry(call: Mapping[str, Any]) -> Optional[ResumeRetry]:
    """The retry a tool call carries in its ``input`` (the arguments); None when there is no ``_kyaos_resume``."""
    args = call.get("input")
    if not isinstance(args, Mapping) or RESUME_CONTROL_ARGUMENT not in args:
        return None
    return ResumeRetry(resume_token=args[RESUME_CONTROL_ARGUMENT], credential=args.get(DELEGATION_CONTROL_ARGUMENT))


def _default_message(context: ChallengeContext) -> str:
    return f"{context.tool} requires delegation with scope: {' '.join(context.scopes)}"


def _refusing_authorizer(_input: RetryAuthorizerInput) -> RetryAuthorization:
    raise ResumeRefusedError(
        ResumeRefusalReasons.AUTHORIZER_MISSING, "no retry authorizer is configured: the delegation credential cannot be verified here"
    )


def _sync(value: Any, what: str) -> Any:
    """The synchronous layer cannot await: an awaitable from a seam means it was given to the sync gate by mistake."""
    if inspect.isawaitable(value):
        close = getattr(value, "close", None)
        if callable(close):
            close()
        raise TypeError(f"{what} returned an awaitable; use async_helixid_mcp_middleware for async seams")
    return value


def _normalise_url(url: str) -> str:
    """An absolute http(s) URL, as WHATWG URL serialises it for the common cases (lower-case scheme and host, ``/`` path)."""
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        raise ValueError(f"create_needs_authorization: authorizationUrl must be an absolute http(s) URL, got {url}")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, parts.fragment))


class _BridgedStore(ResumeTokenStore):
    def __init__(self, store: ResumeTokenStore, bridge: Callable[[Callable[..., Any]], Callable[..., Any]]) -> None:
        self._store = store
        self.issue = bridge(store.issue)  # type: ignore[method-assign]
        self.consume = bridge(store.consume)  # type: ignore[method-assign]


class NeedsAuthorization:
    """Built by create_needs_authorization(); see the module docstring."""

    def __init__(self, options: NeedsAuthorizationOptions) -> None:
        self._options = options
        self._now: Callable[[], float] = options.now if options.now is not None else time.time
        self.store: ResumeTokenStore = (
            options.store if options.store is not None else resume_token_store_from_env(options.env, now=self._now, logger=options.logger)
        )
        ttl = options.ttl_seconds if options.ttl_seconds is not None else DEFAULT_RESUME_TTL_SECONDS
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not ttl > 0 or ttl == float("inf"):
            raise ValueError("create_needs_authorization: ttl_seconds must be a positive number")
        self.ttl_seconds: float = ttl
        self._authorizer: RetryAuthorizer = options.authorizer if options.authorizer is not None else _refusing_authorizer

    async def ready(self) -> None:
        """Resolves at once: in Python the store's settings and package are
        checked when the layer is built, and a problem raises there. Kept so
        hosts can await it as they do helix-sdk-js's ``needsAuthorization.ready()``."""

    def bridged(self, bridge: Callable[[Callable[..., Any]], Callable[..., Any]]) -> "NeedsAuthorization":
        """The same layer with its store, authorizer, audit sink and error
        callback passed through ``bridge``: what async_helixid_mcp_middleware
        uses so they may be async there. The token store is the same one."""
        options = self._options
        layer = NeedsAuthorization(
            NeedsAuthorizationOptions(
                authorization_url=options.authorization_url,
                store=_BridgedStore(self.store, bridge),
                ttl_seconds=self.ttl_seconds,
                authorizer=bridge(self._authorizer),
                audit_sink=bridge(options.audit_sink) if options.audit_sink is not None else None,
                on_audit_error=bridge(options.on_audit_error) if options.on_audit_error is not None else None,
                service_did=options.service_did,
                message=options.message,
                display=options.display,
                now=self._now,
            )
        )
        return layer

    def _url_of(self, context: ChallengeContext) -> str:
        url = self._options.authorization_url
        return _normalise_url(url(context) if callable(url) else url)

    def _audit(
        self,
        context: ChallengeContext,
        required_scope: str,
        auth_method: Optional[str],
        effective_scopes: Optional[Sequence[str]],
        oauth_subject: Optional[str],
        level: Optional[str],
        fresh: Optional[bool],
    ) -> None:
        sink = self._options.audit_sink
        if sink is None:
            return
        event: Dict[str, Any] = {
            "event": "AUTHZ_DENIED",
            "result": "denied",
            "timestamp": datetime.fromtimestamp(self._now(), timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "authMethod": auth_method if auth_method is not None else "kyaos",
            "agentDid": context.agent_did,
            **({"oauthSubject": oauth_subject} if oauth_subject is not None else {}),
            # KYA-OS callers: the level the local verifier derived (story F-2) and whether every status was read live.
            **({"level": level} if level is not None else {}),
            **({"fresh": fresh} if fresh is not None else {}),
            "toolName": context.tool,
            "requiredScope": required_scope,
            "effectiveScopes": list(effective_scopes or []),
            "reason": NEEDS_AUTHORIZATION,
            **({"serviceDid": self._options.service_did} if self._options.service_did is not None else {}),
        }
        try:
            _sync(sink(event), "audit_sink")
        except Exception as error:  # noqa: BLE001 - a failing sink never blocks the challenge
            if self._options.on_audit_error is not None:
                self._options.on_audit_error(error)

    def challenge(
        self,
        *,
        agent_did: str,
        tool: str,
        scopes: Sequence[str],
        missing: Optional[Sequence[str]] = None,
        message: Optional[str] = None,
        display: Optional[Mapping[str, Any]] = None,
        auth_method: Optional[str] = None,
        effective_scopes: Optional[Sequence[str]] = None,
        oauth_subject: Optional[str] = None,
        level: Optional[str] = None,
        fresh: Optional[bool] = None,
    ) -> NeedsAuthorizationError:
        """Issues a resume token bound to the agent, tool and scopes and builds the challenge; audits it."""
        context = ChallengeContext(agent_did=agent_did, tool=tool, scopes=list(scopes))
        if not context.scopes:
            raise ValueError("create_needs_authorization: a challenge needs at least one scope")
        lacking = list(missing) if missing else context.scopes
        authorization_url = self._url_of(context)
        expires_at = self._now() + self.ttl_seconds
        token = _sync(self.store.issue(ResumeTokenBinding(agent_did, tool, list(context.scopes)), expires_at), "store.issue")
        shown = display if display is not None else self._options.display
        body: Dict[str, Any] = {
            "error": NEEDS_AUTHORIZATION,
            "message": message if message is not None else (self._options.message or _default_message)(context),
            "authorizationUrl": authorization_url,
            "resumeToken": token,
            "expiresAt": int(expires_at),
            "scopes": list(context.scopes),
            **({"display": dict(shown)} if shown is not None else {}),
        }
        self._audit(context, lacking[0], auth_method, effective_scopes, oauth_subject, level, fresh)
        return NeedsAuthorizationError(body)

    def authorize_retry(self, resume_token: Any, credential: Any, context: ChallengeContext) -> RetryAuthorization:
        """Consumes ``resume_token`` (single use: a second call with the same
        token is refused), checks it is bound to ``context``, then hands
        ``credential`` to the authorizer. Answers what the credential grants;
        raises ResumeRefusedError."""
        if not is_resume_token(resume_token):
            raise ResumeRefusedError(ResumeRefusalReasons.MALFORMED, f"{RESUME_CONTROL_ARGUMENT} must be the token of a needs_authorization challenge")
        # Consumed before anything else is checked: a token is spent by its first use, whatever that use looked like.
        record = _sync(self.store.consume(resume_token), "store.consume")
        if record is None:
            raise ResumeRefusedError(ResumeRefusalReasons.UNKNOWN, "the resume token is unknown, already used or expired")
        if record.agent_did != context.agent_did:
            raise ResumeRefusedError(ResumeRefusalReasons.AGENT_MISMATCH, "the resume token was issued to another agent")
        if record.tool != context.tool:
            raise ResumeRefusedError(ResumeRefusalReasons.TOOL_MISMATCH, f"the resume token was issued for {record.tool}, not {context.tool}")
        if any(scope not in record.scopes for scope in context.scopes):
            raise ResumeRefusedError(ResumeRefusalReasons.SCOPE_MISMATCH, "the retry asks for scopes the challenge did not")
        if credential is None:
            raise ResumeRefusedError(
                ResumeRefusalReasons.DELEGATION_MISSING,
                f"the retry carries no {DELEGATION_CONTROL_ARGUMENT}: consent alone does not authorise the call",
            )
        try:
            granted = _sync(
                self._authorizer(
                    RetryAuthorizerInput(credential=credential, token=record, agent_did=context.agent_did, tool=context.tool, scopes=list(context.scopes))
                ),
                "authorizer",
            )
        except ResumeRefusedError:
            raise
        except Exception as error:  # noqa: BLE001 - any refusal by the authorizer
            raise ResumeRefusedError(ResumeRefusalReasons.DELEGATION_REFUSED, f"the delegation credential was refused: {error}") from error
        scopes = granted.scopes if isinstance(granted, RetryAuthorization) else (granted.get("scopes") if isinstance(granted, Mapping) else None)
        return RetryAuthorization(scopes=[s for s in scopes if isinstance(s, str)] if isinstance(scopes, (list, tuple)) else [])

    @staticmethod
    def read_retry(call: Mapping[str, Any]) -> Optional[ResumeRetry]:
        """The retry a call carries (``_kyaos_resume`` in its input), or None for an ordinary call."""
        return read_resume_retry(call)


def create_needs_authorization(options: NeedsAuthorizationOptions) -> NeedsAuthorization:
    """The L3-E layer for one server; pass it as ``MCPMiddlewareOptions.needs_authorization``."""
    return NeedsAuthorization(options)


__all__ = [
    "NEEDS_AUTHORIZATION",
    "NEEDS_AUTHORIZATION_CODE",
    "RESUME_REFUSED",
    "RESUME_CONTROL_ARGUMENT",
    "DELEGATION_CONTROL_ARGUMENT",
    "DEFAULT_RESUME_TTL_SECONDS",
    "NeedsAuthorizationError",
    "ResumeRefusedError",
    "ResumeRefusalReasons",
    "ChallengeContext",
    "RetryAuthorizerInput",
    "RetryAuthorization",
    "RetryAuthorizer",
    "ResumeRetry",
    "NeedsAuthorizationOptions",
    "NeedsAuthorization",
    "create_needs_authorization",
    "challenge_tool_result",
    "read_resume_retry",
    "is_needs_authorization_error",
]
