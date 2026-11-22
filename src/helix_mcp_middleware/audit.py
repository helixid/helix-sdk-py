# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS auditability for an MCP server (AUDITABILITY.md, AAP-1 Recorded),
the twin of helix-sdk-js's ``mcp-middleware/src/audit.ts``.

The gate in middleware.py hands ``audit_sink`` one ``ToolAuditEvent`` per
authorization decision; ``McpAuditTrail.tool_audit_sink()`` turns each into
the typed events of the protocol (``proof.verified``, ``delegation.verified``,
``authorization.approved`` / ``authorization.denied``), and
``begin_tool_call()`` records the call's own lifecycle
(``session.established``, ``tool.call.started`` / ``completed`` / ``failed`` /
``denied``) under one correlation id. Every event goes through the SDK's
``AuditTrail``: strictly validated, references bounded, sequenced per source,
digested, and handed to a reporter (``create_helix_audit_reporter``:
``POST /v1/audit-log/events``).

No event ever holds tool arguments, a response, a bearer token or a VP. An
OAuth subject enters only as a keyed commitment under a key the trail holds;
a tool name is withheld unless ``include_tool_names`` is set. Given the same
inputs, clock, event ids and OAuth subject key, this module and the JS one
record byte-identical events.
"""

from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable, Dict, Iterator, List, Optional

from helix_sdk.audit import (
    AUDIT_BINDING_MCP,
    UNKNOWN_DELEGATION_REF,
    AuditSink as TypedAuditSink,
    AuditTrail,
    AuditTrailEntry,
    PartyRef,
    credential_digest,
    delegation_chain_digests,
    delegation_ref,
    keyed_commitment_value,
    pairwise_did,
    public_did,
)

ToolAuditEvent = Dict[str, Any]
"""One authorization decision for one tool call, as middleware.py reports it:
event ('AUTHZ_GRANTED' | 'AUTHZ_DENIED'), result ('allowed' | 'denied'),
timestamp, authMethod ('helixvp' | 'oauth'), effectiveScopes, and when known
agentDid, oauthSubject (never recorded as such), vpId, toolName,
requiredScope, reason, serviceDid; ``correlationId`` and ``delegation``
(a ``DelegationEvidence``) default to the current ``begin_tool_call()``."""

AuditSink = Callable[[ToolAuditEvent], None]
"""Receives every decision for an identified caller, before the tool runs."""

DelegationEvidence = Dict[str, Any]
"""SPEC section 7.8: how the presented delegation credential and its chain are
referenced, ``{delegationRef?, delegationCredentialDigest?, delegationChainDigests?}``."""

McpAuditContext = Dict[str, Any]
"""What every event of a tool call shares: ``actor``, ``responsibleParty``,
``authorization``, ``correlationId``, ``causationId``; each member overrides
the current ``begin_tool_call()`` context."""

AuditContext = McpAuditContext

OAUTH_SUBJECT_KEY_ID = "oauth-subject-v1"
"""The keyId of the keyed commitment an OAuth subject is recorded as."""

_DELEGATION_MEMBERS = ("delegationRef", "delegationCredentialDigest", "delegationChainDigests")


def _is_agent_credential(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    types = value.get("type")
    if isinstance(types, list) and "HelixAgentCredential" in types:
        return True
    subject = value.get("credentialSubject")
    return isinstance(subject, dict) and subject.get("type") == "HelixAgent"


def delegation_evidence_of(credential: Any) -> Optional[DelegationEvidence]:
    """The delegation evidence of a decoded HelixID VP (SPEC section 7.8): the
    presented credential is its last agent credential, the chain is that
    credential's ``delegationChain`` (root first) followed by the credential
    itself. None when the value is not a VP or shows no agent credential."""
    if not isinstance(credential, dict):
        return None
    presented_list = credential.get("verifiableCredential")
    if not isinstance(presented_list, list):
        return None
    agents = [vc for vc in presented_list if _is_agent_credential(vc)]
    if not agents:
        return None
    presented = agents[-1]
    chain = presented.get("delegationChain")
    ref = delegation_ref(presented)
    digest = credential_digest(presented)
    chain_digests = delegation_chain_digests([*(chain if isinstance(chain, list) else []), presented])
    evidence: DelegationEvidence = {}
    if ref is not None:
        evidence["delegationRef"] = ref
    if digest is not None:
        evidence["delegationCredentialDigest"] = digest
    if chain_digests is not None:
        evidence["delegationChainDigests"] = chain_digests
    return evidence


def _delegation_authorization(delegation: DelegationEvidence, decision: str, scope_id: Optional[str] = None) -> Dict[str, Any]:
    """The authorization evidence that carries the delegation members (``decision`` as given)."""
    authorization: Dict[str, Any] = {"source": "delegation", "decision": decision}
    if scope_id is not None:
        authorization["scopeId"] = scope_id
    for member in _DELEGATION_MEMBERS:
        if delegation.get(member) is not None:
            authorization[member] = delegation[member]
    return authorization


class ToolCallAudit:
    """The lifecycle events of one tool call; see ``McpAuditTrail.begin_tool_call``."""

    def __init__(
        self,
        audit: "McpAuditTrail",
        correlation_id: str,
        tool_name: Optional[str],
        actor: Optional[PartyRef],
        delegation: Optional[DelegationEvidence],
    ) -> None:
        self._audit = audit
        self.correlation_id = correlation_id
        """The id every event of this call carries."""
        self.tool_name = tool_name
        self.actor = actor
        """The caller, once known (given at ``begin_tool_call``, or learned from the authorization decision)."""
        self.delegation = delegation
        """The presented delegation credential's evidence, when the credential was a HelixID VP."""

    def started(self) -> Optional[AuditTrailEntry]:
        """The tool is about to run."""
        return self._tool_event("started", "unknown")

    def completed(self) -> Optional[AuditTrailEntry]:
        """The tool answered."""
        return self._tool_event("completed", "succeeded")

    def failed(self, reason_code: str) -> Optional[AuditTrailEntry]:
        """The tool failed; ``reason_code`` is a code, never the exception text."""
        return self._tool_event("failed", "failed", reason_code)

    def denied(self, reason_code: str) -> Optional[AuditTrailEntry]:
        """The guard refused the call before the tool ran; ``reason_code`` is the error code."""
        return self._tool_event("denied", "denied", reason_code)

    def context(self) -> McpAuditContext:
        context: McpAuditContext = {"correlationId": self.correlation_id}
        if self.actor is not None:
            context["actor"] = self.actor
        return context

    def _tool_event(self, phase: str, outcome: str, reason_code: Optional[str] = None) -> Optional[AuditTrailEntry]:
        return self._audit.tool(phase, outcome, tool_name=self.tool_name, attempt="1", reason_code=reason_code, context=self.context())


_CURRENT_CALL: "ContextVar[Optional[ToolCallAudit]]" = ContextVar("helix_mcp_audit_current_call", default=None)


def current_tool_call() -> Optional[ToolCallAudit]:
    """The tool call ``begin_tool_call`` opened in this context, if any."""
    return _CURRENT_CALL.get()


class McpAuditTrail:
    """One MCP server's audit source. Every method records one typed event
    (the returned entry holds the event, its canonical text and digest) under
    the MCP binding, with this server as the resource and the current tool
    call's correlation id and actor unless the context says otherwise.
    Errors propagate, as in JS: a call that cannot be recorded does not run.
    ``on_error`` (Python only, for a delivery that degrades instead of
    failing) receives a failed record instead, and the method returns None."""

    def __init__(
        self,
        reporter: TypedAuditSink,
        service_did: Optional[str] = None,
        source_id: Optional[str] = None,
        producer: Optional[PartyRef] = None,
        tenant_ref: Optional[PartyRef] = None,
        include_tool_names: bool = False,
        oauth_subject_key: Optional[bytes] = None,
        clock: Optional[Callable[[], int]] = None,
        new_event_id: Optional[Callable[[], str]] = None,
        on_error: Optional[Callable[[BaseException], None]] = None,
    ) -> None:
        """``reporter`` receives every recorded entry (``create_helix_audit_reporter``,
        a ``MemoryAuditSink``, ...). ``service_did`` is this server's DID: the
        default producer (as a pairwise DID) and the resource of every event.
        ``source_id`` defaults to ``mcp-middleware:<service_did>``;
        ``producer`` overrides the producer and is required without a
        ``service_did``; ``tenant_ref`` defaults to the producer.
        ``include_tool_names`` records tool names (default False: a tool
        name is often sensitive in itself). ``oauth_subject_key`` is the key
        OAuth subjects are committed under (default 32 random bytes per
        trail). ``clock`` (milliseconds) and ``new_event_id`` default to the
        trail's. ``on_error``: see the class docstring."""
        if producer is None and service_did is not None:
            producer = pairwise_did(service_did)
        if producer is None:
            raise ValueError("create_mcp_audit_trail needs service_did (this server's DID) or an explicit producer")
        self.service_did = service_did
        self.include_tool_names = include_tool_names
        self.on_error = on_error
        self._oauth_subject_key = bytes(oauth_subject_key) if oauth_subject_key is not None else os.urandom(32)
        self.trail = AuditTrail(
            sink=reporter,
            source_id=source_id or f"mcp-middleware:{service_did if service_did is not None else 'server'}",
            producer=producer,
            tenant_ref=tenant_ref if tenant_ref is not None else producer,
            binding=AUDIT_BINDING_MCP,
            include_tool_names=include_tool_names,
            clock=clock,
            new_event_id=new_event_id,
        )

    def oauth_actor(self, subject: str) -> PartyRef:
        """The actor an OAuth subject is recorded as: a keyed commitment, never the subject itself."""
        return {"kind": "keyed_commitment", "value": keyed_commitment_value(self._oauth_subject_key, subject), "keyId": OAUTH_SUBJECT_KEY_ID}

    # -- one typed event per method ---------------------------------------------

    def session(self, phase: str, succeeded: bool, reason_code: Optional[str] = None, context: Optional[McpAuditContext] = None) -> Optional[AuditTrailEntry]:
        outcome = "succeeded" if succeeded else ("failed" if phase == "expired" else "denied")
        details: Dict[str, Any] = {"family": "session", "phase": phase}
        if reason_code is not None:
            details["reasonCode"] = reason_code
        return self._record(self._input(f"session.{phase}", "session", outcome, details, reason_code), context)

    def proof(
        self,
        phase: str,
        outcome: str,
        proof_digest: Optional[str] = None,
        verification_code: Optional[str] = None,
        reason_code: Optional[str] = None,
        context: Optional[McpAuditContext] = None,
    ) -> Optional[AuditTrailEntry]:
        details: Dict[str, Any] = {"family": "proof", "phase": phase}
        if proof_digest is not None:
            details["proofDigest"] = proof_digest
        if verification_code is not None:
            details["verificationCode"] = verification_code
        return self._record(self._input(f"proof.{phase}", "proof", outcome, details, reason_code), context)

    def delegation(
        self,
        phase: str,
        delegation_ref: str,
        outcome: str,
        reason_code: Optional[str] = None,
        parent_ref: Optional[str] = None,
        context: Optional[McpAuditContext] = None,
    ) -> Optional[AuditTrailEntry]:
        details: Dict[str, Any] = {"family": "delegation", "phase": phase, "delegationRef": delegation_ref}
        if parent_ref is not None:
            details["parentRef"] = parent_ref
        return self._record(self._input(f"delegation.{phase}", "delegation", outcome, details, reason_code), context)

    def authorization(
        self,
        phase: str,
        outcome: str,
        reason_code: Optional[str] = None,
        grant_ref: Optional[str] = None,
        tool_name: Optional[str] = None,
        context: Optional[McpAuditContext] = None,
    ) -> Optional[AuditTrailEntry]:
        details: Dict[str, Any] = {"family": "authorization", "phase": phase}
        if grant_ref is not None:
            details["grantRef"] = grant_ref
        event_type = "grant.used" if phase == "grant_used" else f"authorization.{phase}"
        return self._record(self._input(event_type, "authorization", outcome, details, reason_code), context, tool_name)

    def tool(
        self,
        phase: str,
        outcome: str,
        tool_name: Optional[str] = None,
        attempt: str = "1",
        reason_code: Optional[str] = None,
        context: Optional[McpAuditContext] = None,
    ) -> Optional[AuditTrailEntry]:
        details = {"family": "tool", "phase": phase, "attempt": attempt}
        return self._record(self._input(f"tool.call.{phase}", "tool.call", outcome, details, reason_code), context, tool_name)

    # -- one tool call ----------------------------------------------------------

    @contextmanager
    def begin_tool_call(
        self,
        tool_name: Optional[str] = None,
        correlation_id: Optional[str] = None,
        actor: Optional[PartyRef] = None,
        credential: Any = None,
    ) -> Iterator[ToolCallAudit]:
        """Starts one tool call's audit: records ``session.established``, then
        yields the call with itself as the current context, so a gate sink
        called inside attributes its events to this call (same correlation
        id, same actor). Call ``started()`` / ``completed()`` / ``failed()`` /
        ``denied()`` as the call goes. When ``credential`` is a decoded HelixID
        VP its agent credential becomes the delegation evidence the sink
        attaches to ``proof.verified`` and ``delegation.verified``.
        ``correlation_id`` defaults to ``audit_<uuid>``."""
        call = ToolCallAudit(
            self,
            correlation_id or f"audit_{uuid.uuid4()}",
            tool_name,
            actor,
            delegation_evidence_of(credential),
        )
        self.session("established", True, context=call.context())
        token = _CURRENT_CALL.set(call)
        try:
            yield call
        finally:
            _CURRENT_CALL.reset(token)

    # -- the gate's decisions ---------------------------------------------------

    def tool_audit_sink(self) -> AuditSink:
        """The middleware's ``audit_sink``: translates each authorization
        decision into the typed events. A HelixID caller: ``proof.verified``,
        then ``delegation.verified`` when the presented credential is known,
        then ``authorization.approved`` or ``authorization.denied``. An OAuth
        caller: only the authorization event, with the subject as a keyed
        commitment."""

        def sink(event: ToolAuditEvent) -> None:
            call = _CURRENT_CALL.get()
            actor = self._actor_of(event)
            if actor is None and call is not None:
                actor = call.actor
            if call is not None and call.actor is None and actor is not None:
                call.actor = actor
            delegation = event.get("delegation") if isinstance(event.get("delegation"), dict) else None
            if delegation is None and call is not None:
                delegation = call.delegation
            base: McpAuditContext = {}
            if actor is not None:
                base["actor"] = actor
            if isinstance(event.get("correlationId"), str):
                base["correlationId"] = event["correlationId"]
            tool_name = event.get("toolName") if isinstance(event.get("toolName"), str) else None
            scope_id = event.get("requiredScope") if isinstance(event.get("requiredScope"), str) else None
            helixvp = event.get("authMethod") == "helixvp"
            if helixvp:
                proof_context = dict(base)
                if delegation is not None:
                    proof_context["authorization"] = _delegation_authorization(delegation, "allowed")
                self.proof("verified", "succeeded", verification_code="VP_VERIFIED", context=proof_context)
                if delegation is not None:
                    ref = delegation.get("delegationRef")
                    self.delegation(
                        "verified",
                        ref if isinstance(ref, str) else UNKNOWN_DELEGATION_REF,
                        "succeeded",
                        context={**base, "authorization": _delegation_authorization(delegation, "allowed")},
                    )
            allowed = event.get("result") == "allowed"
            decision = "allowed" if allowed else "denied"
            if helixvp and delegation is not None:
                authorization = _delegation_authorization(delegation, decision, scope_id)
            else:
                authorization = {"source": "delegation" if helixvp else "policy", "decision": decision}
                if scope_id is not None:
                    authorization["scopeId"] = scope_id
            context = {**base, "authorization": authorization}
            if allowed:
                self.authorization("approved", "succeeded", context=context, tool_name=tool_name)
            else:
                self.authorization(
                    "denied",
                    "denied",
                    reason_code="insufficient_scope" if scope_id is not None else "tool_not_permitted",
                    context=context,
                    tool_name=tool_name,
                )

        return sink

    def _actor_of(self, event: ToolAuditEvent) -> Optional[PartyRef]:
        if event.get("authMethod") == "oauth":
            subject = event.get("oauthSubject")
            return self.oauth_actor(subject) if isinstance(subject, str) else None
        agent_did = event.get("agentDid")
        return pairwise_did(agent_did) if isinstance(agent_did, str) else None

    # -- recording --------------------------------------------------------------

    @staticmethod
    def _input(event_type: str, category: str, outcome: str, details: Dict[str, Any], reason_code: Optional[str]) -> Dict[str, Any]:
        event: Dict[str, Any] = {"eventType": event_type, "action": {"category": category}, "outcome": outcome}
        if reason_code is not None:
            event["reason"] = {"code": reason_code}
        event["details"] = details
        return event

    def _record(self, event: Dict[str, Any], context: Optional[McpAuditContext], tool_name: Optional[str] = None) -> Optional[AuditTrailEntry]:
        """Fills the context (explicit members over the current call's) and the resource, applies the tool-name policy, records."""
        call = _CURRENT_CALL.get()
        context = context or {}
        correlation_id = context.get("correlationId")
        if correlation_id is None and call is not None:
            correlation_id = call.correlation_id
        actor = context.get("actor")
        if actor is None and call is not None:
            actor = call.actor
        if correlation_id is not None:
            event["correlationId"] = correlation_id
        if context.get("causationId") is not None:
            event["causationId"] = context["causationId"]
        if actor is not None:
            event["actor"] = actor
        if context.get("responsibleParty") is not None:
            event["responsibleParty"] = context["responsibleParty"]
        if self.service_did is not None:
            event["resource"] = public_did(self.service_did)
        if context.get("authorization") is not None:
            event["authorization"] = context["authorization"]
        if tool_name is not None and self.include_tool_names:
            event["action"] = {**event["action"], "name": tool_name}
        try:
            return self.trail.record(event)
        except Exception as error:  # noqa: BLE001 - reported to on_error when one is set
            if self.on_error is None:
                raise
            self.on_error(error)
            return None


class _HelixAuditReporter:
    """An ``AuditSink`` that posts each recorded event, exactly as the trail built it, to the HelixID API."""

    def __init__(self, base_url: str, api_key: str, timeout_seconds: float, http: Any) -> None:
        self._url = f"{base_url.rstrip('/')}/v1/audit-log/events"
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._http = http

    def append(self, entry: AuditTrailEntry) -> None:
        client = self._http
        if client is None:
            import requests

            client = requests
        # The canonical text is the event's JSON; the API re-derives the same digest from it.
        res = client.post(
            self._url,
            data=entry.canonical.encode("utf-8"),
            headers={"content-type": "application/json", "authorization": f"Bearer {self._api_key}"},
            timeout=self._timeout,
        )
        if not 200 <= res.status_code < 300:
            raise RuntimeError(f"audit-log/events responded {res.status_code}")


def create_helix_audit_reporter(base_url: str, api_key: str, timeout_seconds: float = 5.0, http: Any = None) -> TypedAuditSink:
    """The reporter behind every Helix-backed trail: posts each recorded event
    to ``POST /v1/audit-log/events`` with the key as a bearer token. A non-2xx
    answer raises RuntimeError (the trail's record fails; the gate reports it
    through ``on_audit_error`` and the tool call goes on)."""
    return _HelixAuditReporter(base_url, api_key, timeout_seconds, http)


def create_mcp_audit_trail(
    reporter: TypedAuditSink,
    service_did: Optional[str] = None,
    source_id: Optional[str] = None,
    producer: Optional[PartyRef] = None,
    tenant_ref: Optional[PartyRef] = None,
    include_tool_names: bool = False,
    oauth_subject_key: Optional[bytes] = None,
    clock: Optional[Callable[[], int]] = None,
    new_event_id: Optional[Callable[[], str]] = None,
    on_error: Optional[Callable[[BaseException], None]] = None,
) -> McpAuditTrail:
    """``McpAuditTrail(...)``, as JS's ``createMcpAuditTrail`` (plus the Python-only ``on_error``)."""
    return McpAuditTrail(
        reporter,
        service_did=service_did,
        source_id=source_id,
        producer=producer,
        tenant_ref=tenant_ref,
        include_tool_names=include_tool_names,
        oauth_subject_key=oauth_subject_key,
        clock=clock,
        new_event_id=new_event_id,
        on_error=on_error,
    )


def create_helix_audit_sink(
    base_url: str,
    api_key: str,
    service_did: Optional[str] = None,
    timeout_seconds: float = 5.0,
    http: Any = None,
    source_id: Optional[str] = None,
    include_tool_names: bool = False,
) -> AuditSink:
    """The middleware's ``audit_sink`` backed by the HelixID API: a trail whose
    reporter posts every typed event to ``POST /v1/audit-log/events``, with
    the legacy decision translated by ``McpAuditTrail.tool_audit_sink()``.
    ``service_did`` (this server's DID) is the producer and is required. For
    the call lifecycle events too, build the trail yourself with
    ``create_mcp_audit_trail(create_helix_audit_reporter(...), service_did)``."""
    return create_mcp_audit_trail(
        create_helix_audit_reporter(base_url, api_key, timeout_seconds=timeout_seconds, http=http),
        service_did=service_did,
        source_id=source_id,
        include_tool_names=include_tool_names,
    ).tool_audit_sink()


__all__: List[str] = [
    "AuditContext",
    "AuditSink",
    "DelegationEvidence",
    "McpAuditContext",
    "McpAuditTrail",
    "OAUTH_SUBJECT_KEY_ID",
    "ToolAuditEvent",
    "ToolCallAudit",
    "create_helix_audit_reporter",
    "create_helix_audit_sink",
    "create_mcp_audit_trail",
    "current_tool_call",
    "delegation_evidence_of",
]
