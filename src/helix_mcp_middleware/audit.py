# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Typed audit events for an MCP server (KYA-OS story A-1, AAP-1 Recorded),
the twin of helix-sdk-js's mcp-middleware/src/audit.ts.

The gate in middleware.py reports each authorization decision as a legacy
dict (``ToolAuditEvent``); ``McpAuditTrail.tool_audit_sink()`` turns one
decision into the typed events of the Auditability Protocol (``proof.verified``,
``delegation.verified``, ``authorization.approved`` / ``authorization.denied``)
recorded through a ``helix_sdk.audit.AuditTrail``, and ``begin_tool_call()``
brackets a tool call with ``session.established`` and the ``tool.call.*``
events, all sharing one ``correlationId``. ``create_helix_audit_sink`` keeps
its signature: the sink it returns still takes the legacy dict and now
delivers typed events to ``POST /v1/audit-log/events``.

Nothing caller-presented enters an event verbatim: an OAuth subject becomes
a keyed commitment under a per-trail key, a tool name is withheld unless the
trail was told to record it, and a reason is a code, never exception text.
"""

from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable, Dict, Iterator, Optional, Union

from helix_sdk.audit import (
    AUDIT_BINDING_MCP,
    UNKNOWN_DELEGATION_REF,
    AuditSink as TypedAuditSink,
    AuditTrail,
    AuditTrailEntry,
    PartyRef,
    keyed_commitment,
    keyed_commitment_value,
    pairwise_did,
    public_did,
)

ToolAuditEvent = Dict[str, Any]
"""One authorization decision for one tool call, as middleware.py reports it:
event ('AUTHZ_GRANTED' | 'AUTHZ_DENIED'), result ('allowed' | 'denied'),
timestamp, authMethod ('helixvp' | 'oauth'), effectiveScopes, and when known
agentDid, oauthSubject, vpId, toolName, requiredScope, reason, serviceDid,
and `delegation` ({delegationRef, delegationCredentialDigest,
delegationChainDigests}) once the gate reports the presented credential."""

AuditSink = Callable[[ToolAuditEvent], None]
"""Receives every decision for an identified caller, before the tool runs."""

OAUTH_SUBJECT_KEY_ID = "oauth-subject-v1"
"""The keyId of the keyed commitment an OAuth subject is recorded as."""

AuditContext = Dict[str, Any]
"""Members copied onto an event: actor, responsibleParty, authorization, correlationId, causationId."""

_CONTEXT_MEMBERS = ("actor", "responsibleParty", "authorization", "correlationId", "causationId")


class ToolCallAudit:
    """One tool call's audit scope: the events it records share a correlationId."""

    def __init__(self, audit: "McpAuditTrail", tool_name: Optional[str], correlation_id: str, actor: Optional[PartyRef]) -> None:
        self._audit = audit
        self.tool_name = tool_name
        self.correlation_id = correlation_id
        self.actor = actor
        self.attempt = "1"

    def context(self) -> AuditContext:
        context: AuditContext = {"correlationId": self.correlation_id}
        if self.actor is not None:
            context["actor"] = self.actor
        return context

    # Each returns the recorded entry (with the recorder's receipt under required
    # delivery, A-2), or None when the trail's on_error swallowed a failure.
    def started(self) -> Optional[AuditTrailEntry]:
        return self._audit.tool("started", "unknown", tool_name=self.tool_name, attempt=self.attempt, context=self.context())

    def completed(self) -> Optional[AuditTrailEntry]:
        return self._audit.tool("completed", "succeeded", tool_name=self.tool_name, attempt=self.attempt, context=self.context())

    def failed(self, reason_code: str) -> Optional[AuditTrailEntry]:
        return self._audit.tool("failed", "failed", tool_name=self.tool_name, attempt=self.attempt, reason_code=reason_code, context=self.context())

    def denied(self, reason_code: str) -> Optional[AuditTrailEntry]:
        return self._audit.tool("denied", "denied", tool_name=self.tool_name, attempt=self.attempt, reason_code=reason_code, context=self.context())


_CURRENT_CALL: "ContextVar[Optional[ToolCallAudit]]" = ContextVar("helix_mcp_audit_current_call", default=None)


def current_tool_call() -> Optional[ToolCallAudit]:
    """The tool call `begin_tool_call` opened in this context, if any."""
    return _CURRENT_CALL.get()


class McpAuditTrail:
    """Records an MCP server's decisions and tool calls as typed events on one ``AuditTrail``."""

    def __init__(
        self,
        trail: AuditTrail,
        service_did: Optional[str] = None,
        on_error: Optional[Callable[[BaseException], None]] = None,
        subject_commitment_key: Optional[bytes] = None,
    ) -> None:
        """``service_did`` is this server's DID, the ``resource`` of every
        decision. ``on_error`` receives a failed record instead of it
        raising (audit never blocks a tool call). ``subject_commitment_key``
        keys the commitment OAuth subjects are recorded as; default a random
        per-trail key, so the commitment is stable within one process only."""
        self.trail = trail
        self.service_did = service_did
        self.on_error = on_error
        self._subject_key = bytes(subject_commitment_key) if subject_commitment_key is not None else os.urandom(32)

    # -- one typed event per method -------------------------------------------

    def _record(
        self,
        event_type: str,
        category: str,
        outcome: str,
        details: Dict[str, Any],
        context: Optional[AuditContext],
        reason_code: Optional[str] = None,
        tool_name: Optional[str] = None,
        resource: Optional[PartyRef] = None,
    ) -> Optional[AuditTrailEntry]:
        event: Dict[str, Any] = {"eventType": event_type}
        for member in _CONTEXT_MEMBERS:
            if context is not None and context.get(member) is not None:
                event[member] = context[member]
        if resource is None and self.service_did is not None:
            resource = public_did(self.service_did)
        if resource is not None:
            event["resource"] = resource
        action: Dict[str, Any] = {"category": category}
        # The trail withholds a tool name on tool events; on any other event
        # the same policy applies here, so a name never leaks through `action.name`.
        if tool_name is not None and (details.get("family") == "tool" or self.trail.include_tool_names):
            action["name"] = tool_name
        event["action"] = action
        event["outcome"] = outcome
        if reason_code is not None:
            event["reason"] = {"code": reason_code}
        event["details"] = details
        try:
            return self.trail.record(event)
        except Exception as error:  # noqa: BLE001 - reported, never raised past a tool call
            if self.on_error is None:
                raise
            self.on_error(error)
            return None

    def session(
        self, phase: str, succeeded: bool, reason_code: Optional[str] = None, context: Optional[AuditContext] = None
    ) -> Optional[AuditTrailEntry]:
        details: Dict[str, Any] = {"family": "session", "phase": phase}
        if reason_code is not None:
            details["reasonCode"] = reason_code
        return self._record(f"session.{phase}", "session", "succeeded" if succeeded else "failed", details, context, reason_code)

    def proof(
        self,
        phase: str,
        outcome: str,
        proof_digest: Optional[str] = None,
        verification_code: Optional[str] = None,
        context: Optional[AuditContext] = None,
        resource: Optional[PartyRef] = None,
    ) -> Optional[AuditTrailEntry]:
        details: Dict[str, Any] = {"family": "proof", "phase": phase}
        if proof_digest is not None:
            details["proofDigest"] = proof_digest
        if verification_code is not None:
            details["verificationCode"] = verification_code
        return self._record(f"proof.{phase}", "proof", outcome, details, context, resource=resource)

    def delegation(
        self,
        phase: str,
        delegation_ref: str,
        outcome: str,
        reason_code: Optional[str] = None,
        parent_ref: Optional[str] = None,
        context: Optional[AuditContext] = None,
        resource: Optional[PartyRef] = None,
    ) -> Optional[AuditTrailEntry]:
        details: Dict[str, Any] = {"family": "delegation", "phase": phase, "delegationRef": delegation_ref}
        if parent_ref is not None:
            details["parentRef"] = parent_ref
        return self._record(f"delegation.{phase}", "delegation", outcome, details, context, reason_code, resource=resource)

    def authorization(
        self,
        phase: str,
        outcome: str,
        reason_code: Optional[str] = None,
        grant_ref: Optional[str] = None,
        context: Optional[AuditContext] = None,
        tool_name: Optional[str] = None,
        resource: Optional[PartyRef] = None,
    ) -> Optional[AuditTrailEntry]:
        details: Dict[str, Any] = {"family": "authorization", "phase": phase}
        if grant_ref is not None:
            details["grantRef"] = grant_ref
        event_type = "grant.used" if phase == "grant_used" else f"authorization.{phase}"
        return self._record(event_type, "authorization", outcome, details, context, reason_code, tool_name=tool_name, resource=resource)

    def tool(
        self,
        phase: str,
        outcome: str,
        tool_name: Optional[str] = None,
        attempt: str = "1",
        reason_code: Optional[str] = None,
        context: Optional[AuditContext] = None,
        resource: Optional[PartyRef] = None,
    ) -> Optional[AuditTrailEntry]:
        details = {"family": "tool", "phase": phase, "attempt": attempt}
        return self._record(f"tool.call.{phase}", "tool.call", outcome, details, context, reason_code, tool_name=tool_name, resource=resource)

    # -- the gate's decisions ---------------------------------------------------

    def subject_commitment(self, subject: str) -> PartyRef:
        """An OAuth subject as the event records it: a keyed commitment, never the subject itself."""
        return keyed_commitment(keyed_commitment_value(self._subject_key, subject), OAUTH_SUBJECT_KEY_ID)

    def tool_audit_sink(self) -> AuditSink:
        """A legacy ``audit_sink`` for MCPMiddlewareOptions: each decision of
        the gate becomes ``proof.verified`` (and ``delegation.verified`` when
        the decision names the presented credential) for a HelixID VP, then
        ``authorization.approved`` or ``authorization.denied``. The events
        carry the correlationId of the tool call ``begin_tool_call`` opened."""

        def sink(event: ToolAuditEvent) -> None:
            call = _CURRENT_CALL.get()
            context: AuditContext = {}
            if call is not None:
                context["correlationId"] = call.correlation_id
            service = event.get("serviceDid") or self.service_did
            resource = public_did(service) if isinstance(service, str) else None
            tool_name = event.get("toolName") if isinstance(event.get("toolName"), str) else None
            actor: Optional[PartyRef] = None
            source = "policy"
            if event.get("authMethod") == "helixvp":
                source = "delegation"
                agent_did = event.get("agentDid")
                if isinstance(agent_did, str):
                    actor = pairwise_did(agent_did)
                    context["actor"] = actor
                self.proof("verified", "succeeded", verification_code="VP_VERIFIED", context=context, resource=resource)
                delegation = event.get("delegation")
                if isinstance(delegation, dict):
                    evidence: Dict[str, Any] = {"source": "delegation", "decision": "allowed"}
                    for member in ("delegationRef", "delegationCredentialDigest", "delegationChainDigests"):
                        if delegation.get(member) is not None:
                            evidence[member] = delegation[member]
                    delegation_ref = delegation.get("delegationRef")
                    self.delegation(
                        "verified",
                        delegation_ref if isinstance(delegation_ref, str) else UNKNOWN_DELEGATION_REF,
                        "succeeded",
                        context={**context, "authorization": evidence},
                        resource=resource,
                    )
            elif isinstance(event.get("oauthSubject"), str):
                actor = self.subject_commitment(event["oauthSubject"])
                context["actor"] = actor
            if call is not None and call.actor is None and actor is not None:
                call.actor = actor
            required = event.get("requiredScope") if isinstance(event.get("requiredScope"), str) else None
            denied = event.get("result") == "denied" or event.get("event") == "AUTHZ_DENIED"
            evidence = {"source": source, "decision": "denied" if denied else "allowed"}
            if required is not None:
                evidence["scopeId"] = required
            context["authorization"] = evidence
            if denied:
                self.authorization(
                    "denied",
                    "denied",
                    reason_code="insufficient_scope" if required is not None else "tool_not_permitted",
                    context=context,
                    tool_name=tool_name,
                    resource=resource,
                )
            else:
                self.authorization("approved", "succeeded", context=context, tool_name=tool_name, resource=resource)

        return sink

    @contextmanager
    def begin_tool_call(
        self, tool_name: Optional[str], correlation_id: Optional[str] = None, actor: Optional[PartyRef] = None
    ) -> Iterator[ToolCallAudit]:
        """Brackets one tool call: records ``session.established`` on entry
        and yields the call, whose ``started()``, ``completed()``,
        ``failed(code)`` and ``denied(code)`` record the ``tool.call.*``
        events under the same correlationId. The gate's sink reads the
        current call from a context variable, so its decisions join the
        same correlation."""
        call = ToolCallAudit(self, tool_name, correlation_id or f"call_{uuid.uuid4()}", actor)
        token = _CURRENT_CALL.set(call)
        try:
            self.session("established", True, context=call.context())
            yield call
        finally:
            _CURRENT_CALL.reset(token)


class _HelixAuditReporter:
    """An ``AuditSink`` that POSTs each typed event to the HelixID API with an account API key."""

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
        res = client.post(
            self._url,
            json=entry.event,
            headers={"authorization": f"Bearer {self._api_key}"},
            timeout=self._timeout,
        )
        if not 200 <= res.status_code < 300:
            raise RuntimeError(f"audit-log/events responded {res.status_code}")


def create_helix_audit_reporter(base_url: str, api_key: str, timeout_seconds: float = 5.0, http: Any = None) -> TypedAuditSink:
    """A typed ``AuditSink`` over ``POST /v1/audit-log/events``; a non-2xx answer raises RuntimeError."""
    return _HelixAuditReporter(base_url, api_key, timeout_seconds, http)


def create_mcp_audit_trail(
    reporter_sink: TypedAuditSink,
    service_did: str,
    source_id: Optional[str] = None,
    include_tool_names: bool = False,
    tenant_ref: Optional[PartyRef] = None,
    on_error: Optional[Callable[[BaseException], None]] = None,
) -> McpAuditTrail:
    """The MCP server's trail: producer ``pairwise_did(service_did)``, tenant
    the producer unless given, binding ``AUDIT_BINDING_MCP``, source
    ``helix-mcp-middleware:<service_did>`` unless given."""
    if not isinstance(service_did, str) or not service_did:
        raise ValueError("create_mcp_audit_trail needs service_did: this server's DID is the producer of its audit events")
    producer = pairwise_did(service_did)
    trail = AuditTrail(
        sink=reporter_sink,
        source_id=source_id or f"helix-mcp-middleware:{service_did}",
        producer=producer,
        tenant_ref=tenant_ref if tenant_ref is not None else producer,
        binding=AUDIT_BINDING_MCP,
        include_tool_names=include_tool_names,
    )
    return McpAuditTrail(trail, service_did=service_did, on_error=on_error)


def create_helix_audit_sink(
    base_url: str,
    api_key: str,
    service_did: Optional[str] = None,
    timeout_seconds: float = 5.0,
    http: Any = None,
    source_id: Optional[str] = None,
    include_tool_names: bool = False,
) -> AuditSink:
    """A legacy ``audit_sink`` for MCPMiddlewareOptions that records each
    decision as typed events on an ``McpAuditTrail`` delivered to
    ``POST /v1/audit-log/events`` with an account API key. ``service_did``
    (this server's DID) is the producer of the events and is required."""
    if not service_did:
        raise ValueError("create_helix_audit_sink needs service_did: this server's DID is the producer of its audit events")
    reporter = create_helix_audit_reporter(base_url, api_key, timeout_seconds=timeout_seconds, http=http)
    return create_mcp_audit_trail(reporter, service_did, source_id=source_id, include_tool_names=include_tool_names).tool_audit_sink()
