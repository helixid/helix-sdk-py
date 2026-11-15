# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Audit events and the HelixID audit sink, ported from helix-sdk-js's
mcp-middleware/src/audit.ts."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

ToolAuditEvent = Dict[str, Any]
"""One authorization decision for one tool call. Keys match the JS event and
the API's wire format: event ('AUTHZ_GRANTED' | 'AUTHZ_DENIED'), result
('allowed' | 'denied'), timestamp, authMethod ('helixvp' | 'oauth'),
effectiveScopes, and when known agentDid, oauthSubject, vpId, toolName,
requiredScope, reason, serviceDid."""

AuditSink = Callable[[ToolAuditEvent], None]
"""Receives every decision for an identified caller, before the tool runs."""


def create_helix_audit_sink(
    base_url: str,
    api_key: str,
    service_did: Optional[str] = None,
    timeout_seconds: float = 5.0,
    http: Any = None,
) -> AuditSink:
    """An AuditSink that posts to `POST /v1/audit-log/events` with an account
    API key. OAuth callers have no agent DID, so pass `service_did` (the API
    needs agentDid or serviceDid).

    OAuth callers are identified by `oauthSubject`, which the API shows only
    to accounts with full access to the row (the service side)."""
    base = base_url.rstrip("/")

    def sink(event: ToolAuditEvent) -> None:
        did = event.get("serviceDid") or service_did
        if not event.get("agentDid") and not did:
            raise ValueError("audit event has no agentDid and no serviceDid; set service_did for OAuth callers")
        body: Dict[str, Any] = {
            "event": event["event"],
            "timestamp": event["timestamp"],
            "effectiveScopes": list(event.get("effectiveScopes") or []),
            "result": event["result"],
            "source": "mcp-middleware",
        }
        if did:
            body["serviceDid"] = did
        for key in ("agentDid", "vpId", "toolName", "requiredScope", "reason", "oauthSubject"):
            if event.get(key):
                body[key] = event[key]
        client = http
        if client is None:
            import requests

            client = requests
        res = client.post(
            f"{base}/v1/audit-log/events",
            json=body,
            headers={"authorization": f"Bearer {api_key}"},
            timeout=timeout_seconds,
        )
        if not 200 <= res.status_code < 300:
            raise RuntimeError(f"audit-log/events responded {res.status_code}")

    return sink
