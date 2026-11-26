# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""How the gate (helixid_mcp_middleware) uses the L3-E layer, kept out of
middleware.py so that file only gains two calls; mirrors helix-sdk-js's
mcp-middleware/src/needs-authorization-guard.ts. The agent a challenge or a
retry is bound to is the caller's DID (KYA-OS callers) or OAuth subject
(OAuth callers): whatever identified the caller. ``caller`` is the gate's
internal dict (``authMethod``, ``scopes``, ``agentDid``, ``oauthSubject``,
``level``, ``proofAssurance``, ``fresh``)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from .needs_authorization import ChallengeContext, NeedsAuthorization, NeedsAuthorizationError


def caller_id(caller: Mapping[str, Any]) -> Optional[str]:
    value = caller.get("agentDid") or caller.get("oauthSubject")
    return value if isinstance(value, str) else None


def resume_retry(
    layer: Optional[NeedsAuthorization],
    caller: Dict[str, Any],
    tool_call: Mapping[str, Any],
    tool_name: Optional[str],
    required: List[str],
) -> Optional[Dict[str, Any]]:
    """When the call carries ``_kyaos_resume``: consumes the token, checks the
    binding and verifies the credential, then answers the caller with the
    scopes the credential grants added. Raises ResumeRefusedError. None for
    an ordinary call, or when the layer is not configured."""
    if layer is None:
        return None
    retry = layer.read_retry(tool_call)
    if retry is None:
        return None
    context = ChallengeContext(agent_did=caller_id(caller) or "", tool=tool_name or "", scopes=list(required))
    granted = layer.authorize_retry(retry.resume_token, retry.credential, context)
    return {**caller, "scopes": list(dict.fromkeys([*caller["scopes"], *granted.scopes]))}


def challenge_for(
    layer: Optional[NeedsAuthorization],
    caller: Mapping[str, Any],
    tool_name: Optional[str],
    required: List[str],
) -> Optional[NeedsAuthorizationError]:
    """The challenge for an identified caller lacking ``required``; None when the
    layer is not configured or the caller has no identity to bind to."""
    agent_did = caller_id(caller)
    if layer is None or agent_did is None or tool_name is None:
        return None
    return layer.challenge(
        agent_did=agent_did,
        tool=tool_name,
        scopes=required,
        missing=[scope for scope in required if scope not in caller["scopes"]],
        auth_method=caller.get("authMethod"),
        effective_scopes=list(caller["scopes"]),
        oauth_subject=caller.get("oauthSubject"),
        level=caller.get("level"),
        fresh=caller.get("fresh"),
    )


#: Helix error codes that refuse a consent request because of the caller, not
#: the service: the agent is not attested for the scope (or for any scope the
#: request names), or Helix does not know it as an agent it may ask consent for.
CALLER_CONSENT_REFUSALS = frozenset({"CONSENT_GRANT_SCOPE_NOT_ALLOWED", "CONSENT_NO_GRANTABLE_SCOPES", "DID_NOT_FOUND"})


def consent_failure_of(error: BaseException) -> Optional[Dict[str, str]]:
    """Sorts an error raised while the challenge's consent request was made at
    Helix (a ``ConsentFlowError``, matched by its code):
    ``{"kind": "refused", "helixCode", "message"}`` when Helix refused it because
    of the caller (CALLER_CONSENT_REFUSALS); ``{"kind": "unavailable", "message"}``
    when Helix could not be reached or failed (5xx, 408, 429, or no usable
    answer); None for anything else (the service's own setup, say), left to the
    host as a server error."""
    if getattr(error, "code", None) != "CONSENT_FLOW_FAILED":
        return None
    message = getattr(error, "message", None)
    message = message if isinstance(message, str) else "consent flow failed"
    status = getattr(error, "http_status", None)
    status = status if isinstance(status, int) else 0
    reason = getattr(error, "reason", None)
    if reason == "consent_unreachable" or status >= 500 or status in (408, 429):
        return {"kind": "unavailable", "message": message}
    helix_code = getattr(error, "helix_code", None)
    if reason == "consent_request_refused" and isinstance(helix_code, str) and helix_code in CALLER_CONSENT_REFUSALS:
        return {"kind": "refused", "helixCode": helix_code, "message": message}
    return None
