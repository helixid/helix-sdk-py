# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The sample's DEMO_MODE stand-in for the retry authorizer of KYA-OS story
L3-E, until story F-2 (local chain verification) and L3-H (the root hop
signed by the user's did:key at consent) replace it; the twin of the JS
sample's src/demo-authorizer.ts. It reads the DelegationCredential a retry
carries in the §6.10 shape and checks only what a structural reader can: the
credential is a DelegationCredential for this agent (``invoker``) at this
service (``invocationTarget``), covers the scopes the challenge asked for
(``allowedAction``), has not expired (``validUntil``) and carries a
``proof``. It does not verify that proof: a demo server has no verifier yet,
and says so in its startup banner."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Callable, Mapping

from helix_mcp_middleware import RetryAuthorization, RetryAuthorizer, RetryAuthorizerInput


def _instant(value: str) -> float:
    """An ISO 8601 date-time as Unix seconds (``Z`` accepted on Python 3.9 too); raises ValueError when unreadable."""
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value).timestamp()


def demo_retry_authorizer(service_did: str, now: Callable[[], float] = time.time) -> RetryAuthorizer:
    def authorize(request: RetryAuthorizerInput) -> RetryAuthorization:
        credential = request.credential
        if not isinstance(credential, Mapping):
            raise ValueError("the delegation credential must be an object")
        types = credential.get("type")
        if "DelegationCredential" not in (types if isinstance(types, list) else [types]):
            raise ValueError("not a DelegationCredential")
        subject = credential.get("credentialSubject")
        if not isinstance(subject, Mapping):
            raise ValueError("credentialSubject is missing")
        if subject.get("invoker") != request.agent_did:
            raise ValueError(f"invoker {subject.get('invoker')} is not the caller {request.agent_did}")
        if subject.get("invocationTarget") != service_did:
            raise ValueError(f"invocationTarget {subject.get('invocationTarget')} is not this service")
        allowed_raw: Any = subject.get("allowedAction")
        allowed = [a for a in allowed_raw if isinstance(a, str)] if isinstance(allowed_raw, list) else []
        uncovered = [scope for scope in request.token.scopes if scope not in allowed]
        if uncovered:
            raise ValueError(f"allowedAction does not cover {' '.join(uncovered)}")
        valid_until = credential.get("validUntil")
        if isinstance(valid_until, str) and _instant(valid_until) <= now():
            raise ValueError("the credential has expired")
        if not isinstance(credential.get("proof"), Mapping):
            raise ValueError("the credential carries no proof")
        return RetryAuthorization(scopes=allowed)

    return authorize
