# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""
The service's half of KYA-OS story L3-H in the middleware (parity with
helix-sdk-js's ``createHelixConsent`` / ``consentRetryAuthorizer``): the consent
page a ``needs_authorization`` challenge (L3-E) points at is Helix's, and the
root of the agent's new chain is signed there by the user's own did:key.

- :func:`create_helix_consent` ``.authorization_url`` is the challenge's
  ``authorization_url`` function: per challenge it builds the unsigned root
  DelegationCredential (``invoker`` the agent, ``invocationTarget`` and
  ``parentCapability`` this service, ``allowedAction`` the tool's scopes,
  ``validUntil`` the end of the consented window), submits it to Helix in a
  request this service signs, and answers the consent page URL, which the
  challenge proof then covers.
- :func:`consent_retry_authorizer` is the L3-E retry authorizer: the credential
  a retry carries (the signed root hop, or a chain) is verified in full by this
  service's local verifier, must delegate to the agent the resume token was
  issued to, and grants what the verifier derives. Completing consent alone
  never authorises a call.
- ``withdraw(consent_id)``: the user withdrew in this service's settings; Helix
  revokes the hops under the user's key.

The service never holds a key able to sign as a user.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional

from helix_sdk import consent as helix_consent_api
from helix_sdk.crypto.jws import Signer

from .needs_authorization import ChallengeContext, ChallengeInput, RetryAuthorization, RetryAuthorizer, RetryAuthorizerInput


class ConsentUserUnknownError(Exception):
    """Raised by ``authorization_url`` when the service cannot say which of its users the agent acts for."""

    def __init__(self) -> None:
        super().__init__("create_helix_consent: no service user for this call (service_user_of returned nothing); consent needs to know whose it is")


@dataclass
class HelixConsent:
    authorization_url: Callable[[ChallengeContext, ChallengeInput], str]
    withdraw: Callable[[str], Dict[str, Any]]


def create_helix_consent(
    helix_url: str,
    service_did: str,
    signer: Signer,
    window_seconds: float,
    *,
    hop_lifetime_seconds: Optional[int] = None,
    service_user_of: Optional[Callable[[ChallengeInput], Optional[str]]] = None,
    display: Optional[Mapping[str, Any]] = None,
    return_url: Optional[str] = None,
    http: Any = None,
    now: Optional[Callable[[], float]] = None,
) -> HelixConsent:
    """The challenge's consent page at Helix. ``service_user_of`` names this service's user for a call;
    default the caller's OAuth subject (an id taken from the agent's word would let an agent ask consent under
    someone else's key)."""
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)) or not window_seconds > 0 or window_seconds == float("inf"):
        raise ValueError("create_helix_consent: window_seconds must be a positive number")
    if signer.did != service_did:
        raise ValueError("create_helix_consent: the signer must be the service DID")
    clock = now if now is not None else time.time
    user_of = service_user_of if service_user_of is not None else (lambda details: details.oauth_subject)

    def authorization_url(context: ChallengeContext, details: ChallengeInput) -> str:
        service_user_id = user_of(details)
        if not service_user_id:
            raise ConsentUserUnknownError()
        created = helix_consent_api.create_consent_request(
            helix_url,
            signer,
            service_user_id,
            helix_consent_api.unsigned_root_grant(
                context.agent_did, service_did, context.scopes, datetime.fromtimestamp(clock() + window_seconds, timezone.utc)
            ),
            hop_lifetime_seconds=hop_lifetime_seconds,
            display=display,
            return_url=return_url,
            http=http,
            now=clock(),
        )
        return str(created["authorizationUrl"])

    def withdraw(consent_id: str) -> Dict[str, Any]:
        return helix_consent_api.withdraw_consent(helix_url, signer, consent_id, http=http, now=clock())

    return HelixConsent(authorization_url=authorization_url, withdraw=withdraw)


def consent_retry_authorizer(verifier: Any) -> RetryAuthorizer:
    """The L3-E retry authorizer over the local verifier: the retry's credential (one hop or a chain, root
    first) is verified in full, without a request proof of its own, every status read live; it must delegate
    to the agent the token was issued to. Grants the verifier's effective scopes."""

    def authorize(details: RetryAuthorizerInput) -> RetryAuthorization:
        chain = list(details.credential) if isinstance(details.credential, list) else [details.credential]
        result = verifier.verify(None, chain=chain, require_proof=False, live_status=True)
        if not result.ok:
            raise ValueError(f"the delegation did not verify: {', '.join(result.reasons)}")
        if result.agent_did != details.agent_did:
            raise ValueError(f"the delegation is for {result.agent_did}, not {details.agent_did}")
        return RetryAuthorization(scopes=list(result.effective_scopes))

    return authorize


__all__ = ["ConsentUserUnknownError", "HelixConsent", "consent_retry_authorizer", "create_helix_consent"]
