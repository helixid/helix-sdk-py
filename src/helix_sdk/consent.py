# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The consent flow of KYA-OS story L3-H, both sides, over Helix's consent API:
the Python twin of helix-sdk-js's ``kyaos.consent``. The root of an agent's
chain is signed by the user's own did:key on the Helix-hosted consent page;
neither the service nor the SDK ever holds a key able to sign as the user.

Service side (the middleware uses these): :func:`create_consent_request`
submits the unsigned root DelegationCredential for one of the service's users
in a request the service signs (``helix-consent-request+jwt``) and answers the
consent page URL, the ``authorizationUrl`` of the signed ``needs_authorization``
challenge (L3-E); :func:`withdraw_consent` withdraws it (Helix revokes the hops
under the user's key).

Agent side: :func:`await_consent_hop` reads the signed root hop once the user
approved, checked by :func:`verify_consent_hop` (issuer a did:key whose
signature verifies from the DID alone, delegating to this agent at this
service, a root); :class:`ConsentHopKeeper` stores it in the CredentialStore
and renews it before it expires (:func:`renew_before`) inside the consented
window, without a click (``helix-consent-renewal+jwt``, signed by the agent).
A renewal asking for more than was consented is ``step_up_required``.

Self-custody invariant (rule 7): every request carries a JWS, never key
material.
"""

from __future__ import annotations

import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Union
from urllib.parse import urlsplit

from .credential_store import CredentialStore
from .credentials import evaluate_delegation_chain, invoker_of, validate_credential, verify_data_integrity
from .crypto.jws import Signer, sign_jws
from .errors import ConsentFlowError
from .verifier.resolve import did_key_document

CONSENT_REQUEST_TYP = "helix-consent-request+jwt"
CONSENT_RENEWAL_TYP = "helix-consent-renewal+jwt"
CONSENT_WITHDRAWAL_TYP = "helix-consent-withdrawal+jwt"

#: Renew a hop this long before its ``validUntil`` by default.
DEFAULT_RENEW_MARGIN_SECONDS = 60


class ConsentReasons:
    REQUEST_REFUSED = "consent_request_refused"
    HOP_INVALID = "consent_hop_invalid"
    NOT_APPROVED = "consent_not_approved"
    TIMEOUT = "consent_timeout"
    STEP_UP_REQUIRED = "step_up_required"
    WINDOW_ENDED = "consent_window_ended"
    WITHDRAWN = "consent_withdrawn"
    RENEWAL_REFUSED = "consent_renewal_refused"
    WITHDRAWAL_REFUSED = "consent_withdrawal_refused"
    URL_INVALID = "consent_url_invalid"
    #: Helix could not be reached (the request never got an answer).
    UNREACHABLE = "consent_unreachable"


Http = Any
"""``requests``-shaped: ``get(url, timeout=…)`` and ``post(url, json=…, timeout=…)`` returning a response with ``status_code`` and ``json()``."""


def _http(http: Optional[Http]) -> Http:
    if http is not None:
        return http
    import requests

    return requests


def _iso(value: Union[datetime, str]) -> str:
    if isinstance(value, str):
        return value
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_time(value: Any) -> Optional[float]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def unsigned_root_grant(
    agent_did: str,
    service_did: str,
    scopes: Sequence[str],
    valid_until: Union[datetime, str],
    caveats: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """The unsigned root DelegationCredential a service fills from its catalog (SPEC.md §6.10; L3-H point 2)."""
    subject: Dict[str, Any] = {
        "invoker": agent_did,
        "invocationTarget": service_did,
        "parentCapability": service_did,
        "allowedAction": list(scopes),
    }
    if caveats is not None:
        subject["caveats"] = [dict(caveat) for caveat in caveats]
    return {"validUntil": _iso(valid_until), "credentialSubject": subject}


def _signed_request(body: Mapping[str, Any], signer: Signer, typ: str, audience: str, now: Optional[float]) -> str:
    claims = {**body, "iss": signer.did, "aud": audience, "iat": int(now if now is not None else time.time()), "jti": f"urn:uuid:{uuid.uuid4()}"}
    return sign_jws(claims, signer, header={"typ": typ})


def _body(response: Any) -> Any:
    try:
        return response.json()
    except Exception:  # noqa: BLE001 - a body that is not JSON reads as none
        return None


def _post(http: Http, url: str, request: str) -> Any:
    try:
        return _http(http).post(url, json={"request": request}, timeout=10)
    except Exception as error:  # no answer at all: an outage, never a refusal
        raise ConsentFlowError(ConsentReasons.UNREACHABLE, f"Helix could not be reached: {error}", 503) from error


def _refusal(reason: str, what: str, status: int, body: Any) -> ConsentFlowError:
    error = body.get("error") if isinstance(body, Mapping) else None
    code = error.get("code") if isinstance(error, Mapping) else None
    message = error.get("message") if isinstance(error, Mapping) else None
    return ConsentFlowError(reason, f"{what}: {code or status} {message or ''}".strip(), status, code if isinstance(code, str) else None)


def _trim(url: str) -> str:
    return url.rstrip("/")


def create_consent_request(
    helix_url: str,
    signer: Signer,
    service_user_id: str,
    grant: Mapping[str, Any],
    *,
    hop_lifetime_seconds: Optional[int] = None,
    display: Optional[Mapping[str, Any]] = None,
    return_url: Optional[str] = None,
    http: Optional[Http] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Service side: ``POST /v1/consent/requests``. Returns ``{id, authorizationUrl, resultUrl, expiresAt, status}``."""
    audience = f"{_trim(helix_url)}/v1/consent/requests"
    body: Dict[str, Any] = {"serviceUserId": service_user_id, "grant": dict(grant)}
    if hop_lifetime_seconds is not None:
        body["hopLifetimeSeconds"] = hop_lifetime_seconds
    if display is not None:
        body["display"] = dict(display)
    if return_url is not None:
        body["returnUrl"] = return_url
    response = _post(http, audience, _signed_request(body, signer, CONSENT_REQUEST_TYP, audience, now))
    answer = _body(response)
    if response.status_code >= 300:
        raise _refusal(ConsentReasons.REQUEST_REFUSED, "Helix refused the consent request", response.status_code, answer)
    if not isinstance(answer, Mapping) or not isinstance(answer.get("id"), str) or not isinstance(answer.get("authorizationUrl"), str):
        raise ConsentFlowError(ConsentReasons.REQUEST_REFUSED, "Helix answered the consent request without an authorizationUrl", 502)
    return dict(answer)


def withdraw_consent(helix_url: str, signer: Signer, consent_id: str, *, http: Optional[Http] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """Service side: ``POST /v1/consent/withdrawals``. Helix revokes every live hop of the consent under the user's key."""
    audience = f"{_trim(helix_url)}/v1/consent/withdrawals"
    response = _post(http, audience, _signed_request({"consentId": consent_id}, signer, CONSENT_WITHDRAWAL_TYP, audience, now))
    answer = _body(response)
    if response.status_code >= 300:
        raise _refusal(ConsentReasons.WITHDRAWAL_REFUSED, "Helix refused the withdrawal", response.status_code, answer)
    return dict(answer)


_PAGE_PATH = re.compile(r"^(.*)/consent/([^/]+)$")


def consent_result_url(authorization_url: str) -> str:
    """Where Helix answers for the consent request an ``authorizationUrl`` names: ``<API>/consent/<id>`` → ``<API>/v1/consent/requests/<id>``."""
    try:
        parts = urlsplit(authorization_url)
    except ValueError as error:
        raise ConsentFlowError(ConsentReasons.URL_INVALID, f"not a URL: {authorization_url}") from error
    match = _PAGE_PATH.match(parts.path)
    if parts.scheme not in ("http", "https") or not parts.netloc or match is None:
        raise ConsentFlowError(ConsentReasons.URL_INVALID, f"not a Helix consent page URL: {authorization_url}")
    return f"{parts.scheme}://{parts.netloc}{match.group(1)}/v1/consent/requests/{match.group(2)}"


def helix_url_of(authorization_url: str) -> str:
    """The API base URL of the Helix deployment whose consent page ``authorization_url`` is."""
    result = consent_result_url(authorization_url)
    return result[: result.index("/v1/consent/requests/")]


def fetch_consent_result(authorization_url: str, http: Optional[Http] = None) -> Dict[str, Any]:
    """``GET /v1/consent/requests/:id`` for the request ``authorization_url`` names."""
    response = _http(http).get(consent_result_url(authorization_url), timeout=10)
    answer = _body(response)
    if response.status_code >= 300:
        raise _refusal(ConsentReasons.NOT_APPROVED, "Helix has no such consent request", response.status_code, answer)
    return dict(answer)


def _did_key_only(did: str) -> Optional[Mapping[str, Any]]:
    return did_key_document(did) if did.startswith("did:key:") else None


def verify_consent_hop(value: Any, agent_did: str, service_did: str, now: Optional[float] = None) -> Dict[str, Any]:
    """The root hop the consent page signed, checked before the agent stores or carries it: a §6.10 hop whose
    issuer is a did:key and whose proof verifies from that DID alone, delegating to ``agent_did`` at
    ``service_did`` as a root, not yet expired. Raises ConsentFlowError."""

    def invalid(message: str) -> ConsentFlowError:
        return ConsentFlowError(ConsentReasons.HOP_INVALID, message)

    if not isinstance(value, Mapping) or validate_credential("hop", value):
        raise invalid("not a DelegationCredential")
    hop = dict(value)
    issuer = hop.get("issuer")
    if not isinstance(issuer, str) or not issuer.startswith("did:key:"):
        raise invalid("the root issuer must be the user did:key")
    if invoker_of(hop) != agent_did:
        raise invalid(f"the hop delegates to {invoker_of(hop)}, not {agent_did}")
    if hop["credentialSubject"].get("invocationTarget") != service_did:
        raise invalid(f"the hop targets {hop['credentialSubject'].get('invocationTarget')}, not {service_did}")
    now_s = now if now is not None else time.time()
    evaluation = evaluate_delegation_chain([hop], resource=service_did, now_ms=int(now_s * 1000))
    if not evaluation.ok:
        raise invalid(f"the hop is not a valid root: {', '.join(evaluation.reasons)}")
    proof = verify_data_integrity(hop, _did_key_only)
    if not proof.ok:
        raise invalid(f"the user's signature does not verify: {proof.reason}")
    until = _parse_time(hop.get("validUntil"))
    if until is None or until <= now_s:
        raise invalid("the hop has expired")
    return hop


def await_consent_hop(
    authorization_url: str,
    agent_did: str,
    service_did: str,
    *,
    http: Optional[Http] = None,
    interval_seconds: float = 1.0,
    timeout_seconds: float = 300.0,
    sleep: Callable[[float], None] = time.sleep,
) -> Dict[str, Any]:
    """Agent side: polls the consent request the (verified) ``authorization_url`` names until the user decided.
    Returns ``{consentId, hop, windowUntil, helixUrl}``; raises when declined, expired or too slow."""
    deadline = time.time() + timeout_seconds
    while True:
        result = fetch_consent_result(authorization_url, http)
        status = result.get("status")
        if status == "approved" and result.get("hop") is not None and result.get("consentId") is not None:
            hop = verify_consent_hop(result["hop"], agent_did, service_did)
            window = result.get("windowUntil")
            return {
                "consentId": result["consentId"],
                "hop": hop,
                "windowUntil": window if isinstance(window, int) else int(_parse_time(hop["validUntil"]) or 0),
                "helixUrl": helix_url_of(authorization_url),
            }
        if status in ("denied", "expired"):
            raise ConsentFlowError(ConsentReasons.NOT_APPROVED, f"the consent request is {status}", 403)
        if time.time() >= deadline:
            raise ConsentFlowError(ConsentReasons.TIMEOUT, "the user did not decide in time", 408)
        sleep(interval_seconds)


_RENEWAL_REASONS = {
    "CONSENT_STEP_UP_REQUIRED": ConsentReasons.STEP_UP_REQUIRED,
    "CONSENT_WINDOW_ENDED": ConsentReasons.WINDOW_ENDED,
    "CONSENT_WITHDRAWN": ConsentReasons.WITHDRAWN,
}


def renew_consent_hop(
    helix_url: str,
    consent_id: str,
    signer: Signer,
    service_did: str,
    *,
    allowed_action: Optional[Sequence[str]] = None,
    http: Optional[Http] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Agent side: ``POST /v1/consent/renewals``. Returns ``{hop, windowUntil}``; the fresh hop is checked like the first."""
    audience = f"{_trim(helix_url)}/v1/consent/renewals"
    body: Dict[str, Any] = {"consentId": consent_id}
    if allowed_action is not None:
        body["allowedAction"] = list(allowed_action)
    response = _post(http, audience, _signed_request(body, signer, CONSENT_RENEWAL_TYP, audience, now))
    answer = _body(response)
    if response.status_code >= 300:
        error = answer.get("error") if isinstance(answer, Mapping) else None
        code = error.get("code") if isinstance(error, Mapping) else None
        raise _refusal(_RENEWAL_REASONS.get(str(code), ConsentReasons.RENEWAL_REFUSED), "Helix refused the renewal", response.status_code, answer)
    hop = verify_consent_hop(answer.get("hop") if isinstance(answer, Mapping) else None, signer.did, service_did, now)
    window = answer.get("windowUntil")
    return {"hop": hop, "windowUntil": window if isinstance(window, int) else int(_parse_time(hop["validUntil"]) or 0)}


def renew_before(valid_until: Union[str, datetime], margin_seconds: float = DEFAULT_RENEW_MARGIN_SECONDS, now: Optional[float] = None) -> float:
    """When to renew a hop valid until ``valid_until``: ``margin_seconds`` before it ends, never before now (seconds since the epoch)."""
    until = valid_until.timestamp() if isinstance(valid_until, datetime) else _parse_time(valid_until)
    if until is None:
        raise ConsentFlowError(ConsentReasons.HOP_INVALID, "validUntil is not a date-time")
    current = now if now is not None else time.time()
    return max(current, until - margin_seconds)


class ConsentHopKeeper:
    """Keeps an agent's consent hop for one service: stores the root hop in the CredentialStore (where
    ``present_chain(invocation_target=…)`` finds it) and renews it when :func:`renew_before` says so, as long
    as the consented window allows. :meth:`chain` is what a request carries."""

    def __init__(
        self,
        store: CredentialStore,
        signer: Signer,
        service_did: str,
        consent: Mapping[str, Any],
        *,
        margin_seconds: float = DEFAULT_RENEW_MARGIN_SECONDS,
        http: Optional[Http] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._signer = signer
        self._service_did = service_did
        self._consent = dict(consent)
        self._margin = margin_seconds
        self._http = http
        self._clock = clock
        self._hop: Dict[str, Any] = dict(consent["hop"])
        store.add_hop(self._hop)

    @property
    def hop(self) -> Dict[str, Any]:
        return self._hop

    @property
    def consent_id(self) -> str:
        return str(self._consent["consentId"])

    def current(self) -> Dict[str, Any]:
        """The current hop, renewed first when it is due and the window still allows it."""
        now = self._clock()
        window_end = float(self._consent["windowUntil"])
        until = _parse_time(self._hop.get("validUntil")) or 0.0
        if now >= renew_before(self._hop["validUntil"], self._margin, now) and now < window_end and until < window_end:
            self.renew()
        return self._hop

    def renew(self, allowed_action: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        """Renews now: the new hop replaces the old one in the store."""
        renewed = renew_consent_hop(
            str(self._consent["helixUrl"]),
            self.consent_id,
            self._signer,
            self._service_did,
            allowed_action=allowed_action,
            http=self._http,
            now=self._clock(),
        )
        self._store.remove_hop(str(self._hop["id"]))
        self._store.add_hop(renewed["hop"])
        self._hop = renewed["hop"]
        return self._hop

    def chain(self) -> List[Dict[str, Any]]:
        """The chain to carry at this service, root first: here, the one root hop."""
        return [self.current()]


__all__ = [
    "CONSENT_REQUEST_TYP", "CONSENT_RENEWAL_TYP", "CONSENT_WITHDRAWAL_TYP", "DEFAULT_RENEW_MARGIN_SECONDS",
    "ConsentReasons", "ConsentHopKeeper", "await_consent_hop", "consent_result_url", "create_consent_request",
    "fetch_consent_result", "helix_url_of", "renew_before", "renew_consent_hop", "unsigned_root_grant",
    "verify_consent_hop", "withdraw_consent",
]
