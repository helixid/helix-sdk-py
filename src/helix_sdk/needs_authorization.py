# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The client's side of the signed ``needs_authorization`` challenge and the
resume flow (KYA-OS story L3-E; SPEC §9.2, §9.3, §11.1 "consent-URL
substitution"), mirroring helix-sdk-js's core/kyaos/needs-authorization.ts.

A service that lacks the authority for a call answers with a challenge
``{"error": "needs_authorization", "message", "authorizationUrl",
"resumeToken", "expiresAt", "scopes", "display"?}`` as the tool result
(``structuredContent``, and the same JSON as text), signed per L2-A with
``outcome: needs_authorization`` and a ``responseHash`` over the whole
result. ``handle_needs_authorization`` verifies that proof against the
service DID, recomputing both hashes, BEFORE it reads the challenge: a
tampered ``authorizationUrl`` is refused with ``response_hash_mismatch`` and
nothing of the challenge is surfaced. ``retry_with_resume`` retries the
same call with the ``resumeToken`` and the new DelegationCredential as the
``_kyaos_resume`` and ``_kyaos_delegation`` control arguments.

Cross-border rule: the only input besides the response, the request and the
challenge is the DID document the injected resolver returns.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional
from urllib.parse import urlsplit

from .errors import NeedsAuthorizationError
from .response_proof import DidResolver, VerifiedProof, verify_response_proof

NEEDS_AUTHORIZATION = "needs_authorization"
RESUME_CONTROL_ARGUMENT = "_kyaos_resume"
DELEGATION_CONTROL_ARGUMENT = "_kyaos_delegation"
DISPLAY_HINTS = ("link", "qr", "code")


class ChallengeReasons:
    """Why a challenge was refused; the same strings as helix-sdk-js."""

    OUTCOME_MISMATCH = "challenge_outcome_mismatch"
    MISSING = "challenge_missing"
    MALFORMED = "challenge_malformed"
    URL_INVALID = "authorization_url_invalid"
    EXPIRED = "challenge_expired"


def _refuse(reason: str, message: str) -> None:
    raise NeedsAuthorizationError(reason, message)


def _is_record(value: Any) -> bool:
    return isinstance(value, Mapping)


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


@dataclass
class NeedsAuthorizationChallenge:
    """SPEC §9.2 ``NeedsAuthorizationError``: the challenge a service answers with."""

    message: str
    authorization_url: str
    resume_token: str
    expires_at: int
    scopes: list
    display: Optional[Dict[str, Any]] = None
    error: str = NEEDS_AUTHORIZATION

    def to_dict(self) -> Dict[str, Any]:
        """The challenge in its wire shape (camelCase), as the fixture and the JS SDK write it."""
        out: Dict[str, Any] = {
            "error": self.error,
            "message": self.message,
            "authorizationUrl": self.authorization_url,
            "resumeToken": self.resume_token,
            "expiresAt": self.expires_at,
            "scopes": list(self.scopes),
        }
        if self.display is not None:
            out["display"] = dict(self.display)
        return out


@dataclass
class HandledChallenge:
    challenge: NeedsAuthorizationChallenge
    proof: VerifiedProof


def find_challenge(response: Any) -> Optional[Mapping[str, Any]]:
    """The challenge a response carries: at its top level, or as its ``structuredContent``; None when neither looks like one."""
    if not _is_record(response):
        return None
    if response.get("error") == NEEDS_AUTHORIZATION:
        return response
    structured = response.get("structuredContent")
    if _is_record(structured) and structured.get("error") == NEEDS_AUTHORIZATION:
        return structured
    return None


def is_needs_authorization(response: Any) -> bool:
    """Whether ``response`` looks like a needs_authorization challenge (its shape only; nothing is verified)."""
    return find_challenge(response) is not None


def read_challenge(response: Any, now: Optional[float] = None) -> NeedsAuthorizationChallenge:
    """Reads and checks the challenge's shape (SPEC §9.2), without any proof
    check. ``now`` is Unix seconds (default ``time.time()``). Prefer
    ``handle_needs_authorization``, which verifies first."""
    found = find_challenge(response)
    if found is None:
        _refuse(ChallengeReasons.MISSING, "the response is not a needs_authorization challenge")
    assert found is not None
    message = found.get("message")
    if not isinstance(message, str):
        _refuse(ChallengeReasons.MALFORMED, "challenge message must be a string")
    url = found.get("authorizationUrl")
    if not isinstance(url, str) or url == "":
        _refuse(ChallengeReasons.URL_INVALID, "challenge authorizationUrl must be a string")
    assert isinstance(url, str)
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        _refuse(ChallengeReasons.URL_INVALID, "challenge authorizationUrl must be an absolute http(s) URL")
    token = found.get("resumeToken")
    if not isinstance(token, str) or token == "":
        _refuse(ChallengeReasons.MALFORMED, "challenge resumeToken must be a non-empty string")
    expires_at = found.get("expiresAt")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at < 1:
        _refuse(ChallengeReasons.MALFORMED, "challenge expiresAt must be Unix seconds")
    scopes = found.get("scopes")
    if not _is_string_list(scopes):
        _refuse(ChallengeReasons.MALFORMED, "challenge scopes must be an array of strings")
    display = found.get("display")
    shown: Optional[Dict[str, Any]] = None
    if display is not None:
        if not _is_record(display):
            _refuse(ChallengeReasons.MALFORMED, "challenge display must be an object")
        shown = {}
        for name in ("title", "authorizationCode", "qrUrl"):
            value = display.get(name)
            if value is None:
                continue
            if not isinstance(value, str):
                _refuse(ChallengeReasons.MALFORMED, f"challenge display.{name} must be a string")
            shown[name] = value
        hint = display.get("hint")
        if hint is not None:
            if not _is_string_list(hint) or any(h not in DISPLAY_HINTS for h in hint):
                _refuse(ChallengeReasons.MALFORMED, f"challenge display.hint must list {', '.join(DISPLAY_HINTS)}")
            shown["hint"] = list(hint)
    now_seconds = int(time.time() if now is None else now)
    assert isinstance(expires_at, int)
    if expires_at <= now_seconds:
        _refuse(ChallengeReasons.EXPIRED, f"the challenge expired at {expires_at} (now {now_seconds})")
    assert isinstance(message, str) and isinstance(token, str) and isinstance(scopes, list)
    return NeedsAuthorizationChallenge(
        message=message,
        authorization_url=url,
        resume_token=token,
        expires_at=expires_at,
        scopes=list(scopes),
        display=shown,
    )


def handle_needs_authorization(
    response: Any,
    service_did: str,
    resolve_did: DidResolver,
    *,
    request: Mapping[str, Any],
    now: Optional[float] = None,
    skew_seconds: int = 120,
) -> HandledChallenge:
    """Verifies the challenge's proof against ``service_did`` (signature,
    signer, ``outcome: needs_authorization``, requestHash recomputed from
    ``request``, responseHash recomputed over the whole ``response``), then
    reads the challenge. ``now`` is Unix seconds. Raises ResponseProofError
    (a tampered authorizationUrl is ``response_hash_mismatch``),
    InvalidJWSError, or NeedsAuthorizationError. Only a returned
    ``authorization_url`` is safe to show."""
    proof = verify_response_proof(response, service_did, resolve_did, request=request, now=now, skew_seconds=skew_seconds)
    if proof.outcome != NEEDS_AUTHORIZATION:
        _refuse(ChallengeReasons.OUTCOME_MISMATCH, f"the proof's outcome is {proof.outcome}, not needs_authorization")
    return HandledChallenge(challenge=read_challenge(response, now=now), proof=proof)


def with_resume(params: Mapping[str, Any], resume_token: str, credential: Any) -> Dict[str, Any]:
    """``params`` (``{"name", "arguments"?, "_meta"?}``) with the resume token and the credential as control arguments."""
    if not isinstance(resume_token, str) or resume_token == "":
        raise TypeError("with_resume: resume_token must be a non-empty string")
    if credential is None:
        raise TypeError("with_resume: the retry must carry the DelegationCredential")
    out = dict(params)
    out["arguments"] = {**dict(params.get("arguments") or {}), RESUME_CONTROL_ARGUMENT: resume_token, DELEGATION_CONTROL_ARGUMENT: credential}
    return out


@dataclass
class RetriedCall:
    params: Dict[str, Any]
    response: Any
    proof: Optional[VerifiedProof] = None


def retry_with_resume(
    resume_token: str,
    hop: Any,
    *,
    call: Mapping[str, Any],
    send: Callable[[Dict[str, Any]], Any],
    service_did: Optional[str] = None,
    resolve_did: Optional[DidResolver] = None,
    now: Optional[float] = None,
    skew_seconds: int = 120,
) -> RetriedCall:
    """Retries ``call`` with ``resume_token`` and the new DelegationCredential
    ``hop`` through ``send`` (which takes the tools/call params and returns
    the result body). With ``service_did`` and ``resolve_did`` the answer's
    proof is verified against the request that was sent."""
    params = with_resume(call, resume_token, hop)
    response = send(params)
    if service_did is None or resolve_did is None:
        return RetriedCall(params=params, response=response)
    proof = verify_response_proof(
        response,
        service_did,
        resolve_did,
        request={"method": "tools/call", "params": params},
        now=now,
        skew_seconds=skew_seconds,
    )
    return RetriedCall(params=params, response=response, proof=proof)
