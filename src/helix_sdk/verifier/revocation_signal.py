# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The revocation signal (KYA-OS story L3-C point 7): one RFC 8417 Security
Event Token per revoked credential, signed by the Helix issuer, carrying only
the credential id. Honoured only from a trusted issuer whose signature
verifies; a cache hint, never a revocation by itself. Mirrors helix-sdk-js
``verifier/revocation-signal.ts``.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence, Union

from ..credentials import DidResolver
from ..crypto.jws import InvalidJWSError, Signer, read_jws_header, sign_jws, verify_jws_by_kid

REVOCATION_EVENT_TYPE = "https://helixid.io/secevent/credential-revoked"
SECEVENT_JWT_TYP = "secevent+jwt"
SECEVENT_JWT_MEDIA_TYPE = "application/secevent+jwt"
DEFAULT_SIGNAL_MAX_AGE_SECONDS = 24 * 60 * 60


class SignalReasons:
    MALFORMED = "signal_malformed"
    UNKNOWN_ISSUER = "signal_unknown_issuer"
    BAD_SIGNATURE = "signal_bad_signature"
    WRONG_EVENT = "signal_wrong_event"
    STALE = "signal_stale"


@dataclass(frozen=True)
class RevocationSignal:
    jti: str
    iss: str
    iat: int
    credential_id: str
    aud: Union[str, Sequence[str], None] = None


@dataclass(frozen=True)
class SignalVerification:
    ok: bool
    signal: Optional[RevocationSignal] = None
    reason: Optional[str] = None
    message: Optional[str] = None


def sign_revocation_signal(
    credential_id: str,
    signer: Signer,
    jti: Optional[str] = None,
    iat: Optional[int] = None,
    aud: Union[str, Sequence[str], None] = None,
) -> str:
    """The SET for one revoked credential, signed by ``signer`` (the Helix issuer)."""
    if not isinstance(credential_id, str) or not credential_id:
        raise TypeError("credential_id must be a non-empty string")
    payload = {
        "iss": signer.did,
        "iat": int(time.time()) if iat is None else iat,
        "jti": jti or f"urn:uuid:{uuid.uuid4()}",
        **({} if aud is None else {"aud": aud}),
        "events": {REVOCATION_EVENT_TYPE: {"subject": {"format": "uri", "uri": credential_id}}},
    }
    return sign_jws(payload, signer, header={"typ": SECEVENT_JWT_TYP})


def _payload(set_jwt: str) -> Optional[Mapping[str, Any]]:
    try:
        segment = set_jwt.split(".")[1]
        parsed = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, IndexError):
        return None
    return parsed if isinstance(parsed, dict) else None


def verify_revocation_signal(
    set_jwt: Any,
    trusted_issuers: Sequence[str],
    resolve_did: DidResolver,
    now_ms: Optional[int] = None,
    max_age_seconds: int = DEFAULT_SIGNAL_MAX_AGE_SECONDS,
    skew_seconds: int = 300,
) -> SignalVerification:
    """Shape, trusted issuer (before any resolution), signature, event, ``iat``; never raises."""

    def refuse(reason: str, message: str) -> SignalVerification:
        return SignalVerification(False, reason=reason, message=message)

    if not isinstance(set_jwt, str) or len(set_jwt.split(".")) != 3:
        return refuse(SignalReasons.MALFORMED, "a SET is a compact JWS")
    try:
        typ = read_jws_header(set_jwt).get("typ")
    except InvalidJWSError as exc:
        return refuse(SignalReasons.MALFORMED, str(exc))
    if typ != SECEVENT_JWT_TYP:
        return refuse(SignalReasons.MALFORMED, f"typ is not {SECEVENT_JWT_TYP}")
    claims = _payload(set_jwt)
    if claims is None:
        return refuse(SignalReasons.MALFORMED, "the SET payload is not a JSON object")
    iss = claims.get("iss")
    if not isinstance(iss, str) or not iss.startswith("did:"):
        return refuse(SignalReasons.MALFORMED, "iss is not a DID")
    if iss not in trusted_issuers:
        return refuse(SignalReasons.UNKNOWN_ISSUER, f"{iss} is not an issuer whose signals are honoured")
    try:
        verify_jws_by_kid(set_jwt, resolve_did, expected_did=iss)
    except InvalidJWSError as exc:
        return refuse(SignalReasons.BAD_SIGNATURE, f"{exc.reason}: {exc}")
    except Exception as exc:  # noqa: BLE001 - a resolver that raises cannot vouch for the signature
        return refuse(SignalReasons.BAD_SIGNATURE, str(exc))
    iat = claims.get("iat")
    jti = claims.get("jti")
    if isinstance(iat, bool) or not isinstance(iat, int) or not isinstance(jti, str) or not jti:
        return refuse(SignalReasons.MALFORMED, "iat and jti are required")
    events = claims.get("events")
    event = events.get(REVOCATION_EVENT_TYPE) if isinstance(events, dict) else None
    if not isinstance(events, dict) or len(events) != 1 or not isinstance(event, dict):
        return refuse(SignalReasons.WRONG_EVENT, f"the SET carries no single {REVOCATION_EVENT_TYPE} event")
    subject = event.get("subject")
    if not isinstance(subject, dict) or subject.get("format") != "uri" or not isinstance(subject.get("uri"), str) or not subject["uri"]:
        return refuse(SignalReasons.WRONG_EVENT, "the event subject is not a credential id (format uri)")
    now_seconds = (int(time.time() * 1000) if now_ms is None else now_ms) // 1000
    if iat > now_seconds + skew_seconds:
        return refuse(SignalReasons.STALE, "iat is in the future")
    if iat < now_seconds - max_age_seconds:
        return refuse(SignalReasons.STALE, "the SET is older than the signals honoured")
    aud = claims.get("aud")
    return SignalVerification(
        True,
        signal=RevocationSignal(jti=jti, iss=iss, iat=iat, credential_id=subject["uri"], aud=aud if isinstance(aud, (str, list)) else None),
    )
