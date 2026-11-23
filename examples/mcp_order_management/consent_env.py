# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""Story L3-H from the environment (parity with the JS sample's consent-env.ts): ``KYAOS_HELIX_CONSENT_URL``
(Helix's API base) turns the challenge's consent page into Helix's, where the user's own did:key signs the root
hop; ``KYAOS_CONSENT_WINDOW_SECONDS`` (default one day), ``KYAOS_CONSENT_HOP_LIFETIME_SECONDS`` (each hop's
life, renewed by the agent without a click), ``KYAOS_CONSENT_USER`` (the service user when the caller carries no
OAuth subject: a one-user demo) and ``KYAOS_CONSENT_SERVICE_NAME`` (the page's branding)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from helix_mcp_middleware import ChallengeInput, RetryAuthorization, RetryAuthorizer, RetryAuthorizerInput, consent_retry_authorizer, create_helix_consent
from helix_sdk.crypto.jws import Signer

CONSENT_VARIABLES = ("KYAOS_HELIX_CONSENT_URL", "KYAOS_CONSENT_WINDOW_SECONDS", "KYAOS_CONSENT_HOP_LIFETIME_SECONDS", "KYAOS_CONSENT_USER", "KYAOS_CONSENT_SERVICE_NAME")


@dataclass(frozen=True)
class ConsentSettings:
    helix_url: str
    window_seconds: int = 86_400
    hop_lifetime_seconds: Optional[int] = None
    demo_user: Optional[str] = None
    service_name: Optional[str] = None


def _seconds(env: Mapping[str, str], name: str) -> Optional[int]:
    raw = (env.get(name) or "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value < 1 or str(value) != raw:
        raise ValueError(f"{name}: {raw} is not a positive whole number of seconds")
    return value


def read_consent_settings(env: Mapping[str, str]) -> Optional[ConsentSettings]:
    """None when the URL is unset; raises ValueError on anything malformed, or on another variable set without it."""
    helix_url = (env.get("KYAOS_HELIX_CONSENT_URL") or "").strip()
    if not helix_url:
        stray = next((name for name in CONSENT_VARIABLES[1:] if (env.get(name) or "").strip()), None)
        if stray is not None:
            raise ValueError(f"{stray} needs KYAOS_HELIX_CONSENT_URL")
        return None
    parts = urlsplit(helix_url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"KYAOS_HELIX_CONSENT_URL: {helix_url} is not an http(s) URL")
    window = _seconds(env, "KYAOS_CONSENT_WINDOW_SECONDS")
    return ConsentSettings(
        helix_url=helix_url.rstrip("/"),
        window_seconds=window if window is not None else 86_400,
        hop_lifetime_seconds=_seconds(env, "KYAOS_CONSENT_HOP_LIFETIME_SECONDS"),
        demo_user=(env.get("KYAOS_CONSENT_USER") or "").strip() or None,
        service_name=(env.get("KYAOS_CONSENT_SERVICE_NAME") or "").strip() or None,
    )


def consent_from_settings(
    settings: ConsentSettings, service_did: str, signer: Signer, verifier_of: Callable[[], Any], http: Any = None
) -> Tuple[Callable[..., str], RetryAuthorizer]:
    """The challenge's consent page and retry authorizer over Helix; the verifier is read when a retry arrives."""
    consent = create_helix_consent(
        settings.helix_url,
        service_did,
        signer,
        settings.window_seconds,
        hop_lifetime_seconds=settings.hop_lifetime_seconds,
        display={"serviceName": settings.service_name} if settings.service_name else None,
        service_user_of=lambda details: details.oauth_subject or settings.demo_user,
        http=http,
    )

    def authorize(details: RetryAuthorizerInput) -> RetryAuthorization:
        verifier = verifier_of()
        if verifier is None:
            raise ValueError("no local verifier: the retry cannot be verified here")
        return consent_retry_authorizer(verifier)(details)

    return consent.authorization_url, authorize


def describe_consent(settings: Optional[ConsentSettings]) -> str:
    if settings is None:
        return "off (set KYAOS_HELIX_CONSENT_URL)"
    hops = "" if settings.hop_lifetime_seconds is None else f", hops {settings.hop_lifetime_seconds} s"
    user = "" if settings.demo_user is None else f", demo user {settings.demo_user}"
    return f"Helix {settings.helix_url}, window {settings.window_seconds} s{hops}{user}"


__all__ = ["CONSENT_VARIABLES", "ConsentSettings", "consent_from_settings", "describe_consent", "read_consent_settings", "ChallengeInput"]
