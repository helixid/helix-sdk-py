# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""Story L3-H in the Python sample (parity with the JS sample's consent-env tests): the challenge's consent page
is Helix's when KYAOS_HELIX_CONSENT_URL is set."""

from __future__ import annotations

import base64
import json
import os
import sys
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

pytest.importorskip("mcp")
pytest.importorskip("uvicorn")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))

from helix_mcp_middleware import ChallengeContext, ChallengeInput, RetryAuthorizerInput  # noqa: E402
from helix_mcp_middleware.resume_token_store import ResumeTokenRecord  # noqa: E402
from helix_sdk.crypto.jws import EnvSigner  # noqa: E402
from helix_sdk.keys import generate_key_pair  # noqa: E402
from mcp_order_management import __main__ as sample  # noqa: E402
from mcp_order_management.consent_env import ConsentSettings, consent_from_settings, describe_consent, read_consent_settings  # noqa: E402

SERVICE = "did:web:shop.example:services:aa"
AGENT = "did:web:helix.example:agents:bb"


def test_off_without_the_url_and_refuses_strays() -> None:
    assert read_consent_settings({}) is None
    with pytest.raises(ValueError, match="KYAOS_CONSENT_USER needs KYAOS_HELIX_CONSENT_URL"):
        read_consent_settings({"KYAOS_CONSENT_USER": "u"})


def test_reads_every_setting() -> None:
    assert read_consent_settings({"KYAOS_HELIX_CONSENT_URL": "https://helix.example/"}) == ConsentSettings(helix_url="https://helix.example")
    assert read_consent_settings(
        {
            "KYAOS_HELIX_CONSENT_URL": "http://127.0.0.1:3000",
            "KYAOS_CONSENT_WINDOW_SECONDS": "600",
            "KYAOS_CONSENT_HOP_LIFETIME_SECONDS": "60",
            "KYAOS_CONSENT_USER": " user-1 ",
            "KYAOS_CONSENT_SERVICE_NAME": "Orders",
        }
    ) == ConsentSettings(helix_url="http://127.0.0.1:3000", window_seconds=600, hop_lifetime_seconds=60, demo_user="user-1", service_name="Orders")
    for env in (
        {"KYAOS_HELIX_CONSENT_URL": "not a url"},
        {"KYAOS_HELIX_CONSENT_URL": "ftp://helix.example"},
        {"KYAOS_HELIX_CONSENT_URL": "https://helix.example", "KYAOS_CONSENT_WINDOW_SECONDS": "0"},
        {"KYAOS_HELIX_CONSENT_URL": "https://helix.example", "KYAOS_CONSENT_HOP_LIFETIME_SECONDS": "1.5"},
    ):
        with pytest.raises(ValueError):
            read_consent_settings(env)


def test_describes_itself() -> None:
    assert "off" in describe_consent(None)
    assert describe_consent(ConsentSettings(helix_url="https://h", window_seconds=60, hop_lifetime_seconds=10, demo_user="u")) == "Helix https://h, window 60 s, hops 10 s, demo user u"
    assert describe_consent(ConsentSettings(helix_url="https://h", window_seconds=60)) == "Helix https://h, window 60 s"


class Helix:
    def __init__(self) -> None:
        self.requests: List[str] = []

    def post(self, url: str, json: Any = None, timeout: float = 0) -> Any:
        self.requests.append(json["request"])
        return SimpleNamespace(status_code=201, json=lambda: {"id": "x", "authorizationUrl": "https://helix.example/consent/x", "resultUrl": "", "expiresAt": 1, "status": "pending"})


def claims(jws: str) -> Dict[str, Any]:
    part = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def test_consent_from_settings_asks_for_the_caller_and_verifies_retries() -> None:
    signer = EnvSigner(did=SERVICE, env_var="K", env={"K": generate_key_pair().private_key})
    helix = Helix()
    verifier: List[Any] = [None]
    url_of, authorize = consent_from_settings(ConsentSettings(helix_url="https://helix.example", window_seconds=60, hop_lifetime_seconds=10, demo_user="demo", service_name="Orders"), SERVICE, signer, lambda: verifier[0], http=helix)
    context = ChallengeContext(agent_did=AGENT, tool="list_orders", scopes=["orders:read"])
    assert url_of(context, ChallengeInput(agent_did=AGENT, tool="list_orders", scopes=["orders:read"])) == "https://helix.example/consent/x"
    url_of(context, ChallengeInput(agent_did=AGENT, tool="list_orders", scopes=["orders:read"], oauth_subject="alice"))
    assert [claims(jws)["serviceUserId"] for jws in helix.requests] == ["demo", "alice"]
    assert claims(helix.requests[0])["display"] == {"serviceName": "Orders"}
    retry = RetryAuthorizerInput(credential={"id": "hop"}, token=ResumeTokenRecord(AGENT, "list_orders", ["orders:read"], 0), agent_did=AGENT, tool="list_orders", scopes=["orders:read"])
    with pytest.raises(ValueError, match="no local verifier"):
        authorize(retry)
    verifier[0] = SimpleNamespace(verify=lambda proof, **kwargs: SimpleNamespace(ok=True, agent_did=AGENT, effective_scopes=["orders:read"], reasons=[]))
    assert authorize(retry).scopes == ["orders:read"]


def test_the_sample_builds_the_layer_from_the_environment() -> None:
    key = generate_key_pair().private_key
    env = {"KYAOS_HELIX_CONSENT_URL": "https://helix.example", "SERVICE_SIGNING_KEY": key}
    layer = sample.needs_authorization_from_env(env, SERVICE, False, None, lambda: None)
    assert layer is not None
    with pytest.raises(SystemExit):
        sample.needs_authorization_from_env({**env, "KYAOS_AUTHORIZATION_URL": "https://x.example"}, SERVICE, False, None)
    with pytest.raises(SystemExit):
        sample.needs_authorization_from_env(env, None, False, None)
    with pytest.raises(SystemExit):
        sample.needs_authorization_from_env({"KYAOS_CONSENT_USER": "u"}, SERVICE, False, None)
    with pytest.raises(SystemExit):
        sample.needs_authorization_from_env({"KYAOS_RESUME_TTL_SECONDS": "5"}, SERVICE, False, None)
