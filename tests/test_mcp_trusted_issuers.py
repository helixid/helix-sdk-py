# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story C-B: the middleware's trusted-issuer setting in both modes
(stories rule 9). Mirrors helix-sdk-js mcp-middleware/tests/trusted-issuers.test.ts
case for case, plus the cases Python's types make possible (tuples, a bare
string that is not the wildcard)."""

from __future__ import annotations

from typing import Any

from helix_mcp_middleware import (
    DEFAULT_TRUSTED_ISSUERS,
    TrustedIssuers,
    attestation_trust,
    is_trusted_issuer,
)
from helix_mcp_middleware import credentials as middleware_credentials
from helix_mcp_middleware import trusted_issuers as trusted_issuers_module

HELIX = "did:web:helix.example"
OWNER = "did:key:z6MkOwner"


def test_ships_as_allow_all() -> None:
    assert DEFAULT_TRUSTED_ISSUERS == "*"
    assert middleware_credentials.DEFAULT_TRUSTED_ISSUERS == "*"
    assert is_trusted_issuer(OWNER) is True
    assert is_trusted_issuer(HELIX, "*") is True
    assert attestation_trust(OWNER) == "verified"


def test_with_a_list_set_an_unlisted_issuer_is_unverified_and_a_listed_one_verified() -> None:
    setting: TrustedIssuers = [HELIX]
    assert is_trusted_issuer(HELIX, setting) is True
    assert is_trusted_issuer(OWNER, setting) is False
    assert attestation_trust(OWNER, setting) == "unverified"
    assert attestation_trust(HELIX, setting) == "verified"
    assert is_trusted_issuer(OWNER, [HELIX, OWNER]) is True
    assert is_trusted_issuer(HELIX, []) is False
    assert is_trusted_issuer(HELIX, (HELIX,)) is True


def test_fails_closed_on_anything_that_is_neither_the_wildcard_nor_a_list() -> None:
    bare: Any = HELIX
    assert is_trusted_issuer(HELIX, bare) is False
    assert is_trusted_issuer(None, [HELIX]) is False
    assert is_trusted_issuer(HELIX, {HELIX}) is False
    assert is_trusted_issuer(HELIX, None) is False  # type: ignore[arg-type]
    assert attestation_trust(HELIX, bare) == "unverified"


def test_the_functions_are_the_module_s_own_and_exported() -> None:
    import helix_mcp_middleware

    for name in ("TrustedIssuers", "DEFAULT_TRUSTED_ISSUERS", "is_trusted_issuer", "attestation_trust"):
        assert name in helix_mcp_middleware.__all__, name
    assert helix_mcp_middleware.is_trusted_issuer is trusted_issuers_module.is_trusted_issuer
    assert helix_mcp_middleware.attestation_trust is trusted_issuers_module.attestation_trust
