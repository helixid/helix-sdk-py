# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story C-B point 4: the middleware's trusted-issuer allowlist for
capability attestations, ported from helix-sdk-js's
mcp-middleware/src/trusted-issuers.ts.

``"*"`` (the shipped default, stories rule 9) trusts every issuer; a list
such as ``[helix_issuer_did]`` trusts those DIDs only, and an attestation
from any other issuer is ``"unverified"``. A restrictive default is a phase 4
discussion."""

from __future__ import annotations

from typing import Any

from .credentials import DEFAULT_TRUSTED_ISSUERS, TrustedIssuers


def is_trusted_issuer(issuer_did: Any, setting: TrustedIssuers = DEFAULT_TRUSTED_ISSUERS) -> bool:
    """Whether ``issuer_did`` may back a capability under ``setting``. Pure: no
    I/O, no defaults beyond ``"*"``. Fails closed on anything that is neither
    the wildcard nor a list (a bare DID string is not a list)."""
    if setting == "*":
        return True
    if not isinstance(setting, (list, tuple)):
        return False
    return isinstance(issuer_did, str) and issuer_did in setting


def attestation_trust(issuer_did: Any, setting: TrustedIssuers = DEFAULT_TRUSTED_ISSUERS) -> str:
    """How a verifier reports an attestation from ``issuer_did``: ``"verified"``
    only when the issuer is trusted, else ``"unverified"``."""
    return "verified" if is_trusted_issuer(issuer_did, setting) else "unverified"
