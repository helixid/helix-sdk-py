# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
selfIssueVC, ported from helix-sdk-js's src/core/self-signed.ts.

Dev-only flow: an agent signs its own agent-authority VC instead of getting
one from an issuer. This is the other explicit local carveout (alongside
VPBuilder.sign()) from docs/proposal-sdk-api-only.md -- everything else
routes through the API. NOT FOR PRODUCTION USE, same as the JS side (see
the `evidence` block on the resulting VC).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from . import proof

_DURATION_RE = re.compile(r"^(\d+)([smhd])$")
_UNIT_MS = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}


@dataclass
class SelfIssueOptions:
    scopes: List[str]
    expires_in: str = "24h"
    max_delegation_depth: int = 0


def _parse_duration_ms(value: str) -> int:
    match = _DURATION_RE.match(value)
    if not match:
        raise ValueError("expires_in must use s, m, h, or d suffix")
    amount = int(match.group(1))
    unit = match.group(2)
    return amount * _UNIT_MS[unit]


def self_issue_vc(
    options: SelfIssueOptions,
    wallet_did: str,
    wallet_private_key_hex: str,
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(milliseconds=_parse_duration_ms(options.expires_in))
    payload: Dict[str, Any] = {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://helixid.io/contexts/v1"],
        "id": f"vc:helix:self:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "HelixAgentCredential"],
        "issuer": wallet_did,
        "validFrom": proof._to_iso_z(now),
        "validUntil": proof._to_iso_z(expires_at),
        "credentialSubject": {
            "id": wallet_did,
            "type": "HelixAgent",
            "privilegeScopes": options.scopes,
            "agentName": wallet_did,
            "delegationDepth": 0,
            "maxDelegationDepth": options.max_delegation_depth,
        },
        "evidence": [{"type": "SelfSignedDevCredential", "warning": "Not for production use"}],
    }
    signed = dict(payload)
    signed["proof"] = proof.create_ed25519_proof(
        payload, wallet_private_key_hex, f"{wallet_did}#key-1"
    )
    return signed
