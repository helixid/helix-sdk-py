# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
VPBuilder, ported from helix-sdk-js's src/core/vp-builder-impl.ts.

VPBuilder.sign() is local-signing logic -- one of the explicit carveouts
that stays client-side per docs/proposal-sdk-api-only.md (private-key
operations never call the API). Every other SDK operation on a VP
(verification) goes through HelixClient instead; see verify.py.

Verified byte-for-byte against fixtures/golden-vectors/vp-builder.json,
including both single-credential and agent-plus-delegation-grant-plus-user
shapes -- see tests/test_golden_vectors.py.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from . import proof
from .errors import VPInvalidStructureError


def _is_agent_authority_type(vc: Dict[str, Any]) -> bool:
    return isinstance(vc.get("type"), list) and "HelixAgentCredential" in vc["type"]


def _is_grant_type(vc: Dict[str, Any]) -> bool:
    return isinstance(vc.get("type"), list) and "DelegationGrantCredential" in vc["type"]


@dataclass
class VPBuilderSignOverrides:
    """Test-only override hooks for VPBuilder.sign(). Never used in
    production call sites: omitting these preserves the normal random
    id/nonce/expirationDate behavior exactly. These exist so this SDK can
    reproduce the cross-language golden vectors deterministically."""

    id: Optional[str] = None
    nonce: Optional[str] = None
    expires_at: Optional[datetime] = None
    proof_created_at: Optional[datetime] = None


@dataclass
class VPBuilder:
    """1 or 2 credentials: exactly one agent-authority VC, optionally one
    consent grant."""

    credentials: List[Dict[str, Any]]
    holder_did: str
    target_service: str
    user_did: Optional[str] = field(default=None)

    def __post_init__(self) -> None:
        credentials = self.credentials
        if not isinstance(credentials, list) or not (1 <= len(credentials) <= 2):
            raise VPInvalidStructureError("VP must carry 1 or 2 credentials")
        agent_entries = [vc for vc in credentials if _is_agent_authority_type(vc)]
        grant_entries = [vc for vc in credentials if _is_grant_type(vc)]
        if (
            len(agent_entries) != 1
            or len(grant_entries) > 1
            or len(agent_entries) + len(grant_entries) != len(credentials)
        ):
            raise VPInvalidStructureError(
                "VP credential array must contain exactly one agent-authority "
                "credential and at most one consent grant"
            )

    def sign(
        self,
        private_key_hex: str,
        verification_method_id: str,
        overrides: Optional[VPBuilderSignOverrides] = None,
    ) -> Dict[str, Any]:
        overrides = overrides or VPBuilderSignOverrides()
        expires_at = overrides.expires_at or (datetime.now(timezone.utc) + timedelta(minutes=5))
        payload: Dict[str, Any] = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "id": overrides.id or f"vp:helix:{uuid.uuid4()}",
            "holder": self.holder_did,
            "verifiableCredential": self.credentials,
            "nonce": overrides.nonce or os.urandom(32).hex(),
            "expirationDate": proof._to_iso_z(expires_at),
        }
        # "No user" is one semantic state with one wire shape: the key is
        # absent, never serialized as null.
        if self.user_did is not None:
            payload["delegatedBy"] = self.user_did
        payload["targetService"] = self.target_service

        signed = dict(payload)
        signed["proof"] = proof.create_ed25519_proof(
            payload, private_key_hex, verification_method_id, overrides.proof_created_at
        )
        return signed
