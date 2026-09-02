# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Ed25519Signature2020 linked-data proof creation, ported from
helix-sdk-js's src/core/proof.ts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, MutableMapping, Optional

from . import vp_crypto


def create_ed25519_proof(
    payload: Mapping[str, Any],
    private_key_hex: str,
    verification_method: str,
    created_at: Optional[datetime] = None,
) -> MutableMapping[str, Any]:
    """Signs `payload` and returns an Ed25519Signature2020 proof block.

    `created_at`, when given, overrides `datetime.now()` -- test-only, for
    deterministic golden-vector reproduction, mirroring the JS
    `createdAt?: Date` parameter exactly.
    """
    signature_hex = vp_crypto.sign_bytes(vp_crypto.hash_canonical_payload(payload), private_key_hex)
    created = created_at if created_at is not None else datetime.now(timezone.utc)
    return {
        "type": "Ed25519Signature2020",
        "created": _to_iso_z(created),
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        "proofValue": vp_crypto.base58btc_encode(bytes.fromhex(signature_hex)),
    }


def verify_ed25519_proof(
    payload: Mapping[str, Any],
    proof: Mapping[str, Any],
    public_key_hex: str,
) -> bool:
    """Verifies a proof block against a caller-supplied public key hex
    (extracted from the resolved DID document by the caller -- DID
    resolution is an API call in this SDK, not something proof.py does
    itself)."""

    def verify_proof_value(proof_value: str) -> bool:
        try:
            decoded = vp_crypto.base58btc_decode(proof_value)
        except ValueError:
            return False
        return vp_crypto.verify_signature(
            vp_crypto.hash_canonical_payload(payload), decoded.hex(), public_key_hex
        )

    proof_value = proof.get("proofValue", "")
    if verify_proof_value(proof_value):
        return True
    if proof_value.startswith("z"):
        return verify_proof_value(proof_value[1:])
    return False


def _to_iso_z(dt: datetime) -> str:
    """Matches JS `Date.prototype.toISOString()`: millisecond precision,
    trailing 'Z', always UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
