# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Cross-language parity safety net: asserts this SDK's local-signing
primitives produce byte-for-byte identical output to helix-core /
helix-sdk-js against the same committed fixtures those SDKs assert
against (see fixtures/golden-vectors/README.md).

If this file ever fails, the Python and JS/core implementations have
drifted -- do not "fix" it by editing the fixtures; regenerate them from
helix-core (see fixtures/golden-vectors/README.md) and re-copy here, the
same way helix-sdk-js's own copy is maintained.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from helix_sdk.keys import derive_public_key
from helix_sdk.proof import create_ed25519_proof
from helix_sdk.vp_builder import VPBuilder, VPBuilderSignOverrides
from helix_sdk.vp_crypto import hash_canonical_payload, sign_bytes, to_canonical_json

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "golden-vectors"


def _load(name: str) -> dict:
    with open(FIXTURES_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def _parse_iso(value: str) -> datetime:
    # All golden-vector timestamps are "...Z" millisecond-precision UTC.
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


class TestCanonicalJson:
    @pytest.mark.parametrize("vector", _load("canonical-json.json")["vectors"], ids=lambda v: v["name"])
    def test_canonical_string_and_hash(self, vector: dict) -> None:
        canonical = to_canonical_json(vector["input"])
        assert canonical == vector["canonical_string"]
        assert hash_canonical_payload(vector["input"]).hex() == vector["hash_hex"]


class TestSigning:
    @pytest.mark.parametrize("vector", _load("signing.json")["vectors"], ids=lambda v: v["name"])
    def test_pubkey_hash_and_signature(self, vector: dict) -> None:
        assert derive_public_key(vector["private_key_hex"]) == vector["public_key_hex"]
        h = hash_canonical_payload(vector["input"])
        assert h.hex() == vector["hash_hex"]
        sig = sign_bytes(h, vector["private_key_hex"])
        assert sig == vector["signature_hex"]
        assert vector["verifies"] is True


class TestVPBuilder:
    @pytest.mark.parametrize("vector", _load("vp-builder.json")["vectors"], ids=lambda v: v["name"])
    def test_signed_vp_matches_exactly(self, vector: dict) -> None:
        inp = vector["input"]
        overrides = vector["overrides"]

        builder = VPBuilder(
            credentials=inp["credentials"],
            holder_did=inp["holderDid"],
            target_service=inp["targetService"],
            user_did=inp.get("userDid"),
        )
        result = builder.sign(
            vector["private_key_hex"],
            vector["verification_method"],
            VPBuilderSignOverrides(
                id=overrides["id"],
                nonce=overrides["nonce"],
                expires_at=_parse_iso(overrides["expiresAt"]),
                proof_created_at=_parse_iso(overrides["proofCreatedAt"]),
            ),
        )

        # Compare via canonical JSON rather than dict equality so key
        # ordering differences (which carry no semantic weight) can't
        # cause a false failure -- the actual wire-compatibility contract
        # is the JSON content, not Python dict insertion order.
        assert to_canonical_json(result) == to_canonical_json(vector["signed_vp"])


class TestProof:
    def test_create_ed25519_proof_matches_vp_builder_vector(self) -> None:
        """Sanity check that proof.create_ed25519_proof() alone (not just
        through VPBuilder) produces the same proof block, since
        VPBuilder.sign() is a thin wrapper around it."""
        vectors = _load("vp-builder.json")["vectors"]
        vector = vectors[0]
        payload = {k: v for k, v in vector["signed_vp"].items() if k != "proof"}
        created_at = _parse_iso(vector["overrides"]["proofCreatedAt"])
        proof = create_ed25519_proof(
            payload, vector["private_key_hex"], vector["verification_method"], created_at
        )
        assert proof == vector["signed_vp"]["proof"]
