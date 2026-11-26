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
from helix_sdk.proof import create_ed25519_proof, verify_ed25519_proof
from helix_sdk.crypto.common import base58btc_encode, hash_canonical_payload, sign_bytes, to_canonical_json

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


class TestProof:
    @pytest.mark.parametrize("vector", _load("signing.json")["vectors"], ids=lambda v: v["name"])
    def test_create_ed25519_proof_carries_the_vector_signature(self, vector: dict) -> None:
        """proof.create_ed25519_proof() signs the canonical hash with the vector's key: its
        proofValue is the vector's signature, base58btc, and it verifies. (The VP vector,
        vp-builder.json, is gone with the Helix VP, KYA-OS story C-C.)"""
        created_at = _parse_iso("2026-01-01T00:00:00.000Z")
        proof = create_ed25519_proof(vector["input"], vector["private_key_hex"], "did:key:z6Mk#key-1", created_at)
        assert proof == {
            "type": "Ed25519Signature2020",
            "created": "2026-01-01T00:00:00.000Z",
            "verificationMethod": "did:key:z6Mk#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": base58btc_encode(bytes.fromhex(vector["signature_hex"])),
        }
        assert verify_ed25519_proof(vector["input"], proof, vector["public_key_hex"])


def test_base58btc_keeps_leading_zero_bytes_as_ones() -> None:
    # Each leading zero byte is a leading "1" (the alphabet's zero), whatever the data.
    assert base58btc_encode(b"\x00\x00\x01") == "112"
    assert base58btc_encode(b"") == ""
