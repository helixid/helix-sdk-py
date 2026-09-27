# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
AgentWallet / VPBuilder tests.

Split out of the old test_delegation_flow_mocked.py: that file's
TestDelegateFlow class tested the wallet-based delegate() function, which
has been removed (agent self-custody is retired, so nothing produces a
wallet holding a real agent key to delegate with). AgentWallet itself
remains -- for other actors' key storage (e.g. an issuer's own key
material), not for agent onboarding -- so its encrypted persistence and
local-signing behavior (used by VPBuilder) still need coverage.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from typing import Any, Dict, List

import pytest

from helix_sdk import (
    AgentWallet,
    HelixClient,
    VPBuilder,
    generate_key_pair,
    public_key_to_multibase,
    verify_signature,
)
from helix_sdk.errors import CredentialAlreadyInWalletError, CredentialNotForThisAgentError
from helix_sdk.vp_crypto import hash_canonical_payload


def _build_agent_vc(did: str, scopes: List[str], max_delegation_depth: int = 0) -> Dict[str, Any]:
    """Agent self-issuance is gone -- a hand-built VC stands in for what
    self_issue_vc() used to produce."""
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://helixid.io/contexts/v1"],
        "id": f"vc:helix:test:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "HelixAgentCredential"],
        "issuer": did,
        "validFrom": "2026-01-01T00:00:00.000Z",
        "validUntil": "2026-01-01T01:00:00.000Z",
        "credentialSubject": {
            "id": did,
            "type": "HelixAgent",
            "privilegeScopes": scopes,
            "agentName": did,
            "delegationDepth": 0,
            "maxDelegationDepth": max_delegation_depth,
        },
    }


def _build_grant_vc(agent_did: str, issuer_did: str, user_did: str, scopes: List[str]) -> Dict[str, Any]:
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://helixid.io/contexts/v1"],
        "id": f"vc:helix:grant:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "DelegationGrantCredential"],
        "issuer": issuer_did,
        "validFrom": "2026-01-01T00:00:00.000Z",
        "validUntil": "2026-01-01T01:00:00.000Z",
        "credentialSubject": {
            "id": agent_did,
            "userDid": user_did,
            "scopes": scopes,
            "durability": "standing",
        },
    }


def _decode_proof_value(proof_value: str) -> str:
    from helix_sdk.vp_crypto import base58btc_decode

    value = proof_value[1:] if proof_value.startswith("z") else proof_value
    return base58btc_decode(value).hex()


@pytest.fixture()
def wallet_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


class TestVPBuilderAgainstWalletCredentials:
    def test_build_and_verify_signed_vp_round_trip(self, wallet_dir: str) -> None:
        """No server needed for this one: VPBuilder.sign() is local, and
        we verify the resulting proof with the same local primitives a
        verifier's DID-resolution step would end up using."""
        client = HelixClient()  # SDK-only mode
        key_pair = generate_key_pair()
        did = f"did:key:{public_key_to_multibase(key_pair.public_key)}"
        wallet = AgentWallet(private_key_hex=key_pair.private_key, did_value=did)

        vc = _build_agent_vc(did, ["read:orders"])
        wallet.wallet_credentials = []
        # Bypass add_credential's client-audit best-effort call by adding directly:
        from helix_sdk.wallet import WalletCredential

        wallet.wallet_credentials.append(WalletCredential.from_vc(vc["id"], vc))

        vp = VPBuilder(
            credentials=wallet.credentials, holder_did=did, target_service="https://svc.example.invalid"
        ).sign(wallet.get_private_key_hex(), f"{did}#key-1")

        payload = {k: v for k, v in vp.items() if k != "proof"}
        payload_hash = hash_canonical_payload(payload)
        assert verify_signature(
            payload_hash,
            _decode_proof_value(vp["proof"]["proofValue"]),
            key_pair.public_key,
        )


class TestWalletEncryptedPersistence:
    def test_save_and_load_round_trip(self, wallet_dir: str) -> None:
        path = os.path.join(wallet_dir, "roundtrip.json")
        key_pair = generate_key_pair()
        did = f"did:key:{public_key_to_multibase(key_pair.public_key)}"
        wallet = AgentWallet(private_key_hex=key_pair.private_key, did_value=did, passphrase="correct-horse")
        wallet.save(path)

        loaded = AgentWallet.load(path, "correct-horse")
        assert loaded.get_did() == did
        assert loaded.get_private_key_hex() == key_pair.private_key

        with pytest.raises(RuntimeError):
            AgentWallet.load(path, "wrong-passphrase")

    def test_add_credential_rejects_wrong_subject(self, wallet_dir: str) -> None:
        key_pair = generate_key_pair()
        did = f"did:key:{public_key_to_multibase(key_pair.public_key)}"
        wallet = AgentWallet(private_key_hex=key_pair.private_key, did_value=did)

        other_key_pair = generate_key_pair()
        other_did = f"did:key:{public_key_to_multibase(other_key_pair.public_key)}"
        vc = _build_agent_vc(other_did, ["read:orders"])

        with pytest.raises(CredentialNotForThisAgentError):
            wallet.add_credential(vc)

    def test_add_credential_rejects_duplicate(self, wallet_dir: str) -> None:
        key_pair = generate_key_pair()
        did = f"did:key:{public_key_to_multibase(key_pair.public_key)}"
        wallet = AgentWallet(private_key_hex=key_pair.private_key, did_value=did)

        vc = _build_agent_vc(did, ["read:orders"])
        wallet.add_credential(vc)

        with pytest.raises(CredentialAlreadyInWalletError):
            wallet.add_credential(vc)


class TestWalletCredentialQueries:
    def test_select_grant_matches_by_issuer_and_user(self, wallet_dir: str) -> None:
        key_pair = generate_key_pair()
        agent_did = f"did:key:{public_key_to_multibase(key_pair.public_key)}"
        wallet = AgentWallet(private_key_hex=key_pair.private_key, did_value=agent_did)

        issuer_did = "did:web:sp.example.com"
        user_did = "did:key:zUser"

        grant = _build_grant_vc(agent_did, issuer_did, user_did, ["read:orders"])
        wallet.add_credential(grant)
        # A grant for a different user must not be selected.
        wallet.add_credential(_build_grant_vc(agent_did, issuer_did, "did:key:zOtherUser", ["read:orders"]))

        selected = wallet.select_grant(issuer_did, user_did)
        assert selected is not None
        assert selected.vc_id == grant["id"]

        assert wallet.select_grant(issuer_did, "did:key:zNoSuchUser") is None

    def test_get_latest_credential_filters_by_type(self, wallet_dir: str) -> None:
        key_pair = generate_key_pair()
        agent_did = f"did:key:{public_key_to_multibase(key_pair.public_key)}"
        wallet = AgentWallet(private_key_hex=key_pair.private_key, did_value=agent_did)

        agent_vc = _build_agent_vc(agent_did, ["read:orders"])
        wallet.add_credential(agent_vc)
        grant_vc = _build_grant_vc(agent_did, "did:web:sp.example.com", "did:key:zUser", ["read:orders"])
        wallet.add_credential(grant_vc)

        latest_grant = wallet.get_latest_credential("DelegationGrantCredential")
        assert latest_grant is not None
        assert latest_grant.vc_id == grant_vc["id"]

        assert wallet.get_latest_credential("NoSuchType") is None
