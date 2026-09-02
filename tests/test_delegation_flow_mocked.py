# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Mocked-HTTP integration tests for the delegate() / VPBuilder / verify_vp()
flow used by examples/agent_delegation_demo.py and
examples/verify_vp_demo.py.

These stand in for a live network integration test: this sandbox cannot
run a real helix-api instance (server.ts imports the generated Prisma
client unconditionally, even in sqlite-storage mode, and `prisma generate`
needs binaries.prisma.sh, which is outside this sandbox's egress
allowlist -- a pre-existing, already-documented limitation, not new here).

What this DOES verify, faithfully reproducing helix-api's real prepare/
finalize contract (see helix-api's PreparedPayloadService and
/v1/vcs/delegation/{prepare,finalize} routes):
  - delegate() calls prepare with the correct fields, signs exactly the
    canonical hash the (fake) server returned, and calls finalize with
    that signature -- the delegator's private key never appears in any
    HTTP request body.
  - The signature delegate() produces verifies against the delegator's
    real public key over the exact hash bytes the server provided.
  - HelixError subclasses are correctly reconstructed from error response
    bodies (e.g. MAX_DELEGATION_DEPTH_EXCEEDED -> MaxDelegationDepthExceededError).
  - AgentWallet's encrypted save/load round-trips correctly and
    add_credential() rejects a credential for the wrong DID.

Before helix-server (or a real deployment) is available to test against,
this is the strongest verification available in this environment; it
should be supplemented with a real live run against an actual helix-api
instance before shipping v0.1.0.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from helix_sdk import (
    AgentWallet,
    HelixClient,
    VPBuilder,
    delegate,
    generate_key_pair,
    public_key_to_multibase,
    verify_signature,
)
from helix_sdk.errors import (
    CredentialNotForThisAgentError,
    MaxDelegationDepthExceededError,
)
from helix_sdk.self_signed import self_issue_vc, SelfIssueOptions
from helix_sdk.vp_crypto import hash_canonical_payload, to_canonical_json


class FakeResponse:
    def __init__(self, status_code: int, body: Dict[str, Any]):
        self.status_code = status_code
        self._body = body
        self.ok = 200 <= status_code < 300

    def json(self) -> Dict[str, Any]:
        return self._body


class FakeServer:
    """A minimal in-process stand-in for helix-api's delegation
    prepare/finalize endpoints, faithful to the real contract: prepare()
    returns an unsigned payload + its canonical hash; finalize() checks
    the signature against the delegator's known public key before
    attaching a proof and returning the finished VC."""

    def __init__(self, delegator_did: str, delegator_public_key_hex: str, max_depth: int = 1):
        self.delegator_did = delegator_did
        self.delegator_public_key_hex = delegator_public_key_hex
        self.max_depth = max_depth
        self.pending: Dict[str, Dict[str, Any]] = {}
        self.calls: List[Dict[str, Any]] = []

    def handle(self, method: str, url: str, json_body: Dict[str, Any]) -> FakeResponse:
        self.calls.append({"method": method, "url": url, "body": json_body})
        path = url.split("://", 1)[-1].split("/", 1)[-1]
        path = "/" + path

        if path == "/v1/vcs/delegation/prepare":
            return self._prepare_delegation(json_body)
        if path == "/v1/vcs/delegation/finalize":
            return self._finalize_delegation(json_body)
        raise AssertionError(f"FakeServer got unexpected path: {path}")

    def _prepare_delegation(self, body: Dict[str, Any]) -> FakeResponse:
        if body["delegatorDid"] != self.delegator_did:
            return FakeResponse(400, {"error": {"code": "VALIDATION_ERROR", "message": "unknown delegator"}})

        from_vc = body["fromVC"]
        current_depth = from_vc["credentialSubject"].get("delegationDepth", 0)
        if current_depth >= self.max_depth:
            return FakeResponse(
                400,
                {"error": {"code": "MAX_DELEGATION_DEPTH_EXCEEDED", "message": "depth exceeded"}},
            )

        unsigned_vc = {
            "@context": ["https://www.w3.org/ns/credentials/v2", "https://helixid.io/contexts/v1"],
            "id": "vc:helix:delegation:00000000-0000-4000-8000-000000000099",
            "type": ["VerifiableCredential", "HelixAgentCredential"],
            "issuer": self.delegator_did,
            "validFrom": "2026-01-01T00:00:00.000Z",
            "validUntil": "2026-01-01T01:00:00.000Z",
            "credentialSubject": {
                "id": body["to"],
                "type": "HelixAgent",
                "privilegeScopes": body["scopes"],
                "agentName": body["to"],
                "delegationDepth": current_depth + 1,
                "maxDelegationDepth": from_vc["credentialSubject"].get("maxDelegationDepth", 0),
            },
        }
        canonical_hash = hash_canonical_payload(unsigned_vc).hex()
        token = f"prepared-token-{len(self.pending)}"
        self.pending[token] = {"unsignedVc": unsigned_vc, "canonicalHash": canonical_hash}
        return FakeResponse(200, {"token": token, "canonicalHash": canonical_hash})

    def _finalize_delegation(self, body: Dict[str, Any]) -> FakeResponse:
        prepared = self.pending.get(body["token"])
        if prepared is None:
            return FakeResponse(404, {"error": {"code": "PREPARED_PAYLOAD_NOT_FOUND", "message": "not found"}})

        hash_bytes = bytes.fromhex(prepared["canonicalHash"])
        if not verify_signature(hash_bytes, body["signatureHex"], self.delegator_public_key_hex):
            return FakeResponse(
                400, {"error": {"code": "PREPARED_PAYLOAD_SIGNATURE_INVALID", "message": "bad signature"}}
            )

        signed_vc = dict(prepared["unsignedVc"])
        signed_vc["proof"] = {
            "type": "Ed25519Signature2020",
            "created": "2026-01-01T00:00:00.000Z",
            "verificationMethod": body["verificationMethod"],
            "proofPurpose": "assertionMethod",
            "proofValue": "zFakeServerSignedProofValue",
        }
        return signed_vc if False else FakeResponse(200, signed_vc)


@pytest.fixture()
def wallet_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def _make_delegator_wallet(wallet_dir: str, client: HelixClient, max_depth: int = 1) -> AgentWallet:
    key_pair = generate_key_pair()
    did = f"did:key:{public_key_to_multibase(key_pair.public_key)}"
    wallet = AgentWallet(
        client=client,
        private_key_hex=key_pair.private_key,
        did_value=did,
        wallet_path=os.path.join(wallet_dir, "delegator.json"),
        passphrase="test-pass-delegator",
    )
    wallet.save(wallet.wallet_path)
    root_vc = self_issue_vc(
        SelfIssueOptions(scopes=["read:orders", "write:orders"], max_delegation_depth=max_depth),
        did,
        key_pair.private_key,
    )
    wallet.add_credential(root_vc)
    return wallet


class TestDelegateFlow:
    def test_delegate_signs_exact_server_provided_hash(self, wallet_dir: str) -> None:
        client = HelixClient("http://fake-server.invalid")
        delegator = _make_delegator_wallet(wallet_dir, client, max_depth=1)
        server = FakeServer(delegator.get_did(), delegator.get_public_key(), max_depth=1)

        sub_key_pair = generate_key_pair()
        sub_did = f"did:key:{public_key_to_multibase(sub_key_pair.public_key)}"

        with patch("helix_sdk.http_adapter.requests.request") as mock_request:
            mock_request.side_effect = lambda method, url, json=None, headers=None, timeout=None: server.handle(
                method, url, json
            )
            sub_agent_vc = delegate(delegator, to=sub_did, scopes=["read:orders"], expires_in=3600)

        assert sub_agent_vc["credentialSubject"]["id"] == sub_did
        assert sub_agent_vc["credentialSubject"]["privilegeScopes"] == ["read:orders"]
        assert sub_agent_vc["credentialSubject"]["delegationDepth"] == 1

        # The private key must never appear in any outgoing request body.
        for call in server.calls:
            assert delegator.get_private_key_hex() not in json.dumps(call["body"])

        # Exactly two calls: prepare, then finalize.
        assert [c["url"].split("/v1/")[-1] for c in server.calls] == [
            "vcs/delegation/prepare",
            "vcs/delegation/finalize",
        ]

    def test_delegate_raises_typed_error_on_depth_exceeded(self, wallet_dir: str) -> None:
        client = HelixClient("http://fake-server.invalid")
        # max_depth=0 means the root VC (delegationDepth=0) is already at the limit.
        delegator = _make_delegator_wallet(wallet_dir, client, max_depth=0)
        server = FakeServer(delegator.get_did(), delegator.get_public_key(), max_depth=0)

        with patch("helix_sdk.http_adapter.requests.request") as mock_request:
            mock_request.side_effect = lambda method, url, json=None, headers=None, timeout=None: server.handle(
                method, url, json
            )
            with pytest.raises(MaxDelegationDepthExceededError) as exc_info:
                delegate(delegator, to="did:key:z6MkPlaceholder", scopes=["read:orders"], expires_in=3600)

        assert exc_info.value.code == "MAX_DELEGATION_DEPTH_EXCEEDED"
        assert exc_info.value.http_status == 400


class TestVPBuilderAgainstWalletCredentials:
    def test_build_and_verify_signed_vp_round_trip(self, wallet_dir: str) -> None:
        """No server needed for this one: VPBuilder.sign() is local, and
        we verify the resulting proof with the same local primitives a
        verifier's DID-resolution step would end up using."""
        client = HelixClient()  # SDK-only mode
        key_pair = generate_key_pair()
        did = f"did:key:{public_key_to_multibase(key_pair.public_key)}"
        wallet = AgentWallet(private_key_hex=key_pair.private_key, did_value=did)

        vc = self_issue_vc(SelfIssueOptions(scopes=["read:orders"]), did, key_pair.private_key)
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


def _decode_proof_value(proof_value: str) -> str:
    from helix_sdk.vp_crypto import base58btc_decode

    value = proof_value[1:] if proof_value.startswith("z") else proof_value
    return base58btc_decode(value).hex()


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
        vc = self_issue_vc(SelfIssueOptions(scopes=["read:orders"]), other_did, other_key_pair.private_key)

        with pytest.raises(CredentialNotForThisAgentError):
            wallet.add_credential(vc)
