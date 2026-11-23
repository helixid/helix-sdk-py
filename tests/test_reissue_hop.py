# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story C-E point 4: a self-custody issuer reissues its hop for a
delegate's new key. Parity with helix-sdk-js ``custody-reissue.test.ts``."""

from __future__ import annotations

import nacl.signing
import pytest

from helix_sdk import reissue_hop
from helix_sdk.credentials import build_delegation_hop, verify_data_integrity
from helix_sdk.crypto.jws import EnvSigner

ISSUER = "did:web:issuer.example:accounts:01"
DELEGATE = "did:web:helix.example:agents:02"
SEED = bytes([5] * 32)
SIGNER = EnvSigner(ISSUER, kid="key-1", env_var="K", env={"K": SEED.hex()})
STATUS = {"type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": "7", "statusListCredential": "https://issuer.example/status/1"}


def _resolve(did: str):  # type: ignore[no-untyped-def]
    import base64

    x = base64.urlsafe_b64encode(bytes(nacl.signing.SigningKey(SEED).verify_key)).rstrip(b"=").decode()
    method = {"id": f"{ISSUER}#key-1", "type": "Ed25519VerificationKey2020", "controller": ISSUER, "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}
    return {"id": ISSUER, "verificationMethod": [method], "assertionMethod": [method["id"]]}


def _old() -> dict:  # type: ignore[type-arg]
    return build_delegation_hop(
        SIGNER, DELEGATE, "did:web:orders.example", "did:web:orders.example", ["orders:read"], "2027-06-01T00:00:00Z",
        {**STATUS, "statusListIndex": "1"}, caveats=[{"type": "MaxAmount", "limit": "10"}], id="urn:zcap:old", valid_from="2026-06-01T00:00:00Z",
    )


def test_keeps_the_grant_takes_a_new_id_and_status_entry_and_is_signed_again() -> None:
    old = _old()
    fresh = reissue_hop(old, SIGNER, STATUS, id="urn:zcap:new", proof_created="2026-06-02T00:00:00Z")
    assert fresh["id"] == "urn:zcap:new" and fresh["credentialSubject"]["id"] == "urn:zcap:new"
    assert {k: fresh["credentialSubject"][k] for k in ("invoker", "allowedAction", "caveats")} == {k: old["credentialSubject"][k] for k in ("invoker", "allowedAction", "caveats")}
    assert (fresh["validFrom"], fresh["validUntil"]) == (old["validFrom"], old["validUntil"])
    assert fresh["credentialStatus"] == {**STATUS, "id": "https://issuer.example/status/1#7"}
    assert fresh["proof"]["created"] == "2026-06-02T00:00:00Z"
    assert verify_data_integrity(fresh, _resolve).ok
    generated = reissue_hop(old, SIGNER, {**STATUS, "id": "x#1"})
    assert generated["id"].startswith("urn:zcap:") and generated["credentialStatus"]["id"] == "x#1"


def test_refuses_a_hop_it_did_not_issue_or_one_with_no_subject() -> None:
    old = _old()
    with pytest.raises(ValueError, match="not the issuer of this hop"):
        reissue_hop(old, EnvSigner("did:web:stranger.example", env_var="K", env={"K": SEED.hex()}), STATUS)
    with pytest.raises(ValueError, match="no credentialSubject"):
        reissue_hop({**old, "credentialSubject": None}, SIGNER, STATUS)
