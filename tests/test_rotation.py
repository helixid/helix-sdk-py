# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story C-E points 2 and 3, Python parity with helix-sdk-js
``tests/unit/kyaos/verifier/rotation.test.ts``: key validity by kid and
created, the last-seen sequence, the jwks.json projection."""

from __future__ import annotations

from typing import Any, Dict, Optional

import nacl.signing
import pytest

from helix_sdk.credentials import ProofReasons, sign_data_integrity, verify_data_integrity
from helix_sdk.crypto.jws import EnvSigner, JwsReasons, sign_jws, verify_jws_by_kid
from helix_sdk.errors import InvalidJWSError
from helix_sdk.key_validity import KeyValidityReasons, key_validity_problem, proof_time, rfc3339_instant
from helix_sdk.verifier import (
    DID_DOCUMENT_STALE,
    MemoryRotationSequenceStore,
    RequestProofOptions,
    RequestProofSeams,
    RotationSequenceGuard,
    StaleDidDocumentError,
    create_did_resolver,
    ed25519_keys_of,
    guarded_resolver,
    project_jwks,
    read_jwks,
    rotation_sequence_of,
    sign_request_proof,
    verify_request_proof,
)

DID = "did:web:agent.helix.test:agents:0a1b"
AUDIENCE = "did:web:orders.helix.test"
OLD_SEED = bytes([7] * 32)
NEW_SEED = bytes([9] * 32)
NOW = rfc3339_instant("2026-06-01T12:00:00Z")
assert NOW is not None


def _x(seed: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(bytes(nacl.signing.SigningKey(seed).verify_key)).rstrip(b"=").decode()


OLD = EnvSigner(DID, kid="key-1", env_var="K", env={"K": OLD_SEED.hex()})
NEW = EnvSigner(DID, kid="key-2", env_var="K", env={"K": NEW_SEED.hex()})


def _method(fragment: str, seed: bytes, **extra: Any) -> Dict[str, Any]:
    return {"id": f"{DID}#{fragment}", "type": "Ed25519VerificationKey2020", "controller": DID, "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": _x(seed)}, **extra}


def rotated(until: str, revoked: Optional[str] = None, sequence: int = 2) -> Dict[str, Any]:
    old = _method("key-1", OLD_SEED, validUntil=until, **({"revoked": revoked} if revoked else {}))
    ids = [f"{DID}#key-2", f"{DID}#key-1"]
    return {"id": DID, "verificationMethod": [_method("key-2", NEW_SEED), old], "authentication": ids, "assertionMethod": ids, "rotationSequence": sequence, "updated": "2026-06-01T10:00:00Z"}


def resolver_of(document: Any) -> Any:
    return lambda did: document


class TestKeyValidity:
    def test_the_same_rules_as_helix_core(self) -> None:
        at = rfc3339_instant("2026-06-01T10:00:00Z")
        assert key_validity_problem({"id": "k", "validUntil": "2026-06-02T00:00:00Z"}, at) is None
        assert key_validity_problem({"id": "k", "validUntil": "2026-05-31T00:00:00Z"}, at).reason == KeyValidityReasons.KEY_SUPERSEDED  # type: ignore[union-attr]
        assert key_validity_problem({"id": "k", "validFrom": "2026-06-02T00:00:00+05:30"}, at).reason == "key_superseded"  # type: ignore[union-attr]
        assert key_validity_problem({"id": "k", "revoked": "2026-06-02T00:00:00Z"}, at).reason == "key_revoked"  # type: ignore[union-attr]
        assert key_validity_problem({"id": "k", "validUntil": "soon"}, at).reason == "key_validity_malformed"  # type: ignore[union-attr]
        assert key_validity_problem({"validUntil": "2026-05-31T00:00:00Z"}, None, at).message.startswith("the key")  # type: ignore[union-attr]
        assert key_validity_problem({"id": "k", "validUntil": "2999-01-01T00:00:00Z"}, None) is None

    def test_instants_and_proof_times(self) -> None:
        assert rfc3339_instant("2026-06-01T10:00:00.123456789Z") == rfc3339_instant("2026-06-01T10:00:00.123Z")
        assert rfc3339_instant("2026-06-01t10:00:00z") == rfc3339_instant("2026-06-01T10:00:00Z")
        for bad in ("2026-06-01", "2026-13-01T00:00:00Z", 5, None):
            assert rfc3339_instant(bad) is None
        assert proof_time(1) == 1000
        assert proof_time(True) is None
        assert proof_time(-1) is None
        assert proof_time("x") is None


class TestVerifiersPickTheKeyByKid:
    def test_data_integrity_before_after_and_revoked(self) -> None:
        before = sign_data_integrity({"issuer": DID, "n": 1}, OLD, created="2026-06-01T09:00:00Z")
        after = sign_data_integrity({"issuer": DID, "n": 2}, OLD, created="2026-06-03T09:00:00Z")
        resolve = resolver_of(rotated("2026-06-02T10:00:00Z"))
        assert verify_data_integrity(before, resolve).ok
        assert verify_data_integrity(after, resolve).reason == ProofReasons.KEY_SUPERSEDED
        assert verify_data_integrity(before, resolver_of(rotated("2026-06-01T09:30:00Z", "2026-06-01T09:30:00Z"))).reason == ProofReasons.KEY_REVOKED

    def test_jws_at_iat_given_time_or_now(self) -> None:
        resolve = resolver_of(rotated("2026-06-02T10:00:00Z"))
        early = sign_jws({"iss": DID, "iat": rfc3339_instant("2026-06-01T09:00:00Z") // 1000}, OLD)  # type: ignore[operator]
        late = sign_jws({"iss": DID, "iat": rfc3339_instant("2026-06-03T09:00:00Z") // 1000}, OLD)  # type: ignore[operator]
        assert verify_jws_by_kid(early, resolve).kid == f"{DID}#key-1"
        with pytest.raises(InvalidJWSError) as late_error:
            verify_jws_by_kid(late, resolve)
        assert late_error.value.reason == JwsReasons.KEY_SUPERSEDED
        assert verify_jws_by_kid(late, resolve, at=rfc3339_instant("2026-06-01T00:00:00Z")).did == DID
        with pytest.raises(InvalidJWSError) as timeless:
            verify_jws_by_kid(sign_jws({"iss": DID}, OLD), resolve, now=rfc3339_instant("2026-06-03T00:00:00Z"))
        assert timeless.value.reason == JwsReasons.KEY_SUPERSEDED
        with pytest.raises(InvalidJWSError) as revoked:
            verify_jws_by_kid(early, resolver_of(rotated("2026-06-02T10:00:00Z", "2026-06-01T09:30:00Z")))
        assert revoked.value.reason == JwsReasons.KEY_REVOKED
        malformed = rotated("2026-06-02T10:00:00Z")
        malformed["verificationMethod"][1]["validUntil"] = "soon"
        with pytest.raises(InvalidJWSError) as bad:
            verify_jws_by_kid(early, resolver_of(malformed))
        assert bad.value.reason == JwsReasons.KEY_VALIDITY_MALFORMED


REQUEST = {"method": "tools/call", "params": {"name": "t", "arguments": {}}}


def _run(proof: Any, document: Any, clock: int = NOW, resolve: Any = None) -> Any:
    seams = RequestProofSeams(
        clock=lambda: clock,
        resolve_did=resolve or (lambda did: document),
        resolve_did_keys=lambda did: ed25519_keys_of(document),
        nonce_store=type("Store", (), {"insert": lambda self, *args: True})(),
    )
    return verify_request_proof(proof, REQUEST, seams, RequestProofOptions(expected_audience=AUDIENCE))


class TestRequestProofsAcrossARotation:
    def test_overlap_then_new_key_only_and_never_a_revoked_key(self) -> None:
        document = rotated("2026-06-01T12:30:00Z")
        assert _run(sign_request_proof(REQUEST, OLD, audience=AUDIENCE, now_ms=NOW), document).ok
        assert _run(sign_request_proof(REQUEST, NEW, audience=AUDIENCE, now_ms=NOW), document).ok
        later = NOW + 3_600_000
        assert _run(sign_request_proof(REQUEST, OLD, audience=AUDIENCE, now_ms=later), document, later).reasons == ["key_superseded"]
        assert _run(sign_request_proof(REQUEST, NEW, audience=AUDIENCE, now_ms=later), document, later).ok
        earlier = NOW - 7_200_000
        compromised = rotated("2026-06-01T11:00:00Z", "2026-06-01T11:00:00Z", 3)
        assert _run(sign_request_proof(REQUEST, OLD, audience=AUDIENCE, now_ms=earlier), compromised, earlier).reasons == ["key_revoked"]
        assert _run(sign_request_proof(REQUEST, OLD, audience=AUDIENCE, now_ms=NOW), rotated("later")).reasons == ["key_validity_malformed"]

    def test_a_resolver_that_saw_a_newer_document_refuses_the_older_one(self) -> None:
        served = [rotated("2026-06-02T00:00:00Z", sequence=3), rotated("2026-06-02T00:00:00Z", sequence=2)]
        resolve = create_did_resolver(fetch_json=lambda url: served.pop(0))
        proof = sign_request_proof(REQUEST, NEW, audience=AUDIENCE, now_ms=NOW)
        assert _run(proof, rotated("2026-06-02T00:00:00Z"), resolve=resolve).ok
        assert _run(proof, rotated("2026-06-02T00:00:00Z"), resolve=resolve).reasons == ["did_document_stale"]


class TestTheLastSeenSequence:
    def test_a_shared_guard_refuses_a_lower_sequence_another_resolver_saw(self) -> None:
        guard = RotationSequenceGuard()
        a = create_did_resolver(fetch_json=lambda url: rotated("2026-06-02T00:00:00Z", sequence=4), sequence_guard=guard)
        b = create_did_resolver(fetch_json=lambda url: rotated("2026-06-02T00:00:00Z", sequence=3), sequence_guard=guard)
        assert a(DID)["rotationSequence"] == 4  # type: ignore[index]
        with pytest.raises(StaleDidDocumentError) as stale:
            b(DID)
        assert (stale.value.reason, stale.value.sequence, stale.value.last_seen) == (DID_DOCUMENT_STALE, 3, 4)
        assert "carries no rotationSequence" in str(guard.check(DID, {}))
        assert guard.check("did:web:other.example", {}) is None
        assert guarded_resolver(lambda did: None)(DID) is None
        stale_resolve = guarded_resolver(lambda did: {"rotationSequence": 1}, guard)
        with pytest.raises(StaleDidDocumentError):
            stale_resolve(DID)

    def test_the_memory_store_keeps_the_highest_and_drops_the_oldest(self) -> None:
        store = MemoryRotationSequenceStore(2)
        store.raise_to("a", 2)
        store.raise_to("a", 1)
        assert store.get("a") == 2
        store.raise_to("b", 1)
        store.raise_to("c", 1)
        assert store.get("a") is None and store.get("c") == 1
        for value in (0, -1, 1.5, "3", None, True):
            assert rotation_sequence_of({"rotationSequence": value}) is None
        assert rotation_sequence_of(None) is None


class TestTheJwksProjection:
    def test_projects_and_reads_under_the_same_guard(self) -> None:
        guard = RotationSequenceGuard()
        document = rotated("2026-06-02T00:00:00Z", "2026-06-01T11:00:00Z", 5)
        document["verificationMethod"].append({"id": "#x", "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": "a"}})
        document["verificationMethod"].append({"id": "#key-3", "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": _x(NEW_SEED)}, "validFrom": "2026-06-01T00:00:00Z"})
        jwks = project_jwks(document)
        assert jwks["rotationSequence"] == 5 and jwks["updated"] == "2026-06-01T10:00:00Z"
        assert [key["kid"] for key in jwks["keys"]] == [f"{DID}#key-2", f"{DID}#key-1", f"{DID}#key-3"]
        assert jwks["keys"][1]["revoked"] == "2026-06-01T11:00:00Z" and jwks["keys"][2]["validFrom"] == "2026-06-01T00:00:00Z"
        foreign = {**jwks, "keys": [*jwks["keys"], {**jwks["keys"][0], "kid": "did:web:evil#key-1"}, "junk"]}
        assert [key["kid"] for key in read_jwks(DID, foreign, guard)] == [f"{DID}#key-2", f"{DID}#key-1", f"{DID}#key-3"]
        with pytest.raises(StaleDidDocumentError, match="lower than 5"):
            read_jwks(DID, {**jwks, "rotationSequence": 4}, guard)
        with pytest.raises(ValueError, match="not a JWK Set"):
            read_jwks(DID, {}, guard)
        assert project_jwks({"id": DID}) == {"keys": []}
