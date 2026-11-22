# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story F-1: the credential split in Python.

Two layers:
  1. unit tests of helix_sdk.credentials and helix_sdk.credential_store on
     their own (builders, verifiers, the chain evaluator, scopes, card level,
     the store and the owner-signed attestation path);
  2. the cross-language fixture helix-core generated
     (fixtures/kya-os-helix/credentials.json): every credential must verify
     here, the owner-signed attestation must sign to the same bytes, every
     chain must come to the recorded verdict, every scope and card-level case
     must match, and every schema rejection must be refused at the same path.

Layer 2 reads the sibling helix-core checkout (../helix-core/fixtures) or the
directory HELIX_CORE_FIXTURES_DIR names, and skips when neither exists.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

import helix_sdk
from helix_sdk import (
    CAPABILITY_ATTESTATION_TYPE,
    DELEGATION_CREDENTIAL_TYPE,
    IDENTITY_CREDENTIAL_TYPE,
    CapabilityAttestation,
    CredentialStore,
    PresentedChain,
    SignAttestationsOptions,
    StoredCredential,
    sign_attestation_document,
)
from helix_sdk.credentials import (
    CAPABILITY_ATTESTATION_SCHEMA,
    DELEGATION_HOP_SCHEMA,
    IDENTITY_CREDENTIAL_SCHEMA,
    JsonSchemaError,
    ProofReasons,
    assert_supported_schema,
    attested_capabilities,
    attested_capability_entry,
    build_capability_attestation,
    build_delegation_hop,
    build_identity_credential,
    build_identity_verification_credential,
    capability_name,
    caveat_narrows,
    check_capabilities,
    clock_skew_ms,
    decimal_lte,
    derive_conformance_level,
    derive_effective_scopes,
    describe_violations,
    evaluate_delegation_chain,
    hash_data,
    is_revoked_in,
    is_trusted_issuer,
    issuer_of,
    parse_date_time,
    sign_data_integrity,
    validate_credential,
    validate_json_schema,
    verify_capability_attestation,
    verify_data_integrity,
    verify_delegation_chain_proofs,
    verify_delegation_hop,
    verify_identity_credential,
    verify_identity_verification_credential,
    window_verdict,
)
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.did import build_did_document
from helix_sdk.keys import derive_public_key, public_key_to_multibase

NOW = parse_date_time("2026-06-01T00:00:00Z")
RESOURCE = "did:web:service.example:orders"
LIST_URL = "https://helix.example/v1/status-list/1"


class Actor:
    def __init__(self, seed: str) -> None:
        self.key = (seed * 64)[:64]
        self.did = f"did:key:{public_key_to_multibase(derive_public_key(self.key))}"
        self.signer = EnvSigner(self.did, env_var="K", env={"K": self.key})
        self.document = build_did_document(self.did, derive_public_key(self.key))


HELIX, OWNER, USER, PARENT, AGENT, STRANGER = (Actor(seed) for seed in "123456")
DOCUMENTS = {a.did: a.document for a in (HELIX, OWNER, USER, PARENT, AGENT, STRANGER)}


def resolve(did: str) -> Any:
    return DOCUMENTS.get(did)


def entry(index: int) -> Dict[str, Any]:
    return {"type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": str(index), "statusListCredential": LIST_URL}


def _status_list(revoked: set) -> str:
    import base64
    import gzip

    bits = bytearray(32)
    for index in revoked:
        bits[index // 8] |= 1 << (7 - index % 8)
    return base64.urlsafe_b64encode(gzip.compress(bytes(bits), mtime=0)).decode().rstrip("=")


# ── 1. unit ────────────────────────────────────────────────────────────────────


class TestDates:
    def test_parse_date_time_requires_an_offset(self) -> None:
        assert parse_date_time("2026-01-01T00:00:00Z") == 1767225600000
        assert parse_date_time("2026-01-01T02:00:00.250+02:00") == 1767225600250
        assert parse_date_time("2026-01-01t00:00:00z") == 1767225600000
        assert parse_date_time("2026-01-01T00:00:00") is None
        assert parse_date_time("2026-13-01T00:00:00Z") is None
        assert parse_date_time(1) is None

    def test_window_verdict_and_clock_skew(self) -> None:
        assert window_verdict("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", NOW) == "inside"
        assert window_verdict(None, "2026-05-31T23:59:00Z", NOW) == "inside"
        assert window_verdict(None, "2026-05-31T23:57:00Z", NOW) == "expired"
        assert window_verdict("2026-06-01T00:03:00Z", None, NOW) == "not_yet_valid"
        assert window_verdict("2026-06-01T00:00:30Z", None, NOW, 0) == "not_yet_valid"
        assert window_verdict("2026-01-01T00:00:00", None, NOW) == "malformed"
        assert window_verdict(None, "soon", NOW) == "malformed"
        assert window_verdict(None, None, NOW, -1) == "skew_invalid"
        assert clock_skew_ms(None) == 120_000
        assert clock_skew_ms(600_000) == 600_000
        assert clock_skew_ms(600_001) is None
        assert clock_skew_ms("120") is None
        assert clock_skew_ms(True) is None


class TestJsonSchema:
    @staticmethod
    def v(schema: Dict[str, Any], value: Any) -> List[str]:
        return [f"{e.path}: {e.message}" for e in validate_json_schema(schema, value)]

    def test_types_const_enum_strings(self) -> None:
        v = self.v
        assert v({"type": "integer"}, 1) == []
        assert v({"type": "integer"}, 1.5) == ["$: expected type integer, got number"]
        assert v({"type": "number"}, 1) == []
        assert v({"type": ["string", "null"]}, None) == []
        assert v({"type": "boolean"}, True) == []
        assert v({"type": "integer"}, True) == ["$: expected type integer, got boolean"]
        assert v({"type": "object"}, object()) == ["$: expected type object, got unknown"]
        assert v({"const": "a"}, "b") == ['$: expected the constant "a"']
        assert v({"enum": ["a"]}, "c") == ['$: expected one of ["a"]']
        assert v({"minLength": 2}, "a") == ["$: expected at least 2 characters"]
        assert v({"pattern": "^did:"}, "nope") == ["$: does not match pattern ^did:"]
        assert v({"format": "date-time"}, "2026-01-01T00:00:00") == ["$: is not an RFC 3339 date-time with offset"]

    def test_arrays_objects_and_combinators(self) -> None:
        v = self.v
        array = {"type": "array", "minItems": 2, "items": {"type": "string"}, "contains": {"const": "b"}}
        assert v(array, ["a", "b"]) == []
        assert v(array, ["a"]) == ["$: expected at least 2 items", '$: no item satisfies {"const": "b"}']
        assert v(array, ["b", 1]) == ["$[1]: expected type string, got integer"]
        closed = {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}, "additionalProperties": False}
        assert v(closed, {"b": 1}) == ['$: missing required member "a"', "$.b: unknown member is not allowed"]
        opened = {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": {"type": "number"}}
        assert v(opened, {"b": "y"}) == ["$.b: expected type number, got string"]
        assert v({"allOf": [{"type": "string"}, {"minLength": 2}]}, "a") == ["$: expected at least 2 characters"]
        assert v({"anyOf": [{"type": "string"}, {"type": "number"}]}, True) == ["$: matches none of the anyOf alternatives"]
        assert v({"oneOf": [{"type": "string"}, {"minLength": 1}]}, "a") == ["$: matches 2 oneOf alternatives, expected exactly one"]
        ref = {"$defs": {"Did": {"pattern": "^did:"}}, "properties": {"id": {"$ref": "#/$defs/Did"}}}
        assert v(ref, {"id": "x"}) == ["$.id: does not match pattern ^did:"]

    def test_refuses_unsupported_keywords_and_bad_refs(self) -> None:
        with pytest.raises(JsonSchemaError, match="maximum"):
            assert_supported_schema({"maximum": 1})
        with pytest.raises(JsonSchemaError, match="#/properties/a"):
            assert_supported_schema({"properties": {"a": {"maximum": 1}}})
        with pytest.raises(JsonSchemaError, match="#/allOf/1"):
            assert_supported_schema({"allOf": [{}, {"if": {}}]})
        with pytest.raises(JsonSchemaError, match="#/items"):
            assert_supported_schema({"items": {"not": {}}})
        assert_supported_schema({"properties": None, "items": True, "allOf": "x"})
        with pytest.raises(JsonSchemaError, match="local"):
            validate_json_schema({"properties": {"id": {"$ref": "https://x"}}}, {"id": 1})
        with pytest.raises(JsonSchemaError, match="does not resolve"):
            validate_json_schema({"properties": {"id": {"$ref": "#/$defs/Missing"}}}, {"id": 1})
        with pytest.raises(JsonSchemaError, match="does not resolve"):
            validate_json_schema({"$defs": {"D": "x"}, "properties": {"id": {"$ref": "#/$defs/D/x"}}}, {"id": 1})
        for schema in (IDENTITY_CREDENTIAL_SCHEMA, CAPABILITY_ATTESTATION_SCHEMA, DELEGATION_HOP_SCHEMA):
            assert_supported_schema(schema)


class TestDataIntegrity:
    document = {"@context": ["https://www.w3.org/ns/credentials/v2"], "id": "urn:uuid:1", "type": ["VerifiableCredential"], "issuer": HELIX.did, "credentialSubject": {"id": "did:key:z6MkS"}}

    def test_sign_and_verify(self) -> None:
        signed = sign_data_integrity(self.document, HELIX.signer, "2026-01-01T00:00:00Z")
        assert signed["proof"]["verificationMethod"] == f"{HELIX.did}#key-1"
        assert signed["proof"]["proofValue"].startswith("z")
        assert len(hash_data({}, {})) == 64
        verdict = verify_data_integrity(signed, resolve)
        assert verdict.ok and verdict.details == {"issuer": HELIX.did, "verificationMethod": f"{HELIX.did}#key-1"}
        assert verify_data_integrity(sign_data_integrity({**self.document, "issuer": {"id": HELIX.did}}, HELIX.signer), resolve).ok
        bare = {k: v for k, v in self.document.items() if k != "@context"}
        assert verify_data_integrity(sign_data_integrity(bare, HELIX.signer), resolve).ok
        assert issuer_of({"id": "did:x"}) == "did:x" and issuer_of("https://x") is None and issuer_of(None) is None

    def test_sign_refusals(self) -> None:
        signed = sign_data_integrity(self.document, HELIX.signer)
        with pytest.raises(ValueError, match="already carries"):
            sign_data_integrity(signed, HELIX.signer)
        with pytest.raises(ValueError, match="is not the issuer"):
            sign_data_integrity({**self.document, "issuer": OWNER.did}, HELIX.signer)

        class Odd:
            did = HELIX.did
            kid = "a#b"

            def sign(self, data: bytes) -> bytes:
                return b""

        with pytest.raises(ValueError, match="fragment"):
            sign_data_integrity(self.document, Odd())  # type: ignore[arg-type]

        class Short:
            did = HELIX.did
            kid = "key-1"

            def sign(self, data: bytes) -> bytes:
                return b"short"

        with pytest.raises(ValueError, match="64-byte"):
            sign_data_integrity(self.document, Short())  # type: ignore[arg-type]

    def test_verify_refusals(self) -> None:
        signed = sign_data_integrity(self.document, HELIX.signer)
        proof = signed["proof"]

        def refusal(doc: Any, resolver: Any = resolve) -> str:
            verdict = verify_data_integrity(doc, resolver)
            assert not verdict.ok
            return verdict.reason or ""

        assert refusal(self.document) == ProofReasons.PROOF_MISSING
        assert refusal({**signed, "proof": {**proof, "type": "Ed25519Signature2020"}}) == ProofReasons.PROOF_UNSUPPORTED
        assert refusal({**signed, "proof": {**proof, "proofPurpose": "authentication"}}) == ProofReasons.PROOF_PURPOSE_MISMATCH
        assert refusal({**signed, "proof": {**proof, "proofValue": "u" + "A" * 86}}) == ProofReasons.PROOF_VALUE_MALFORMED
        assert refusal({**signed, "proof": {**proof, "proofValue": "z0OIl"}}) == ProofReasons.PROOF_VALUE_MALFORMED
        assert refusal({**signed, "proof": {**proof, "proofValue": "z2"}}) == ProofReasons.PROOF_VALUE_MALFORMED
        assert refusal({**signed, "proof": {**proof, "verificationMethod": 7}}) == ProofReasons.PROOF_METHOD_MALFORMED
        assert refusal({**signed, "proof": {**proof, "verificationMethod": f"{OWNER.did}#key-1"}}) == ProofReasons.PROOF_ISSUER_MISMATCH
        assert refusal({**signed, "proof": {**proof, "@context": ["https://elsewhere"]}}) == ProofReasons.PROOF_CONTEXT_MISMATCH
        assert verify_data_integrity({**signed, "proof": {**proof, "@context": ["https://www.w3.org/ns/credentials/v2"]}}, resolve).ok
        assert refusal(signed, lambda did: None) == ProofReasons.DID_UNRESOLVED

        def boom(did: str) -> Any:
            raise RuntimeError("offline")

        assert refusal(signed, boom) == ProofReasons.DID_UNRESOLVED
        assert refusal(signed, lambda did: {**DOCUMENTS[HELIX.did], "assertionMethod": []}) == ProofReasons.KEY_REJECTED
        assert refusal({**signed, "credentialSubject": {"id": "did:key:z6MkOther"}}) == ProofReasons.SIGNATURE_INVALID
        assert refusal({**signed, "extra": float("nan")}) == ProofReasons.DOCUMENT_NOT_CANONICAL


class TestBuildersAndVerifiers:
    def test_identity(self) -> None:
        identity = build_identity_credential(HELIX.signer, AGENT.did, "orders-agent", OWNER.did, entry(1), id="urn:uuid:x", valid_from="2026-01-01T00:00:00Z", valid_until="2027-01-01T00:00:00Z", proof_created="2026-01-01T00:00:00Z")
        assert identity["credentialSubject"] == {"id": AGENT.did, "name": "orders-agent", "responsibleParty": OWNER.did}
        assert identity["type"] == ["VerifiableCredential", "AgentIdentityCredential"]
        verdict = verify_identity_credential(identity, resolve, agent_did=AGENT.did, now_ms=NOW)
        assert verdict.ok and verdict.details["responsibleParty"] == OWNER.did
        assert verify_identity_credential(build_identity_credential(HELIX.signer, AGENT.did, "a", OWNER.did, entry(1)), resolve).ok
        assert verify_identity_credential({**identity, "credentialSubject": {**identity["credentialSubject"], "scopes": []}}, resolve, now_ms=NOW).reason == "schema_invalid"
        assert verify_identity_credential(identity, resolve, agent_did=STRANGER.did, now_ms=NOW).reason == "subject_mismatch"
        assert verify_identity_credential(identity, resolve, now_ms=parse_date_time("2028-01-01T00:00:00Z")).reason == "credential_expired"
        assert verify_identity_credential({**identity, "issuer": STRANGER.did}, resolve, now_ms=NOW).reason == ProofReasons.PROOF_ISSUER_MISMATCH
        with pytest.raises(ValueError, match="agent_did"):
            build_identity_credential(HELIX.signer, "x", "a", OWNER.did, entry(1))
        with pytest.raises(ValueError, match="owner_did"):
            build_identity_credential(HELIX.signer, AGENT.did, "a", "x", entry(1))
        with pytest.raises(ValueError, match="name"):
            build_identity_credential(HELIX.signer, AGENT.did, " ", OWNER.did, entry(1))

    def test_identity_verification(self) -> None:
        kyb = build_identity_verification_credential(HELIX.signer, OWNER.did, "organization", "enhanced", "2027-01-01T00:00:00Z", entry(2), provider="kyb.example", id="urn:uuid:v", valid_from="2026-01-01T00:00:00Z", proof_created="2026-01-01T00:00:00Z")
        assert kyb["credentialSubject"] == {"id": OWNER.did, "subjectType": "organization", "verificationLevel": "enhanced", "provider": "kyb.example"}
        assert verify_identity_verification_credential(kyb, resolve, subject_did=OWNER.did, now_ms=NOW).details["verificationLevel"] == "enhanced"
        bare = build_identity_verification_credential(HELIX.signer, OWNER.did, "individual", "basic", "2027-01-01T00:00:00Z", entry(2))
        assert "provider" not in bare["credentialSubject"] and verify_identity_verification_credential(bare, resolve).ok
        assert verify_identity_verification_credential(None, resolve).reason == "schema_invalid"
        assert verify_identity_verification_credential({**kyb, "type": ["VerifiableCredential"]}, resolve).reason == "schema_invalid"
        assert verify_identity_verification_credential(kyb, resolve, subject_did=AGENT.did).reason == "subject_mismatch"
        assert verify_identity_verification_credential(kyb, resolve, now_ms=parse_date_time("2028-01-01T00:00:00Z")).reason == "credential_expired"
        assert verify_identity_verification_credential({**kyb, "issuer": STRANGER.did}, resolve).reason == ProofReasons.PROOF_ISSUER_MISMATCH
        with pytest.raises(ValueError, match="verification_level"):
            build_identity_verification_credential(HELIX.signer, OWNER.did, "organization", "gold", "x", entry(2))
        with pytest.raises(ValueError, match="subject_type"):
            build_identity_verification_credential(HELIX.signer, OWNER.did, "robot", "basic", "x", entry(2))
        with pytest.raises(ValueError, match="subject_did"):
            build_identity_verification_credential(HELIX.signer, "x", "individual", "basic", "x", entry(2))

    def test_attestation(self) -> None:
        attestation = build_capability_attestation(OWNER.signer, AGENT.did, "read:orders", "2026-12-31T00:00:00Z", entry(3), valid_from="2026-01-01T00:00:00Z", id="urn:uuid:a", proof_created="2026-01-01T00:00:00Z")
        assert attestation["credentialSubject"] == {"id": AGENT.did, "capability": "read:orders"}
        ok = verify_capability_attestation(attestation, resolve, subject_did=AGENT.did, capability="read:orders", now_ms=NOW)
        assert ok.ok and ok.details == {"capability": "read:orders", "issuer": OWNER.did}
        assert verify_capability_attestation(build_capability_attestation(HELIX.signer, AGENT.did, "x", "2027-01-01T00:00:00Z", entry(3)), resolve).ok

        def at(**kw: Any) -> Any:
            kw.setdefault("now_ms", NOW)
            return verify_capability_attestation(attestation, resolve, **kw)

        assert verify_capability_attestation({k: v for k, v in attestation.items() if k != "validUntil"}, resolve).reason == "schema_invalid"
        assert at(subject_did=STRANGER.did).reason == "subject_mismatch"
        assert at(capability="write:orders").reason == "capability_mismatch"
        assert at(trusted_issuers=[HELIX.did]).reason == "issuer_untrusted"
        assert at(trusted_issuers=[HELIX.did, OWNER.did]).ok
        assert at(now_ms=parse_date_time("2027-06-01T00:00:00Z")).reason == "credential_expired"
        assert verify_capability_attestation({**attestation, "issuer": HELIX.did}, resolve, now_ms=NOW).reason == ProofReasons.PROOF_ISSUER_MISMATCH
        assert at(status_list={"credentialSubject": {"encodedList": _status_list({3})}}).reason == "credential_revoked"
        assert at(status_list={"credentialSubject": {"encodedList": _status_list(set())}}).ok
        with pytest.raises(ValueError, match="capability"):
            build_capability_attestation(OWNER.signer, AGENT.did, "read orders", "x", entry(3))
        with pytest.raises(ValueError, match="valid_until"):
            build_capability_attestation(OWNER.signer, AGENT.did, "read:orders", None, entry(3))  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="subject_did"):
            build_capability_attestation(OWNER.signer, "x", "read:orders", "x", entry(3))

    def test_trusted_issuers_and_revocation_bits(self) -> None:
        assert is_trusted_issuer("did:web:a", "*") and is_trusted_issuer("did:web:a", ["did:web:a"])
        assert not is_trusted_issuer("did:web:a", []) and not is_trusted_issuer("did:web:a", "did:web:a") and not is_trusted_issuer("did:web:a", 7)  # type: ignore[arg-type]
        lst = _status_list({5})
        assert is_revoked_in(entry(5), lst) and not is_revoked_in(entry(6), lst)
        assert is_revoked_in({**entry(6), "statusListIndex": "six"}, lst)
        assert is_revoked_in(entry(-1), lst) and is_revoked_in(entry(99999), lst) and is_revoked_in(entry(1), "not-a-list")

    def test_hop(self) -> None:
        hop = build_delegation_hop(OWNER.signer, AGENT.did, RESOURCE, RESOURCE, ["read:orders"], "2027-01-01T00:00:00Z", entry(7), caveats=[{"type": "MaxAmount", "limit": "10", "currency": "USD"}], valid_from="2026-01-01T00:00:00Z", id="urn:zcap:root", proof_created="2026-01-01T00:00:00Z")
        assert hop["id"] == "urn:zcap:root" and hop["credentialSubject"]["id"] == "urn:zcap:root"
        assert hop["@context"] == ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/zcap/v1", "https://kya-os.org/ns/delegation/v1"]
        verdict = verify_delegation_hop(hop, resolve)
        assert verdict.ok and verdict.details == {"issuer": OWNER.did, "invoker": AGENT.did}
        bare = build_delegation_hop(OWNER.signer, AGENT.did, RESOURCE, RESOURCE, [], "2027-01-01T00:00:00Z", entry(7))
        assert "caveats" not in bare["credentialSubject"] and "validFrom" not in bare
        assert verify_delegation_hop({**hop, "credentialSubject": {**hop["credentialSubject"], "scopes": []}}, resolve).reason == "schema_invalid"
        assert verify_delegation_hop({**hop, "credentialSubject": {**hop["credentialSubject"], "allowedAction": ["admin"]}}, resolve).reason == ProofReasons.SIGNATURE_INVALID
        assert verify_delegation_chain_proofs([hop], resolve).ok
        refused = verify_delegation_chain_proofs([hop, {**hop, "issuer": STRANGER.did}], resolve)
        assert not refused.ok and refused.reason == "proof_invalid" and (refused.message or "").startswith("hop 1:")
        base = {"invoker": AGENT.did, "parent_capability": RESOURCE, "invocation_target": RESOURCE, "allowed_action": ["read:orders"], "valid_until": "2027-01-01T00:00:00Z"}
        for kwargs, pattern in (
            ({"invoker": "x"}, "invoker"),
            ({"parent_capability": ""}, "parent_capability"),
            ({"invocation_target": ""}, "invocation_target"),
            ({"allowed_action": ["", "x"]}, "allowed_action"),
            ({"valid_until": None}, "valid_until"),
        ):
            args = {**base, **kwargs}
            with pytest.raises(ValueError, match=pattern):
                build_delegation_hop(OWNER.signer, args["invoker"], args["parent_capability"], args["invocation_target"], args["allowed_action"], args["valid_until"], entry(7))  # type: ignore[arg-type]


def _chain() -> List[Dict[str, Any]]:
    root = build_delegation_hop(USER.signer, PARENT.did, RESOURCE, RESOURCE, ["read:orders", "write:orders"], "2027-01-01T00:00:00Z", entry(1), caveats=[{"type": "MaxAmount", "limit": "100", "currency": "USD"}], valid_from="2026-01-01T00:00:00Z", id="urn:zcap:root")
    leaf = build_delegation_hop(PARENT.signer, AGENT.did, "urn:zcap:root", RESOURCE, ["read:orders"], "2026-12-01T00:00:00Z", entry(2), caveats=[{"type": "MaxAmount", "limit": "50", "currency": "USD"}], id="urn:zcap:leaf")
    return [root, leaf]


class TestChain:
    def test_valid_chain_reports_the_join(self) -> None:
        hops = _chain()
        evaluation = evaluate_delegation_chain(hops, resource=RESOURCE, now_ms=NOW)
        assert evaluation.ok and evaluation.reasons == [] and evaluation.code is None
        assert evaluation.responsible_party == USER.did and evaluation.leaf_invoker == AGENT.did
        assert evaluation.invocation_target == RESOURCE and evaluation.allowed_action == ["read:orders"] and evaluation.depth == 2
        assert evaluate_delegation_chain(hops, resource_owner=USER.did, now_ms=NOW).ok
        assert evaluate_delegation_chain(hops).ok

    def test_bounded_before_parsing(self) -> None:
        junk = ["not a hop"] * 11
        refused = evaluate_delegation_chain(junk, now_ms=NOW)
        assert refused.code == "chain_invalid" and refused.depth == 11 and refused.allowed_action == []
        assert refused.reasons == ["delegation chain depth 11 exceeds the maximum of 10"]
        assert evaluate_delegation_chain(["x", "y"], max_chain_length=1, now_ms=NOW).code == "chain_invalid"
        assert evaluate_delegation_chain(["x"], max_chain_length=0, now_ms=NOW).code == "configuration_error"
        assert evaluate_delegation_chain(["x"], max_chain_length=True, now_ms=NOW).code == "configuration_error"
        assert evaluate_delegation_chain(["x"], max_clock_skew_ms=-1, now_ms=NOW).code == "configuration_error"
        assert evaluate_delegation_chain([], now_ms=NOW).reasons == ["empty delegation chain"]
        assert evaluate_delegation_chain("nope", now_ms=NOW).code == "chain_invalid"

    def test_malformed_and_broken_hops(self) -> None:
        root, leaf = _chain()
        malformed = evaluate_delegation_chain([root, {**leaf, "credentialSubject": {**leaf["credentialSubject"], "scopes": ["x"]}}], now_ms=NOW)
        assert malformed.code == "delegation_malformed" and malformed.reasons[0].startswith("hop 1: $.credentialSubject.scopes") and malformed.responsible_party is None
        subject = leaf["credentialSubject"]

        def at(hops: Any, **kw: Any) -> Any:
            kw.setdefault("resource", RESOURCE)
            return evaluate_delegation_chain(hops, now_ms=NOW, **kw)

        assert at([root, {**leaf, "credentialSubject": {**subject, "allowedAction": ["read:orders", "admin:all"]}}]).reasons == ["hop 1: allowedAction escalation: [admin:all] not in parent"]
        assert at([root, {**leaf, "credentialSubject": {**subject, "caveats": []}}]).reasons == ['hop 1: caveat "MaxAmount" broadened or dropped by child']
        assert at([root, {**leaf, "validUntil": "2027-06-01T00:00:00Z"}]).reasons == ["hop 1: validUntil broadened: child must expire no later than its parent"]
        assert at([root, {**leaf, "issuer": AGENT.did}]).reasons == ["hop 1: broken continuity: parent invoker is not the child issuer"]
        assert at([root, {**leaf, "credentialSubject": {**subject, "parentCapability": "urn:zcap:other"}}]).reasons == ["hop 1: broken continuity: child parentCapability is not the parent capability id"]
        assert at([root, {**leaf, "credentialSubject": {**subject, "invocationTarget": "did:web:other"}}]).reasons == ["hop 1: invocationTarget drift: the resource must be constant along the chain"]
        assert at([{**root, "credentialSubject": {**root["credentialSubject"], "parentCapability": "urn:zcap:x"}}]).reasons == ["root delegation: parentCapability must equal invocationTarget"]
        assert at([root], resource="did:web:other").reasons == ["root invocationTarget is not the expected resource"]
        assert at([root], resource_owner=PARENT.did).code == "untrusted_root"
        no_invoker = {**root, "credentialSubject": {k: v for k, v in root["credentialSubject"].items() if k != "invoker"}}
        assert at([no_invoker, leaf]).code == "delegation_malformed"
        controlled = {**no_invoker, "credentialSubject": {**no_invoker["credentialSubject"], "controller": PARENT.did}}
        assert at([controlled, leaf]).reasons == []

    def test_windows(self) -> None:
        root, leaf = _chain()

        def at(now: str, hops: Any = None, **kw: Any) -> Any:
            return evaluate_delegation_chain(hops or [root, leaf], now_ms=parse_date_time(now), **kw)

        assert at("2026-12-01T00:01:59Z").ok
        expired = at("2026-12-01T00:02:01Z")
        assert expired.code == "delegation_expired" and expired.reasons == ["hop 1: expired (validUntil 2026-12-01T00:00:00Z is in the past)"]
        assert at("2025-12-31T23:57:59Z").code == "delegation_not_yet_valid"
        assert at("2026-12-01T00:00:30Z", max_clock_skew_ms=0).code == "delegation_expired"
        with_caveat = {**leaf, "credentialSubject": {**leaf["credentialSubject"], "caveats": [{"type": "MaxAmount", "limit": "50", "currency": "USD"}, {"type": "ValidUntil", "date": "2026-03-01T00:00:00Z"}]}}
        assert at("2026-06-01T00:00:00Z", [root, with_caveat]).reasons == ["hop 1: expired caveat (ValidUntil 2026-03-01T00:00:00Z is in the past)"]
        bad_caveat = {**leaf, "credentialSubject": {**leaf["credentialSubject"], "caveats": [{"type": "MaxAmount", "limit": "50", "currency": "USD"}, {"type": "ValidUntil", "date": "soon"}]}}
        assert at("2026-06-01T00:00:00Z", [root, bad_caveat]).code == "delegation_malformed"
        assert at("2026-06-01T00:00:00Z", [root, {**leaf, "validFrom": "2026-01-01T00:00:00"}]).code == "delegation_malformed"
        dateless = {**leaf, "credentialSubject": {**leaf["credentialSubject"], "caveats": [{"type": "MaxAmount", "limit": "50", "currency": "USD"}, {"type": "ValidUntil"}]}}
        assert at("2026-06-01T00:00:00Z", [root, dateless]).ok

    def test_helpers(self) -> None:
        assert decimal_lte("100", "100") and decimal_lte("99.999999999", "100") and decimal_lte(" 5 ", "5.0")
        assert not decimal_lte("100.0000009", "100") and not decimal_lte("1e2", "100") and not decimal_lte("100", "-1") and not decimal_lte(5, "5")
        assert caveat_narrows({"type": "ValidUntil", "date": "2027-01-01T00:00:00Z"}, {"type": "ValidUntil", "date": "2026-01-01T00:00:00Z"})
        assert not caveat_narrows({"type": "ValidUntil"}, {"type": "ValidUntil", "date": "2027-01-01T00:00:00Z"})
        assert not caveat_narrows({"type": "ValidUntil", "date": "x"}, {"type": "MaxAmount"})
        assert caveat_narrows({"type": "MaxAmount", "limit": "10"}, {"type": "MaxAmount", "limit": "5", "currency": "USD"})
        assert not caveat_narrows({"type": "MaxAmount", "limit": "10", "currency": "USD"}, {"type": "MaxAmount", "limit": "5", "currency": "EUR"})
        assert not caveat_narrows({"type": "MaxAmount", "currency": "USD"}, {"type": "MaxAmount", "limit": "5", "currency": "USD"})
        assert caveat_narrows({"type": "Region", "regions": ["EU"]}, {"type": "Region", "regions": ["EU"]})
        assert not caveat_narrows({"type": "Region", "regions": ["EU"]}, {"type": "Region", "regions": ["EU", "US"]})


class TestScopesAndCard:
    def test_effective_scopes(self) -> None:
        assert derive_effective_scopes(["read:orders", "write:orders", "read:catalog"], ["read:orders", "read:catalog"], ["read:catalog", "read:orders"]) == ["read:orders", "read:catalog"]
        assert derive_effective_scopes(["read:orders"], [], ["read:orders"]) == []
        assert derive_effective_scopes(["a", "a", "b"], ["a", "b"], ["a", "b"]) == ["a", "b"]
        assert attested_capabilities([{"credentialSubject": {"capability": "x"}}, "x", "y"]) == ["x", "y"]

    def test_card_level(self) -> None:
        assert derive_conformance_level({"verified": [], "unverified": []}) == "L1"
        assert derive_conformance_level({"verified": ["a"], "unverified": ["b"]}) == "L1"
        assert derive_conformance_level({"verified": ["a"], "unverified": []}) == "L2"
        assert derive_conformance_level({"verified": ["a"], "unverified": []}, True) == "L3"
        assert derive_conformance_level({"verified": ["a"], "unverified": []}, True, False) == "L2"
        read = build_capability_attestation(HELIX.signer, AGENT.did, "read:orders", "2026-12-31T00:00:00Z", entry(11), valid_from="2026-01-01T00:00:00Z")
        write = build_capability_attestation(OWNER.signer, AGENT.did, "write:orders", "2026-12-31T00:00:00Z", entry(12), valid_from="2026-01-01T00:00:00Z")
        expired = build_capability_attestation(HELIX.signer, AGENT.did, "write:orders", "2026-02-01T00:00:00Z", entry(13), valid_from="2026-01-01T00:00:00Z")
        capabilities = [attested_capability_entry("read:orders", [read]), attested_capability_entry("write:orders", [expired, write]), "handshake"]
        assert [capability_name(c) for c in capabilities] == ["read:orders", "write:orders", "handshake"]
        check = check_capabilities(capabilities, resolve, subject_did=AGENT.did, now_ms=NOW)
        assert check == {"verified": ["read:orders", "write:orders"], "unverified": ["handshake"]}
        assert check_capabilities(capabilities[:2], resolve, subject_did=AGENT.did, now_ms=NOW, trusted_issuers=[HELIX.did]) == {"verified": ["read:orders"], "unverified": ["write:orders"]}
        lists = {LIST_URL: {"credentialSubject": {"encodedList": _status_list({11})}}}
        assert check_capabilities(capabilities[:2], resolve, subject_did=AGENT.did, now_ms=NOW, status_lists=lists) == {"verified": ["write:orders"], "unverified": ["read:orders"]}
        assert check_capabilities([{"name": "x", "attestations": [{"vc": "jwt"}, {"vc": None}]}], resolve, subject_did=AGENT.did) == {"verified": [], "unverified": ["x"]}


class TestCredentialStore:
    identity = {"id": "urn:uuid:identity", "type": ["VerifiableCredential", "AgentIdentityCredential"], "issuer": HELIX.did, "credentialSubject": {"id": AGENT.did, "name": "agent", "responsibleParty": OWNER.did}}

    @staticmethod
    def hop(hop_id: str, invoker: str, parent: str, issuer: str = "did:key:z6MkParent", target: str = RESOURCE) -> Dict[str, Any]:
        return {"id": hop_id, "type": ["VerifiableCredential", "DelegationCredential"], "issuer": issuer, "validUntil": "2027-01-01T00:00:00Z", "credentialSubject": {"id": hop_id, "invoker": invoker, "parentCapability": parent, "invocationTarget": target, "allowedAction": ["read:orders"]}}

    @staticmethod
    def attestation(att_id: str, capability: str) -> Dict[str, Any]:
        return {"id": att_id, "type": ["VerifiableCredential", "CapabilityAttestationCredential"], "issuer": OWNER.did, "credentialSubject": {"id": AGENT.did, "capability": capability}}

    def test_holds_routes_and_round_trips(self) -> None:
        store = CredentialStore()
        assert store.identity is None and store.agent_did is None
        store.add(self.identity).add(self.attestation("a1", "read:orders")).add(self.hop("urn:zcap:root", AGENT.did, RESOURCE))
        assert store.agent_did == AGENT.did and len(store.attestations) == 1 and len(store.hops) == 1
        with pytest.raises(ValueError, match="not an identity"):
            store.add({"type": ["VerifiableCredential", "HelixAgentCredential"]})
        with pytest.raises(ValueError, match="AgentIdentityCredential"):
            store.set_identity(self.attestation("a", "x"))
        with pytest.raises(ValueError, match="CapabilityAttestationCredential"):
            store.add_attestation(self.identity)
        with pytest.raises(ValueError, match="DelegationCredential"):
            store.add_hop(self.identity)
        assert CredentialStore.from_json(store.to_json()).to_dict() == store.to_dict()
        assert CredentialStore.from_json(store.to_dict()).hops == store.hops
        assert CredentialStore.from_onboarding({"identity": self.identity, "attestations": [self.attestation("a1", "read:orders")]}).attested_capabilities() == ["read:orders"]
        assert CredentialStore.from_onboarding({"identity": self.identity}).attestations == []
        assert CredentialStore({**self.identity, "credentialSubject": {"name": "no id"}}).agent_did is None

    def test_replace_and_remove(self) -> None:
        store = CredentialStore(self.identity)
        store.add_attestation(self.attestation("a1", "read:orders")).add_attestation(self.attestation("a2", "read:orders")).add_attestation(self.attestation("a3", "write:orders"))
        store.add_attestation({**self.attestation("a3", "write:orders"), "issuer": HELIX.did})
        assert len(store.attestations) == 3 and store.attestations[2]["issuer"] == HELIX.did
        assert store.attested_capabilities() == ["read:orders", "write:orders"]
        assert store.remove_attestation("read:orders") == 2 and store.remove_attestation("read:orders") == 0
        store.add_attestation({**self.attestation("a4", "x"), "credentialSubject": {"id": AGENT.did}})
        assert store.attested_capabilities() == ["write:orders"]
        store.add_hop(self.hop("urn:zcap:root", AGENT.did, RESOURCE))
        store.add_hop({**self.hop("urn:zcap:root", AGENT.did, RESOURCE), "validUntil": "2026-06-01T00:00:00Z"})
        assert len(store.hops) == 1 and store.remove_hop("urn:zcap:root") and not store.remove_hop("urn:zcap:root")

    def test_present_chain(self) -> None:
        store = CredentialStore(self.identity)
        store.add_hop(self.hop("urn:zcap:root", "did:key:z6MkParent", RESOURCE, USER.did))
        store.add_hop(self.hop("urn:zcap:leaf", AGENT.did, "urn:zcap:root"))
        chain = store.present_chain()
        assert chain["identity"]["id"] == "urn:uuid:identity" and [h["id"] for h in chain["hops"]] == ["urn:zcap:root", "urn:zcap:leaf"]
        assert len(store.present_chain(RESOURCE)["hops"]) == 2 and store.present_chain("did:web:other")["hops"] == []
        store.add_hop(self.hop("urn:zcap:orphan", AGENT.did, "urn:zcap:missing"))
        with pytest.raises(ValueError, match="does not hold"):
            store.present_chain()
        loop = CredentialStore(self.identity)
        loop.add_hop(self.hop("urn:zcap:a", "did:key:z6MkB", "urn:zcap:b")).add_hop(self.hop("urn:zcap:b", AGENT.did, "urn:zcap:a"))
        with pytest.raises(ValueError, match="terminate"):
            loop.present_chain()
        with pytest.raises(ValueError, match="no identity"):
            CredentialStore().present_chain()
        controlled = CredentialStore(self.identity)
        hop = self.hop("urn:zcap:c", AGENT.did, RESOURCE)
        hop["credentialSubject"] = {**hop["credentialSubject"], "controller": AGENT.did}
        del hop["credentialSubject"]["invoker"]
        controlled.add_hop(hop)
        assert [h["id"] for h in controlled.present_chain()["hops"]] == ["urn:zcap:c"]

    def test_sign_attestations_owner_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = CredentialStore(self.identity)
        calls: List[bytes] = []
        original = OWNER.signer.sign

        def spy(data: bytes) -> bytes:
            calls.append(data)
            return original(data)

        monkeypatch.setattr(OWNER.signer, "sign", spy)
        signed = store.sign_attestations(["read:orders", "read:catalog"], OWNER.signer, valid_until="2026-12-31T00:00:00Z", valid_from="2026-01-01T00:00:00Z", status_entries=[entry(1), entry(2)], ids=["urn:uuid:a1", "urn:uuid:a2"], created="2026-01-01T00:00:00Z")
        assert [a["credentialSubject"] for a in signed] == [{"id": AGENT.did, "capability": "read:orders"}, {"id": AGENT.did, "capability": "read:catalog"}]
        assert signed[0]["id"] == "urn:uuid:a1" and signed[0]["issuer"] == OWNER.did and signed[0]["credentialStatus"] == entry(1)
        assert all(verify_capability_attestation(a, resolve, subject_did=AGENT.did, now_ms=NOW).ok for a in signed)
        assert store.attested_capabilities() == ["read:orders", "read:catalog"]
        # Self-custody invariant: the signer was asked for the 64 hash bytes only, and no key is in the output.
        assert len(calls) == 2 and all(len(c) == 64 for c in calls)
        assert OWNER.key not in json.dumps(signed)
        bare = CredentialStore().sign_attestations(["read:orders"], OWNER.signer, subject_did=AGENT.did, valid_until="2026-12-31T00:00:00Z", status_entries=[entry(1)])
        assert bare[0]["id"].startswith("urn:uuid:")
        with pytest.raises(ValueError, match="subject_did"):
            CredentialStore().sign_attestations(["x"], OWNER.signer, valid_until="x", status_entries=[entry(1)])
        with pytest.raises(ValueError, match="one status entry"):
            store.sign_attestations(["a", "b"], OWNER.signer, valid_until="x", status_entries=[entry(1)])


# ── 2. the cross-language fixture ──────────────────────────────────────────────

FIXTURES_DIR = Path(os.environ.get("HELIX_CORE_FIXTURES_DIR") or Path(__file__).resolve().parents[2] / "helix-core" / "fixtures")
FIXTURE_PATH = FIXTURES_DIR / "kya-os-helix" / "credentials.json"


@pytest.fixture(scope="module")
def fixture() -> Dict[str, Any]:
    if not FIXTURE_PATH.exists():
        pytest.skip(f"{FIXTURE_PATH} not found: check out helix-core beside this repo or set HELIX_CORE_FIXTURES_DIR")
    with open(FIXTURE_PATH, encoding="utf-8") as f:
        return json.load(f)


class TestHelixCoreFixture:
    def test_identity_and_verification(self, fixture: Dict[str, Any]) -> None:
        resolver = fixture["did_documents"].get
        now = parse_date_time(fixture["now"])
        verdict = verify_identity_credential(fixture["identity"]["credential"], resolver, agent_did=fixture["keys"]["child"]["did"], now_ms=now)
        assert verdict.ok and verdict.details["responsibleParty"] == fixture["keys"]["owner"]["did"]
        assert sorted(fixture["identity"]["credential"]["credentialSubject"]) == ["id", "name", "responsibleParty"]
        assert verify_identity_verification_credential(fixture["identity_verification"]["credential"], resolver, subject_did=fixture["keys"]["owner"]["did"], now_ms=now).details["verificationLevel"] == "enhanced"
        assert validate_credential("identity", fixture["identity"]["credential"]) == []

    def test_attestations_verify_and_the_owner_signed_one_signs_to_the_same_bytes(self, fixture: Dict[str, Any]) -> None:
        resolver = fixture["did_documents"].get
        now = parse_date_time(fixture["now"])
        status_list = {"credentialSubject": {"encodedList": fixture["status_list_encoded"]}}
        for attestation in fixture["attestations"]:
            verdict = verify_capability_attestation(attestation["credential"], resolver, subject_did=fixture["keys"]["child"]["did"], now_ms=now)
            assert verdict.ok, attestation["name"]
            assert verdict.details["issuer"] == fixture["keys"][attestation["signer"]]["did"]
            with_list = verify_capability_attestation(attestation["credential"], resolver, now_ms=now, status_list=status_list)
            assert with_list.ok == (not attestation["revoked"]), attestation["name"]
            assert validate_credential("attestation", attestation["credential"]) == []
        owner_signed = next(a for a in fixture["attestations"] if a["signer"] == "owner")
        owner = fixture["keys"]["owner"]
        signer = EnvSigner(owner["did"], env_var="K", env={"K": owner["private_key_hex"]})
        inp = owner_signed["input"]
        store = CredentialStore()
        [signed] = store.sign_attestations([inp["capability"]], signer, subject_did=inp["subjectDid"], valid_until=inp["validUntil"], valid_from=inp["validFrom"], status_entries=[owner_signed["credential"]["credentialStatus"]], ids=[inp["id"]], created=inp["proofCreated"])
        assert signed == owner_signed["credential"]
        rebuilt = build_capability_attestation(signer, inp["subjectDid"], inp["capability"], inp["validUntil"], owner_signed["credential"]["credentialStatus"], id=inp["id"], valid_from=inp["validFrom"], proof_created=inp["proofCreated"])
        assert rebuilt == owner_signed["credential"]
        # The standalone signer (JS signAttestationDocument) yields the same bytes from the unsigned document.
        unsigned = {k: v for k, v in owner_signed["credential"].items() if k != "proof"}
        assert sign_attestation_document(unsigned, signer, inp["proofCreated"]) == owner_signed["credential"]

    def test_every_chain_comes_to_the_recorded_verdict(self, fixture: Dict[str, Any]) -> None:
        resolver = fixture["did_documents"].get
        for chain in fixture["chains"]:
            options = chain["options"]
            evaluation = evaluate_delegation_chain(
                chain["hops"],
                resource=options.get("resource"),
                resource_owner=options.get("resourceOwner"),
                now_ms=parse_date_time(options["now"]),
                max_chain_length=options.get("maxChainLength", 10),
            )
            expected = chain["expected"]
            assert evaluation.ok == expected["ok"], chain["name"]
            assert evaluation.code == expected.get("code"), chain["name"]
            assert evaluation.allowed_action == expected["allowedAction"], chain["name"]
            assert evaluation.depth == expected["depth"], chain["name"]
            assert evaluation.responsible_party == expected.get("responsibleParty"), chain["name"]
            assert evaluation.leaf_invoker == expected.get("leafInvoker"), chain["name"]
            if 0 < len(chain["hops"]) <= 10 and chain["name"] not in ("unsigned_leaf", "extra_subject_member"):
                assert verify_delegation_chain_proofs(chain["hops"], resolver).ok == chain["proofs_ok"], chain["name"]
        names = {chain["name"] for chain in fixture["chains"]}
        assert {"three_hop_valid", "broadened_action", "dropped_caveat", "extended_valid_until", "extra_subject_member", "too_long", "tampered_proof"} <= names

    def test_effective_scopes_and_card_levels(self, fixture: Dict[str, Any]) -> None:
        for case in fixture["effective_scopes"]:
            assert derive_effective_scopes(case["attestations"], case["leaf_allowed_action"], case["catalog"]) == case["expected"], case["name"]
            legacy = case.get("legacy")
            if legacy:
                old = legacy["privilege_scopes"] if legacy["grant_scopes"] is None else [s for s in legacy["privilege_scopes"] if s in legacy["grant_scopes"]]
                assert old == legacy["expected"] == case["expected"], case["name"]
        resolver = fixture["did_documents"].get
        lists = {fixture["status_list_url"]: {"credentialSubject": {"encodedList": fixture["status_list_encoded"]}}}
        for card in fixture["card_levels"]:
            check = check_capabilities(card["capabilities"], resolver, subject_did=card["subject_did"], trusted_issuers=card["trusted_issuers"], now_ms=parse_date_time(fixture["now"]), status_lists=lists)
            assert check == card["expected_check"], card["name"]
            assert derive_conformance_level(check, card["proof_floor_ok"], card["revocation_fresh"]) == card["expected_level"], card["name"]

    def test_schema_rejections(self, fixture: Dict[str, Any]) -> None:
        for rejection in fixture["schema_rejections"]:
            violations = validate_credential(rejection["kind"], rejection["document"])
            assert violations, rejection["name"]
            assert rejection["violation_path"] in [v.path for v in violations], rejection["name"]
            assert rejection["violation_path"] in describe_violations(violations)
        for hop in next(c for c in fixture["chains"] if c["name"] == "three_hop_valid")["hops"]:
            assert validate_credential("hop", hop) == []

    def test_schemas_match_helix_core(self, fixture: Dict[str, Any]) -> None:
        schema_dir = FIXTURES_DIR.parent / "src" / "core" / "schemas"
        if not schema_dir.exists():
            pytest.skip("helix-core sources not beside the fixtures")
        for name, schema in (("identity-credential", IDENTITY_CREDENTIAL_SCHEMA), ("capability-attestation", CAPABILITY_ATTESTATION_SCHEMA), ("delegation-hop", DELEGATION_HOP_SCHEMA)):
            with open(schema_dir / f"{name}.schema.json", encoding="utf-8") as f:
                assert json.load(f) == schema, name


class TestPublicSurface:
    """The names helix-sdk-js exports for F-1 exist on helix_sdk, in Python style."""

    def test_every_js_export_has_a_python_counterpart(self) -> None:
        for name in [
            "CredentialStore",
            "sign_attestation_document",
            "CredentialSigner",
            "BitstringStatusEntry",
            "DataIntegrityProof",
            "StoredCredential",
            "CapabilityAttestation",
            "DelegationHop",
            "CredentialStoreData",
            "PresentedChain",
            "SignAttestationsOptions",
            "IDENTITY_CREDENTIAL_TYPE",
            "CAPABILITY_ATTESTATION_TYPE",
            "DELEGATION_CREDENTIAL_TYPE",
        ]:
            assert name in helix_sdk.__all__, name
            assert hasattr(helix_sdk, name), name
        assert (IDENTITY_CREDENTIAL_TYPE, CAPABILITY_ATTESTATION_TYPE, DELEGATION_CREDENTIAL_TYPE) == (
            "AgentIdentityCredential",
            "CapabilityAttestationCredential",
            "DelegationCredential",
        )

    def test_typed_shapes_mark_the_members_the_store_relies_on(self) -> None:
        assert {"id", "type", "issuer", "credentialSubject"} <= StoredCredential.__required_keys__
        assert {"@context", "validUntil", "proof"} <= StoredCredential.__optional_keys__
        assert {"validFrom", "credentialStatus"} <= CapabilityAttestation.__required_keys__
        assert PresentedChain.__required_keys__ == {"identity", "hops"}
        assert SignAttestationsOptions.__required_keys__ == {"valid_until", "status_entries"}
        assert SignAttestationsOptions.__optional_keys__ == {"subject_did", "valid_from", "ids", "created"}

    def test_sign_attestations_accepts_a_built_options_mapping(self) -> None:
        options: SignAttestationsOptions = {
            "subject_did": AGENT.did,
            "valid_until": "2026-12-31T00:00:00Z",
            "valid_from": "2026-01-01T00:00:00Z",
            "status_entries": [entry(1)],
            "ids": ["urn:uuid:opt"],
            "created": "2026-01-01T00:00:00Z",
        }
        [signed] = CredentialStore().sign_attestations(["read:orders"], OWNER.signer, **options)
        assert signed["id"] == "urn:uuid:opt" and signed["proof"]["created"] == "2026-01-01T00:00:00Z"


class TestSignAttestationDocument:
    def _document(self, issuer: str) -> Dict[str, Any]:
        return {
            "@context": ["https://www.w3.org/ns/credentials/v2", "https://helixid.io/contexts/v1"],
            "id": "urn:uuid:doc",
            "type": ["VerifiableCredential", CAPABILITY_ATTESTATION_TYPE],
            "issuer": issuer,
            "validFrom": "2026-01-01T00:00:00Z",
            "validUntil": "2026-12-31T00:00:00Z",
            "credentialSubject": {"id": AGENT.did, "capability": "read:orders"},
            "credentialStatus": entry(7),
        }

    def test_signs_like_sign_data_integrity_and_verifies(self) -> None:
        document = self._document(OWNER.did)
        signed = sign_attestation_document(document, OWNER.signer, "2026-01-01T00:00:00Z")
        assert signed == sign_data_integrity(document, OWNER.signer, "2026-01-01T00:00:00Z")
        assert signed["proof"]["verificationMethod"] == f"{OWNER.did}#key-1"
        assert "proof" not in document
        assert verify_capability_attestation(signed, resolve, subject_did=AGENT.did, now_ms=parse_date_time("2026-06-01T00:00:00Z")).ok

    def test_refuses_a_signer_that_is_not_the_issuer(self) -> None:
        with pytest.raises(ValueError, match="not the issuer"):
            sign_attestation_document(self._document(HELIX.did), OWNER.signer, "2026-01-01T00:00:00Z")

    def test_refuses_a_signer_that_returns_a_short_signature(self) -> None:
        class Short:
            did = OWNER.did
            kid = "key-1"

            def sign(self, data: bytes) -> bytes:
                return b"\x00" * 63

        with pytest.raises(ValueError, match="64-byte"):
            sign_attestation_document(self._document(OWNER.did), Short(), "2026-01-01T00:00:00Z")

    def test_refuses_a_document_that_already_carries_a_proof(self) -> None:
        signed = sign_attestation_document(self._document(OWNER.did), OWNER.signer, "2026-01-01T00:00:00Z")
        with pytest.raises(ValueError, match="already carries a proof"):
            sign_attestation_document(signed, OWNER.signer, "2026-01-01T00:00:00Z")

    def test_add_refuses_a_credential_whose_type_is_not_a_list(self) -> None:
        with pytest.raises(ValueError, match="not an identity"):
            CredentialStore().add({"id": "urn:uuid:x", "type": "AgentIdentityCredential", "issuer": HELIX.did, "credentialSubject": {}})
