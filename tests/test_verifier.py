# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story F-2: the local verifier in Python.

Two layers:
  1. the shared fixture set helix-core generated with the JavaScript reference
     (fixtures/verifier/*.json): every case must come to the recorded verdict,
     level, effective scopes, reason codes and chain summary, which is the
     parity the story asks for (helix-sdk-js runs the same cases);
  2. unit tests of the pieces on their own: the request proof, status lists,
     DID resolution, the chain rules, the card schema and the nonce store.

Layer 1 reads the sibling helix-core checkout (../helix-core/fixtures) or the
directory HELIX_CORE_FIXTURES_DIR names, and skips when neither exists.
"""

from __future__ import annotations

import base64
import gzip
import json
from typing import Any, Dict, List

import pytest

from helix_sdk.credentials import evaluate_delegation_chain
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.did import build_did_document
from helix_sdk.keys import derive_public_key, public_key_to_multibase
from helix_sdk.verifier import (
    ALL_REASON_CODES,
    ENTITY_CARD_SCHEMA,
    MemoryNonceStore,
    ReasonCodes,
    StatusListRead,
    VerifierOptions,
    VerifierSeams,
    check_capabilities,
    check_status_entry,
    covered_request,
    create_did_keys_resolver,
    create_did_resolver,
    decode_status_list_bits,
    decode_status_list_credential,
    did_key_document,
    did_of_kid,
    did_web_document_url,
    ed25519_keys_of,
    evaluate_delegation_chain_rules,
    jwk_thumbprint,
    parse_request_proof,
    parse_status_list_index,
    public_key_of_did_key,
    read_carried_chain,
    read_request_proof,
    read_status_bit,
    request_hash_content_digest,
    sign_request_proof,
    validate_entity_card,
    verify,
    verify_capability_attestation,
    verify_detached_jws,
    window_problems,
)
from verifier_harness import SeamCalls, core_fixtures_dir, have_verifier_fixtures, load_cases, load_environment, run_case

NOW = 1780272000000  # 2026-06-01T00:00:00Z
AUDIENCE = "did:web:orders.helix.test"
REQUEST = {"method": "tools/call", "params": {"name": "lookup_order", "arguments": {"orderId": "ORD-1"}}}


class Actor:
    def __init__(self, seed: str, did: str = "") -> None:
        self.key = (seed * 64)[:64]
        self.public_key_hex = derive_public_key(self.key)
        self.did = did or f"did:key:{public_key_to_multibase(self.public_key_hex)}"
        self.signer = EnvSigner(self.did, env_var="K", env={"K": self.key})
        self.document = build_did_document(self.did, self.public_key_hex)


AGENT = Actor("a", "did:web:agent.helix.test")
OTHER = Actor("b")


# ── 1. the shared fixtures ───────────────────────────────────────────────────

skip_without_fixtures = pytest.mark.skipif(not have_verifier_fixtures(), reason=f"helix-core fixtures not found at {core_fixtures_dir()}; set HELIX_CORE_FIXTURES_DIR")


def _fixture_cases() -> List[Any]:
    if not have_verifier_fixtures():
        return []
    return [pytest.param(file, case, id=f"{file}/{case['name']}") for file, cases in load_cases().items() for case in cases]


@skip_without_fixtures
class TestSharedFixtures:
    env = load_environment() if have_verifier_fixtures() else {}

    def test_covers_the_five_case_files(self) -> None:
        files = load_cases()
        assert sorted(files) == ["chain", "proof", "seams", "status", "valid"]
        assert sum(len(cases) for cases in files.values()) >= 90

    @pytest.mark.parametrize("file,case", _fixture_cases())
    def test_case_comes_to_the_recorded_verdict(self, file: str, case: Dict[str, Any]) -> None:
        assert run_case(self.env, case) == case["expected"], f"{file}/{case['name']}: {case['description']}"

    def test_over_long_chain_is_refused_before_any_resolution(self) -> None:
        case = next(c for c in load_cases()["chain"] if c["name"] == "chain_too_long")
        calls = SeamCalls()
        assert run_case(self.env, case, calls)["reasons"] == [ReasonCodes.CHAIN_TOO_LONG]
        assert calls.resolve_did == [] and calls.fetch_status_list == [] and calls.nonces == []

    def test_failed_carried_chain_has_no_fallback_lookup(self) -> None:
        case = next(c for c in load_cases()["chain"] if c["name"] == "no_fallback_after_failed_chain")
        calls = SeamCalls()
        assert run_case(self.env, case, calls)["ok"] is False
        assert calls.resolve_did == [self.env["keys"]["agent"]["did"]]
        assert calls.fetch_status_list == []

    def test_every_recorded_code_is_a_known_code(self) -> None:
        codes = {code for cases in load_cases().values() for case in cases for code in case["expected"]["reasons"]}
        assert codes <= set(ALL_REASON_CODES)
        assert len(codes) >= 40

    def test_card_schema_is_the_vendored_one(self) -> None:
        vendored = json.loads((core_fixtures_dir() / "kya-os" / "schemas" / "kya-os-card.schema.json").read_text("utf-8"))
        assert ENTITY_CARD_SCHEMA == vendored

    def test_chain_rules_agree_with_the_credentials_fixture(self) -> None:
        fixture = json.loads((core_fixtures_dir() / "kya-os-helix" / "credentials.json").read_text("utf-8"))
        from helix_sdk.credentials import parse_date_time

        for chain in fixture["chains"]:
            options = chain["options"]
            kwargs = {"resource": options.get("resource"), "resource_owner": options.get("resourceOwner"), "now_ms": parse_date_time(options["now"])}
            if "maxChainLength" in options:
                kwargs["max_chain_length"] = options["maxChainLength"]
            rules = evaluate_delegation_chain_rules(chain["hops"], **kwargs)
            plain = evaluate_delegation_chain(chain["hops"], **kwargs)
            assert (rules.ok, rules.code, rules.reasons, rules.allowed_action, rules.depth) == (plain.ok, plain.code, plain.reasons, plain.allowed_action, plain.depth), chain["name"]
            assert [reason for _code, reason in rules.broken] == rules.reasons


# ── 2. units ─────────────────────────────────────────────────────────────────


class TestReasonCodes:
    def test_the_set_is_the_javascript_set(self) -> None:
        assert len(ALL_REASON_CODES) == len(set(ALL_REASON_CODES)) == 47
        assert ReasonCodes.NONCE_SEAM_MISSING == "nonce_seam_missing"
        assert ReasonCodes.DID_MEMBERSHIP_UNVERIFIABLE == "did_membership_unverifiable"


class TestRequestProof:
    def test_mint_verify_and_bind(self) -> None:
        proof = sign_request_proof(REQUEST, AGENT.signer, audience=AUDIENCE, now_ms=NOW, nonce="bm9uY2U")
        assert proof["prf"] == "org.kya-os/proof.v1" and proof["kid"] == f"{AGENT.did}#key-1"
        assert proof["created"] == NOW // 1000 and proof["expires"] == NOW // 1000 + 60
        assert proof["jws"].split(".")[1] == ""
        assert verify_detached_jws(proof, bytes.fromhex(AGENT.public_key_hex))
        assert request_hash_content_digest({**REQUEST, "params": {**REQUEST["params"], "_meta": {"x": 1}}}) == proof["requestHash"]
        assert request_hash_content_digest({"method": "tools/call"}).startswith("sha-256=:")
        assert covered_request({"method": "ping", "params": "raw"}) == {"method": "ping", "params": "raw"}
        assert covered_request({"method": "ping"}) == {"method": "ping"}
        legacy = sign_request_proof(REQUEST, AGENT.signer, audience=AUDIENCE, now_ms=NOW, profile="org.kya-os/proof@1", cnf_jkt="abc")
        assert parse_request_proof(legacy) is not None
        fresh = sign_request_proof(REQUEST, AGENT.signer, audience=AUDIENCE)
        assert parse_request_proof(fresh) is not None and len(fresh["nonce"]) == 22

    def test_meta_keys(self) -> None:
        assert read_request_proof({"org.kya-os/request-proof": {"a": 1}, "org.kya-os/proof@1": {"b": 2}}) == {"a": 1}
        assert read_request_proof({"org.kya-os/proof@1": {"b": 2}}) == {"b": 2}
        assert read_request_proof({"org.kya-os/request-proof": None}) is None
        assert read_request_proof("nope") is None
        assert read_carried_chain({"org.kya-os/delegation-chain": [1]}) == [1]
        assert read_carried_chain(None) is None

    def test_parses_only_the_section_8_2_shape(self) -> None:
        proof = sign_request_proof(REQUEST, AGENT.signer, audience=AUDIENCE, now_ms=NOW, cnf_jkt="abc")
        assert parse_request_proof(proof) == proof
        for variant in (
            {**proof, "prf": "org.kya-os/proof.v2"},
            {**proof, "alg": "HS256"},
            {**proof, "did": "not-a-did"},
            {**proof, "kid": "did:web:x"},
            {**proof, "audience": 42},
            {**proof, "nonce": "has space"},
            {**proof, "created": 1.5},
            {**proof, "created": True},
            {**proof, "expires": -1},
            {**proof, "requestHash": ""},
            {**proof, "jws": ""},
            {**proof, "httpSig": ""},
            {**proof, "cnf": {"jkt": "abc", "extra": 1}},
            {**proof, "cnf": "abc"},
            {**proof, "extra": 1},
        ):
            assert parse_request_proof(variant) is None, variant
        assert parse_request_proof(None) is None
        assert parse_request_proof({**proof, "httpSig": "sig"}) is not None

    def test_detached_jws_refusals(self) -> None:
        proof = sign_request_proof(REQUEST, AGENT.signer, audience=AUDIENCE, now_ms=NOW)
        public_key = bytes.fromhex(AGENT.public_key_hex)
        from helix_sdk.crypto.jws import base64url_encode

        header = lambda value: base64url_encode(json.dumps(value, separators=(",", ":")))  # noqa: E731
        signature = proof["jws"].split(".")[2]
        assert not verify_detached_jws({**proof, "jws": f"{header({'alg': 'EdDSA', 'kid': 'did:web:other#k'})}..{signature}"}, public_key)
        assert not verify_detached_jws({**proof, "jws": f"{header({'alg': 'ES256', 'kid': proof['kid']})}..{signature}"}, public_key)
        assert not verify_detached_jws({**proof, "jws": f"{proof['jws'].split('.')[0]}.cGF5bG9hZA.{signature}"}, public_key)
        assert not verify_detached_jws({**proof, "jws": "a..b"}, public_key)
        assert not verify_detached_jws({**proof, "jws": f"bm90LWpzb24..{signature}"}, public_key)
        assert not verify_detached_jws({**proof, "jws": f"{proof['jws'].split('.')[0]}..{signature}="}, public_key)
        assert not verify_detached_jws(proof, bytes(32))
        assert not verify_detached_jws({**proof, "nonce": "other"}, public_key)

    def test_window_problems(self) -> None:
        base = {"created": 1000, "expires": 1060}
        assert window_problems(base, 1000, 5) == []
        assert window_problems({**base, "expires": 1000}, 1000, 5) == ["invalid_window"]
        assert window_problems({**base, "expires": 1061}, 1000, 5) == ["ttl_too_long"]
        assert window_problems(base, 990, 5) == ["created_in_future"]
        assert window_problems(base, 1070, 5) == ["expired"]
        assert window_problems(base, 1065, 5) == []

    def test_thumbprint_and_kid(self) -> None:
        assert jwk_thumbprint({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        assert did_of_kid("did:web:a#k") == "did:web:a" and did_of_kid("did:web:a") == "did:web:a"


def _encoded(bits: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(gzip.compress(bits, mtime=0)).decode().rstrip("=")


class TestStatusLists:
    bits = bytes([0, 0b0100_0000] + [0] * 30)
    url = "https://issuer.example/status/1"

    def entry(self, index: str, **extra: Any) -> Dict[str, Any]:
        return {"type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": index, "statusListCredential": self.url, **extra}

    def read(self, **extra: Any) -> StatusListRead:
        return StatusListRead(bits=decode_status_list_bits(_encoded(self.bits)), **extra)

    def test_decode_and_bits(self) -> None:
        assert decode_status_list_bits(_encoded(self.bits)) == self.bits
        assert decode_status_list_bits(_encoded(self.bits)[1:]) == self.bits
        assert read_status_bit(self.bits, 9) == 1 and read_status_bit(self.bits, 8) == 0 and read_status_bit(self.bits, 256) is None
        with pytest.raises(ValueError, match="GZIP"):
            decode_status_list_bits(base64.urlsafe_b64encode(b"not gzip").decode().rstrip("="))

    def test_decode_credential(self) -> None:
        value = {
            "id": self.url,
            "issuer": {"id": "did:web:issuer.example"},
            "validFrom": "2026-01-01T00:00:00Z",
            "expirationDate": "2027-01-01T00:00:00Z",
            "credentialSubject": {"statusPurpose": ["revocation", "suspension"], "encodedList": _encoded(self.bits)},
        }
        read = decode_status_list_credential(value, fresh=False)
        assert (read.issuer, read.status_purpose, read.id, read.valid_from, read.valid_until, read.fresh) == ("did:web:issuer.example", ["revocation", "suspension"], self.url, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", False)
        assert decode_status_list_credential({"issuer": "did:web:i", "validUntil": 42, "credentialSubject": {"encodedList": _encoded(self.bits)}}).valid_until == ""
        with pytest.raises(ValueError):
            decode_status_list_credential(None)
        with pytest.raises(ValueError):
            decode_status_list_credential({"credentialSubject": {}})

    def test_index_parsing(self) -> None:
        assert parse_status_list_index("0007") == 7 and parse_status_list_index("7") == 7
        for bad in (7, "7.0", " 7", "99999999999999999", "9007199254740992"):
            assert parse_status_list_index(bad) is None

    def test_check_status_entry(self) -> None:
        issuer = "did:web:issuer.example"
        ok = check_status_entry(self.entry("8"), issuer, self.read(), now_ms=NOW)
        assert (ok.ok, ok.fresh) == (True, True)
        assert check_status_entry(self.entry("9"), issuer, self.read(), now_ms=NOW).code == "status_revoked"
        assert "suspended" in (check_status_entry(self.entry("9", statusPurpose="suspension"), issuer, self.read(), now_ms=NOW).message or "")
        assert check_status_entry(self.entry("8", statusSize=2), issuer, self.read(), now_ms=NOW).code == "status_entry_malformed"
        assert check_status_entry(self.entry("x"), issuer, self.read(), now_ms=NOW).code == "status_entry_malformed"
        assert check_status_entry(self.entry("8"), issuer, None, now_ms=NOW).code == "status_unavailable"
        assert check_status_entry(self.entry("8"), issuer, self.read(issuer="did:web:other"), now_ms=NOW).code == "status_list_mismatch"
        assert check_status_entry(self.entry("8"), issuer, self.read(status_purpose="suspension"), now_ms=NOW).code == "status_list_mismatch"
        assert check_status_entry(self.entry("8"), issuer, self.read(status_purpose=["suspension", "revocation"]), now_ms=NOW).ok
        assert check_status_entry(self.entry("8"), issuer, self.read(id="https://issuer.example/status/2"), now_ms=NOW).code == "status_list_mismatch"
        assert check_status_entry(self.entry("8"), issuer, self.read(valid_until="2026-03-01T00:00:00Z"), now_ms=NOW).code == "status_stale"
        assert check_status_entry(self.entry("8"), issuer, self.read(valid_from="yesterday"), now_ms=NOW).code == "status_stale"
        cached = check_status_entry(self.entry("8"), issuer, self.read(fresh=False), now_ms=NOW)
        assert (cached.ok, cached.fresh) == (True, False)
        assert check_status_entry(self.entry("4096"), issuer, self.read(), now_ms=NOW).code == "status_entry_malformed"


class TestDidResolution:
    KEY = "did:key:z6MkiupQ1QPitvNtmEwCb47mkfCtCoU9A6znu7ECSqyFbVXH"

    def test_did_key(self) -> None:
        assert len(public_key_of_did_key(self.KEY) or b"") == 32
        for bad in ("did:key:z6Mk", self.KEY[:-1] + "!", "did:key:z6Mk" + "1" * 80, "did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc", "did:web:example.com"):
            assert public_key_of_did_key(bad) is None, bad
        document = did_key_document(self.KEY)
        assert document is not None and document["assertionMethod"] == [f"{self.KEY}#{self.KEY[len('did:key:'):]}"]
        assert did_key_document("did:web:x") is None

    def test_did_web_urls(self) -> None:
        assert did_web_document_url("did:web:example.com") == "https://example.com/.well-known/did.json"
        assert did_web_document_url("did:web:example.com%3A8443:agents:a1") == "https://example.com:8443/agents/a1/did.json"
        assert did_web_document_url("did:web:a:b:c:d") == "https://a/b/c/d/did.json"
        for bad in ("did:web:example.com:..:x", "did:web:example.com:a%2Fb", "did:web:exa%2Fmple.com", "did:web:%E0%A4%A", "did:web:example.com:a%E0%A4%A", "did:web:", "did:key:z6Mk", "did:web:bad host", "did:web:a%C3%28", "did:web:[::1]:x:y"):
            assert did_web_document_url(bad) is None or bad == "did:web:[::1]:x:y", bad

    def test_resolver_and_keys(self) -> None:
        served = {"https://agent.helix.test/.well-known/did.json": AGENT.document}

        def fetch(url: str) -> Any:
            if url not in served:
                raise LookupError(url)
            return served[url]

        resolve = create_did_resolver(fetch)
        assert resolve(AGENT.did) == AGENT.document
        assert resolve("did:web:bad host") is None
        assert resolve("did:pkh:eip155:1:0xabc") is None
        assert resolve(self.KEY) is not None
        served["https://agent.helix.test/.well-known/did.json"] = {**AGENT.document, "id": "did:web:other"}
        assert resolve(AGENT.did) is None
        rewritten = create_did_resolver(lambda url: {**AGENT.document, "id": url}, rewrite_url=lambda _url: AGENT.did)
        assert rewritten(AGENT.did)["id"] == AGENT.did
        keys = ed25519_keys_of(
            {
                "id": AGENT.did,
                "verificationMethod": [
                    AGENT.document["verificationMethod"][0],
                    {"id": "#relative", "controller": AGENT.did, "publicKeyMultibase": AGENT.document["verificationMethod"][0]["publicKeyMultibase"]},
                    {"id": f"{AGENT.did}#broken", "controller": AGENT.did, "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "short"}},
                    {"id": f"{AGENT.did}#none", "controller": AGENT.did},
                    "not a method",
                ],
            }
        )
        assert [key["kid"] for key in keys] == [f"{AGENT.did}#key-1", f"{AGENT.did}#relative"]
        resolve_keys = create_did_keys_resolver(lambda did: AGENT.document if did == AGENT.did else None)
        assert len(resolve_keys(AGENT.did)) == 1
        with pytest.raises(LookupError):
            resolve_keys("did:web:other")

    def test_default_fetch_refuses_http(self) -> None:
        from helix_sdk.verifier.resolve import _default_fetch

        with pytest.raises(ValueError):
            _default_fetch("http://example.com/did.json")


class TestCardAndNonceStore:
    def test_card_schema(self) -> None:
        card = {"id": "did:web:example.com:agents:a", "entityType": "agent", "name": "A", "capabilities": ["x"]}
        assert validate_entity_card(card) == []
        assert "extra" in validate_entity_card({**card, "extra": 1})[0]
        assert validate_entity_card({**card, "id": "did:pkh:x"})

    def test_memory_nonce_store(self) -> None:
        clock = [1000]
        store = MemoryNonceStore(now_ms=lambda: clock[0])
        assert store.insert("n", "did:web:a", 2000)
        assert not store.insert("n", "did:web:a", 2000)
        assert store.insert("n", "did:web:b", 2000)
        clock[0] = 2000
        assert store.insert("n", "did:web:a", 3000)
        default = MemoryNonceStore()
        assert default.insert("x", None, 10**15)


class TestVerifyEdges:
    def seams(self, **changes: Any) -> VerifierSeams:
        base = VerifierSeams(
            resolve_did=lambda did: AGENT.document if did == AGENT.did else None,
            resolve_did_keys=lambda did: ed25519_keys_of(AGENT.document),
            nonce_store=MemoryNonceStore(now_ms=lambda: NOW),
            clock=lambda: NOW,
        )
        for name, value in changes.items():
            setattr(base, name, value)
        return base

    def test_configuration_and_seams(self) -> None:
        assert verify({}, self.seams(), VerifierOptions(expected_audience="")).reasons == ["configuration_error"]
        assert verify({}, self.seams(), VerifierOptions(expected_audience=AUDIENCE, max_chain_length=0)).reasons == ["configuration_error"]
        assert verify({}, self.seams(nonce_store=object()), {"expectedAudience": AUDIENCE}).reasons == ["nonce_seam_missing"]
        assert verify(None, self.seams(), {"expectedAudience": AUDIENCE}).reasons == ["proof_missing"]

    def test_proof_without_chain_or_card(self) -> None:
        proof = sign_request_proof(REQUEST, AGENT.signer, audience=AUDIENCE, now_ms=NOW)
        result = verify(proof, self.seams(), {"expectedAudience": AUDIENCE}, request=REQUEST)
        assert (result.ok, result.level, result.proof_assurance, result.effective_scopes) == (True, "L1", "L3-minus", [])
        assert result.to_dict()["chainSummary"] == {"depth": 0, "allowedAction": [], "fresh": True}
        replay = verify(proof, self.seams(nonce_store=result and self.seams().nonce_store), {"expectedAudience": AUDIENCE}, request=REQUEST)
        assert replay.ok

    def test_request_without_canonical_form(self) -> None:
        proof = sign_request_proof(REQUEST, AGENT.signer, audience=AUDIENCE, now_ms=NOW)
        result = verify(proof, self.seams(), {"expectedAudience": AUDIENCE}, request={"method": "x", "params": {"n": float("nan")}})
        assert result.reasons == ["request_hash_mismatch"]

    def test_bad_key_in_membership_list_is_ignored(self) -> None:
        proof = sign_request_proof(REQUEST, AGENT.signer, audience=AUDIENCE, now_ms=NOW)
        seams = self.seams(resolve_did_keys=lambda did: [{"kty": "OKP", "crv": "Ed25519"}, *ed25519_keys_of(AGENT.document)])
        assert verify(proof, seams, {"expectedAudience": AUDIENCE}, request=REQUEST).ok

    def test_attestation_units(self) -> None:
        resolve = lambda did: AGENT.document if did == AGENT.did else None  # noqa: E731
        vc = {
            "@context": ["https://www.w3.org/ns/credentials/v2", "https://helixid.io/contexts/v1"],
            "id": "urn:uuid:1",
            "type": ["VerifiableCredential", "CapabilityAttestationCredential"],
            "issuer": AGENT.did,
            "validFrom": "2026-01-01T00:00:00Z",
            "validUntil": "2026-12-31T00:00:00Z",
            "credentialSubject": {"id": "did:web:subject", "capability": "read:orders"},
            "credentialStatus": {"type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": "1", "statusListCredential": "https://issuer.example/status/1"},
        }
        from helix_sdk.credentials import sign_data_integrity

        signed = sign_data_integrity(vc, AGENT.signer, created="2026-01-01T00:00:00Z")
        fetch = lambda _url: StatusListRead(bits=bytes(32))  # noqa: E731
        check = check_capabilities(
            [{"name": "read:orders", "attestations": [{"vc": signed}]}, "bare", {"name": "write", "attestations": [{"vc": {**signed, "credentialSubject": {**signed["credentialSubject"], "capability": "write"}}}]}],
            resolve,
            subject_did="did:web:subject",
            now_ms=NOW,
            fetch_status_list=fetch,
        )
        assert (check.verified, check.unverified, check.fresh, check.refusals) == (["read:orders"], ["bare", "write"], True, {"write": "signature_invalid"})
        kwargs = {"now_ms": NOW, "subject_did": "did:web:subject", "fetch_status_list": fetch}
        assert verify_capability_attestation(signed, resolve, **{**kwargs, "subject_did": "did:web:other"}).reason == "subject_mismatch"
        assert verify_capability_attestation(signed, resolve, **{**kwargs, "capability": "other"}).reason == "capability_mismatch"
        assert verify_capability_attestation(signed, resolve, **{**kwargs, "trusted_issuers": ["did:web:other"]}).reason == "issuer_untrusted"
        assert verify_capability_attestation(signed, resolve, **{**kwargs, "now_ms": NOW + 400 * 86400 * 1000}).reason == "credential_expired"
        assert verify_capability_attestation(signed, resolve, **{**kwargs, "fetch_status_list": None}).reason == "status_seam_missing"

        def down(_url: str) -> StatusListRead:
            raise RuntimeError("down")

        assert verify_capability_attestation(signed, resolve, **{**kwargs, "fetch_status_list": down}).reason == "status_unavailable"
        assert verify_capability_attestation(signed, resolve, **{**kwargs, "fetch_status_list": lambda _url: None}).reason == "status_unavailable"
        assert verify_capability_attestation({**signed, "extra": 1}, resolve, **kwargs).reason == "schema_invalid"
        from helix_sdk.verifier import capability_name

        assert capability_name("x") == "x" and capability_name({"name": "y"}) == "y"

    def test_chain_rule_refusals(self) -> None:
        assert evaluate_delegation_chain_rules([], ).code == "chain_invalid"
        assert evaluate_delegation_chain_rules([{}], max_chain_length=0).code == "configuration_error"
        assert evaluate_delegation_chain_rules([{}], max_clock_skew_ms=-5).code == "configuration_error"
        assert evaluate_delegation_chain_rules([{}, {}], max_chain_length=1).reasons == ["delegation chain depth 2 exceeds the maximum of 1"]
        assert evaluate_delegation_chain_rules([{}]).code == "delegation_malformed"
