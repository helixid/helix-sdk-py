# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story F-2: the SDK's ConformanceAdapter over the seven pinned vector
categories of the vendored suite (helix-core fixtures/kya-os at a4d7f61, suite
1.10.0), read from the sibling helix-core checkout or HELIX_CORE_FIXTURES_DIR,
plus the refusals of its pieces beyond the vectors."""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
from typing import Any, Dict

import pytest

from helix_sdk.conformance import F2_CATEGORIES, HelixConformanceAdapter, format_report, load_vectors, run_conformance
from helix_sdk.conformance.delegation_binding import (
    chain_digest,
    credential_digest,
    credential_shown_id,
    credential_signed_form,
    delegation_ref,
    delegation_reference,
    json_text_nesting_depth,
    read_json,
    read_signature_base64,
    value_nesting_depth,
)
from helix_sdk.conformance.legacy import assertion_key, issuer_did, legacy_chain_refusal, verify_legacy_proof, verify_vc_jwt
from helix_sdk.conformance.response_proof import proof_verifies, request_hash, response_hash
from helix_sdk.conformance.runner import main
from helix_sdk.conformance.status_list import accepts_list, keeper, list_bits, status_configuration, status_index, status_list_refusal, within_window
from helix_sdk.crypto.jcs import canonicalize
from helix_sdk.crypto.jws import EnvSigner, base64url_encode
from helix_sdk.did import build_did_document
from helix_sdk.keys import derive_public_key
from verifier_harness import core_fixtures_dir

VECTORS = core_fixtures_dir() / "kya-os" / "conformance" / "vectors"
skip_without_vectors = pytest.mark.skipif(not VECTORS.exists(), reason=f"vendored vectors not found at {VECTORS}")


@skip_without_vectors
def test_every_vector_of_the_seven_categories_passes() -> None:
    report = run_conformance(HelixConformanceAdapter(), load_vectors(VECTORS, F2_CATEGORIES))
    failures = [f"{r['id']}: expected {r['expected']}, got {r['actual']} ({r['detail']})" for r in report["results"] if not r["ok"]]
    assert failures == []
    assert report["total"] == 153
    assert report["categories"] == {
        "card-proof": {"total": 7, "passed": 7},
        "delegation-chain": {"total": 20, "passed": 20},
        "did-key-resolution": {"total": 3, "passed": 3},
        "did-web-resolution": {"total": 3, "passed": 3},
        "entity-card": {"total": 8, "passed": 8},
        "signed-proof": {"total": 62, "passed": 62},
        "status-list": {"total": 50, "passed": 50},
    }
    assert "RESULT: PASS" in format_report(report)


@skip_without_vectors
def test_command_line(capsys: pytest.CaptureFixture) -> None:
    assert main([str(VECTORS)]) == 0
    assert "RESULT: PASS" in capsys.readouterr().out


def test_runner_errors_and_duplicates(tmp_path: Path) -> None:
    class Throwing(HelixConformanceAdapter):
        def resolve_did_key(self, value: Any) -> Any:
            raise RuntimeError("boom")

    report = run_conformance(Throwing(), [{"id": "a", "category": "did-key-resolution", "expected": "pass", "input": {}}])
    assert report["results"][0]["actual"] == "error" and "RESULT: FAIL" in format_report(report)
    for category in ("audit-integrity", "negotiation"):
        assert run_conformance(HelixConformanceAdapter(), [{"id": category, "category": category, "expected": "fail", "input": {}}])["allMatched"]
    file = {"version": "1", "category": "did-key-resolution", "vectors": [{"id": "dup", "category": "did-key-resolution", "expected": "pass", "input": {}}]}
    (tmp_path / "a.json").write_text(json.dumps(file))
    (tmp_path / "b.json").write_text(json.dumps(file))
    with pytest.raises(ValueError, match="duplicate"):
        load_vectors(tmp_path)
    assert load_vectors(tmp_path, ["card-proof"]) == []


KEY = "11" * 32
DID = "did:web:issuer.example"
SIGNER = EnvSigner(DID, env_var="K", env={"K": KEY})
DOCUMENT = build_did_document(DID, derive_public_key(KEY))
DOCS = {DID: DOCUMENT}


def _sign(credential: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    signature = SIGNER.sign(canonicalize(credential).encode("utf-8"))
    proof = {"type": "Ed25519Signature2020", "verificationMethod": f"{DID}#key-1", "proofPurpose": "assertionMethod", "proofValue": base64url_encode(signature)}
    proof.update(extra)
    return {**credential, "proof": proof}


def _delegation(identifier: str, issuer: str, subject: str, **extra: Any) -> Dict[str, Any]:
    delegation = {"id": identifier, "issuerDid": issuer, "subjectDid": subject, "scopes": ["read"], "constraints": {"audience": "did:web:server"}, "status": "active", **extra}
    return {"id": f"urn:uuid:{identifier}", "type": ["VerifiableCredential", "DelegationCredential"], "issuer": issuer, "credentialSubject": {"id": subject, "delegation": delegation}}


def test_adapter_fails_closed() -> None:
    adapter = HelixConformanceAdapter(now_ms=lambda: 1780272000000)
    assert adapter.verify_signed_proof({"proof": "x"})["outcome"] == "fail"
    assert adapter.verify_signed_proof({"proof": {"meta": {"did": 1}}, "didDocuments": {}})["outcome"] == "fail"
    assert adapter.verify_signed_proof({"proof": {"meta": {"did": DID}}, "didDocuments": DOCS, "keyId": "#nope"})["outcome"] == "fail"
    assert adapter.verify_signed_proof({"proof": {"meta": {}}, "now": 1, "skewSeconds": 1, "expected": None})["outcome"] == "fail"
    assert adapter.resolve_did_key({"did": "did:web:x"})["outcome"] == "fail"
    assert adapter.resolve_did_web({"did": "did:key:z6Mk"})["outcome"] == "fail"
    assert adapter.resolve_did_web({"did": "did:web:%E0%A4%A"})["outcome"] == "fail"
    assert adapter.verify_card_proof({"jwks": None})["outcome"] == "fail"
    assert "no delegation chain" in adapter.verify_entity_card({"card": {"id": "did:web:a", "entityType": "agent", "name": "a", "responsibleParty": "did:web:b"}})["detail"]
    assert adapter.verify_entity_card({"card": None})["outcome"] == "fail"
    assert adapter.verify_entity_card({"card": {"id": "did:web:a", "entityType": "agent", "name": "a", "responsibleParty": "did:web:b"}, "accountability": {"chain": "x"}})["outcome"] == "fail"
    assert adapter.verify_delegation_chain({"leaf": "not.a.jwt", "serverDid": "did:web:server", "didDocuments": {}})["outcome"] == "fail"
    assert adapter.verify_delegation_chain({"leaf": None})["outcome"] == "fail"


def test_legacy_reading() -> None:
    root = _sign(_delegation("root", DID, DID))
    assert legacy_chain_refusal([root], "did:web:server", DOCS, 0) is None
    assert "repeats" in legacy_chain_refusal([root, root], "did:web:server", DOCS, 0)
    assert "names a parent" in legacy_chain_refusal([_sign(_delegation("r", DID, DID, parentId="x"))], "did:web:server", DOCS, 0)
    assert "another audience" in legacy_chain_refusal([root], "did:web:other", DOCS, 0)
    assert "widens" in legacy_chain_refusal([root, _sign(_delegation("c", DID, "did:web:c", parentId="root", scopes=["write"]))], "did:web:server", DOCS, 0)
    assert "does not name its parent" in legacy_chain_refusal([root, _sign(_delegation("c", DID, "did:web:c", parentId="x"))], "did:web:server", DOCS, 0)
    assert "not issued by its parent" in legacy_chain_refusal([root, _sign(_delegation("c", "did:web:z", "did:web:c", parentId="root"))], "did:web:server", DOCS, 0)
    for credential, words in [
        ({**root, "type": ["VerifiableCredential"]}, "not a DelegationCredential"),
        ({**root, "credentialSubject": {**root["credentialSubject"], "extra": 1}}, "more than id"),
        ({**root, "credentialSubject": {"id": DID, "delegation": {"id": 1}}}, "malformed"),
        (_sign(_delegation("i", DID, DID, status="revoked")), "not active"),
        ({**root, "issuer": 42}, "no issuer"),
        ({**root, "expirationDate": "2020-01-01T00:00:00Z"}, "expired"),
        (_sign(_delegation("n", DID, DID, constraints={"notAfter": 1})), "notAfter"),
        (_sign(_delegation("b", DID, DID, constraints={"notBefore": 9999999999})), "notBefore"),
        ("text", "not a credential"),
    ]:
        assert words in legacy_chain_refusal([credential], "did:web:server", DOCS, 1780272000000), words
    base = _delegation("root", DID, DID)
    assert verify_legacy_proof(_sign(base), DOCS) is None
    assert "not a credential" in verify_legacy_proof("x", DOCS)
    assert "no proof" in verify_legacy_proof(base, DOCS)
    assert "unsupported" in verify_legacy_proof(_sign(base, type="Other"), DOCS)
    assert "assertionMethod" in verify_legacy_proof(_sign(base, proofPurpose="authentication"), DOCS)
    assert "names no key" in verify_legacy_proof(_sign(base, verificationMethod=""), DOCS)
    assert "no signature" in verify_legacy_proof(_sign(base, proofValue="!!"), DOCS)
    assert "does not verify" in verify_legacy_proof({**_sign(base), "issuanceDate": "2026-02-01T00:00:00Z"}, DOCS)
    assert "canonical" in verify_legacy_proof({**_sign(base), "n": float("nan")}, DOCS)
    assert "no issuer" in verify_legacy_proof({**_sign(base), "issuer": 7}, DOCS)
    assert assertion_key(DOCUMENT, DID, "key-1", True) is not None
    assert assertion_key({**DOCUMENT, "assertionMethod": "x"}, DID, None, False) is None
    assert assertion_key(DOCUMENT, DID, 7, True) is None
    assert assertion_key(DOCUMENT, DID, "did:web:other#k", True) is None
    assert assertion_key(DOCUMENT, DID, DID, True) is None
    method = DOCUMENT["verificationMethod"][0]
    assert assertion_key({**DOCUMENT, "verificationMethod": [{**method, "controller": "did:web:x"}]}, DID, None, False) is None
    assert assertion_key({**DOCUMENT, "verificationMethod": [{**method, "publicKeyMultibase": "zz"}]}, DID, None, False) is None
    assert issuer_did({"id": ""}) is None


def test_vc_jwt() -> None:
    vc = _delegation("jwt", DID, DID)

    def encode(value: Any) -> str:
        return base64url_encode(json.dumps(value).encode())

    def jwt(header: Dict[str, Any], payload: Dict[str, Any]) -> str:
        signing_input = f"{encode(header)}.{encode(payload)}"
        return f"{signing_input}.{base64url_encode(SIGNER.sign(signing_input.encode()))}"

    assert "credential" in verify_vc_jwt(jwt({"alg": "EdDSA", "kid": f"{DID}#key-1"}, {"iss": DID, "vc": vc}), DOCS, 0)
    for token, words in [
        ("a.b", "three segments"),
        ("!!.!!.!!", "not an EdDSA"),
        (jwt({"alg": "ES256"}, {"iss": DID, "vc": vc}), "not an EdDSA"),
        (jwt({"alg": "EdDSA", "kid": ""}, {"iss": DID, "vc": vc}), "names no key"),
        (jwt({"alg": "EdDSA"}, {"iss": "did:web:z", "vc": vc}), "iss claim"),
        (jwt({"alg": "EdDSA"}, {"iss": DID, "vc": vc, "exp": "soon"}), "NumericDate"),
        (jwt({"alg": "EdDSA"}, {"iss": DID, "vc": vc, "exp": 1}), "expired"),
        (jwt({"alg": "EdDSA"}, {"iss": DID, "vc": vc, "nbf": 9999999999}), "not yet valid"),
        (jwt({"alg": "EdDSA", "kid": "#nope"}, {"iss": DID, "vc": vc}), "no assertionMethod"),
    ]:
        assert words in verify_vc_jwt(token, DOCS, 1780272000000)["refusal"], words
    good = jwt({"alg": "EdDSA"}, {"iss": DID, "vc": vc})
    assert "base64url" in verify_vc_jwt(good[:-2] + "+/", DOCS, 0)["refusal"]
    assert "does not verify" in verify_vc_jwt(".".join(good.split(".")[:2]) + "." + base64url_encode(bytes(64)), DOCS, 0)["refusal"]


def test_status_list_reading() -> None:
    for value, words in [
        ({"trustedRootIssuer": ""}, "non-empty"),
        ({"statusListIssuers": "x"}, "does not map"),
        ({"statusListIssuers": {"a": "x"}}, "does not map"),
        ({"statusListIssuers": {"a": ["ftp://x"]}}, "does not map"),
        ({"statusListIssuers": {"a": ["https://x.example/"]}}, "followed by"),
        ({"statusListIssuers": {"a": ["https://X.example"]}}, "lower case"),
        ({"statusListIssuers": {"a": ["https://x.example/a/"]}}, "ends in"),
        ({"statusListIssuers": {"a": ["https://x.example/a"], "b": ["https://x.example/a"]}}, "two issuers"),
    ]:
        with pytest.raises(ValueError, match=words):
            status_configuration(value)
    root, root_list, services = status_configuration({"statusListIssuers": {"did:web:svc": ["https://svc.example"]}})
    assert keeper("https://svc.example/list", "did:web:o", root, root_list, services) == ("did:web:svc", False)
    assert not accepts_list(None, "did:web:o", "u", "revocation", None, None, {})
    assert not accepts_list({"issuer": 42}, "did:web:o", "u", "revocation", None, None, {})
    assert not accepts_list({"issuer": "did:web:o", "id": "u"}, "did:web:o", "u", "revocation", None, None, {})
    assert within_window({"validUntil": "2026-01-01T00:00:00.123456789+05:00"}, 1735689600000)
    with pytest.raises(ValueError):
        within_window({"validFrom": "2026-01-01"}, 0)
    with pytest.raises(ValueError):
        within_window({"validFrom": "2026-02-30T00:00:00Z"}, 0)
    assert status_index(7) is None and status_index("0" * 20 + "7") == 7 and status_index("99999999999999999") is None
    with pytest.raises(ValueError):
        list_bits("u!!")
    assert len(list_bits(base64.urlsafe_b64encode(gzip.compress(bytes(2))).decode().rstrip("="))) == 2
    assert "credentialStatus" in status_list_refusal({"credential": {"credentialStatus": "x"}, "statusLists": {}, "didDocuments": {}}, 0)
    assert "names no list" in status_list_refusal({"credential": {"credentialStatus": {}}, "statusLists": {}, "didDocuments": {}}, 0)
    assert "unreadable" in status_list_refusal({"credential": None}, 0)
    assert status_list_refusal({"credential": None}) is not None


def test_delegation_binding_and_response_proof() -> None:
    assert credential_signed_form("a..b") is None
    assert credential_signed_form("a.b.!!") is None
    assert credential_signed_form({"proof": "x"}) is None
    assert credential_signed_form({"proof": {"proofValue": 7}}) is None
    assert credential_digest({"n": float("nan"), "proof": {"proofValue": "AAAA"}}) is None
    assert chain_digest([]) is None and chain_digest([{"proof": {"proofValue": ""}}]) is None
    assert credential_shown_id(42) is None and credential_shown_id("a.b") is None
    for payload in (b"\xff", "﻿{}".encode(), b"{not json", b'{"vc":1}', b"!!"):
        assert credential_shown_id(f"h.{base64url_encode(payload)}.s") is None
    assert credential_shown_id("h.!!.s") is None
    jti_payload = base64url_encode(json.dumps({"vc": {}, "jti": "j"}).encode())
    assert credential_shown_id(f"h.{jti_payload}.s") == "j"
    assert delegation_reference("x" * 257).startswith("sha256:") and delegation_reference("a\ud800").startswith("sha256:") and delegation_reference("ok") == "ok"
    assert delegation_ref({}) is None
    assert json_text_nesting_depth('{"a":"[\\"]"}') == 1 and json_text_nesting_depth("[" * 70, 64) == 65
    assert value_nesting_depth(7) == 0
    assert read_signature_base64("AA==", True) == b"\x00" and read_signature_base64("AA=", True) is None and read_signature_base64("A", True) is None
    assert read_signature_base64("AA=A", False) is None and read_signature_base64("A A\n==", False) == b"\x00" and read_signature_base64(7, False) is None
    with pytest.raises(ValueError):
        read_json("NaN")
    assert read_json("1" * 700) == float("inf")
    assert proof_verifies({"jws": "a", "meta": {}}, None, 1, 1) is not None
    meta = {"did": DID, "kid": "did:web:other#k", "nonce": "n", "audience": "a", "sessionId": "s", "ts": 1, "requestHash": "sha256:" + "0" * 64}
    assert "another DID" in proof_verifies({"jws": "a.b.c", "meta": meta}, None, 1, 1)
    meta["kid"] = DID + "#key-1"
    assert "numbers" in proof_verifies({"jws": "a.b.c", "meta": meta}, None, "1", 1)
    assert "skew" in proof_verifies({"jws": "a.b.c", "meta": meta}, None, 100, 1)
    assert "three segments" in proof_verifies({"jws": "a.b", "meta": meta}, None, 1, 1)
    assert "base64url" in proof_verifies({"jws": "!!.b.c", "meta": meta}, None, 1, 1)
    header = base64url_encode(json.dumps({"alg": "EdDSA", "kid": meta["kid"]}).encode())
    assert "strict base64url" in proof_verifies({"jws": f"{header}..!!", "meta": meta}, None, 1, 1)
    assert "header" in proof_verifies({"jws": f"{base64url_encode(b'{}')}..AA", "meta": meta}, None, 1, 1)
    assert "JWK" in proof_verifies({"jws": f"{header}..AA", "meta": meta}, None, 1, 1)
    assert "32 bytes" in proof_verifies({"jws": f"{header}..AA", "meta": meta}, {"kty": "OKP", "crv": "Ed25519", "kid": meta["kid"], "x": "AA"}, 1, 1)
    assert request_hash({"method": "ping"}).startswith("sha256:")
    assert request_hash({"method": "x", "params": "raw"}).startswith("sha256:")
    with pytest.raises(ValueError):
        response_hash({}, None)
