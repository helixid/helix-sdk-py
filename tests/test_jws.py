# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story L1-C: EdDSA compact JWS sign and verify (Core L1.3 to L1.5).

Three layers:
  1. unit tests of helix_sdk.crypto.jws on their own (full coverage);
  2. the cross-language fixture helix-core generated
     (fixtures/kya-os-helix/jws.json): the same keys and payloads must sign to
     the same bytes here, and every rejection must be refused for the same
     reason;
  3. the vendored KYA-OS vectors (fixtures/kya-os/conformance/vectors/
     signed-proof*.json) read as helix-core's tests read them.

Layers 2 and 3 read the sibling helix-core checkout (../helix-core/fixtures)
or the directory HELIX_CORE_FIXTURES_DIR names, and skip when neither exists.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List

import nacl.signing
import pytest

from helix_sdk.crypto import jws as jws_module
from helix_sdk.crypto.jws import (
    EnvSigner,
    JwsReasons,
    base64url_decode_strict,
    base64url_encode,
    public_key_hex_to_jwk,
    read_jws_header,
    select_assertion_method,
    sign_jws,
    verification_method_to_jwk,
    verify_jws,
    verify_jws_by_kid,
)
from helix_sdk.did import build_did_document
from helix_sdk.errors import InvalidJWSError
from helix_sdk.keys import derive_public_key, generate_key_pair, public_key_to_multibase
from helix_sdk.vp_crypto import base58btc_encode

DID = "did:web:agent.helix.test"
KEYS = generate_key_pair()
OTHER_KEYS = generate_key_pair()
ENV = {"TEST_SIGNING_KEY": KEYS.private_key}
SIGNER = EnvSigner(DID, env_var="TEST_SIGNING_KEY", env=ENV)
JWK = public_key_hex_to_jwk(KEYS.public_key)
DOCUMENT = build_did_document(DID, KEYS.public_key)


def resolver(did: str) -> Any:
    return DOCUMENT if did == DID else None


def refusal(run: Callable[[], Any]) -> str:
    with pytest.raises(InvalidJWSError) as refused:
        run()
    return refused.value.reason


def segment_text(segment: str) -> str:
    return base64url_decode_strict(segment).decode("utf-8")  # type: ignore[union-attr]


def raw_jws(header: Dict[str, Any], payload: str, private_key_hex: str) -> str:
    signing_input = f"{base64url_encode(json.dumps(header, separators=(',', ':')))}.{base64url_encode(payload)}"
    signature = nacl.signing.SigningKey(bytes.fromhex(private_key_hex)).sign(signing_input.encode()).signature
    return f"{signing_input}.{base64url_encode(signature)}"


class StubSigner:
    def __init__(self, did: str, kid: str, sign: Callable[[bytes], Any]) -> None:
        self.did = did
        self.kid = kid
        self._sign = sign

    def sign(self, data: bytes) -> Any:
        return self._sign(data)


# ── 1. unit ────────────────────────────────────────────────────────────────────


class TestSignJws:
    def test_header_payload_signature_with_alg_and_kid_in_order(self) -> None:
        jws = sign_jws({"iss": DID, "n": 1}, SIGNER)
        h, p, s = jws.split(".")
        assert segment_text(h) == f'{{"alg":"EdDSA","kid":"{DID}#key-1"}}'
        assert segment_text(p) == f'{{"iss":"{DID}","n":1}}'
        assert len(base64url_decode_strict(s)) == 64  # type: ignore[arg-type]

    def test_strings_as_utf8_and_bytes_as_given(self) -> None:
        assert segment_text(sign_jws("plain", SIGNER).split(".")[1]) == "plain"
        jws = sign_jws(b"\x00\xff\x10", SIGNER)
        assert base64url_decode_strict(jws.split(".")[1]) == b"\x00\xff\x10"
        assert verify_jws(jws, JWK).payload is None
        assert verify_jws(sign_jws(bytearray(b"ab"), SIGNER), JWK).payload_bytes == b"ab"

    def test_extra_header_members_follow_alg_and_kid_and_cannot_override(self) -> None:
        jws = sign_jws({"a": 1}, SIGNER, header={"typ": "JWT", "alg": "HS256", "kid": "nope"})
        assert segment_text(jws.split(".")[0]) == f'{{"alg":"EdDSA","kid":"{DID}#key-1","typ":"JWT"}}'

    def test_signer_kid_with_leading_hash(self) -> None:
        assert read_jws_header(sign_jws({}, StubSigner(DID, "#key-1", SIGNER.sign)))["kid"] == f"{DID}#key-1"

    def test_refuses_signer_without_did_or_with_malformed_fragment(self) -> None:
        for did, kid in (("agent", "key-1"), (DID, "a#b"), (DID, "#")):
            assert refusal(lambda: sign_jws({}, StubSigner(did, kid, SIGNER.sign))) == JwsReasons.KID_MALFORMED

    def test_refuses_signer_returning_no_64_byte_signature(self) -> None:
        assert refusal(lambda: sign_jws({}, StubSigner(DID, "key-1", lambda _d: b"short"))) == JwsReasons.SIGNATURE_INVALID
        assert refusal(lambda: sign_jws({}, StubSigner(DID, "key-1", lambda _d: "sig"))) == JwsReasons.SIGNATURE_INVALID

    def test_self_custody_invariant_only_bytes_reach_the_signer_and_no_key_leaks(self) -> None:
        seen: List[bytes] = []

        def spy(data: bytes) -> bytes:
            seen.append(data)
            return SIGNER.sign(data)

        jws = sign_jws({"iss": DID}, StubSigner(DID, "key-1", spy))
        assert len(seen) == 1
        assert seen[0].decode() == ".".join(jws.split(".")[:2])
        for leak in (KEYS.private_key, base64url_encode(bytes.fromhex(KEYS.private_key))):
            assert leak not in jws
            assert leak not in repr(SIGNER)
            assert leak not in json.dumps(vars(SIGNER), default=str)
        assert repr(SIGNER) == f"EnvSigner(did={DID!r}, kid='key-1')"


class TestVerifyJws:
    def test_verifies_and_returns_the_parsed_payload(self) -> None:
        result = verify_jws(sign_jws({"iss": DID, "sub": "x"}, SIGNER), JWK)
        assert (result.kid, result.did, result.payload) == (f"{DID}#key-1", DID, {"iss": DID, "sub": "x"})
        assert result.header == {"alg": "EdDSA", "kid": f"{DID}#key-1"}
        assert result.payload_bytes == f'{{"iss":"{DID}","sub":"x"}}'.encode()

    def test_jwk_kid_and_expected_kid(self) -> None:
        jws = sign_jws({}, SIGNER)
        assert verify_jws(jws, public_key_hex_to_jwk(KEYS.public_key, f"{DID}#key-1")).did == DID
        assert refusal(lambda: verify_jws(jws, public_key_hex_to_jwk(KEYS.public_key, f"{DID}#key-2"))) == JwsReasons.KID_MISMATCH
        assert refusal(lambda: verify_jws(jws, JWK, expected_kid=f"{DID}#key-2")) == JwsReasons.KID_MISMATCH
        assert verify_jws(jws, JWK, expected_kid=f"{DID}#key-1").kid == f"{DID}#key-1"

    @pytest.mark.parametrize("alg", ["HS256", "RS256", "ES256", "none", "eddsa", None])
    def test_refuses_any_alg_but_eddsa(self, alg: Any) -> None:
        header = {"kid": f"{DID}#key-1"} if alg is None else {"alg": alg, "kid": f"{DID}#key-1"}
        assert refusal(lambda: verify_jws(raw_jws(header, "{}", KEYS.private_key), JWK)) == JwsReasons.ALG_UNSUPPORTED

    def test_refuses_missing_null_non_string_or_malformed_kid(self) -> None:
        assert refusal(lambda: verify_jws(raw_jws({"alg": "EdDSA"}, "{}", KEYS.private_key), JWK)) == JwsReasons.KID_MISSING
        assert refusal(lambda: verify_jws(raw_jws({"alg": "EdDSA", "kid": None}, "{}", KEYS.private_key), JWK)) == JwsReasons.KID_MISSING
        assert refusal(lambda: verify_jws(raw_jws({"alg": "EdDSA", "kid": 7}, "{}", KEYS.private_key), JWK)) == JwsReasons.KID_MALFORMED
        for kid in ("key-1", "#key-1", DID, f"{DID}#", "did:#x", "http://x#y"):
            assert refusal(lambda: verify_jws(raw_jws({"alg": "EdDSA", "kid": kid}, "{}", KEYS.private_key), JWK)) == JwsReasons.KID_MALFORMED

    def test_refuses_kid_of_another_did_than_the_claimed_signer(self) -> None:
        other = raw_jws({"alg": "EdDSA", "kid": "did:web:other.test#key-1"}, json.dumps({"iss": DID}), KEYS.private_key)
        assert refusal(lambda: verify_jws(other, JWK)) == JwsReasons.KID_DID_MISMATCH
        jws = sign_jws({"sub": "no iss"}, SIGNER)
        assert refusal(lambda: verify_jws(jws, JWK, expected_did="did:web:other.test")) == JwsReasons.KID_DID_MISMATCH
        assert verify_jws(jws, JWK, expected_did=DID).did == DID
        assert verify_jws(sign_jws({"iss": 5}, SIGNER), JWK).payload == {"iss": 5}
        assert verify_jws(sign_jws(["iss"], SIGNER), JWK).payload == ["iss"]

    def test_refuses_bad_signature_tampered_payload_and_wrong_key(self) -> None:
        jws = sign_jws({"iss": DID}, SIGNER)
        h, p, s = jws.split(".")
        assert refusal(lambda: verify_jws(jws, public_key_hex_to_jwk(OTHER_KEYS.public_key))) == JwsReasons.SIGNATURE_INVALID
        tampered = f"{h}.{base64url_encode(json.dumps({'iss': DID, 'sub': 'tampered'}))}.{s}"
        assert refusal(lambda: verify_jws(tampered, JWK)) == JwsReasons.SIGNATURE_INVALID
        flipped = ("B" if s.startswith("A") else "A") + s[1:]
        assert refusal(lambda: verify_jws(f"{h}.{p}.{flipped}", JWK)) == JwsReasons.SIGNATURE_INVALID
        assert refusal(lambda: verify_jws(f"{h}.{p}.{base64url_encode(bytes(10))}", JWK)) == JwsReasons.SIGNATURE_INVALID
        assert refusal(lambda: verify_jws(f"{h}.{p}.{base64url_encode(bytes([255] * 64))}", JWK)) == JwsReasons.SIGNATURE_INVALID

    def test_reads_segments_strictly(self) -> None:
        jws = sign_jws({"iss": DID}, SIGNER)
        h, p, s = jws.split(".")
        trimmed = s[: len(s) - (len(s) % 4)] + "A"  # length 1 mod 4
        for value in (
            f"{h}.{p}",
            f"{h}.{p}.{s}.{s}",
            f".{p}.{s}",
            f"{h}..{s}",
            f"{h}.{p}.",
            f"{h}.{p}.{s}=",
            f"{h}.{p}.{s}==",
            f"{h}.{p}. {s}",
            f"{h}.{p}.{s}\n",
            f"{h}.{p}.{s[:-1]}+",
            f"{h}.{p}.{s}é",
            f"{h}.{p}.{trimmed}",
        ):
            assert refusal(lambda: verify_jws(value, JWK)) == JwsReasons.MALFORMED, value
        assert refusal(lambda: verify_jws(42, JWK)) == JwsReasons.MALFORMED  # type: ignore[arg-type]
        assert refusal(lambda: verify_jws(f"{base64url_encode('nope')}.{p}.{s}", JWK)) == JwsReasons.HEADER_INVALID
        assert refusal(lambda: verify_jws(f"{base64url_encode('[1]')}.{p}.{s}", JWK)) == JwsReasons.HEADER_INVALID
        assert refusal(lambda: verify_jws(f"{base64url_encode('null')}.{p}.{s}", JWK)) == JwsReasons.HEADER_INVALID

    @pytest.mark.parametrize(
        "candidate",
        [
            None,
            "key",
            {"kty": "EC", "crv": "P-256", "x": JWK["x"]},
            {"kty": "OKP", "crv": "X25519", "x": JWK["x"]},
            {"kty": "OKP", "crv": "Ed25519"},
            {"kty": "OKP", "crv": "Ed25519", "x": JWK["x"] + "="},
            {"kty": "OKP", "crv": "Ed25519", "x": JWK["x"][:10]},
            {"kty": "OKP", "crv": "Ed25519", "x": JWK["x"], "kid": 5},
        ],
    )
    def test_refuses_a_key_that_is_not_a_strict_ed25519_jwk(self, candidate: Any) -> None:
        assert refusal(lambda: verify_jws(sign_jws({}, SIGNER), candidate)) == JwsReasons.JWK_INVALID

    def test_error_carries_code_reason_and_details(self) -> None:
        with pytest.raises(InvalidJWSError) as refused:
            verify_jws(sign_jws({}, SIGNER), public_key_hex_to_jwk(OTHER_KEYS.public_key))
        assert refused.value.code == "JWS_INVALID"
        assert refused.value.http_status == 400
        assert refused.value.details == {"reason": JwsReasons.SIGNATURE_INVALID}
        assert InvalidJWSError("x").message == "JWS is invalid"


class TestVerifyJwsByKid:
    def test_resolves_selects_and_verifies(self) -> None:
        result = verify_jws_by_kid(sign_jws({"iss": DID, "sub": "x"}, SIGNER), resolver)
        assert (result.did, result.payload) == (DID, {"iss": DID, "sub": "x"})

    def test_only_the_injected_resolver_is_called_once_with_the_kid_did(self) -> None:
        calls: List[str] = []

        def spy(did: str) -> Any:
            calls.append(did)
            return DOCUMENT

        verify_jws_by_kid(sign_jws({"iss": DID}, SIGNER), spy)
        assert calls == [DID]

    def test_refuses_before_resolving_when_kid_did_is_not_expected(self) -> None:
        calls: List[str] = []

        def spy(did: str) -> Any:
            calls.append(did)
            return DOCUMENT

        assert refusal(lambda: verify_jws_by_kid(sign_jws({}, SIGNER), spy, expected_did="did:web:other.test")) == JwsReasons.KID_DID_MISMATCH
        assert calls == []

    def test_refuses_malformed_without_resolving(self) -> None:
        assert refusal(lambda: verify_jws_by_kid("a.b", resolver)) == JwsReasons.MALFORMED
        assert refusal(lambda: verify_jws_by_kid(raw_jws({"alg": "EdDSA"}, "{}", KEYS.private_key), resolver)) == JwsReasons.KID_MISSING

    def test_refuses_unresolved_or_foreign_document(self) -> None:
        jws = sign_jws({}, SIGNER)
        assert refusal(lambda: verify_jws_by_kid(jws, lambda _d: None)) == JwsReasons.DID_UNRESOLVED
        foreign = build_did_document("did:web:other.test", KEYS.public_key)
        assert refusal(lambda: verify_jws_by_kid(jws, lambda _d: foreign)) == JwsReasons.DID_DOCUMENT_MISMATCH
        assert refusal(lambda: verify_jws_by_kid(jws, lambda _d: "doc")) == JwsReasons.DID_DOCUMENT_MISMATCH  # type: ignore[arg-type, return-value]

    def test_refuses_undefined_unlisted_duplicate_foreign_controlled_or_unusable_keys(self) -> None:
        jws = sign_jws({}, SIGNER)
        method = DOCUMENT["verificationMethod"][0]
        cases = [
            ({"id": DID, "verificationMethod": [], "assertionMethod": [method["id"]]}, JwsReasons.KEY_NOT_FOUND),
            ({"id": DID}, JwsReasons.KEY_NOT_FOUND),
            ({"id": DID, "verificationMethod": "x", "assertionMethod": "y"}, JwsReasons.KEY_NOT_FOUND),
            ({"id": DID, "verificationMethod": [method], "authentication": [method["id"]]}, JwsReasons.KEY_NOT_ASSERTION),
            ({"id": DID, "verificationMethod": [method], "assertionMethod": []}, JwsReasons.KEY_NOT_ASSERTION),
            ({"id": DID, "verificationMethod": [method], "assertionMethod": [method]}, JwsReasons.KEY_AMBIGUOUS),
            ({"id": DID, "verificationMethod": [method, method], "assertionMethod": [method["id"]]}, JwsReasons.KEY_AMBIGUOUS),
            (
                {"id": DID, "verificationMethod": [{**method, "controller": "did:web:other.test"}], "assertionMethod": [method["id"]]},
                JwsReasons.KEY_FOREIGN_CONTROLLER,
            ),
            (
                {"id": DID, "verificationMethod": [{"id": method["id"], "type": "Ed25519VerificationKey2020", "controller": DID}], "assertionMethod": [method["id"]]},
                JwsReasons.KEY_UNSUPPORTED,
            ),
            (build_did_document(DID, OTHER_KEYS.public_key), JwsReasons.SIGNATURE_INVALID),
        ]
        for document, reason in cases:
            assert refusal(lambda: verify_jws_by_kid(jws, lambda _d: document)) == reason, document

    def test_accepts_relative_ids_embedded_methods_and_none_entries(self) -> None:
        jws = sign_jws({}, SIGNER)
        method = DOCUMENT["verificationMethod"][0]
        relative = {"id": DID, "verificationMethod": [None, {**method, "id": "#key-1"}], "assertionMethod": ["#key-1"]}
        assert verify_jws_by_kid(jws, lambda _d: relative).did == DID
        embedded = {"id": DID, "assertionMethod": [None, "did:web:x#y", method]}
        assert verify_jws_by_kid(jws, lambda _d: embedded).did == DID


class TestVerificationMethodKeyForms:
    @staticmethod
    def method(**extra: Any) -> Dict[str, Any]:
        return {"id": f"{DID}#key-1", "type": "Ed25519VerificationKey2020", "controller": DID, **extra}

    def test_reads_jwk_multibase_and_base58(self) -> None:
        expected = {"kty": "OKP", "crv": "Ed25519", "x": JWK["x"], "kid": f"{DID}#key-1"}
        assert verification_method_to_jwk(self.method(publicKeyJwk={"kty": "OKP", "crv": "Ed25519", "x": JWK["x"]})) == expected
        assert verification_method_to_jwk(self.method(publicKeyMultibase=public_key_to_multibase(KEYS.public_key))) == expected
        assert verification_method_to_jwk(self.method(publicKeyBase58=base58btc_encode(bytes.fromhex(KEYS.public_key)))) == expected

    def test_refuses_invalid_or_undecodable_key_material(self) -> None:
        assert refusal(lambda: verification_method_to_jwk(self.method(publicKeyJwk={"kty": "OKP", "crv": "Ed25519", "x": "bad="}))) == JwsReasons.JWK_INVALID
        assert refusal(lambda: verification_method_to_jwk(self.method(publicKeyMultibase="f00"))) == JwsReasons.KEY_UNSUPPORTED
        assert refusal(lambda: verification_method_to_jwk(self.method(publicKeyBase58="0OIl"))) == JwsReasons.KEY_UNSUPPORTED
        assert refusal(lambda: verification_method_to_jwk(self.method())) == JwsReasons.KEY_UNSUPPORTED

    def test_select_assertion_method_is_exported(self) -> None:
        assert select_assertion_method(DOCUMENT, DID, f"{DID}#key-1") is DOCUMENT["verificationMethod"][0]


class TestHelpers:
    def test_base64url_encode_and_strict_decode(self) -> None:
        assert base64url_encode("hi") == "aGk"
        assert base64url_encode(bytes([250, 251, 252])) == "-vv8"
        assert base64url_decode_strict("aGk") == b"hi"
        assert base64url_decode_strict("") == b""
        for bad in ("aGk=", "a", "aGk ", "a+b/", "ü", "aGkaa", 5):
            assert base64url_decode_strict(bad) is None, bad  # type: ignore[arg-type]

    def test_read_jws_header_and_jwk_round_trip(self) -> None:
        assert read_jws_header(sign_jws({}, SIGNER, header={"typ": "JWT"})) == {"alg": "EdDSA", "kid": f"{DID}#key-1", "typ": "JWT"}
        assert base64url_decode_strict(JWK["x"]).hex() == KEYS.public_key  # type: ignore[union-attr]
        assert public_key_hex_to_jwk(KEYS.public_key, "k") == {"kty": "OKP", "crv": "Ed25519", "x": JWK["x"], "kid": "k"}


class TestEnvSigner:
    def test_reads_the_key_at_sign_time_and_derives_the_public_key(self) -> None:
        dynamic: Dict[str, str] = {}
        lazy = EnvSigner(DID, kid="#key-9", env_var="LATER", env=dynamic)
        assert (lazy.kid, lazy.verification_method_id) == ("key-9", f"{DID}#key-9")
        with pytest.raises(ValueError, match="LATER is not set"):
            lazy.sign(b"x")
        dynamic["LATER"] = "  "
        with pytest.raises(ValueError, match="LATER is not set"):
            lazy.sign(b"x")
        dynamic["LATER"] = KEYS.private_key
        assert lazy.public_key_hex() == derive_public_key(KEYS.private_key)
        assert verify_jws(sign_jws({"iss": DID}, lazy), JWK).kid == f"{DID}#key-9"
        dynamic["LATER"] = "not-a-key"
        with pytest.raises(ValueError):
            lazy.sign(b"x")

    def test_defaults_to_helix_signing_key_in_os_environ_and_kid_key_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HELIX_SIGNING_KEY", KEYS.private_key)
        signer = EnvSigner(DID)
        assert signer.kid == "key-1"
        assert verify_jws(sign_jws({}, signer), JWK).did == DID

    def test_accepts_a_pkcs8_der_seed(self) -> None:
        der = EnvSigner(DID, env_var="K", env={"K": "302e020100300506032b657004220420" + KEYS.private_key})
        assert verify_jws(sign_jws({}, der), JWK).did == DID

    def test_refuses_non_did_or_malformed_kid(self) -> None:
        with pytest.raises(ValueError, match="must be a DID"):
            EnvSigner("agent", env=ENV)
        for kid in ("a#b", "#"):
            with pytest.raises(ValueError, match="fragment"):
                EnvSigner(DID, kid=kid, env=ENV)

    def test_protocol_base_class_sign_is_abstract(self) -> None:
        with pytest.raises(NotImplementedError):
            jws_module.Signer().sign(b"x")


# ── 2 and 3. helix-core fixtures ───────────────────────────────────────────────

FIXTURES_DIR = Path(os.environ.get("HELIX_CORE_FIXTURES_DIR") or Path(__file__).resolve().parents[2] / "helix-core" / "fixtures")


def _load_or_skip(relative: str) -> Dict[str, Any]:
    path = FIXTURES_DIR / relative
    if not path.is_file():
        pytest.skip(f"{path} not found: check out helix-core beside this repo or set HELIX_CORE_FIXTURES_DIR")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _fixture_vectors(name: str) -> List[Dict[str, Any]]:
    path = FIXTURES_DIR / name
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)["vectors"]


def _fixture_rejections() -> List[Dict[str, Any]]:
    path = FIXTURES_DIR / "kya-os-helix/jws.json"
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)["rejections"]


class TestHelixJwsFixtures:
    """fixtures/kya-os-helix/jws.json, generated by helix-core."""

    @staticmethod
    def fixtures() -> Dict[str, Any]:
        return _load_or_skip("kya-os-helix/jws.json")

    @staticmethod
    def jwk_for(fixtures: Dict[str, Any], key: str, with_kid: bool) -> Dict[str, Any]:
        fixture = fixtures["keys"][key]
        return public_key_hex_to_jwk(fixture["public_key_hex"], fixture["kid"] if with_kid else None)

    @staticmethod
    def resolver(fixtures: Dict[str, Any]) -> Callable[[str], Any]:
        return lambda did: next((k["did_document"] for k in fixtures["keys"].values() if k["did"] == did), None)

    def test_keys_are_consistent(self) -> None:
        for key in self.fixtures()["keys"].values():
            assert key["kid"] == f"{key['did']}#{key['kid_fragment']}"
            assert key["public_key_jwk"] == public_key_hex_to_jwk(key["public_key_hex"], key["kid"])
            assert derive_public_key(key["private_key_hex"]) == key["public_key_hex"]
            assert key["did_document"]["id"] == key["did"]

    @pytest.mark.parametrize("vector", _fixture_vectors("kya-os-helix/jws.json"), ids=lambda v: v["name"])
    def test_vector_signs_to_the_same_bytes_and_verifies_by_jwk_and_by_kid(self, vector: Dict[str, Any]) -> None:
        fixtures = self.fixtures()
        key = fixtures["keys"][vector["signer"]]
        signer = EnvSigner(key["did"], kid=key["kid_fragment"], env_var="K", env={"K": key["private_key_hex"]})
        spec = vector["payload"]
        payload: Any = spec["json"] if "json" in spec else spec["text"] if "text" in spec else bytes.fromhex(spec["bytes_hex"])
        assert sign_jws(payload, signer, header=vector.get("header_extra")) == vector["jws"]

        by_jwk = verify_jws(vector["jws"], self.jwk_for(fixtures, vector["signer"], True))
        assert by_jwk.header == vector["header"]
        assert by_jwk.did == key["did"]
        by_kid = verify_jws_by_kid(vector["jws"], self.resolver(fixtures))
        assert by_kid.payload_bytes == by_jwk.payload_bytes
        if "json" in spec:
            assert by_kid.payload == spec["json"]
        if "text" in spec:
            assert by_kid.payload_bytes.decode("utf-8") == spec["text"]
        if "bytes_hex" in spec:
            assert by_kid.payload_bytes.hex() == spec["bytes_hex"]

    @pytest.mark.parametrize("rejection", _fixture_rejections(), ids=lambda r: r["name"])
    def test_rejection_is_refused_for_the_same_reason_as_in_js(self, rejection: Dict[str, Any]) -> None:
        fixtures = self.fixtures()
        jwk = self.jwk_for(fixtures, rejection["verify_with"]["key"], rejection["verify_with"]["kid"])
        expected_did = rejection.get("expected_did")
        assert refusal(lambda: verify_jws(rejection["jws"], jwk, expected_did=expected_did)) == rejection["reason"]
        if "by_kid_reason" in rejection and rejection["by_kid_reason"] is None:
            assert verify_jws_by_kid(rejection["jws"], self.resolver(fixtures), expected_did=expected_did).did == fixtures["keys"]["signer"]["did"]
        else:
            assert refusal(lambda: verify_jws_by_kid(rejection["jws"], self.resolver(fixtures), expected_did=expected_did)) == rejection.get(
                "by_kid_reason", rejection["reason"]
            )


# Fail vectors whose refusal is the JWS layer's (L1.3 to L1.5); the same table as helix-core's test.
JWS_LAYER_REFUSALS = {
    "signed-proof/tampered-signature": JwsReasons.SIGNATURE_INVALID,
    "signed-proof/wrong-key": JwsReasons.KID_MISMATCH,
    "signed-proof/delegation-proof-signature-stray-character": JwsReasons.MALFORMED,
    "signed-proof/delegation-proof-signature-stray-characters": JwsReasons.MALFORMED,
    "signed-proof/delegation-proof-signature-base64": JwsReasons.MALFORMED,
    "signed-proof/delegation-proof-signature-white-space": JwsReasons.MALFORMED,
    "signed-proof/delegation-proof-signature-padded": JwsReasons.MALFORMED,
    "signed-proof/delegation-proof-fourth-segment": JwsReasons.MALFORMED,
    "signed-proof/delegation-proof-header-non-ascii": JwsReasons.MALFORMED,
    "signed-proof/delegation-proof-header-algorithm": JwsReasons.ALG_UNSUPPORTED,
    "signed-proof/delegation-proof-header-key": JwsReasons.KID_MISMATCH,
    "signed-proof/delegation-proof-signer-of-another-did": JwsReasons.KID_DID_MISMATCH,
}


class TestKyaOsVectors:
    """fixtures/kya-os/conformance/vectors, vendored at kya-os-mcp a4d7f61 (suite 1.10.0)."""

    def test_vendored_files_match_the_pinned_manifest(self) -> None:
        manifest = _load_or_skip("kya-os/conformance/SUITE-MANIFEST.json")
        assert manifest["suiteVersion"] == "1.10.0"
        for name in ("signed-proof.json", "signed-proof-key-relationship.json"):
            pinned = dict(manifest["files"])[name]
            digest = hashlib.sha256((FIXTURES_DIR / "kya-os/conformance/vectors" / name).read_bytes()).hexdigest()
            assert digest == pinned, name

    @pytest.mark.parametrize("vector", _fixture_vectors("kya-os/conformance/vectors/signed-proof.json"), ids=lambda v: v["id"])
    def test_signed_proof_through_verify_jws(self, vector: Dict[str, Any]) -> None:
        proof, jwk = vector["input"]["proof"], vector["input"]["publicKeyJwk"]
        meta = proof["meta"]
        run = lambda: verify_jws(proof["jws"], jwk, expected_kid=meta["kid"], expected_did=meta["did"])  # noqa: E731
        if vector["expected"] == "pass":
            result = run()
            assert (result.header["alg"], result.kid, result.did, result.payload["iss"]) == ("EdDSA", meta["kid"], meta["did"], meta["did"])
        elif vector["id"] in JWS_LAYER_REFUSALS:
            assert refusal(run) == JWS_LAYER_REFUSALS[vector["id"]]
        else:
            # Refused above the JWS layer (timestamp, meta and hash binding, delegation chain): L2-A's verifier.
            assert run().kid == meta["kid"]

    def test_the_jws_layer_table_names_real_vectors(self) -> None:
        ids = {v["id"] for v in _load_or_skip("kya-os/conformance/vectors/signed-proof.json")["vectors"]}
        assert set(JWS_LAYER_REFUSALS) <= ids

    @pytest.mark.parametrize(
        "vector", _fixture_vectors("kya-os/conformance/vectors/signed-proof-key-relationship.json"), ids=lambda v: v["id"]
    )
    def test_key_relationship_through_verify_jws_by_kid(self, vector: Dict[str, Any]) -> None:
        proof = vector["input"]["proof"]
        meta = proof["meta"]
        documents = vector["input"]["didDocuments"]
        key_id = vector["input"].get("keyId")
        run = lambda: verify_jws_by_kid(proof["jws"], documents.get, expected_kid=key_id, expected_did=meta["did"])  # noqa: E731
        if key_id is None:
            # The suite's no-kid vectors; kid is mandatory under L1-C, and the header's kid selects a usable key in both.
            assert run().kid == meta["kid"]
        elif vector["expected"] == "pass":
            assert run().did == meta["did"]
        else:
            refusal(run)
