# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story L1-A in Python: the agent key is generated client side, only its
public half leaves (JWK, did:key, registration body), and did:web / did:key
resolve to the same raw key and JWK as helix-core gives.

Layers:
  1. the module alone (generate, JWK, did:key, base58btc, refusals);
  2. the cross-language fixture helix-core generated
     (fixtures/kya-os-helix/did.json): same seeds must give the same bytes;
  3. the vendored KYA-OS vectors (did-key-resolution.json,
     did-web-resolution.json, Core L1.6 to L1.9);
  4. registering the key goes through enrollment only (helix_init); the L1-A
     key route and HelixClient.register_agent_key are gone.

Layers 2 and 3 read the sibling helix-core checkout (../helix-core/fixtures)
or the directory HELIX_CORE_FIXTURES_DIR names, and skip when neither exists.
"""

from __future__ import annotations

import base64
import inspect
import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

from helix_sdk import HelixClient
from helix_sdk import did_resolver as did_resolver_module
from helix_sdk.agent_key import (
    DEFAULT_AGENT_KEY_ID,
    agent_public_key,
    assert_no_private_material,
    decode_base58btc,
    encode_base58btc,
    generate_agent_key,
    public_key_from_did_key,
    public_key_jwk_bytes,
    to_did_key,
    to_public_key_jwk,
)
from helix_sdk.crypto.jws import EnvSigner, InvalidJWSError, sign_jws, verify_jws, verify_jws_by_kid
from helix_sdk.did_resolver import (
    did_key_document,
    did_web_to_url,
    key_from_document,
    resolve_did,
    resolve_did_key,
    resolve_did_web,
)
from helix_sdk.errors import UnsupportedDIDMethodError, ValidationError
from helix_sdk.keys import derive_public_key, public_key_to_multibase, sign_data, verify_signature

FIXTURES_DIR = Path(os.environ.get("HELIX_CORE_FIXTURES_DIR") or Path(__file__).resolve().parents[2] / "helix-core" / "fixtures")


def _load_or_skip(relative: str) -> Dict[str, Any]:
    path = FIXTURES_DIR / relative
    if not path.is_file():
        pytest.skip(f"{path} not found: check out helix-core beside this repo or set HELIX_CORE_FIXTURES_DIR")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _fixture_list(relative: str, member: str) -> List[Any]:
    path = FIXTURES_DIR / relative
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as f:
        value = json.load(f)[member]
    return list(value.items()) if isinstance(value, dict) else value


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ── 1. the module alone ────────────────────────────────────────────────────────


class TestGenerateAgentKey:
    def test_fresh_seed_and_public_key_that_sign_and_verify(self) -> None:
        key = generate_agent_key()
        assert len(bytes.fromhex(key.private_key_hex)) == 32
        assert len(bytes.fromhex(key.public_key_hex)) == 32
        assert derive_public_key(key.private_key_hex) == key.public_key_hex
        assert agent_public_key(key.private_key_hex).hex() == key.public_key_hex
        assert generate_agent_key().private_key_hex != key.private_key_hex
        signature = sign_data(b"hello", key.private_key_hex)
        assert verify_signature(b"hello", signature, key.public_key_hex)

    def test_public_key_from_pkcs8_seed_form_and_refusal(self) -> None:
        key = generate_agent_key()
        assert agent_public_key("302e020100300506032b657004220420" + key.private_key_hex).hex() == key.public_key_hex
        with pytest.raises(ValueError):
            agent_public_key("nope")


class TestPublicForms:
    key = generate_agent_key()
    raw = bytes.fromhex(key.public_key_hex)

    def test_jwk_and_did_key_from_hex_or_bytes(self) -> None:
        assert to_public_key_jwk(self.key.public_key_hex) == {"kty": "OKP", "crv": "Ed25519", "x": _b64url(self.raw)}
        assert to_public_key_jwk(self.raw, "k") == {"kty": "OKP", "crv": "Ed25519", "x": _b64url(self.raw), "kid": "k"}
        assert to_public_key_jwk(bytearray(self.raw)) == to_public_key_jwk(self.raw)
        assert to_did_key(self.key.public_key_hex) == "did:key:" + public_key_to_multibase(self.key.public_key_hex)
        assert to_did_key(self.raw) == to_did_key(self.key.public_key_hex)
        assert to_did_key(self.raw).startswith("did:key:z6Mk")
        assert public_key_from_did_key(to_did_key(self.raw)) == self.raw

    @pytest.mark.parametrize("bad", ["abcd", "zz" * 32, b"\x00" * 31])
    def test_refuse_a_key_that_is_not_32_bytes(self, bad: Any) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            to_public_key_jwk(bad)
        with pytest.raises(ValueError, match="32 bytes"):
            to_did_key(bad)

    def test_public_key_from_did_key_is_none_for_anything_else(self) -> None:
        assert public_key_from_did_key("did:web:a") is None
        assert public_key_from_did_key("did:key:z!!!") is None
        assert public_key_from_did_key("did:key:z") is None
        assert public_key_from_did_key(7) is None  # type: ignore[arg-type]
        assert public_key_from_did_key("did:key:z" + encode_base58btc(b"\xec\x01" + self.raw)) is None
        assert public_key_from_did_key("did:key:z" + encode_base58btc(b"\xed\x01" + self.raw[2:])) is None


class TestPublicKeyJwk:
    key = generate_agent_key()
    jwk = to_public_key_jwk(key.public_key_hex)

    def test_refuses_private_material_and_non_public_jwks(self) -> None:
        d = _b64url(bytes.fromhex(self.key.private_key_hex))
        assert to_public_key_jwk(bytes.fromhex(self.key.public_key_hex), DEFAULT_AGENT_KEY_ID) == {**self.jwk, "kid": "key-1"}
        with pytest.raises(ValueError, match=r"found publicKeyJwk\.d"):
            assert_no_private_material({"publicKeyJwk": {**self.jwk, "d": d}})
        with pytest.raises(ValueError, match="found d"):
            public_key_jwk_bytes({**self.jwk, "d": d})
        with pytest.raises(ValueError, match=r"unexpected members \(use\)"):
            public_key_jwk_bytes({**self.jwk, "use": "sig"})
        with pytest.raises(ValueError, match="OKP"):
            public_key_jwk_bytes({**self.jwk, "kty": "EC"})
        with pytest.raises(ValueError, match="Ed25519"):
            public_key_jwk_bytes({**self.jwk, "crv": "X25519"})
        with pytest.raises(ValueError, match="kid must be a string"):
            public_key_jwk_bytes({**self.jwk, "kid": 4})
        with pytest.raises(ValueError, match="strict base64url"):
            public_key_jwk_bytes({**self.jwk, "x": self.jwk["x"] + "="})
        with pytest.raises(ValueError, match="strict base64url"):
            public_key_jwk_bytes({**self.jwk, "x": self.jwk["x"] + "AA"})
        with pytest.raises(ValueError, match="strict base64url"):
            public_key_jwk_bytes({"kty": "OKP", "crv": "Ed25519"})
        with pytest.raises(ValueError, match="32-byte"):
            public_key_jwk_bytes({**self.jwk, "x": self.jwk["x"][4:]})
        with pytest.raises(ValueError, match="JSON object"):
            public_key_jwk_bytes(None)
        with pytest.raises(ValueError, match="JSON object"):
            public_key_jwk_bytes([])
        assert public_key_jwk_bytes({**self.jwk, "kid": "k"}) == bytes.fromhex(self.key.public_key_hex)

    def test_assert_no_private_material_looks_at_every_depth(self) -> None:
        with pytest.raises(ValueError, match=r"found a\.b\.0\.seed"):
            assert_no_private_material({"a": {"b": [{"seed": "x"}]}})
        with pytest.raises(ValueError, match="found privateKeyHex"):
            assert_no_private_material({"privateKeyHex": "x"})
        assert_no_private_material({"ok": 1, "nested": {"x": "y"}, "list": (1, [2])})
        assert_no_private_material("string")
        assert_no_private_material(None)


class TestParityWithHelixSdkJs:
    """Names and refusals that must match helix-sdk-js's src/core/agent-key.ts and index.ts."""

    key = generate_agent_key()

    @pytest.mark.parametrize("not_an_object", [None, [1] * 32, (1,) * 32, []], ids=["none", "list32", "tuple32", "empty"])
    def test_a_jwk_that_is_not_a_json_object_is_refused_as_js_does(self, not_an_object: Any) -> None:
        with pytest.raises(ValueError, match="publicKeyJwk must be a JSON object"):
            public_key_jwk_bytes(not_an_object)

    @pytest.mark.parametrize("not_bytes", [5, 1.5, object()], ids=["int", "float", "object"])
    def test_other_values_are_refused_as_not_a_32_byte_key(self, not_bytes: Any) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            to_public_key_jwk(not_bytes)

    def test_bytearray_is_read_as_key_bytes(self) -> None:
        raw = bytearray.fromhex(self.key.public_key_hex)
        assert to_public_key_jwk(raw) == to_public_key_jwk(self.key.public_key_hex)

    def test_every_name_js_exports_is_exported_from_helix_sdk(self) -> None:
        import helix_sdk

        js_to_python = {
            "generateAgentKey": "generate_agent_key",
            "agentPublicKey": "agent_public_key",
            "toPublicKeyJwk": "to_public_key_jwk",
            "toDidKey": "to_did_key",
            "publicKeyFromDidKey": "public_key_from_did_key",
            "publicKeyJwkBytes": "public_key_jwk_bytes",
            "assertNoPrivateMaterial": "assert_no_private_material",
            "encodeBase58btc": "encode_base58btc",
            "decodeBase58btc": "decode_base58btc",
            "DEFAULT_AGENT_KEY_ID": "DEFAULT_AGENT_KEY_ID",
            "AgentKey": "AgentKey",
            "AgentPublicKeyJwk": "AgentPublicKeyJwk",
        }
        for js_name, python_name in js_to_python.items():
            assert python_name in helix_sdk.__all__, js_name
            assert getattr(helix_sdk, python_name) is not None, js_name
        assert helix_sdk.DEFAULT_AGENT_KEY_ID == "key-1"
        # agentKeyRegistration / HelixClient.registerAgentKey went with POST /v1/agents/{did}/keys (story F-3).
        assert not hasattr(helix_sdk, "agent_key_registration") and not hasattr(HelixClient, "register_agent_key")

    def test_typed_dict_describes_the_jwk(self) -> None:
        from helix_sdk import AgentPublicKeyJwk

        assert set(AgentPublicKeyJwk.__annotations__) == {"kty", "crv", "x", "kid"}
        assert AgentPublicKeyJwk.__required_keys__ == frozenset({"kty", "crv", "x"})
        assert set(to_public_key_jwk(self.key.public_key_hex)) == AgentPublicKeyJwk.__required_keys__


class TestBase58btc:
    def test_leading_zeros_and_round_trips(self) -> None:
        assert encode_base58btc(b"") == ""
        assert encode_base58btc(b"\x00") == "1"
        assert encode_base58btc(b"\x00\x00\x01\x02\x03") == "11Ldp"
        assert encode_base58btc(b"Hello") == "9Ajdvzr"
        assert decode_base58btc("") == b""
        assert decode_base58btc("111") == b"\x00\x00\x00"
        assert decode_base58btc("11Ldp") == b"\x00\x00\x01\x02\x03"
        key = b"\xed\x01" + bytes([42] * 32)
        assert decode_base58btc(encode_base58btc(key)) == key
        for bad in ("0invalid", "testO", "testI", "testl"):
            with pytest.raises(ValueError, match="Invalid base58 character"):
                decode_base58btc(bad)


class TestResolve:
    key = generate_agent_key()
    raw = bytes.fromhex(key.public_key_hex)
    jwk = to_public_key_jwk(key.public_key_hex)
    did_key = to_did_key(key.public_key_hex)
    did_web = "did:web:agents.example.com:agents:abc"
    kid = f"{did_web}#key-1"
    document = {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
        "id": did_web,
        "alsoKnownAs": [did_key],
        "verificationMethod": [
            {"id": kid, "type": "Ed25519VerificationKey2020", "controller": did_web, "publicKeyJwk": jwk, "publicKeyMultibase": did_key[len("did:key:"):]}
        ],
        "authentication": [kid],
        "assertionMethod": [kid],
    }

    def served(self, document: Any = None, expect_url: str = "https://agents.example.com/agents/abc/did.json") -> Any:
        calls: List[str] = []

        def fetch_json(url: str) -> Any:
            calls.append(url)
            assert url == expect_url
            return self.document if document is None else document

        fetch_json.calls = calls  # type: ignore[attr-defined]
        return fetch_json

    def test_did_key_locally_and_did_web_over_the_network_give_the_same_key(self) -> None:
        from_key = resolve_did(self.did_key)
        multibase = self.did_key[len("did:key:"):]
        assert from_key.raw_key == self.raw
        assert from_key.kid == f"{self.did_key}#{multibase}"
        assert from_key.jwk == {**self.jwk, "kid": from_key.kid}
        assert from_key.document == did_key_document(self.did_key)
        assert resolve_did_key(self.did_key) == from_key

        fetch = self.served()
        from_web = resolve_did(self.did_web, fetch_json=fetch)
        assert from_web.raw_key == from_key.raw_key
        assert from_web.jwk["x"] == from_key.jwk["x"]
        assert from_web.jwk == {**self.jwk, "kid": self.kid}
        assert from_web.kid == self.kid
        assert from_web.document == self.document
        assert fetch.calls == ["https://agents.example.com/agents/abc/did.json"]

    def test_did_key_document_has_the_reference_shape(self) -> None:
        multibase = self.did_key[len("did:key:"):]
        assert did_key_document(self.did_key) == {
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
            "id": self.did_key,
            "verificationMethod": [
                {"id": f"{self.did_key}#{multibase}", "type": "Ed25519VerificationKey2020", "controller": self.did_key, "publicKeyJwk": self.jwk, "publicKeyMultibase": multibase}
            ],
            "authentication": [f"{self.did_key}#{multibase}"],
            "assertionMethod": [f"{self.did_key}#{multibase}"],
        }

    def test_selects_the_method_a_kid_names_in_any_form(self) -> None:
        assert resolve_did_web(self.did_web, kid="key-1", fetch_json=self.served()).kid == self.kid
        assert resolve_did(self.did_web, kid="#key-1", fetch_json=self.served()).kid == self.kid
        assert resolve_did(self.did_web, kid=self.kid, fetch_json=self.served()).kid == self.kid
        with pytest.raises(InvalidJWSError) as refused:
            resolve_did(self.did_web, kid="key-2", fetch_json=self.served())
        assert refused.value.reason == "jws_key_not_found"
        with pytest.raises(InvalidJWSError):
            resolve_did_key(self.did_key, kid="key-1")

    def test_reads_embedded_and_relative_assertion_methods(self) -> None:
        embedded = {"id": self.did_web, "assertionMethod": [{"id": "#k", "type": "Ed25519VerificationKey2020", "controller": self.did_web, "publicKeyJwk": self.jwk}]}
        assert key_from_document(embedded, self.did_web).kid == f"{self.did_web}#k"
        relative = {"id": self.did_web, "verificationMethod": [{"id": "#k", "controller": self.did_web, "publicKeyJwk": self.jwk}], "assertionMethod": ["#k"]}
        assert key_from_document(relative, self.did_web).raw_key == self.raw
        for empty in ({"id": self.did_web, "assertionMethod": []}, {"id": self.did_web}, {"id": self.did_web, "assertionMethod": [7]}, {"id": self.did_web, "assertionMethod": [{"id": 3}]}, "text"):
            with pytest.raises(ValidationError, match="no assertion method"):
                key_from_document(empty, self.did_web)

    def test_refuses_malformed_did_key_and_other_methods(self) -> None:
        with pytest.raises(ValidationError):
            resolve_did_key("did:key:z6MkNOTVALIDbase58!!!!")
        with pytest.raises(ValidationError):
            resolve_did_key("did:key:z")
        with pytest.raises(UnsupportedDIDMethodError):
            did_key_document("did:web:example.com")
        with pytest.raises(UnsupportedDIDMethodError):
            resolve_did_web(self.did_key)
        with pytest.raises(UnsupportedDIDMethodError):
            resolve_did("did:hedera:testnet:abc")
        with pytest.raises(ValidationError):
            resolve_did(42)  # type: ignore[arg-type]

    def test_refuses_a_document_of_another_id_or_shape(self) -> None:
        with pytest.raises(ValidationError, match="Invalid DID document"):
            resolve_did(self.did_web, fetch_json=self.served({**self.document, "id": "did:web:evil.example.com"}))
        with pytest.raises(ValidationError, match="Invalid DID document"):
            resolve_did(self.did_web, fetch_json=self.served({**self.document, "verificationMethod": "none"}))
        with pytest.raises(ValidationError, match="Invalid DID document"):
            resolve_did(self.did_web, fetch_json=self.served("not a document"))

    def test_did_web_to_url_mirrors_helix_core(self) -> None:
        assert did_web_to_url("did:web:example.com") == "https://example.com/.well-known/did.json"
        assert did_web_to_url("did:web:example.com:agents:a:b") == "https://example.com/agents/a/b/did.json"
        assert did_web_to_url("did:web:example.com%3A8443:agents:a") == "https://example.com:8443/agents/a/did.json"
        assert did_web_to_url("did:web:localhost%3A3000:agents:a") == "http://localhost:3000/agents/a/did.json"
        assert did_web_to_url("did:web:127.0.0.1:3680:agents:a") == "http://127.0.0.1:3680/agents/a/did.json"
        assert did_web_to_url("did:web:localhost") == "http://localhost/.well-known/did.json"
        assert did_web_to_url("did:web:LOCALHOST:services:s") == "http://LOCALHOST/services/s/did.json"
        for bad in ("did:web:", "did:web", "did:key:z", "web:example.com"):
            with pytest.raises(ValidationError, match="Invalid did:web"):
                did_web_to_url(bad)

    def test_default_fetch_goes_over_http_and_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import requests

        class Response:
            def __init__(self, ok: bool, status_code: int, payload: Any) -> None:
                self.ok, self.status_code, self._payload = ok, status_code, payload

            def json(self) -> Any:
                return self._payload

        seen: List[Any] = []

        def fake_get(url: str, headers: Dict[str, str], timeout: int) -> Response:
            seen.append((url, headers["accept"], timeout))
            return Response(url.endswith("abc/did.json"), 200 if url.endswith("abc/did.json") else 404, self.document)

        monkeypatch.setattr(requests, "get", fake_get)
        assert resolve_did(self.did_web).raw_key == self.raw
        assert seen == [("https://agents.example.com/agents/abc/did.json", "application/did+json, application/json", 10)]
        with pytest.raises(ValidationError, match="HTTP 404"):
            resolve_did("did:web:agents.example.com:agents:nobody")

    def test_cross_border_rule_resolution_imports_no_client_or_http_adapter(self) -> None:
        source = inspect.getsource(did_resolver_module)
        for forbidden in ("client", "http_adapter", "HelixClient", "wallet", "sqlite", "prisma"):
            assert f"import {forbidden}" not in source and f"from .{forbidden}" not in source, forbidden


class TestEnvSignerKidForms:
    did = "did:web:agents.example.com:agents:abc"
    env = {"K": "44" * 32}

    def test_fragment_hash_fragment_or_full_id_all_announce_did_hash_fragment(self) -> None:
        for kid in ("key-1", "#key-1", f"{self.did}#key-1"):
            signer = EnvSigner(self.did, kid=kid, env_var="K", env=self.env)
            assert signer.kid == "key-1"
            assert signer.verification_method_id == f"{self.did}#key-1"
            jws = sign_jws({"iss": self.did}, signer)
            assert verify_jws(jws, to_public_key_jwk(signer.public_key_hex())).kid == f"{self.did}#key-1"

    @pytest.mark.parametrize("kid", ["did:web:other.example.com#key-1", "did:web:agents.example.com:agents:abc#", ""])
    def test_refuses_another_dids_id_and_an_empty_fragment(self, kid: str) -> None:
        with pytest.raises(ValueError, match="fragment of this DID"):
            EnvSigner(self.did, kid=kid, env_var="K", env=self.env)


# ── 2. the cross-language fixture ─────────────────────────────────────────────


class TestHelixDidFixtures:
    """fixtures/kya-os-helix/did.json, generated by helix-core."""

    @pytest.mark.parametrize("entry", _fixture_list("kya-os-helix/did.json", "keys"), ids=lambda e: e[0])
    def test_same_seed_gives_the_same_public_forms_as_helix_core(self, entry: Any) -> None:
        _name, key = entry
        raw = bytes.fromhex(key["public_key_hex"])
        assert agent_public_key(key["private_key_hex"]).hex() == key["public_key_hex"]
        assert to_public_key_jwk(key["public_key_hex"]) == key["public_key_jwk"]
        assert to_did_key(key["public_key_hex"]) == key["did_key"]
        assert "z" + encode_base58btc(b"\xed\x01" + raw) == key["public_key_multibase"]
        assert public_key_from_did_key(key["did_key"]) == raw
        assert key["kid"] == f"{key['did_web']}#{key['kid_fragment']}"
        assert did_key_document(key["did_key"]) == key["did_key_document"]

    @pytest.mark.parametrize("entry", _fixture_list("kya-os-helix/did.json", "keys"), ids=lambda e: e[0])
    def test_did_web_and_did_key_resolve_identically_and_a_jws_carries_the_kid(self, entry: Any) -> None:
        _name, key = entry
        via_web = resolve_did(key["did_web"], fetch_json=lambda _url: key["did_web_document"])
        via_key = resolve_did(key["did_key"])
        assert via_web.raw_key.hex() == key["resolved"]["raw_key_hex"]
        assert via_key.raw_key.hex() == key["resolved"]["raw_key_hex"]
        assert {k: via_web.jwk[k] for k in ("kty", "crv", "x")} == key["resolved"]["jwk"]
        assert {k: via_key.jwk[k] for k in ("kty", "crv", "x")} == key["resolved"]["jwk"]
        assert via_web.kid == key["resolved"]["did_web_kid"]
        assert via_key.kid == key["resolved"]["did_key_kid"]

        signer = EnvSigner(key["did_web"], kid=key["kid_fragment"], env_var="FIXTURE_KEY", env={"FIXTURE_KEY": key["private_key_hex"]})
        jws = sign_jws({"iss": key["did_web"], "sub": "fixture"}, signer)
        assert verify_jws_by_kid(jws, lambda did: key["did_web_document"] if did == key["did_web"] else None).kid == key["kid"]
        assert verify_jws(jws, via_web.jwk).kid == key["kid"]

    def test_base58btc_vectors(self) -> None:
        for vector in _load_or_skip("kya-os-helix/did.json")["base58btc"]:
            assert encode_base58btc(bytes.fromhex(vector["bytes_hex"])) == vector["base58btc"], vector
            assert decode_base58btc(vector["base58btc"]).hex() == vector["bytes_hex"], vector

    def test_did_key_rejections(self) -> None:
        for rejection in _load_or_skip("kya-os-helix/did.json")["did_key_rejections"]:
            assert public_key_from_did_key(rejection["did"]) is None, rejection["name"]


# ── 3. the vendored KYA-OS vectors ────────────────────────────────────────────


class TestKyaOsVectors:
    @pytest.mark.parametrize("vector", _fixture_list("kya-os/conformance/vectors/did-key-resolution.json", "vectors"), ids=lambda v: v["id"])
    def test_did_key_resolution(self, vector: Dict[str, Any]) -> None:
        did = vector["input"]["did"]
        if vector["expected"] == "pass":
            resolved = resolve_did_key(did)
            assert len(resolved.raw_key) == 32
            assert resolved.kid == f"{did}#{did[len('did:key:'):]}"
            assert resolved.jwk == {"kty": "OKP", "crv": "Ed25519", "x": _b64url(resolved.raw_key), "kid": resolved.kid}
            assert decode_base58btc(did[len("did:key:z"):]) == b"\xed\x01" + resolved.raw_key
            assert to_did_key(resolved.raw_key) == did
        else:
            assert public_key_from_did_key(did) is None
            with pytest.raises((ValidationError, UnsupportedDIDMethodError)):
                resolve_did_key(did)

    @pytest.mark.parametrize("vector", _fixture_list("kya-os/conformance/vectors/did-web-resolution.json", "vectors"), ids=lambda v: v["id"])
    def test_did_web_resolution(self, vector: Dict[str, Any]) -> None:
        did = vector["input"]["did"]
        document = vector["input"].get("didDocument")

        def fetch_json(url: str) -> Any:
            assert url == "https://agent.example.com/.well-known/did.json"
            if document is None:
                raise ValidationError("did:web resolution failed with HTTP 404")
            return document

        if vector["expected"] == "pass":
            resolved = resolve_did(did, fetch_json=fetch_json)
            method = document["verificationMethod"][0]
            assert resolved.kid == method["id"]
            assert resolved.jwk == {"kty": "OKP", "crv": "Ed25519", "x": method["publicKeyJwk"]["x"], "kid": method["id"]}
            assert decode_base58btc(method["publicKeyMultibase"][1:]) == b"\xed\x01" + resolved.raw_key
        else:
            with pytest.raises(ValidationError):
                resolve_did(did, fetch_json=fetch_json)


# ── 4. registering the key ──────────────────────────────────────────────────


def test_an_agent_key_registers_through_enrollment_only() -> None:
    """helix_init sends the public JWK with a proof of possession; the L1-A key route is gone."""
    assert not hasattr(HelixClient, "register_agent_key")
