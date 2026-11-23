# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""F-1 fix: a did:key signer names its own verification method, did:key:z…#z…
(the one a did:key document defines), unless given a kid. Parity with
helix-sdk-js kyaos.defaultKidFragment and helix-core."""

from __future__ import annotations

from helix_sdk import kyaos
from helix_sdk.crypto.jws import DEFAULT_KID_FRAGMENT, EnvSigner, default_kid_fragment, sign_jws, verify_jws_by_kid
from helix_sdk.custody import HelixCustodialSigner, kid_fragment
from helix_sdk.did_resolver import did_key_document
from helix_sdk.keys import derive_public_key, public_key_to_multibase

KEY = "6" * 64
MULTIBASE = public_key_to_multibase(derive_public_key(KEY))
DID_KEY = f"did:key:{MULTIBASE}"
ENV = {"K": KEY}


def test_the_default_is_the_multibase_value_for_a_did_key_and_key_1_otherwise() -> None:
    assert default_kid_fragment(DID_KEY) == MULTIBASE
    assert default_kid_fragment("did:web:helix.example") == DEFAULT_KID_FRAGMENT
    assert default_kid_fragment("did:key:") == DEFAULT_KID_FRAGMENT
    assert kyaos.default_kid_fragment is default_kid_fragment


def test_a_did_key_env_signer_names_its_w3c_method_and_a_jws_verifies_against_its_document() -> None:
    signer = EnvSigner(DID_KEY, env_var="K", env=ENV)
    assert signer.kid == MULTIBASE
    assert signer.verification_method_id == f"{DID_KEY}#{MULTIBASE}"
    verified = verify_jws_by_kid(sign_jws({"sub": "x"}, signer), did_key_document)
    assert verified.kid == f"{DID_KEY}#{MULTIBASE}"


def test_an_explicit_kid_still_wins_and_a_did_web_keeps_key_1() -> None:
    assert EnvSigner(DID_KEY, kid="#key-1", env_var="K", env=ENV).kid == "key-1"
    assert EnvSigner(DID_KEY, kid=f"{DID_KEY}#{MULTIBASE}", env_var="K", env=ENV).kid == MULTIBASE
    assert EnvSigner("did:web:helix.example", env_var="K", env=ENV).kid == "key-1"


def test_the_custody_helpers_use_the_same_default() -> None:
    assert kid_fragment(DID_KEY) == MULTIBASE
    assert kid_fragment("did:web:helix.example") == "key-1"
    assert HelixCustodialSigner(DID_KEY, api_url="http://127.0.0.1:1").kid == MULTIBASE
