# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""L1-B: helix_sdk.crypto.jcs against RFC 8785, the vendored KYA-OS
conformance suite and helix-core's generated fixture set.

The suite and the fixture set live in helix-core (stories rules 5, 6 and 23)
and are read from the sibling checkout, ``../helix-core`` next to this
repository, or from ``HELIX_CORE_DIR`` when set. Tests that need them skip
with a message when neither is present; the edge-case tests below need
nothing and cover the module on their own.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

from helix_sdk.crypto.jcs import CanonicalJsonError, canonicalize, hash_json

BS = chr(0x5C)


def _esc(hex4: str) -> str:
    return BS + "u" + hex4


def _helix_core_dir() -> Path:
    override = os.environ.get("HELIX_CORE_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "helix-core"


def _core_fixture(relative: str) -> Any:
    path = _helix_core_dir() / "fixtures" / relative
    if not path.is_file():
        pytest.skip(f"{path} not found: check out helix-core next to this repository or set HELIX_CORE_DIR")
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _vectors(name: str) -> List[Dict[str, Any]]:
    return _core_fixture(f"kya-os/conformance/vectors/{name}")["vectors"]


def covered_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """The covered request of SPEC 7.3: method and params minus _meta, arguments minus _kyaos*."""
    covered: Dict[str, Any] = {"method": request["method"]}
    if "params" in request:
        params = {name: value for name, value in request["params"].items() if name != "_meta"}
        if request["method"] == "tools/call":
            params["arguments"] = {
                name: value for name, value in params.get("arguments", {}).items() if not name.startswith("_kyaos")
            }
        covered["params"] = params
    return covered


def response_hash(data: Any, profile: Any) -> str:
    if profile == "org.kya-os/response-proof.envelope":
        return hash_json({name: value for name, value in data.items() if name != "_meta"})
    return hash_json(data)


def jws_payload(jws: str) -> Dict[str, Any]:
    segment = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


class TestCanonicalize:
    def test_scalars(self) -> None:
        assert canonicalize(None) == "null"
        assert canonicalize(True) == "true"
        assert canonicalize(False) == "false"
        assert canonicalize("text") == '"text"'
        assert canonicalize(42) == "42"
        assert canonicalize(-1) == "-1"
        assert canonicalize([]) == "[]"
        assert canonicalize({}) == "{}"
        assert canonicalize(()) == "[]"

    def test_sorts_members_and_keeps_array_order_at_every_depth(self) -> None:
        assert canonicalize({"zeta": 1, "alpha": 2, "mid": 3}) == '{"alpha":2,"mid":3,"zeta":1}'
        nested = {"outer": {"z": [{"b": 2, "a": 1}], "a": {"d": None, "c": (3, 1, 2)}}, "": 0}
        assert canonicalize(nested) == '{"":0,"outer":{"a":{"c":[3,1,2],"d":null},"z":[{"a":1,"b":2}]}}'
        assert canonicalize({"10": 1, "9": 2, "Alpha": 3, "_u": 4, "alpha": 5}) == '{"10":1,"9":2,"Alpha":3,"_u":4,"alpha":5}'

    def test_sorts_member_names_by_utf16_code_units(self) -> None:
        value = {
            "€": "Euro Sign",
            chr(0x0D): "Carriage Return",
            chr(0xFB33): "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "😀": "Emoji: Grinning Face",
            chr(0x80): "Control",
            "ö": "Latin Small Letter O With Diaeresis",
        }
        order = [chr(0x0D), "1", chr(0x80), "ö", "€", "😀", chr(0xFB33)]
        assert list(json.loads(canonicalize(value))) == order
        # Non-BMP before U+FB01: the surrogate pair sorts first (the suite's code-point-sorted-keys vector).
        assert canonicalize({"ﬁ": 1, "😀": 2}) == '{"😀":2,"ﬁ":1}'

    def test_number_layout_follows_ecmascript(self) -> None:
        assert (
            canonicalize([-0.0, 1e-7, 1e21 / 1e6, 0.1 + 0.2, 333333333.33333329, 5e-324, 100.0, 0.000001, 1e-5])
            == "[0,1e-7,1000000000000000,0.30000000000000004,333333333.3333333,5e-324,100,0.000001,0.00001]"
        )
        assert (
            canonicalize([9007199254740991, -9007199254740991, 9007199254740991.0, 2.220446049250313e-16, -2.5, 4.5, 2e-3, 1e-27])
            == "[9007199254740991,-9007199254740991,9007199254740991,2.220446049250313e-16,-2.5,4.5,0.002,1e-27]"
        )
        assert canonicalize([0.0, 0.5, 123.456, 1234567890123456.7, 1e15, 0.001, 1.5e-6, 12345678.9e-3]) == (
            "[0,0.5,123.456,1234567890123456.8,1000000000000000,0.001,0.0000015,12345.6789]"
        )

    def test_escapes_strings_like_json_stringify(self) -> None:
        value = chr(0) + chr(0x1F) + '"' + BS + "/" + chr(0x7F) + chr(0x2028) + "€😀"
        assert canonicalize(value) == (
            '"' + _esc("0000") + _esc("001f") + BS + '"' + BS + BS + "/" + chr(0x7F) + chr(0x2028) + '€😀"'
        )
        assert canonicalize(chr(8) + chr(12) + chr(10) + chr(13) + chr(9)) == '"' + BS + "b" + BS + "f" + BS + "n" + BS + "r" + BS + 't"'

    def test_rfc8785_appendix_sample(self) -> None:
        sample = {
            "numbers": [333333333.33333329, 4.5, 2e-3, 0.000000000000000000000000001],
            "string": "€$" + chr(0x0F) + chr(0x0A) + "A'B\"" + BS + BS + '"/',
            "literals": [None, True, False],
        }
        assert canonicalize(sample) == (
            '{"literals":[null,true,false],"numbers":[333333333.3333333,4.5,0.002,1e-27],"string":"€$'
            + _esc("000f") + BS + "nA'B" + BS + '"' + BS + BS + BS + BS + BS + '"/"}'
        )

    def test_reuse_is_not_a_cycle(self) -> None:
        leaf = {"a": 1}
        assert canonicalize([leaf, {"x": leaf}, leaf]) == '[{"a":1},{"x":{"a":1}},{"a":1}]'

    @pytest.mark.parametrize(
        ("value", "message"),
        [
            (float("nan"), "Cannot canonicalize a non-finite number (nan) at $"),
            ([float("inf")], "Cannot canonicalize a non-finite number (inf) at $[0]"),
            ({"n": float("-inf")}, "Cannot canonicalize a non-finite number (-inf) at $.n"),
            (2**53, "Cannot canonicalize an integer outside the safe range (9007199254740992) at $"),
            (-(2**53), "Cannot canonicalize an integer outside the safe range (-9007199254740992) at $"),
            (1e21, "Cannot canonicalize an integer outside the safe range (1e+21) at $"),
            (float(2**53), "Cannot canonicalize an integer outside the safe range (9007199254740992.0) at $"),
            ({"a": object()}, "Cannot canonicalize a object at $.a"),
            ([1, [b"bytes"]], "Cannot canonicalize a bytes at $[1][0]"),
            ({"s": {1, 2}}, "Cannot canonicalize a set at $.s"),
            ({1: "one"}, "Cannot canonicalize a non-string member name (1) at $"),
            ({"a": {None: 1}}, "Cannot canonicalize a non-string member name (None) at $.a"),
            ("a" + chr(0xD83D), "Cannot canonicalize a string with a lone surrogate at $"),
            ({"s": chr(0xDC00) + "b"}, "Cannot canonicalize a string with a lone surrogate at $.s"),
            ({chr(0xD800): 1}, "Cannot canonicalize a string with a lone surrogate at $." + chr(0xD800)),
        ],
        ids=lambda item: item if isinstance(item, str) else "",
    )
    def test_refuses_values_with_no_single_json_form(self, value: Any, message: str) -> None:
        with pytest.raises(CanonicalJsonError) as excinfo:
            canonicalize(value)
        assert str(excinfo.value) == message
        assert isinstance(excinfo.value, TypeError)
        with pytest.raises(CanonicalJsonError):
            hash_json(value)

    def test_refuses_cycles_by_path(self) -> None:
        obj: Dict[str, Any] = {"a": 1}
        obj["self"] = {"back": obj}
        with pytest.raises(CanonicalJsonError, match=r"a cyclic reference at \$\.self\.back"):
            canonicalize(obj)
        arr: List[Any] = [1]
        arr.append(arr)
        with pytest.raises(CanonicalJsonError, match=r"a cyclic reference at \$\[1\]"):
            canonicalize(arr)


class TestHashJson:
    def test_format_and_known_values(self) -> None:
        assert hash_json({}) == "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        assert hash_json({"b": "€", "a": 1}) == hash_json({"a": 1, "b": "€"})
        assert hash_json({"a": 1}) != hash_json({"a": 1.0000001})
        digest = hash_json({"b": "€", "a": 1})
        assert digest.startswith("sha256:") and len(digest) == 71 and digest[7:] == digest[7:].lower()

    def test_spec_appendix_c1(self) -> None:
        empty_args = "sha256:5057521f310b536837b619f0ac040ef8064f8c597da8ec22a56801b435744033"
        msg_hi = "sha256:c8f3d59959c9247211de8c76b94ef17f0c279f09362350ced67f69ecdb89d6c7"
        plain = {"method": "tools/call", "params": {"name": "echo", "arguments": {}}}
        assert canonicalize(plain) == '{"method":"tools/call","params":{"arguments":{},"name":"echo"}}'
        assert hash_json(plain) == empty_args
        with_control = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {"_kyaos_proof": {"jws": "...", "meta": {}}},
                "_meta": {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
            },
        }
        assert hash_json(covered_request(with_control)) == empty_args
        assert hash_json(covered_request({"method": "tools/call", "params": {"name": "echo"}})) == empty_args
        business = covered_request(
            {
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"msg": "hi", "_kyaos_delegation": {"id": "urn:uuid:1111-aaaa"}}, "_meta": {"progressToken": 7}},
            }
        )
        assert canonicalize(business) == '{"method":"tools/call","params":{"arguments":{"msg":"hi"},"name":"echo"}}'
        assert hash_json(business) == msg_hi
        assert hash_json(covered_request({"method": "tools/call"})) == hash_json({"method": "tools/call"})


class TestVendoredSuite:
    def test_pin_holds_suite_1_10_0_at_the_pinned_vector_set_hash(self) -> None:
        manifest = _core_fixture("kya-os/conformance/SUITE-MANIFEST.json")
        vectors_dir = _helix_core_dir() / "fixtures" / "kya-os" / "conformance" / "vectors"
        files = []
        count = 0
        for name in sorted(path.name for path in vectors_dir.glob("*.json")):
            data = (vectors_dir / name).read_bytes()
            count += len(json.loads(data)["vectors"])
            files.append([name, hashlib.sha256(data).hexdigest()])
        assert files == [list(entry) for entry in manifest["files"]]
        assert count == manifest["vectorCount"]
        assert manifest["suiteVersion"] == "1.10.0"
        vector_set_hash = "sha256:" + hashlib.sha256(canonicalize(files).encode("utf-8")).hexdigest()
        assert vector_set_hash == "sha256:6dd5e3dd0526b0fb7e7e3ea9e76b63a3acd0651aeb36ee03ea1f820bb15ebed0"
        assert vector_set_hash == manifest["vectorSetHash"]

    def test_audit_integrity_canonicalization_vectors(self) -> None:
        checked = [vector for vector in _vectors("audit-integrity.json") if vector["input"].get("canonicalization")]
        assert checked
        for vector in checked:
            case = vector["input"]["canonicalization"]
            # A fail vector supplies a canonical form a conformant implementation must not produce.
            assert (canonicalize(case["value"]) == case["canonical"]) is (vector["expected"] == "pass"), vector["id"]

    def test_audit_events_canonicalize_to_event_canonical(self) -> None:
        for vector in _vectors("audit-integrity.json"):
            assert canonicalize(vector["input"]["event"]) == vector["input"]["eventCanonical"], vector["id"]

    HASH_FAILURES = {
        "signed-proof/envelope-tampered-structured-content",
        "signed-proof/delegation-proof-request-hash-altered",
        "signed-proof/delegation-proof-request-substituted",
    }

    def test_signed_proof_hash_part(self) -> None:
        checked = [vector for vector in _vectors("signed-proof.json") if vector["input"].get("expected", {}).get("request")]
        assert len(checked) > 30
        disagreeing = set()
        for vector in checked:
            proof = vector["input"]["proof"]
            expected = vector["input"]["expected"]
            profile = jws_payload(proof["jws"]).get("prf")
            agree = hash_json(covered_request(expected["request"])) == proof["meta"]["requestHash"]
            if "response" in expected:
                agree = agree and response_hash(expected["response"]["data"], profile) == proof["meta"].get("responseHash")
            else:
                assert "responseHash" not in proof["meta"], vector["id"]
            if not agree:
                disagreeing.add(vector["id"])
            if vector["expected"] == "pass":
                assert agree, f"{vector['id']}: hashes must agree on a pass vector"
        assert disagreeing == self.HASH_FAILURES

    def test_valid_basic_request_hash_is_the_covered_request(self) -> None:
        basic = next(vector for vector in _vectors("signed-proof.json") if vector["id"] == "signed-proof/valid-basic")
        request = {"method": "tools/call", "params": {"name": "echo", "arguments": {"msg": "hi"}}}
        assert basic["input"]["proof"]["meta"]["requestHash"] == hash_json(request)
        assert basic["input"]["proof"]["meta"]["requestHash"] != hash_json({"method": "echo", "params": {"msg": "hi"}})


class TestHelixFixture:
    def test_matches_helix_core_byte_for_byte(self) -> None:
        file = _core_fixture("kya-os-helix/jcs.json")
        assert len(file["vectors"]) >= 14
        for vector in file["vectors"]:
            assert canonicalize(vector["input"]) == vector["canonical"], vector["name"]
            assert hash_json(vector["input"]) == vector["hash"], vector["name"]
