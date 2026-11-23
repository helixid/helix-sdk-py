# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Story L3-C in Python: status-list readers (proof before bits, both formats,
both proof suites), the keeper, the revocation checker (fail closed, cached,
stale reads demoted), the chain walk, the status cache (key and JSON shapes
shared with the JavaScript cache) and the revocation signal (RFC 8417 SET).
"""

from __future__ import annotations

import base64
import gzip
import json
from dataclasses import replace
from typing import Any, Dict, List, Optional, Tuple

import nacl.signing
import pytest

from helix_sdk.credentials import parse_date_time, sign_data_integrity
from helix_sdk.crypto.jcs import canonicalize
from helix_sdk.crypto.jws import EnvSigner, sign_jws
from helix_sdk.keys import generate_key_pair, public_key_to_multibase
from helix_sdk.verifier import (
    NO_STATUS_CONFIGURATION,
    REVOCATION_EVENT_TYPE,
    MemoryStatusCacheStore,
    ReasonCodes,
    RevocationContext,
    RevocationVerdict,
    SignalReasons,
    StatusCache,
    StatusListError,
    StatusListRead,
    VerdictKey,
    CachedVerdict,
    check_chain_revocation,
    create_revocation_checker,
    create_status_list_fetcher,
    did_key_document,
    is_calendar_date_time,
    keeper,
    may_omit_list_id,
    read_bitstring_status_list,
    read_status_bit,
    read_status_list_2021,
    read_status_list_credential,
    revocation_checker_of,
    sign_revocation_signal,
    status_configuration,
    status_list_format,
    verify,
    verify_revocation_signal,
)
from helix_sdk.verifier.status import parse_status_bound
from verifier_harness import fixture_seams, have_verifier_fixtures, load_cases, load_environment

URL_A = "https://status.example.com/v1/status-list/a"
NOW = parse_date_time("2026-06-01T00:00:00Z")
assert NOW is not None


class Issuer:
    def __init__(self) -> None:
        pair = generate_key_pair()
        self.private_key = pair.private_key
        self.did = "did:key:" + public_key_to_multibase(pair.public_key)
        self.fragment = self.did[len("did:key:") :]
        self.kid = f"{self.did}#{self.fragment}"
        self.signer = EnvSigner(self.did, kid=self.fragment, env_var="K", env={"K": pair.private_key})


def resolve_did_key(did: str) -> Optional[Dict[str, Any]]:
    return did_key_document(did)


def encode_bits(data: bytes, multibase: bool = True) -> str:
    encoded = base64.urlsafe_b64encode(gzip.compress(data)).decode().rstrip("=")
    return "u" + encoded if multibase else encoded


def bits_with(length: int, set_bits: Tuple[int, ...] = ()) -> bytes:
    out = bytearray(length)
    for index in set_bits:
        out[index // 8] |= 0x80 >> (index % 8)
    return bytes(out)


def unsigned_list(url: str, issuer: Issuer, bits: bytes = bits_with(16), kind: str = "bitstring", purpose: Any = "revocation", valid_from: str = "2026-01-01T00:00:00Z", valid_until: Optional[str] = "2027-01-01T00:00:00Z", omit_id: bool = False) -> Dict[str, Any]:
    bitstring = kind == "bitstring"
    document: Dict[str, Any] = {
        "@context": ["https://www.w3.org/ns/credentials/v2"] if bitstring else ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/vc/status-list/2021/v1"],
        "type": ["VerifiableCredential", "BitstringStatusListCredential" if bitstring else "StatusList2021Credential"],
        "issuer": issuer.did,
        "credentialSubject": {"id": f"{url}#list", "type": "BitstringStatusList" if bitstring else "StatusList2021", "statusPurpose": purpose, "encodedList": encode_bits(bits)},
    }
    if not omit_id:
        document["id"] = url
    if bitstring:
        document["validFrom"] = valid_from
        if valid_until is not None:
            document["validUntil"] = valid_until
    else:
        document["issuanceDate"] = valid_from
        if valid_until is not None:
            document["expirationDate"] = valid_until
    return document


def signed_list(url: str, issuer: Issuer, **kwargs: Any) -> Dict[str, Any]:
    return sign_data_integrity(unsigned_list(url, issuer, **kwargs), issuer.signer, created="2026-01-01T00:00:00Z")


def sign_legacy(document: Dict[str, Any], issuer: Issuer) -> Dict[str, Any]:
    signature = nacl.signing.SigningKey(bytes.fromhex(issuer.private_key)).sign(canonicalize(document).encode("utf-8")).signature
    proof = {"type": "Ed25519Signature2020", "created": "2026-01-01T00:00:00Z", "verificationMethod": issuer.kid, "proofPurpose": "assertionMethod", "proofValue": base64.urlsafe_b64encode(signature).decode().rstrip("=")}
    return {**document, "proof": proof}


def entry_for(url: str, index: int, purpose: str = "revocation") -> Dict[str, Any]:
    return {"id": f"{url}#{index}", "type": "BitstringStatusListEntry", "statusPurpose": purpose, "statusListIndex": str(index), "statusListCredential": url}


class ServingFetch:
    def __init__(self, bodies: Dict[str, Any]) -> None:
        self.bodies = bodies
        self.calls: List[str] = []

    def __call__(self, url: str) -> Tuple[int, Any]:
        self.calls.append(url)
        body = self.bodies.get(url)
        if body is None:
            return 404, None
        if isinstance(body, int):
            return body, None
        return 200, body


def read_error(fn: Any, *args: Any, **kwargs: Any) -> StatusListError:
    with pytest.raises(StatusListError) as info:
        fn(*args, **kwargs)
    return info.value


# ── readers ──────────────────────────────────────────────────────────────────

ISSUER = Issuer()
OTHER = Issuer()


def test_reads_a_signed_bitstring_list() -> None:
    read = read_bitstring_status_list(signed_list(URL_A, ISSUER, bits=bits_with(4, (3,))), resolve_did_key)
    assert (read.issuer, read.status_purpose, read.id, read.fresh, read.proof_verified) == (ISSUER.did, "revocation", URL_A, True, True)
    assert read_status_bit(read.bits, 3) == 1 and read_status_bit(read.bits, 4) == 0
    many = unsigned_list(URL_A, ISSUER, purpose=["revocation", "suspension"])
    many["credentialSubject"]["encodedList"] = encode_bits(bits_with(2), multibase=False)
    read = read_status_list_credential(sign_data_integrity(many, ISSUER.signer), resolve_did_key, fresh=False)
    assert read.status_purpose == ["revocation", "suspension"] and read.fresh is False


def test_reads_status_list_2021_under_both_proof_suites() -> None:
    document = unsigned_list(URL_A, ISSUER, kind="statuslist2021", bits=bits_with(2, (9,)))
    for signed in (sign_data_integrity(document, ISSUER.signer), sign_legacy(document, ISSUER)):
        read = read_status_list_2021(signed, resolve_did_key)
        assert (read.issuer, read.valid_from, read.valid_until) == (ISSUER.did, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
        assert read_status_bit(read.bits, 9) == 1


def test_never_reads_an_unsigned_badly_signed_or_foreign_list() -> None:
    assert read_error(read_bitstring_status_list, unsigned_list(URL_A, ISSUER), resolve_did_key).code == ReasonCodes.STATUS_LIST_PROOF_INVALID
    tampered = signed_list(URL_A, ISSUER)
    tampered["credentialSubject"]["encodedList"] = encode_bits(bits_with(16, (1,)))
    assert "signature_invalid" in str(read_error(read_bitstring_status_list, tampered, resolve_did_key))
    forged = sign_data_integrity(unsigned_list(URL_A, OTHER), OTHER.signer)
    forged["issuer"] = ISSUER.did
    assert "proof_issuer_mismatch" in str(read_error(read_bitstring_status_list, forged, resolve_did_key))
    legacy_forged = sign_legacy(unsigned_list(URL_A, ISSUER, kind="statuslist2021"), OTHER)
    assert read_error(read_status_list_2021, legacy_forged, resolve_did_key).code == ReasonCodes.STATUS_LIST_PROOF_INVALID


def test_refuses_proofs_it_cannot_check() -> None:
    document = unsigned_list(URL_A, ISSUER)
    assert "no single proof object" in str(read_error(read_bitstring_status_list, {**document, "proof": "x"}, resolve_did_key))
    assert "not one a status list" in str(read_error(read_bitstring_status_list, {**document, "proof": {"type": "RsaSignature2018"}}, resolve_did_key))
    assert "no issuer DID" in str(read_error(read_bitstring_status_list, {**document, "issuer": "nobody", "proof": {"type": "DataIntegrityProof"}}, resolve_did_key))
    legacy = sign_legacy(unsigned_list(URL_A, ISSUER, kind="statuslist2021"), ISSUER)

    def down(_did: str) -> Any:
        raise RuntimeError("resolver down")

    assert "resolver down" in str(read_error(read_status_list_2021, legacy, down))
    assert "did not resolve" in str(read_error(read_status_list_2021, legacy, lambda _did: None))


@pytest.mark.parametrize(
    "document,reader,words",
    [
        (None, read_bitstring_status_list, "not a JSON object"),
        ("2021", read_bitstring_status_list, "BitstringStatusListCredential"),
        ("bitstring", read_status_list_2021, "StatusList2021Credential"),
        ({"type": ["VerifiableCredential"], "credentialSubject": {}}, read_status_list_credential, "neither"),
        ("empty-purpose", read_bitstring_status_list, "statusPurpose"),
        ("array-2021", read_status_list_2021, "one statusPurpose"),
        ("no-list", read_bitstring_status_list, "encodedList"),
        ("bad-id", read_bitstring_status_list, "id is not a string"),
        ("feb-30", read_bitstring_status_list, "validUntil is not"),
        ("date-only", read_bitstring_status_list, "validFrom is not"),
        ("not-gzip", read_bitstring_status_list, "does not inflate"),
    ],
)
def test_refuses_lists_of_the_wrong_shape(document: Any, reader: Any, words: str) -> None:
    def signed(raw: Dict[str, Any]) -> Dict[str, Any]:
        return sign_data_integrity(raw, ISSUER.signer)

    no_list = unsigned_list(URL_A, ISSUER)
    del no_list["credentialSubject"]["encodedList"]
    not_gzip = unsigned_list(URL_A, ISSUER)
    not_gzip["credentialSubject"]["encodedList"] = "u" + base64.urlsafe_b64encode(b"plain").decode().rstrip("=")
    built = {
        "2021": lambda: signed(unsigned_list(URL_A, ISSUER, kind="statuslist2021")),
        "bitstring": lambda: signed(unsigned_list(URL_A, ISSUER)),
        "empty-purpose": lambda: signed(unsigned_list(URL_A, ISSUER, purpose=[])),
        "array-2021": lambda: signed(unsigned_list(URL_A, ISSUER, kind="statuslist2021", purpose=["revocation"])),
        "no-list": lambda: signed(no_list),
        "bad-id": lambda: signed({**unsigned_list(URL_A, ISSUER), "id": 7}),
        "feb-30": lambda: signed(unsigned_list(URL_A, ISSUER, valid_until="2027-02-30T00:00:00Z")),
        "date-only": lambda: signed(unsigned_list(URL_A, ISSUER, valid_from="2026-01-01")),
        "not-gzip": lambda: signed(not_gzip),
    }
    value = built[document]() if isinstance(document, str) else document
    error = read_error(reader, value, resolve_did_key)
    assert error.code == ReasonCodes.STATUS_LIST_MALFORMED
    assert words in str(error)


def test_dates_and_formats() -> None:
    assert is_calendar_date_time("2028-02-29T00:00:00+05:30")
    assert not is_calendar_date_time("2027-02-29T00:00:00Z")
    assert not is_calendar_date_time("2027-01-01T00:00:60Z")
    assert not is_calendar_date_time("2027-01-01T00:00:00")
    assert parse_status_bound("2026-01-01T05:30:00.123456789+05:30") == parse_date_time("2026-01-01T00:00:00.123456Z")
    assert status_list_format("x") is None
    assert status_list_format({"type": "x", "credentialSubject": {}}) is None


def test_fetcher_reads_over_the_injected_fetch_and_fails_closed() -> None:
    fetch = ServingFetch({URL_A: signed_list(URL_A, ISSUER), "https://down.example/l": 503})
    fetch_status_list = create_status_list_fetcher(fetch, resolve_did_key)
    assert fetch_status_list(URL_A).proof_verified is True
    error = read_error(fetch_status_list, "https://down.example/l")
    assert error.code == ReasonCodes.STATUS_UNAVAILABLE and "503" in str(error)

    def refuse(_url: str) -> Tuple[int, Any]:
        raise RuntimeError("refused: private address")

    assert "private address" in str(read_error(create_status_list_fetcher(refuse, resolve_did_key), URL_A))


# ── keeper ───────────────────────────────────────────────────────────────────


def test_keeper_rules() -> None:
    config = status_configuration(
        {
            "statusListIssuers": {"did:web:svc": ["https://svc.example"], "did:web:exact": ["https://svc.example/one"]},
            "trustedRootIssuer": "did:web:root",
            "trustedRootStatusList": "https://root.example/l",
        }
    )
    assert keeper("https://svc.example/one", "did:web:o", config) == ("did:web:exact", False)
    assert keeper("https://svc.example/two", "did:web:o", config) == ("did:web:svc", False)
    assert keeper("https://svc.example.evil/x", "did:web:o", config) == ("did:web:o", True)
    assert keeper("https://root.example/l", "did:web:o", config) == ("did:web:root", True)
    assert not may_omit_list_id("https://o.example/l", "did:web:o", config)
    assert may_omit_list_id("https://o.example/l", "did:web:o", NO_STATUS_CONFIGURATION)
    assert may_omit_list_id("https://o.example/l", "did:web:o", status_configuration({"trustedRootIssuer": "did:web:o"}))
    assert not may_omit_list_id("https://o.example/l", "did:web:o", status_configuration({"trustedRootIssuer": "did:web:r"}))
    assert not may_omit_list_id("https://svc.example/x", "did:web:o", config)
    with pytest.raises(ValueError):
        status_configuration({"trustedRootIssuer": ""})


# ── the checker ──────────────────────────────────────────────────────────────


class Setup:
    def __init__(self, lists: Dict[str, Any], cache_options: Optional[Dict[str, Any]] = None, **extra: Any) -> None:
        self.fetch = ServingFetch(dict(lists))
        self.now = NOW
        self.cache = None if cache_options is None else StatusCache(clock=lambda: self.now, **cache_options)
        self.checker = create_revocation_checker(create_status_list_fetcher(self.fetch, resolve_did_key), cache=self.cache, **extra)

    def check(self, index: int, scopes: Tuple[str, ...] = (), live: bool = False, **overrides: Any) -> RevocationVerdict:
        credential = {"id": f"urn:uuid:cred-{index}", "issuer": ISSUER.did, "credentialStatus": entry_for(URL_A, index), **overrides}
        return self.checker(credential, RevocationContext(now_ms=self.now, scopes=scopes, live=live))


def test_clear_bit_live_and_fresh_set_bit_revoked() -> None:
    setup = Setup({URL_A: signed_list(URL_A, ISSUER, bits=bits_with(16, (5,)))})
    assert setup.check(4) == RevocationVerdict(False, True)
    assert setup.check(5).revoked and setup.check(5).code == ReasonCodes.STATUS_REVOKED


def test_fails_closed() -> None:
    tampered = signed_list(URL_A, ISSUER)
    tampered["credentialSubject"]["encodedList"] = encode_bits(bits_with(16, (1,)))
    service = Issuer()
    cases: List[Tuple[Any, int, Dict[str, Any], str]] = [
        (None, 1, {}, ReasonCodes.STATUS_UNAVAILABLE),
        (unsigned_list(URL_A, ISSUER), 1, {}, ReasonCodes.STATUS_LIST_PROOF_INVALID),
        (tampered, 1, {}, ReasonCodes.STATUS_LIST_PROOF_INVALID),
        (signed_list(URL_A, ISSUER, purpose="suspension"), 1, {}, ReasonCodes.STATUS_LIST_MISMATCH),
        (signed_list(URL_A, ISSUER, bits=bits_with(1)), 9, {}, ReasonCodes.STATUS_ENTRY_MALFORMED),
        (signed_list(URL_A, ISSUER, valid_until="2026-05-01T00:00:00Z"), 1, {}, ReasonCodes.STATUS_STALE),
        (signed_list(URL_A, service), 1, {}, ReasonCodes.STATUS_LIST_MISMATCH),
        (signed_list(URL_A, ISSUER), 1, {"credentialStatus": {**entry_for(URL_A, 1), "statusSize": 2}}, ReasonCodes.STATUS_ENTRY_MALFORMED),
        (signed_list(URL_A, ISSUER), 1, {"credentialStatus": {**entry_for(URL_A, 1), "statusListIndex": "-1"}}, ReasonCodes.STATUS_ENTRY_MALFORMED),
        (signed_list(URL_A, ISSUER), 1, {"credentialStatus": None}, ReasonCodes.STATUS_ENTRY_MALFORMED),
    ]
    for body, index, overrides, code in cases:
        setup = Setup({} if body is None else {URL_A: body})
        verdict = setup.check(index, **overrides)
        assert (verdict.revoked, verdict.fresh, verdict.code) == (True, False, code), code


def test_keeper_bound_service_and_pinned_root() -> None:
    service = Issuer()
    bound = {"status_list_issuers": {service.did: ["https://status.example.com"]}}
    assert Setup({URL_A: signed_list(URL_A, service)}, **bound).check(1) == RevocationVerdict(False, True)
    assert Setup({URL_A: signed_list(URL_A, ISSUER)}, **bound).check(1).code == ReasonCodes.STATUS_LIST_MISMATCH
    assert Setup({URL_A: signed_list(URL_A, service, omit_id=True)}, **bound).check(1).code == ReasonCodes.STATUS_LIST_MISMATCH
    with pytest.raises(ValueError):
        create_revocation_checker(lambda _url: None, status_list_issuers={"a": ["https://x/"]})
    root = Issuer()
    checker = create_revocation_checker(create_status_list_fetcher(ServingFetch({URL_A: signed_list(URL_A, root)}), resolve_did_key), trusted_root_issuer=root.did)
    hop = {"id": "urn:uuid:h", "issuer": ISSUER.did, "credentialStatus": entry_for(URL_A, 3)}
    assert checker(hop, RevocationContext(now_ms=NOW, root={"issuer": root.did, "statusListCredential": URL_A})) == RevocationVerdict(False, True)
    assert checker(hop, RevocationContext(now_ms=NOW, root={"issuer": root.did, "statusListCredential": "https://other.example/l"})).revoked


def test_cached_reads_are_not_fresh_and_ttl_ends_them() -> None:
    setup = Setup({URL_A: signed_list(URL_A, ISSUER)}, {"status_cache_ttl": 120})
    assert setup.check(1) == RevocationVerdict(False, True)
    assert setup.check(1) == RevocationVerdict(False, False)
    assert setup.check(2) == RevocationVerdict(False, False)
    assert len(setup.fetch.calls) == 1
    setup.now += 121_000
    assert setup.check(1) == RevocationVerdict(False, True)


def test_live_requests_read_past_the_cache_and_refresh_it() -> None:
    setup = Setup({URL_A: signed_list(URL_A, ISSUER)}, {"status_cache_ttl": 120})
    assert setup.check(3) == RevocationVerdict(False, True)
    assert setup.check(3) == RevocationVerdict(False, False)
    # The list changes: a live request sees it at once, while the cache still says "clear".
    setup.fetch.bodies[URL_A] = signed_list(URL_A, ISSUER, bits=bits_with(16, (3,)))
    verdict = setup.check(3, live=True)
    assert (verdict.revoked, verdict.fresh, verdict.code) == (True, False, ReasonCodes.STATUS_REVOKED)
    assert setup.check(4, live=True) == RevocationVerdict(False, True)
    assert len(setup.fetch.calls) == 3
    # The live reads refreshed the cache: a cached request now reads the new verdict and list.
    assert setup.check(3).code == ReasonCodes.STATUS_REVOKED
    assert setup.check(5) == RevocationVerdict(False, False)
    assert len(setup.fetch.calls) == 3


def test_high_privilege_ttl_and_live_reads_within_one_verification() -> None:
    setup = Setup({URL_A: signed_list(URL_A, ISSUER)}, {"status_cache_ttl": 300, "high_privilege_scopes": ["orders:admin"]})
    setup.check(1, scopes=("orders:read",))
    setup.now += 61_000
    assert setup.check(1, scopes=("orders:read",)) == RevocationVerdict(False, False)
    assert setup.check(1, scopes=("orders:admin",)) == RevocationVerdict(False, True)
    reads: Dict[str, StatusListRead] = {}
    fresh = Setup({URL_A: signed_list(URL_A, ISSUER)}, {})
    for index in (1, 2):
        credential = {"id": f"urn:uuid:r-{index}", "issuer": ISSUER.did, "credentialStatus": entry_for(URL_A, index)}
        assert fresh.checker(credential, RevocationContext(now_ms=NOW, reads=reads)) == RevocationVerdict(False, True)
    assert len(fresh.fetch.calls) == 1


def test_caches_revoked_not_unreadable() -> None:
    setup = Setup({URL_A: signed_list(URL_A, ISSUER, bits=bits_with(16, (1,)))}, {})
    assert setup.check(1).code == ReasonCodes.STATUS_REVOKED
    assert setup.check(1).code == ReasonCodes.STATUS_REVOKED
    assert len(setup.fetch.calls) == 1
    unread = Setup({URL_A: 500}, {})
    assert unread.check(1).code == ReasonCodes.STATUS_UNAVAILABLE
    unread.fetch.bodies[URL_A] = signed_list(URL_A, ISSUER)
    assert unread.check(1) == RevocationVerdict(False, True)


def test_stale_list_served_only_within_the_staleness_window() -> None:
    setup = Setup({URL_A: signed_list(URL_A, ISSUER, valid_until="2026-06-01T00:01:00Z")}, {"status_cache_ttl": 600, "max_stale_seconds": 120, "max_clock_skew_ms": 0})
    assert setup.check(1) == RevocationVerdict(False, True)
    setup.now += 90_000
    assert setup.check(2) == RevocationVerdict(False, False)
    setup.now += 120_000
    assert setup.check(3).code == ReasonCodes.STATUS_STALE


def test_invalidate_drops_the_verdict_and_list_or_every_list() -> None:
    setup = Setup({URL_A: signed_list(URL_A, ISSUER)}, {"status_cache_ttl": 300})
    assert setup.check(1) == RevocationVerdict(False, True)
    setup.fetch.bodies[URL_A] = signed_list(URL_A, ISSUER, bits=bits_with(16, (1, 2)))
    assert setup.check(1) == RevocationVerdict(False, False)
    assert setup.cache.invalidate("urn:uuid:cred-1") == "credential"
    assert setup.check(1).code == ReasonCodes.STATUS_REVOKED
    assert setup.cache.invalidate("urn:uuid:never-seen") == "all-lists"
    assert setup.check(2).code == ReasonCodes.STATUS_REVOKED
    assert setup.cache.invalidate("urn:uuid:cred-1") == "credential"


def test_no_verdict_without_an_id_and_a_mismatched_verdict_is_a_miss() -> None:
    setup = Setup({URL_A: signed_list(URL_A, ISSUER)}, {})
    setup.check(1, id=None)
    setup.check(1, id=None)
    assert len(setup.fetch.calls) == 1
    setup.check(1)
    assert setup.check(1, credentialStatus=entry_for(URL_A, 2)) == RevocationVerdict(False, False)


def test_plain_checker_and_a_raising_seam() -> None:
    checker = revocation_checker_of(lambda _url: StatusListRead(bits=bits_with(1, (0,))))
    assert checker({"issuer": "did:web:o", "credentialStatus": entry_for(URL_A, 0)}, RevocationContext(now_ms=NOW)).code == ReasonCodes.STATUS_REVOKED

    def boom(_url: str) -> StatusListRead:
        raise RuntimeError("down")

    assert revocation_checker_of(boom)({"issuer": "did:web:o", "credentialStatus": entry_for(URL_A, 0)}, RevocationContext(now_ms=NOW)).code == ReasonCodes.STATUS_UNAVAILABLE


# ── the chain walk ───────────────────────────────────────────────────────────

HOPS = [{"id": f"urn:uuid:hop-{i}", "issuer": f"did:web:i{i}", "credentialStatus": entry_for(f"https://s.example/{i}", i)} for i in range(3)]


def test_chain_walk_stops_at_the_first_revoked_hop() -> None:
    seen: List[str] = []

    def checker(hop: Any, _context: RevocationContext) -> RevocationVerdict:
        seen.append(hop["id"])
        return RevocationVerdict(True, False, ReasonCodes.STATUS_REVOKED, "gone") if hop["id"] == "urn:uuid:hop-1" else RevocationVerdict(False, True)

    result = check_chain_revocation(HOPS, checker, RevocationContext(now_ms=NOW))
    assert (result.revoked, result.fresh, result.index, result.code, result.message) == (True, False, 1, ReasonCodes.STATUS_REVOKED, "gone")
    assert seen == ["urn:uuid:hop-0", "urn:uuid:hop-1"]


def test_chain_walk_fresh_root_and_raising_check() -> None:
    roots: List[Any] = []

    def mixed(hop: Any, context: RevocationContext) -> RevocationVerdict:
        roots.append(context.root)
        return RevocationVerdict(False, hop["id"] != "urn:uuid:hop-2")

    assert check_chain_revocation(HOPS, mixed, RevocationContext(now_ms=NOW)).fresh is False
    assert roots[0] == {"issuer": "did:web:i0", "statusListCredential": "https://s.example/0"}

    def boom(_hop: Any, _context: RevocationContext) -> RevocationVerdict:
        raise RuntimeError("boom")

    result = check_chain_revocation(HOPS, boom, RevocationContext(now_ms=NOW))
    assert (result.revoked, result.index, result.code) == (True, 0, ReasonCodes.STATUS_UNAVAILABLE)
    assert check_chain_revocation(HOPS, lambda _h, _c: RevocationVerdict(True, False), RevocationContext(now_ms=NOW)).code == ReasonCodes.STATUS_REVOKED
    assert check_chain_revocation([], boom, RevocationContext(now_ms=NOW)).revoked is False


# ── the cache ────────────────────────────────────────────────────────────────


def test_cache_settings() -> None:
    with pytest.raises(ValueError, match="at most 60"):
        StatusCache(high_privilege_ttl=61)
    with pytest.raises(ValueError, match="positive"):
        StatusCache(status_cache_ttl=0)
    with pytest.raises(ValueError, match="non-negative"):
        StatusCache(max_stale_seconds=-1)
    with pytest.raises(ValueError, match="600000"):
        StatusCache(max_clock_skew_ms=700_000)
    cache = StatusCache(status_cache_ttl=30, high_privilege_scopes=["admin"])
    assert cache.high_privilege_ttl == 30 and cache.ttl_for(["admin"]) == 30
    assert StatusCache(high_privilege_ttl=10, high_privilege_scopes=["admin"]).ttl_for(["admin", "read"]) == 10
    assert StatusCache().ttl_for() == 300


def test_cache_keys_and_json_match_the_javascript_cache() -> None:
    store = MemoryStatusCacheStore(lambda: NOW)
    cache = StatusCache(store=store, clock=lambda: NOW)
    cache.set_list(URL_A, StatusListRead(bits=b"\x00\x01", issuer="did:web:o", status_purpose="revocation", id=URL_A, valid_from="2026-01-01T00:00:00Z", valid_until="2027-01-01T00:00:00Z", fresh=True, proof_verified=True))
    raw = store.get(f"kyaos:status:list:0:{URL_A}")
    assert raw == '{"bits":"AAE=","issuer":"did:web:o","statusPurpose":"revocation","id":"' + URL_A + '","validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z","readAt":' + str(NOW) + "}"
    key = VerdictKey("c", URL_A, "1", "revocation", "did:web:o", "did:web:o")
    cache.set_verdict(key, CachedVerdict(False))
    assert store.get("kyaos:status:verdict:c") == '{"revoked":false,"fingerprint":"[\\"' + URL_A + '\\",\\"1\\",\\"revocation\\",\\"did:web:o\\",\\"did:web:o\\"]","url":"' + URL_A + '","readAt":' + str(NOW) + "}"
    assert cache.get_list(URL_A) == StatusListRead(bits=b"\x00\x01", issuer="did:web:o", status_purpose="revocation", id=URL_A, valid_from="2026-01-01T00:00:00Z", valid_until="2027-01-01T00:00:00Z", fresh=False, proof_verified=True)


def test_cache_keeps_only_servable_reads_and_reads_corrupt_entries_as_misses() -> None:
    store = MemoryStatusCacheStore(lambda: NOW)
    cache = StatusCache(store=store, clock=lambda: NOW)
    read = StatusListRead(bits=bits_with(2), proof_verified=True, fresh=True, valid_until="2027-01-01T00:00:00Z")
    cache.set_list(URL_A, replace(read, proof_verified=False))
    cache.set_list(URL_A, replace(read, fresh=False))
    cache.set_list(URL_A, replace(read, valid_until="not a date"))
    cache.set_list(URL_A, replace(read, valid_until="2026-01-01T00:00:00Z"))
    assert len(store) == 0
    store.set(f"kyaos:status:list:0:{URL_A}", "{not json", 1000)
    assert cache.get_list(URL_A) is None
    key = VerdictKey("c", URL_A, "1", "revocation", "did:web:o", "did:web:o")
    cache.set_verdict(key, CachedVerdict(True, "status_revoked", "gone"))
    assert cache.get_verdict(key) == CachedVerdict(True, "status_revoked", "gone")
    store.set("kyaos:status:verdict:c", "{not json", 1000)
    assert cache.get_verdict(key) is None
    assert cache.invalidate("c") == "all-lists"
    store.set("kyaos:status:verdict:d", json.dumps({"fingerprint": "x"}), 1000)
    assert cache.invalidate("d") == "all-lists"


def test_memory_store() -> None:
    now = [0]
    store = MemoryStatusCacheStore(lambda: now[0])
    store.set("k", "v", 10)
    assert store.get("k") == "v"
    now[0] = 11
    assert store.get("k") is None
    assert store.increment("n") == 1
    store.set("bad", "x", 100)
    assert store.increment("bad") == 1
    store.delete("n")
    assert store.get("n") is None


# ── the signal ───────────────────────────────────────────────────────────────

HELIX = Issuer()
STRANGER = Issuer()


def _verify(set_jwt: Any, **kwargs: Any) -> Any:
    return verify_revocation_signal(set_jwt, trusted_issuers=[HELIX.did], resolve_did=resolve_did_key, now_ms=NOW, **kwargs)


def test_signal_signs_and_verifies() -> None:
    set_jwt = sign_revocation_signal("urn:uuid:c1", HELIX.signer, jti="urn:uuid:j1", iat=NOW // 1000, aud="did:web:svc")
    header = json.loads(base64.urlsafe_b64decode(set_jwt.split(".")[0] + "=="))
    assert header == {"alg": "EdDSA", "kid": HELIX.kid, "typ": "secevent+jwt"}
    payload = json.loads(base64.urlsafe_b64decode(set_jwt.split(".")[1] + "=="))
    assert payload == {"iss": HELIX.did, "iat": NOW // 1000, "jti": "urn:uuid:j1", "aud": "did:web:svc", "events": {REVOCATION_EVENT_TYPE: {"subject": {"format": "uri", "uri": "urn:uuid:c1"}}}}
    verdict = _verify(set_jwt)
    assert verdict.ok and verdict.signal.credential_id == "urn:uuid:c1" and verdict.signal.aud == "did:web:svc"
    assert verify_revocation_signal(sign_revocation_signal("urn:uuid:c2", HELIX.signer), [HELIX.did], resolve_did_key).ok
    with pytest.raises(TypeError):
        sign_revocation_signal("", HELIX.signer)


def test_signal_from_an_unknown_issuer_or_with_a_bad_signature_is_ignored() -> None:
    assert _verify(sign_revocation_signal("c", STRANGER.signer, iat=NOW // 1000)).reason == SignalReasons.UNKNOWN_ISSUER

    class Forger:
        did = HELIX.did
        kid = HELIX.fragment

        def sign(self, data: bytes) -> bytes:
            return STRANGER.signer.sign(data)

    assert _verify(sign_revocation_signal("c", Forger(), iat=NOW // 1000)).reason == SignalReasons.BAD_SIGNATURE

    def down(_did: str) -> Any:
        raise RuntimeError("down")

    assert verify_revocation_signal(sign_revocation_signal("c", HELIX.signer, iat=NOW // 1000), [HELIX.did], down, now_ms=NOW).reason == SignalReasons.BAD_SIGNATURE


def test_signal_shapes_events_and_age() -> None:
    def encode(value: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    sig = base64.urlsafe_b64encode(bytes(64)).decode().rstrip("=")
    assert _verify(42).reason == SignalReasons.MALFORMED
    assert _verify("a.b").reason == SignalReasons.MALFORMED
    assert _verify("!.!.!").reason == SignalReasons.MALFORMED
    assert _verify(f"{encode({'alg': 'EdDSA', 'kid': HELIX.kid})}.{encode({})}.{sig}").reason == SignalReasons.MALFORMED
    assert _verify(f"{encode({'alg': 'EdDSA', 'kid': HELIX.kid, 'typ': 'secevent+jwt'})}.{encode('x')}.{sig}").reason == SignalReasons.MALFORMED
    assert _verify(f"{encode({'alg': 'EdDSA', 'kid': HELIX.kid, 'typ': 'secevent+jwt'})}.%%%.{sig}").reason == SignalReasons.MALFORMED
    assert _verify(f"{encode({'alg': 'EdDSA', 'kid': HELIX.kid, 'typ': 'secevent+jwt'})}.{encode({'iss': 'helix'})}.{sig}").reason == SignalReasons.MALFORMED
    event = {REVOCATION_EVENT_TYPE: {"subject": {"format": "uri", "uri": "urn:uuid:c"}}}
    base = {"iss": HELIX.did, "iat": NOW // 1000, "jti": "j", "events": event}

    def signed(payload: Dict[str, Any]) -> str:
        return sign_jws(payload, HELIX.signer, header={"typ": "secevent+jwt"})

    assert _verify(signed({**base, "jti": None})).reason == SignalReasons.MALFORMED
    assert _verify(signed({**base, "events": {}})).reason == SignalReasons.WRONG_EVENT
    assert _verify(signed({**base, "events": {**event, "other": {}}})).reason == SignalReasons.WRONG_EVENT
    assert _verify(signed({**base, "events": {REVOCATION_EVENT_TYPE: {"subject": {"format": "email"}}}})).reason == SignalReasons.WRONG_EVENT
    assert _verify(signed({**base, "iat": NOW // 1000 + 3600})).reason == SignalReasons.STALE
    assert _verify(signed({**base, "iat": NOW // 1000 - 2 * 86400})).reason == SignalReasons.STALE


# ── verify() with the seam ───────────────────────────────────────────────────


@pytest.mark.skipif(not have_verifier_fixtures(), reason="helix-core fixtures not found")
def test_verify_live_l3_cached_l2_revoked_refused() -> None:
    env = load_environment()
    case = next(entry for entry in load_cases()["valid"] if entry["name"] == "two_hop_chain")
    now = case["now"]
    plain = fixture_seams(env, case["seams"], now)
    cache = StatusCache(clock=lambda: now)
    checker = create_revocation_checker(plain.fetch_status_list, cache=cache)
    from helix_sdk.verifier import VerifierOptions

    options = VerifierOptions.from_dict(case["options"])
    inputs = case["input"]

    def run(**seam_overrides: Any) -> Any:
        seams = replace(fixture_seams(env, case["seams"], now), **seam_overrides)
        return verify(inputs["proof"], seams, options, chain=inputs.get("chain"), request=inputs.get("request"), card=inputs.get("card"))

    live = run(check_revocation=checker)
    assert (live.ok, live.level, live.fresh) == (True, "L3", True)
    cached = run(check_revocation=checker)
    assert (cached.ok, cached.level, cached.fresh) == (True, "L2", False)
    root_id = inputs["chain"][0]["id"]
    refused = run(check_revocation=lambda hop, _c: RevocationVerdict(True, False, ReasonCodes.STATUS_REVOKED, "root revoked") if hop.get("id") == root_id else RevocationVerdict(False, True))
    assert (refused.ok, refused.reasons) == (False, [ReasonCodes.STATUS_REVOKED])
    assert refused.messages[0].startswith("hop 0: root revoked")
    silent = run(check_revocation=lambda _hop, _c: RevocationVerdict(True, False))
    assert "hop 0: revoked" in silent.messages[0]
