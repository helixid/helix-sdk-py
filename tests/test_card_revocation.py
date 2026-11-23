# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The card's own revocation entry (SPEC-ENTITY-CARD section 10.3; Cleanup, Harish's pick A):
the paths the shared fixtures do not reach, as the JS twin card-revocation.test.ts."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List

import pytest

from helix_sdk.verifier import ReasonCodes, RevocationVerdict, VerifierOptions, verify
from verifier_harness import fixture_seams, have_verifier_fixtures, load_cases, load_environment

pytestmark = pytest.mark.skipif(not have_verifier_fixtures(), reason="helix-core verifier fixtures not found")


def _run(**seams: Any) -> Any:
    env = load_environment()
    case = next(c for c in load_cases()["status"] if c["name"] == "live_card")
    base = fixture_seams(env, case["seams"], case["now"])
    inputs = case["input"]
    return verify(
        inputs.get("proof"),
        dataclasses.replace(base, **seams),
        VerifierOptions.from_dict(case["options"]),
        chain=inputs.get("chain"),
        request=inputs.get("request"),
        card=inputs.get("card"),
    ), inputs["card"]


def test_is_read_through_the_revocation_seam_and_stays_fresh_when_read_live() -> None:
    seen: List[Dict[str, Any]] = []

    def check(credential: Dict[str, Any], _context: Any) -> RevocationVerdict:
        seen.append(dict(credential))
        return RevocationVerdict(False, True)

    result, card = _run(check_revocation=check)
    assert (result.ok, result.fresh) == (True, True)
    assert {"issuer": card["id"], "credentialStatus": {"type": "BitstringStatusListEntry", "statusPurpose": "revocation", **card["revocation"]}} in seen


def test_refuses_with_no_seam_a_throwing_checker_and_a_verdict_with_no_code() -> None:
    result, card = _run(fetch_status_list=None, check_revocation=None)
    assert result.reasons[0] == ReasonCodes.STATUS_SEAM_MISSING

    def throwing(credential: Dict[str, Any], _context: Any) -> RevocationVerdict:
        if credential["issuer"] == card["id"]:
            raise RuntimeError("boom")
        return RevocationVerdict(False, True)

    result, _ = _run(check_revocation=throwing)
    assert (result.ok, result.reasons[0]) == (False, ReasonCodes.STATUS_UNAVAILABLE)

    def bare(credential: Dict[str, Any], _context: Any) -> RevocationVerdict:
        return RevocationVerdict(True, False) if credential["issuer"] == card["id"] else RevocationVerdict(False, True)

    result, _ = _run(check_revocation=bare)
    assert (result.reasons[0], result.messages[0]) == (ReasonCodes.STATUS_REVOKED, "the card's revocation entry: revoked")
