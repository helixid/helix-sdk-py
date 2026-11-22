# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story C-C over helix-core's fixtures/kya-os-helix/request-proof.json,
generated with helix-sdk-js's verifier on the F-2 environment: the section
11.2 order, the carrier keys (canonical, legacy, canonical wins) and chains
verified without a proof. helix-sdk-js runs the same cases; every one must
come to the recorded verdict, level, scopes, reasons, chain summary, agent
DID, proof floor, proof assurance and warnings.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from helix_sdk.verifier import VerifierOptions, read_carried_chain, read_request_proof, verify
from verifier_harness import core_fixtures_dir, fixture_seams, have_verifier_fixtures, load_environment

FIXTURE = core_fixtures_dir() / "kya-os-helix" / "request-proof.json"
PRESENT = have_verifier_fixtures() and FIXTURE.exists()
pytestmark = pytest.mark.skipif(not PRESENT, reason=f"no helix-core fixtures at {FIXTURE} (set HELIX_CORE_FIXTURES_DIR)")


def _cases() -> List[Dict[str, Any]]:
    if not PRESENT:
        return []
    return json.loads(FIXTURE.read_text("utf-8"))["cases"]


CASES = _cases()


def test_holds_the_order_carrier_key_and_chain_without_proof_cases() -> None:
    assert len(CASES) >= 25
    for prefix in ("order_", "canonical_key", "legacy_key", "chain_without_proof_"):
        assert any(case["name"].startswith(prefix) for case in CASES), prefix


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_case_comes_to_the_recorded_verdict(case: Dict[str, Any]) -> None:
    inputs = case["input"]
    if "meta" in inputs:
        # The carrier keys: the proof and the chain read from _meta the way the middleware reads them.
        proof = read_request_proof(inputs["meta"])
        chain = read_carried_chain(inputs["meta"])
    else:
        proof = inputs.get("proof")
        chain = inputs.get("chain")
    result = verify(
        proof,
        fixture_seams(load_environment(), case["seams"], case["now"]),
        VerifierOptions.from_dict(case["options"]),
        chain=chain,
        request=inputs.get("request"),
        card=inputs.get("card"),
    )
    comparable: Dict[str, Any] = {**result.to_dict(), "proofFloor": result.proof_floor, "warnings": list(result.warnings)}
    if result.agent_did is not None:
        comparable["agentDid"] = result.agent_did
    if result.proof_assurance is not None:
        comparable["proofAssurance"] = result.proof_assurance
    assert comparable == case["expected"]
