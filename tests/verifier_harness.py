# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The fixture harness of the local verifier (KYA-OS story F-2): reads
helix-core's ``fixtures/verifier/*.json`` (the sibling checkout, or the
directory ``HELIX_CORE_FIXTURES_DIR`` names) and builds each case's seams
from the environment exactly as helix-core's generator and helix-sdk-js's
tests do. Shared by tests/test_verifier.py and e2e-playwright's Python actor.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from helix_sdk.verifier import StatusListRead, VerifierOptions, VerifierSeams, decode_status_list_bits, ed25519_keys_of, verify


def core_fixtures_dir() -> Path:
    override = os.environ.get("HELIX_CORE_FIXTURES_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "helix-core" / "fixtures"


def verifier_fixtures_dir() -> Path:
    return core_fixtures_dir() / "verifier"


def have_verifier_fixtures() -> bool:
    return (verifier_fixtures_dir() / "environment.json").exists()


def load_environment() -> Dict[str, Any]:
    return json.loads((verifier_fixtures_dir() / "environment.json").read_text("utf-8"))


def load_cases() -> Dict[str, List[Dict[str, Any]]]:
    files: Dict[str, List[Dict[str, Any]]] = {}
    for path in sorted(verifier_fixtures_dir().glob("*.json")):
        if path.name == "environment.json":
            continue
        files[path.stem] = json.loads(path.read_text("utf-8"))["cases"]
    return files


class SeamCalls:
    def __init__(self) -> None:
        self.resolve_did: List[str] = []
        self.fetch_status_list: List[str] = []
        self.nonces: List[str] = []


def fixture_seams(env: Dict[str, Any], setting: Dict[str, Any], now_ms: int, calls: Optional[SeamCalls] = None) -> VerifierSeams:
    """The seams of a case, from the environment: the one definition every consumer shares."""
    used_nonces: set = set()
    documents = env["did_documents"]

    def resolve_did(did: str) -> Any:
        if calls is not None:
            calls.resolve_did.append(did)
        if setting["resolveDid"] == "throws":
            raise RuntimeError("resolver down")
        if setting["resolveDid"] == "unknown":
            return None
        return documents.get(did)

    def resolve_did_keys(did: str) -> List[Dict[str, Any]]:
        if setting["resolveDidKeys"] == "throws":
            raise RuntimeError("keys down")
        if setting["resolveDidKeys"] == "empty":
            return []
        document = documents.get(did)
        if document is None:
            raise LookupError(f"no document for {did}")
        return ed25519_keys_of(document)

    def fetch_status_list(url: str) -> Optional[StatusListRead]:
        if calls is not None:
            calls.fetch_status_list.append(url)
        if setting["fetchStatusList"] == "throws":
            raise RuntimeError("status service down")
        entry = env["status_lists"].get(url)
        if entry is None:
            return None
        return StatusListRead(
            bits=decode_status_list_bits(entry["encoded_list"]),
            issuer=entry.get("issuer"),
            status_purpose=entry.get("status_purpose"),
            id=entry.get("id"),
            valid_from=entry.get("valid_from"),
            valid_until=entry.get("valid_until"),
            fresh=entry.get("fresh", True),
        )

    class Store:
        def insert(self, nonce: str, did: Optional[str], expires_at_ms: int) -> bool:
            if calls is not None:
                calls.nonces.append(nonce)
            if setting["nonceStore"] == "throws":
                raise RuntimeError("nonce store down")
            key = f"{did or ''}|{nonce}"
            if setting["nonceStore"] == "replayed" or key in used_nonces:
                return False
            used_nonces.add(key)
            return True

    def resolve_card(_did: str) -> Any:
        if setting["resolveCard"] == "throws":
            raise RuntimeError("card host down")
        return env["cards"].get(setting["resolveCard"])

    return VerifierSeams(
        resolve_did=None if setting["resolveDid"] == "missing" else resolve_did,
        resolve_did_keys=None if setting["resolveDidKeys"] == "missing" else resolve_did_keys,
        fetch_status_list=None if setting["fetchStatusList"] == "missing" else fetch_status_list,
        resolve_card=None if setting["resolveCard"] == "missing" else resolve_card,
        nonce_store=None if setting["nonceStore"] == "missing" else Store(),
        clock=None if setting["clock"] == "missing" else (lambda: now_ms),
        trusted_issuers=setting["trustedIssuers"],
    )


def run_case(env: Dict[str, Any], case: Dict[str, Any], calls: Optional[SeamCalls] = None) -> Dict[str, Any]:
    """One fixture case through the verifier; the comparable part of the result."""
    inputs = case["input"]
    result = verify(
        inputs.get("proof"),
        fixture_seams(env, case["seams"], case["now"], calls),
        VerifierOptions.from_dict(case["options"]),
        chain=inputs.get("chain"),
        request=inputs.get("request"),
        card=inputs.get("card"),
    )
    return result.to_dict()
