# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story F-2 test helpers for helix_mcp_middleware, the Python twin of
helix-sdk-js mcp-middleware/tests/proof-helpers.ts: an agent that mints
request proofs, and a local verifier whose seams read the shared fixture
environment (helix-core fixtures/verifier/environment.json, the sibling
checkout or ``HELIX_CORE_FIXTURES_DIR``), so a test can present a real signed
chain and an attested card without a network."""

from __future__ import annotations

import secrets
from typing import Any, Dict, Mapping, Optional

from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.did import build_did_document
from helix_sdk.keys import derive_public_key
from helix_sdk.verifier import (
    DELEGATION_CHAIN_META_KEY,
    LEGACY_REQUEST_PROOF_META_KEY,
    REQUEST_PROOF_META_KEY,
    StatusListRead,
    decode_status_list_bits,
    did_key_document,
    sign_request_proof,
)
from helix_mcp_middleware import LocalVerifierOptions, MemoryNonceStore

from verifier_harness import have_verifier_fixtures, load_cases, load_environment

NOW_MS = 1_780_272_000_000  # 2026-06-01T00:00:00Z, the fixtures' clock

__all__ = [
    "NOW_MS",
    "have_verifier_fixtures",
    "load_cases",
    "load_environment",
    "fixture_signer",
    "fixture_verifier_options",
    "make_agent",
    "proof_meta",
    "valid_chain",
]


def fixture_signer(env: Mapping[str, Any], label: str) -> EnvSigner:
    key = env["keys"][label]
    # The fixture names its own kid (its did_documents publish the W3C #<multibase> method); sign under it.
    return EnvSigner(key["did"], kid=key["kid"].split("#", 1)[1], env_var="FIXTURE_KEY", env={"FIXTURE_KEY": key["private_key_hex"]})


def make_agent(did: str = "did:web:agent.helix.test") -> Dict[str, Any]:
    """An agent of its own, with a did:web document the verifier resolves through ``documents``."""
    private_key = secrets.token_hex(32)
    public_key = derive_public_key(private_key)
    return {
        "did": did,
        "signer": EnvSigner(did, env_var="AGENT_KEY", env={"AGENT_KEY": private_key}),
        "document": build_did_document(did, public_key),
    }


def _status_list(entry: Mapping[str, Any]) -> StatusListRead:
    return StatusListRead(
        bits=decode_status_list_bits(entry["encoded_list"]),
        issuer=entry.get("issuer"),
        status_purpose=entry.get("status_purpose"),
        id=entry.get("id"),
        valid_from=entry.get("valid_from"),
        valid_until=entry.get("valid_until"),
        fresh=entry.get("fresh", True),
    )


def fixture_verifier_options(service_did: Optional[str], env: Optional[Mapping[str, Any]] = None, documents: Optional[Mapping[str, Any]] = None, **settings: Any) -> LocalVerifierOptions:
    """Local verifier settings over the fixture environment plus any extra documents, with a fixed clock."""
    known: Dict[str, Any] = {**((env or {}).get("did_documents") or {}), **(documents or {})}
    lists = (env or {}).get("status_lists") or {}

    def resolve_did(did: str) -> Any:
        return known.get(did) or did_key_document(did)

    def fetch_status_list(url: str) -> Optional[StatusListRead]:
        entry = lists.get(url)
        return None if entry is None else _status_list(entry)

    defaults: Dict[str, Any] = {
        "service_did": service_did,
        "clock": lambda: NOW_MS,
        "nonce_store": MemoryNonceStore(now=lambda: NOW_MS / 1000),
        "resolve_did": resolve_did,
        "fetch_status_list": fetch_status_list,
        "report_verification": lambda entry: None,
    }
    return LocalVerifierOptions(**{**defaults, **settings})


def proof_meta(
    signer: Any,
    audience: str,
    name: str,
    arguments: Optional[Mapping[str, Any]] = None,
    chain: Any = None,
    now_ms: int = NOW_MS,
    legacy_key: bool = False,
) -> Dict[str, Any]:
    """The ``_meta`` of a tool call: the request proof minted at ``now_ms``, and the chain when given."""
    params: Dict[str, Any] = {"name": name}
    if arguments is not None:
        params["arguments"] = dict(arguments)
    proof = sign_request_proof({"method": "tools/call", "params": params}, signer, audience=audience, now_ms=now_ms)
    meta: Dict[str, Any] = {LEGACY_REQUEST_PROOF_META_KEY if legacy_key else REQUEST_PROOF_META_KEY: proof}
    if chain is not None:
        meta[DELEGATION_CHAIN_META_KEY] = chain
    return meta


def valid_chain(name: str = "two_hop_chain") -> Any:
    """The carried chain of a valid fixture case."""
    for case in load_cases()["valid"]:
        if case["name"] == name:
            return case["input"]["chain"]
    raise LookupError(name)  # pragma: no cover - a fixture name typo
