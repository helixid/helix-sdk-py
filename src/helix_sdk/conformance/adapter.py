# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The SDK's KYA-OS ``ConformanceAdapter`` (story F-2), the Python twin of
helix-sdk-js ``kyaos/conformance/adapter.ts``: every method answers a vector
with the SDK's own code and fails closed (any error is ``fail``, nothing
raises). ``card-proof`` runs the local verifier itself
(``helix_sdk.verifier.verify``); ``did-key``/``did-web`` its resolvers;
``entity-card`` the strict card schema, the revocation rule and the
accountability JOIN over the verifier's chain rules; ``delegation-chain`` and
``status-list`` the section 6.2 readings; ``signed-proof`` the response proof
and the section 7.8 binding.

The contract is the KYA-OS harness's ``ConformanceAdapter``
(decentralized-identity/kya-os-mcp, conformance/types.ts at a4d7f61, MIT
licensed, Copyright (c) 2026 KYA-OS). Its harness code is not vendored.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Mapping, Optional

from ..verifier import (
    VerifierOptions,
    VerifierSeams,
    create_did_resolver,
    did_key_document,
    did_of_kid,
    ed25519_keys_of,
    evaluate_delegation_chain_rules,
    validate_entity_card,
    verify,
)
from .delegation_binding import chain_digest, delegation_ref
from .legacy import assertion_key, legacy_chain_refusal, verify_vc_jwt
from .response_proof import proof_verifies, request_hash, response_hash
from .status_list import status_list_refusal

AdapterResult = Dict[str, str]
PASS: AdapterResult = {"outcome": "pass"}


def fail(detail: str) -> AdapterResult:
    return {"outcome": "fail", "detail": detail}


def _usable_document(document: Any, did: str) -> bool:
    return isinstance(document, dict) and document.get("id") == did and len(ed25519_keys_of(document)) > 0


class HelixConformanceAdapter:
    """See the module docstring."""

    name = "helixid-sdk-py helix_sdk (story F-2)"

    def __init__(self, now_ms: Optional[Callable[[], float]] = None) -> None:
        self._now = now_ms or (lambda: time.time() * 1000)

    # -- signed-proof --------------------------------------------------------

    def verify_signed_proof(self, value: Mapping[str, Any]) -> AdapterResult:
        try:
            proof = value.get("proof")
            meta = proof.get("meta") if isinstance(proof, dict) else None
            if not isinstance(meta, dict):
                return fail("not a detached proof")
            if "didDocuments" in value:
                did = meta.get("did")
                if not isinstance(did, str):
                    return fail("meta.did is not a DID")
                named = "keyId" in value
                key = assertion_key(value["didDocuments"].get(did), did, value.get("keyId") if named else None, named)
                if key is None:
                    return fail("no assertionMethod key of the signer")
                first = (value["didDocuments"][did].get("assertionMethod") or [None])[0]
                kid = str(value["keyId"]) if named else str(first.get("id") if isinstance(first, dict) else first)
                kid = did + kid if kid.startswith("#") else kid
                from ..crypto.jws import base64url_encode

                jwk: Any = {"kty": "OKP", "crv": "Ed25519", "x": base64url_encode(key), "kid": kid}
            else:
                jwk = value.get("publicKeyJwk")
            refusal = proof_verifies(proof, jwk, value.get("now"), value.get("skewSeconds"))
            if refusal is not None:
                return fail(refusal)
            if "expected" not in value:
                return PASS
            expected = value["expected"]
            if not isinstance(expected, dict):
                return fail("expected is not an object")
            held = response_hash(expected["response"], meta.get("prf")) if "response" in expected else None
            if request_hash(expected["request"]) != meta["requestHash"]:
                return fail("requestHash does not bind the request held")
            chain = expected.get("delegationChain")
            required = expected.get("outcome") or ("allowed" if chain is not None else None)
            if required is not None and (meta.get("outcome") or "allowed") != required:
                return fail(f"the proof states {meta.get('outcome') or 'allowed'}, not {required}")
            if ("responseHash" in meta) != (held is not None):
                return fail("the proof binds a response exactly when one is held")
            if "responseHash" in meta and meta["responseHash"] != held:
                return fail("responseHash does not bind the response held")
            if chain is None:
                return PASS
            if meta.get("delegationChainDigest") is None:
                return fail("the proof binds no chain")
            digest = chain_digest(chain)
            if digest is None:
                return fail("the chain has no signed form")
            if digest != meta["delegationChainDigest"]:
                return fail("delegationChainDigest is not the chain held")
            if (meta.get("delegationRef") or None) != delegation_ref(chain[-1]):
                return fail("delegationRef does not name the presented credential")
            return PASS
        except Exception as exc:  # noqa: BLE001 - fail closed
            return fail(f"refused: {exc}")

    # -- delegation-chain, status-list ----------------------------------------

    def verify_delegation_chain(self, value: Mapping[str, Any]) -> AdapterResult:
        try:
            now = self._now()
            verified = set()
            leaf = value.get("leaf")
            if isinstance(leaf, str):
                read = verify_vc_jwt(leaf, value["didDocuments"], now)
                if "refusal" in read:
                    return fail(read["refusal"])
                leaf = read["credential"]
                verified.add(id(leaf))
            refusal = legacy_chain_refusal([*(value.get("ancestors") or []), leaf], value["serverDid"], value["didDocuments"], now, verified)
            return PASS if refusal is None else fail(refusal)
        except Exception as exc:  # noqa: BLE001
            return fail(f"refused: {exc}")

    def verify_status_list(self, value: Mapping[str, Any]) -> AdapterResult:
        refusal = status_list_refusal(value, self._now())
        return PASS if refusal is None else fail(refusal)

    # -- DID resolution --------------------------------------------------------

    def resolve_did_key(self, value: Mapping[str, Any]) -> AdapterResult:
        did = value.get("did")
        if not isinstance(did, str) or not did.startswith("did:key:"):
            return fail("not a did:key")
        return PASS if _usable_document(did_key_document(did), did) else fail("no usable Ed25519 verification method")

    def resolve_did_web(self, value: Mapping[str, Any]) -> AdapterResult:
        did = value.get("did")
        if not isinstance(did, str) or not did.startswith("did:web:"):
            return fail("not a did:web")

        def fetch(_url: str) -> Any:
            if "didDocument" not in value:
                raise LookupError("not found")
            return value["didDocument"]

        try:
            document = create_did_resolver(fetch)(did)
        except Exception as exc:  # noqa: BLE001
            return fail(f"refused: {exc}")
        return PASS if _usable_document(document, did) else fail("no usable, id-matched document")

    # -- card-proof ------------------------------------------------------------

    def verify_card_proof(self, value: Mapping[str, Any]) -> AdapterResult:
        try:
            keys = [key for key in value["jwks"]["keys"] if isinstance(key.get("kid"), str)]

            def document_of(did: str) -> Optional[Dict[str, Any]]:
                own = [key for key in keys if did_of_kid(key["kid"]) == did]
                if not own:
                    return None
                methods = [
                    {"id": key["kid"], "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": {"kty": key["kty"], "crv": key["crv"], "x": key["x"]}}
                    for key in own
                ]
                return {"id": did, "verificationMethod": methods, "assertionMethod": [method["id"] for method in methods]}

            used: set = set()

            class Store:
                def insert(self, nonce: str, did: Optional[str], expires_at_ms: int) -> bool:
                    key = f"{did or ''}|{nonce}"
                    if key in used:
                        return False
                    used.add(key)
                    return True

            seams = VerifierSeams(
                resolve_did=document_of,
                resolve_did_keys=lambda did: [key for key in keys if did_of_kid(key["kid"]) == did],
                nonce_store=None if value.get("omitNonceSeam") else Store(),
                clock=lambda: value["nowMs"],
            )
            options = VerifierOptions(expected_audience=value["expectedAudience"], skew_seconds=value["skewSeconds"], token_cnf_jkt=value.get("tokenCnfJkt"))
            result = verify(value.get("proof"), seams, options, request=value.get("request"))
            return PASS if result.ok else fail(", ".join(result.reasons))
        except Exception as exc:  # noqa: BLE001
            return fail(f"refused: {exc}")

    # -- entity-card -----------------------------------------------------------

    def verify_entity_card(self, value: Mapping[str, Any]) -> AdapterResult:
        try:
            card = value.get("card")
            problems = validate_entity_card(card)
            if problems:
                return fail("malformed card: " + "; ".join(problems))
            if "responsibleParty" in card:
                accountability = value.get("accountability")
                if not isinstance(accountability, dict):
                    return fail("responsibleParty with no delegation chain to recompute it over")
                rules = evaluate_delegation_chain_rules(
                    accountability["chain"],
                    resource=accountability.get("resource"),
                    resource_owner=accountability.get("resourceOwner"),
                    now_ms=accountability.get("now"),
                    proof_shape="any",
                )
                if not rules.ok:
                    return fail("accountability: " + "; ".join(rules.reasons))
                if card["responsibleParty"] != rules.responsible_party:
                    return fail("responsibleParty is not the root issuer")
                if accountability.get("proofDid") is not None and rules.leaf_invoker != accountability["proofDid"]:
                    return fail("the leaf invoker is not the proof DID")
            if "revocation" in card:
                return fail("configuration_error: revocation declared with no status-list checker")
            return PASS
        except Exception as exc:  # noqa: BLE001
            return fail(f"refused: {exc}")

    def verify_audit_integrity(self, value: Any) -> AdapterResult:
        return fail("audit-integrity is outside story F-2 (story A-1 runs it)")

    def evaluate_negotiation(self, value: Any) -> AdapterResult:
        return fail("negotiation is outside story F-2")


METHOD_FOR_CATEGORY: Dict[str, str] = {
    "signed-proof": "verify_signed_proof",
    "delegation-chain": "verify_delegation_chain",
    "status-list": "verify_status_list",
    "did-key-resolution": "resolve_did_key",
    "did-web-resolution": "resolve_did_web",
    "card-proof": "verify_card_proof",
    "entity-card": "verify_entity_card",
    "audit-integrity": "verify_audit_integrity",
    "negotiation": "evaluate_negotiation",
}

F2_CATEGORIES: List[str] = ["signed-proof", "delegation-chain", "status-list", "did-key-resolution", "did-web-resolution", "card-proof", "entity-card"]
