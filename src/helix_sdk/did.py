# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
did:web/did:key DID document construction, ported from helix-sdk-js's
cli/src/core/did.ts. Used by the CLI's offline `did create --method web`
flow -- online DID creation (did:hedera, and any API-registered DID) goes
through HelixClient.create_did() instead.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .keys import multibase_to_public_key_hex, public_key_to_multibase


def build_did_document(
    did: str, public_key_hex: str, service_endpoints: Optional[List[Dict[str, str]]] = None
) -> Dict[str, Any]:
    verification_method_id = f"{did}#key-1"
    multibase = public_key_to_multibase(public_key_hex)

    document: Dict[str, Any] = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        "controller": did,
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": multibase,
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
    }
    if service_endpoints:
        document["service"] = service_endpoints
    return document


def extract_public_key_from_did_document(document: Dict[str, Any]) -> str:
    for method in document.get("verificationMethod", []):
        if method.get("type") == "Ed25519VerificationKey2020":
            return multibase_to_public_key_hex(method["publicKeyMultibase"])
    raise ValueError("DID document contains no Ed25519VerificationKey2020 verification method")


def build_service_endpoints(domains: List[str]) -> List[Dict[str, str]]:
    return [
        {"id": f"#domain-{i + 1}", "type": "LinkedDomains", "serviceEndpoint": domain}
        for i, domain in enumerate(domains)
    ]
