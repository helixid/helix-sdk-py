# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Local/offline issuer operations (no API call involved), ported from
helix-sdk-js's cli/src/lib/issuer-ops.ts. Used by the CLI's `status-list
create`, `vc issue`, and `revoke` commands, which are designed to work
fully offline against local status-list and wallet files -- distinct
from HelixClient's issue_vc()/revoke_vc(), which go through helix-api.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Tuple

from helix_sdk.proof import _to_iso_z, create_ed25519_proof

from .status_list import create_status_list, get_bit, get_status_list_length, set_bit


@dataclass
class IssuerKeyMaterial:
    did: str
    private_key_hex: str
    public_key_hex: str


def sign_credential(credential: Dict[str, Any], issuer_did: str, private_key_hex: str) -> Dict[str, Any]:
    signed = dict(credential)
    signed["proof"] = create_ed25519_proof(credential, private_key_hex, f"{issuer_did}#key-1")
    return signed


def build_cli_status_list_payload(
    base_url: str, issuer_did: str, length: int, registry: Dict[str, int] = None
) -> Dict[str, Any]:
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/status/v1",
        ],
        "id": base_url,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer_did,
        "validFrom": _to_iso_z(datetime.now(timezone.utc)),
        "credentialSubject": {
            "id": f"{base_url}#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": create_status_list(length),
        },
        "helixIndexRegistry": dict(registry or {}),
    }


def find_next_available_index(encoded_list: str, length: int) -> int:
    for index in range(length):
        if get_bit(encoded_list, index) == 0:
            return index
    raise ValueError("Status list is full — no available index")


def issue_agent_credential(
    issuer: IssuerKeyMaterial,
    agent_did: str,
    scopes: list,
    expires_ms: int,
    status_list: Dict[str, Any],
    base_url: str,
    max_delegation_depth: int,
) -> Tuple[Dict[str, Any], Dict[str, Any], int]:
    registry = dict(status_list.get("helixIndexRegistry") or {})
    encoded_list = status_list["credentialSubject"]["encodedList"]
    list_length = get_status_list_length(encoded_list)
    index = find_next_available_index(encoded_list, list_length)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(milliseconds=expires_ms)
    vc_id = f"urn:uuid:{uuid.uuid4()}"

    credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://helixid.io/contexts/v1"],
        "id": vc_id,
        "type": ["VerifiableCredential", "HelixAgentCredential"],
        "issuer": issuer.did,
        "validFrom": _to_iso_z(now),
        "validUntil": _to_iso_z(expires_at),
        "credentialStatus": {
            "id": f"{base_url}#{index}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(index),
            "statusListCredential": base_url,
        },
        "credentialSubject": {
            "id": agent_did,
            "type": "HelixAgent",
            "privilegeScopes": scopes,
            "agentName": agent_did,
            "delegationDepth": 0,
            "maxDelegationDepth": max_delegation_depth,
        },
    }

    vc = sign_credential(credential, issuer.did, issuer.private_key_hex)
    registry[vc_id] = index

    updated_list_payload = {
        **status_list,
        "credentialSubject": {**status_list["credentialSubject"], "encodedList": encoded_list},
        "helixIndexRegistry": registry,
        "validFrom": status_list["validFrom"],
    }
    updated_status_list = sign_credential(updated_list_payload, issuer.did, issuer.private_key_hex)

    return vc, updated_status_list, index


def revoke_credential_in_status_list(
    issuer: IssuerKeyMaterial, status_list: Dict[str, Any], vc_id: str
) -> Tuple[Dict[str, Any], int, int]:
    registry = status_list.get("helixIndexRegistry") or {}
    index = registry.get(vc_id)
    if index is None:
        raise ValueError(f"VC ID not found in status list registry: {vc_id}")

    encoded_list = status_list["credentialSubject"]["encodedList"]
    previous_bit = get_bit(encoded_list, index)
    updated_encoded = set_bit(encoded_list, index, 1)

    updated_list_payload = {
        **status_list,
        "credentialSubject": {**status_list["credentialSubject"], "encodedList": updated_encoded},
        "helixIndexRegistry": registry,
    }
    updated_status_list = sign_credential(updated_list_payload, issuer.did, issuer.private_key_hex)
    return updated_status_list, index, previous_bit


def parse_status_list_file(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Status list file is not valid JSON")
    if not raw.get("credentialSubject", {}).get("encodedList"):
        raise ValueError("Status list file is missing credentialSubject.encodedList")
    return raw
