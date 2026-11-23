# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""KYA-OS story L3-C middleware test helpers, ported from helix-sdk-js's
mcp-middleware/tests/revocation-helpers.ts: signed status lists
(eddsa-jcs-2022) by a did:web issuer, served by a static fetch."""

from __future__ import annotations

import base64
import gzip
from typing import Any, Dict, Optional, Sequence
from urllib.parse import unquote

from helix_sdk.credentials import sign_data_integrity
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.did import build_did_document
from helix_sdk.keys import generate_key_pair


class ListIssuer:
    def __init__(self, did: str) -> None:
        pair = generate_key_pair()
        self.did = did
        self.private_key = pair.private_key
        self.document: Dict[str, Any] = dict(build_did_document(did, pair.public_key))
        self.signer = EnvSigner(did, env_var="K", env={"K": pair.private_key})


def encoded_bits(length: int, set_bits: Sequence[int] = ()) -> str:
    """``length`` bytes with the listed bits set, MSB first, GZIP, multibase ``u``."""
    data = bytearray(length)
    for index in set_bits:
        data[index // 8] |= 0x80 >> (index % 8)
    return "u" + base64.urlsafe_b64encode(gzip.compress(bytes(data))).decode().rstrip("=")


def bitstring_list(
    url: str,
    issuer: ListIssuer,
    set_bits: Sequence[int] = (),
    purpose: str = "revocation",
    valid_from: str = "2026-01-01T00:00:00Z",
    valid_until: str = "2027-01-01T00:00:00Z",
    unsigned: bool = False,
    signed_by: Optional[ListIssuer] = None,
) -> Dict[str, Any]:
    """A Bitstring Status List v1.0 credential at ``url``, signed by ``issuer`` (or ``signed_by``'s key) unless ``unsigned``."""
    document: Dict[str, Any] = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": url,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer.did,
        "validFrom": valid_from,
        "validUntil": valid_until,
        "credentialSubject": {"id": f"{url}#list", "type": "BitstringStatusList", "statusPurpose": purpose, "encodedList": encoded_bits(16, set_bits)},
    }
    if unsigned:
        return document
    key = signed_by or issuer
    signer = EnvSigner(issuer.did, env_var="K", env={"K": key.private_key})
    return sign_data_integrity(document, signer, created="2026-01-01T00:00:00Z")


def well_known_did_url(did: str) -> str:
    """The did:web document URL of a bare-host DID, as the resolver asks for it."""
    return f"https://{unquote(did[len('did:web:'):])}/.well-known/did.json"
