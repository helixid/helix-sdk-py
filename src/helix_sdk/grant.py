# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
issue_grant(), ported from helix-sdk-js's src/grant.ts.

Builds and signs a DelegationGrantCredential via the API's prepare/finalize
endpoints (see docs/proposal-sdk-api-only.md). Payload construction --
index allocation on the status list included -- happens server-side; only
the signature is produced locally, so the SP's issuer key never leaves
this process.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from . import keys
from .client import HelixClient


@dataclass
class IssuerKeyMaterial:
    """SP-held issuer key material. The SP signs grants with its own key,
    which never leaves this process."""

    did: str
    private_key_hex: str


def issue_grant(
    client: HelixClient,
    issuer_wallet: IssuerKeyMaterial,
    agent_did: str,
    user_did: str,
    scopes: List[str],
    durability: str,
    status_list: Dict[str, Any],
    status_list_credential_url: str,
    service_did: Optional[str] = None,
) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = dict(
        issuerDid=issuer_wallet.did,
        agentDid=agent_did,
        userDid=user_did,
        scopes=scopes,
        durability=durability,
        statusList=status_list,
        statusListCredentialUrl=status_list_credential_url,
    )
    if service_did is not None:
        kwargs["serviceDid"] = service_did
    prepared = client.prepare_grant(**kwargs)

    signature_hex = keys.sign_data(bytes.fromhex(prepared["canonicalHash"]), issuer_wallet.private_key_hex)

    grant_vc = client.finalize_grant(
        token=prepared["token"],
        verification_method=f"{issuer_wallet.did}#key-1",
        signature_hex=signature_hex,
    )

    # Same object as the input -- issuance doesn't set status-list bits
    # (only revocation does), returned for drop-in shape compatibility with
    # the JS SDK's IssueGrantResult.
    return {"grantVC": grant_vc, "updatedStatusList": status_list}
