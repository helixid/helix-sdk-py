# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
renew_agent_vc(), ported from helix-sdk-js's src/renewal.ts.

Renews an agent's own VC via the API's prepare/finalize endpoints. Distinct
from HelixClient.renew_vc(), which is fully server-signed -- this path is
for VCs the agent itself signed (e.g. via self_issue_vc()), so the renewal
must be re-signed by the same key. Payload construction -- window/
revocation/renewal-count checks included -- happens server-side; only the
signature is produced locally.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .errors import NoCredentialInWalletError
from .wallet import AgentWallet


def renew_agent_vc(
    wallet: AgentWallet,
    status_list: Dict[str, Any],
    status_list_credential_url: str,
    expires_in: int,
    current_vc: Optional[Dict[str, Any]] = None,
    scopes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    credentials = wallet.credentials
    resolved_current_vc = current_vc if current_vc is not None else (credentials[0] if credentials else None)
    if resolved_current_vc is None:
        raise NoCredentialInWalletError()
    if wallet.client is None:
        raise RuntimeError("Wallet has no HelixClient")

    kwargs: Dict[str, Any] = dict(
        currentVC=resolved_current_vc,
        statusList=status_list,
        statusListCredentialUrl=status_list_credential_url,
        expiresIn=expires_in,
    )
    if scopes is not None:
        kwargs["scopes"] = scopes
    prepared = wallet.client.prepare_agent_renewal(**kwargs)

    signature_hex = wallet.sign(bytes.fromhex(prepared["canonicalHash"]))

    # The server expects the signer to match currentVC.issuer, not
    # necessarily this wallet's own DID -- renewal is signed by whoever
    # signed the original VC. Self-renewal (the common case) has these be
    # the same, but derive from currentVC.issuer rather than assuming it.
    return wallet.client.finalize_agent_renewal(
        token=prepared["token"],
        verification_method=f"{resolved_current_vc['issuer']}#key-1",
        signature_hex=signature_hex,
    )
