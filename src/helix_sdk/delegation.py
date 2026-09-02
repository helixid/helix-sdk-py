# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
delegate(), ported from helix-sdk-js's src/delegation.ts.

Builds and signs a delegation VC via the API's prepare/finalize endpoints
(see docs/proposal-sdk-api-only.md). Payload construction -- scope-subset
and max-depth checks included -- happens server-side; only the signature
is produced locally, so the wallet's private key never leaves this
process.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .errors import NoCredentialInWalletError
from .wallet import AgentWallet


def delegate(
    wallet: AgentWallet,
    to: str,
    scopes: List[str],
    expires_in: int,
    from_vc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    credentials = wallet.credentials
    resolved_from_vc = from_vc if from_vc is not None else (credentials[0] if credentials else None)
    if resolved_from_vc is None:
        raise NoCredentialInWalletError()
    if wallet.client is None:
        raise RuntimeError("Wallet has no HelixClient")

    prepared = wallet.client.prepare_delegation(
        delegator_did=wallet.get_did(),
        from_vc=resolved_from_vc,
        to=to,
        scopes=scopes,
        expires_in=expires_in,
    )

    signature_hex = wallet.sign(bytes.fromhex(prepared["canonicalHash"]))

    return wallet.client.finalize_delegation(
        token=prepared["token"],
        verification_method=f"{wallet.get_did()}#key-1",
        signature_hex=signature_hex,
    )
