# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Shared "select a VC from a wallet and sign a VP for it" helper, factored
out of the near-identical selectVC()/attach logic duplicated across
helix-sdk-js's mcp/src/attach.ts and langchain/src/middleware.ts. Used by
all three of this repo's framework adapters (helix_mcp_middleware, helix_langchain,
helix_crewai) so the selection rule stays in exactly one place.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional

from .wallet import AgentWallet
from .vp_builder import VPBuilder
from .errors import NoCredentialInWalletError


def select_vc(wallet: AgentWallet, target_service: str) -> Dict[str, Any]:
    vcs = wallet.credentials
    if not vcs:
        raise NoCredentialInWalletError("No credential in wallet. Run enrollment first.")
    if len(vcs) == 1:
        return vcs[0]
    for vc in vcs:
        if vc.get("targetService") == target_service:
            return vc
    return vcs[0]


def build_signed_vp(
    wallet_file_path: str,
    wallet_passphrase: str,
    target_service: str,
    user_did: Optional[str] = None,
) -> Dict[str, Any]:
    wallet = AgentWallet.load(wallet_file_path, wallet_passphrase)
    vc = select_vc(wallet, target_service)
    return VPBuilder(
        credentials=[vc],
        holder_did=wallet.get_did(),
        target_service=target_service,
        user_did=user_did or "did:key:anonymous",
    ).sign(wallet.get_private_key_hex(), f"{wallet.get_did()}#key-1")


def encode_base64url_json(value: Any) -> str:
    """Matches helix-sdk-js's encodeBase64UrlJson() (langchain/src/middleware.ts):
    Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')."""
    return base64.urlsafe_b64encode(json.dumps(value).encode("utf-8")).rstrip(b"=").decode("ascii")
