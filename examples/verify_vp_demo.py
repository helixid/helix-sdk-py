#!/usr/bin/env python3
# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
VP verification demo -- Python equivalent of helix-server's
examples/verify-vp.ts, scope-check.ts, and revocation-check.ts combined
into one script.

  1. Onboard a fresh agent, mint its VC, build and sign a VP (VPBuilder.sign()
     -- local signing).
  2. Verify the VP via POST /v1/vp/verify (API call) and inspect
     effectiveScopes with check_scope()/require_scope().
  3. Revoke the agent's VC via the admin API and show the next verification
     attempt failing with VC_REVOKED -- demonstrating that verification is
     always live against current revocation state, never cached locally.

Requires a running helix-api instance and an admin API key (revocation is
an admin-only operation):

    HELIX_API_URL=http://127.0.0.1:3579 \\
    HELIX_ADMIN_API_KEY=your-admin-key \\
    python examples/verify_vp_demo.py
"""

from __future__ import annotations

import json as jsonlib
import os
import shutil
import sys
import tempfile
import urllib.request

from helix_sdk import (
    AgentWallet,
    HelixClient,
    VPBuilder,
    check_scope,
    require_scope,
    InsufficientScopeError,
    VCRevokedError,
    HelixError,
)


def create_enrollment_token(api_url: str, **kwargs) -> str:
    body = jsonlib.dumps(kwargs).encode("utf-8")
    req = urllib.request.Request(
        f"{api_url}/v1/enrollment-tokens",
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return jsonlib.loads(resp.read())["token"]


def main() -> int:
    api_url = os.environ.get("HELIX_API_URL", "http://127.0.0.1:3579")
    admin_api_key = os.environ.get("HELIX_ADMIN_API_KEY")
    target_service = os.environ.get("TARGET_SERVICE", "https://api.example.invalid/v1/tools/orders")

    print("=== HelixID Python SDK: VP Verification Demo ===")
    print(f"API: {api_url}\n")

    client = HelixClient(api_url, admin_api_key=admin_api_key)
    wallet_dir = tempfile.mkdtemp(prefix="helix-py-verify-demo-")

    try:
        print("[Step 1] Onboard a fresh agent with scope 'read:orders'")
        token = create_enrollment_token(
            api_url,
            agentName="Python Verify Demo Agent",
            requestedScopes=["read:orders"],
            requestedDomains=["https://py-verify-demo.agent.example.com"],
        )
        challenge = client.request_onboarding_challenge(
            token, ["https://py-verify-demo.agent.example.com"]
        )
        onboarding = client.complete_onboarding(challenge["challengeId"], challenge["nonce"])

        wallet_path = os.path.join(wallet_dir, "verify-demo-agent.json")
        wallet = AgentWallet(
            client=client,
            private_key_hex=onboarding["privateKeyHex"],
            did_value=onboarding["agentDid"],
            wallet_path=wallet_path,
            passphrase="verify-demo-passphrase",
        )
        wallet.save(wallet_path)
        wallet.add_credential(onboarding["vc"])
        print(f"  agent DID: {wallet.get_did()}")
        print(f"  VC id: {onboarding['vcId']}\n")

        print("[Step 2] Build and sign a VP locally (VPBuilder.sign())")
        vp = VPBuilder(
            credentials=wallet.credentials,
            holder_did=wallet.get_did(),
            target_service=target_service,
        ).sign(wallet.get_private_key_hex(), f"{wallet.get_did()}#key-1")
        print(f"  VP id: {vp['id']}\n")

        print("[Step 3] Verify the VP via POST /v1/vp/verify")
        result = client.verify_vp(vp)
        print(f"  valid: {result['valid']}")
        print(f"  effectiveScopes: {result.get('effectiveScopes')}\n")

        print("[Step 4] Scope checks against the verification result (local, no API call)")
        print(f"  check_scope('read:orders'): {check_scope(result, 'read:orders')}")
        print(f"  check_scope('write:orders'): {check_scope(result, 'write:orders')}")
        try:
            require_scope(result, "write:orders")
            print("  ERROR: expected require_scope to raise")
            return 1
        except InsufficientScopeError as exc:
            print(f"  require_scope('write:orders') raised as expected: {exc.code}\n")

        print("[Step 5] Revoke the VC via the admin API, then verify again")
        client.revoke_vc(onboarding["vcId"])
        print("  VC revoked")

        try:
            client.verify_vp(vp)
            print("  ERROR: expected verification to fail after revocation")
            return 1
        except HelixError as exc:
            print(f"  Verification after revocation failed as expected: {exc.code}")

        print("\n=== Demo complete ===")
        return 0
    finally:
        shutil.rmtree(wallet_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
