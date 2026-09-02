#!/usr/bin/env python3
# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Agent delegation demo -- Python equivalent of what a JS caller does with
helix-sdk-js's delegate()/AgentWallet, exercising a real running helix-api
instance end to end:

  1. Onboard two agents (a "delegator" and a "sub-agent") against the API,
     each getting their own encrypted wallet and agent-authority VC.
  2. The delegator delegates a subset of its own scopes to the sub-agent
     via delegate() -- this calls the API's prepare/finalize endpoints;
     only the signature is produced locally (the delegator's private key
     never leaves this process).
  3. The sub-agent builds and signs a VP presenting its new delegation VC
     (VPBuilder.sign() -- local signing, no API call).
  4. The VP is verified via HelixClient.verify_vp() (API call) -- this
     prints the resolved delegation chain, showing both the delegator and
     the sub-agent.
  5. A second delegation attempt past the delegator's maxDelegationDepth
     is shown being rejected by the API with MAX_DELEGATION_DEPTH_EXCEEDED.

This intentionally does NOT mirror helix-server's examples/delegation-demo.ts:
that file imports buildDelegationVC from the retired @helixid/core package
and is a known-broken, not-yet-rewritten example (see docs/next-steps-
sequencing.md). This script instead follows the current, correct pattern
used by helix-api's own live integration test,
tests/live/agent-delegation.live.integration.test.ts, and its
tests/utils/liveApi.ts helpers -- delegate() + prepare/finalize, not
buildDelegationVC().

Requires a running helix-api instance. Point HELIX_API_URL at it:

    HELIX_API_URL=http://127.0.0.1:3579 \\
    HELIX_ADMIN_API_KEY=your-admin-key \\
    python examples/agent_delegation_demo.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import urllib.request
import json as jsonlib

from helix_sdk import (
    AgentWallet,
    HelixClient,
    VPBuilder,
    delegate,
    MaxDelegationDepthExceededError,
    ScopeEscalationDeniedError,
)


def create_enrollment_token(api_url: str, **kwargs) -> str:
    """The onboarding flow starts with an enrollment token, which in a real
    deployment is normally issued by an operator or admin console. Here we
    hit /v1/enrollment-tokens directly, the same way
    tests/utils/liveApi.ts's onboardLiveAgent() does."""
    body = jsonlib.dumps(kwargs).encode("utf-8")
    req = urllib.request.Request(
        f"{api_url}/v1/enrollment-tokens",
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return jsonlib.loads(resp.read())["token"]


def onboard_agent(
    api_url: str,
    client: HelixClient,
    wallet_dir: str,
    agent_name: str,
    requested_scopes: list,
    requested_domains: list,
    passphrase: str,
    max_delegation_depth: int = 0,
) -> AgentWallet:
    token = create_enrollment_token(
        api_url,
        agentName=agent_name,
        requestedScopes=requested_scopes,
        requestedDomains=requested_domains,
        maxDelegationDepth=max_delegation_depth,
    )
    challenge = client.request_onboarding_challenge(token, requested_domains)
    result = client.complete_onboarding(challenge["challengeId"], challenge["nonce"])

    wallet_path = os.path.join(wallet_dir, f"{agent_name.replace(' ', '_').lower()}.json")
    wallet = AgentWallet(
        client=client,
        private_key_hex=result["privateKeyHex"],
        did_value=result["agentDid"],
        wallet_path=wallet_path,
        passphrase=passphrase,
    )
    wallet.save(wallet_path)
    wallet.add_credential(result["vc"])
    return wallet


def main() -> int:
    api_url = os.environ.get("HELIX_API_URL", "http://127.0.0.1:3579")
    admin_api_key = os.environ.get("HELIX_ADMIN_API_KEY")

    print("=== HelixID Python SDK: Agent Delegation Demo ===")
    print(f"API: {api_url}\n")

    client = HelixClient(api_url, admin_api_key=admin_api_key)
    wallet_dir = tempfile.mkdtemp(prefix="helix-py-delegation-demo-")

    try:
        print("[Step 1] Onboard delegator agent (maxDelegationDepth=1, scopes: read:orders, write:orders)")
        delegator = onboard_agent(
            api_url,
            client,
            wallet_dir,
            agent_name="Python Delegator Agent",
            requested_scopes=["read:orders", "write:orders"],
            requested_domains=["https://py-delegator.agent.example.com"],
            passphrase="delegator-demo-passphrase",
            max_delegation_depth=1,
        )
        print(f"  delegator DID: {delegator.get_did()}")
        print(f"  delegator VC id: {delegator.credentials[0]['id']}\n")

        print("[Step 2] Onboard sub-agent (no delegation authority of its own)")
        sub_agent = onboard_agent(
            api_url,
            client,
            wallet_dir,
            agent_name="Python Sub Agent",
            requested_scopes=[],
            requested_domains=["https://py-subagent.agent.example.com"],
            passphrase="subagent-demo-passphrase",
        )
        print(f"  sub-agent DID: {sub_agent.get_did()}\n")

        print("[Step 3] Delegator delegates 'read:orders' to sub-agent via delegate()")
        print("  (prepare/finalize: server builds the payload, only the signature is local)")
        sub_agent_vc = delegate(
            delegator,
            to=sub_agent.get_did(),
            scopes=["read:orders"],
            expires_in=3600,
        )
        print(f"  sub-agent VC id: {sub_agent_vc['id']}")
        print(f"  delegated scopes: {sub_agent_vc['credentialSubject']['privilegeScopes']}")
        print(f"  delegationDepth: {sub_agent_vc['credentialSubject'].get('delegationDepth')}\n")
        sub_agent.add_credential(sub_agent_vc)

        print("[Step 4] Sub-agent builds and signs a VP presenting its delegation VC (local signing)")
        vp = VPBuilder(
            credentials=[sub_agent_vc],
            holder_did=sub_agent.get_did(),
            target_service="https://api.example.invalid/v1/tools/orders",
        ).sign(sub_agent.get_private_key_hex(), f"{sub_agent.get_did()}#key-1")
        print(f"  VP id: {vp['id']}\n")

        print("[Step 5] Verify the VP via the API (POST /v1/vp/verify)")
        result = client.verify_vp(vp)
        print(f"  valid: {result['valid']}")
        print(f"  agentDid: {result.get('agentDid')}")
        print(f"  effectiveScopes: {result.get('effectiveScopes')}")
        chain = result.get("delegationChain", [])
        print(f"  delegationChain ({len(chain)} link(s)):")
        for link in chain:
            print(f"    - subject={link.get('subject')} issuer={link.get('issuer')}")
        print()

        print("[Step 6] Sub-agent attempts to delegate further (should be blocked -- it has no delegation authority)")
        try:
            delegate(
                sub_agent,
                to="did:key:z6MkSomeOtherAgentPlaceholder",
                scopes=["read:orders"],
                expires_in=3600,
            )
            print("  ERROR: unexpected success -- delegation should have been blocked")
            return 1
        except (MaxDelegationDepthExceededError, ScopeEscalationDeniedError) as exc:
            # Live-verified (2026-09-01): the sub-agent here has zero
            # remaining delegation depth, so its effective delegable scope
            # set is empty. The API currently reports that as
            # ScopeEscalationDeniedError (requested scope not in an empty
            # permitted set) rather than MaxDelegationDepthExceededError.
            # Either is an acceptable "delegation blocked" outcome for this
            # demo; which one the API returns for an exhausted-depth agent
            # is a separate error-precedence question tracked as its own
            # follow-up, not fixed here.
            print(f"  Expected failure: {exc.code} -- delegation blocked as designed")

        print("\n=== Demo complete ===")
        return 0
    finally:
        shutil.rmtree(wallet_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
