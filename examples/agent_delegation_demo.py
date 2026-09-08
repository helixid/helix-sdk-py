#!/usr/bin/env python3
# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Agent delegation demo, rewritten for server custody.

Agent self-custody has been retired, so there is no local keypair, wallet
file or passphrase anywhere in this demo. Both onboarding and delegation are
API calls: onboard_agent() has the server generate and hold the agent's key,
and delegate_authority() authorizes HelixID to sign the delegation on the
delegator's behalf. The SDK's wallet-based delegate() needed the delegator's
own private key and so has had nothing legitimate to call since that sweep.

This file was previously a stub, blocked on "a server-side sign-delegation-VC
capability". That capability is delegate_authority()
(POST /v1/agents/:did/delegate). Mirrors helixid's
examples/delegation-demo.ts. Requires a running helix-api instance:

    HELIX_API_URL=http://127.0.0.1:3579 \
    HELIX_ADMIN_API_KEY=your-admin-key \
    python examples/agent_delegation_demo.py

The admin key is required: in OSS/core the delegation route is admin-key
gated, because there is no per-tenant credential narrower than it. Minting
the enrollment token is not gated.
"""

from __future__ import annotations

import json as jsonlib
import os
import sys
import urllib.request

from helix_sdk import HelixClient, HelixError, codes

DOMAINS = ["https://api.example.invalid"]


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


def onboard_agent(api_url: str, client: HelixClient, agent_name: str, scopes: list, max_delegation_depth: int) -> dict:
    """Two API calls, deliberately: minting the enrollment token is an
    agent-owner action (and is not exposed as an SDK method), while
    onboard_agent() is the agent-side call that redeems it. Calling them back
    to back here is the scripted equivalent of doing both in Console."""
    token = create_enrollment_token(
        api_url,
        agentName=agent_name,
        requestedScopes=scopes,
        requestedDomains=DOMAINS,
        maxDelegationDepth=max_delegation_depth,
    )
    return client.onboard_agent(token, DOMAINS)


def main() -> int:
    api_url = os.environ.get("HELIX_API_URL", "http://127.0.0.1:3579")
    admin_api_key = os.environ.get("HELIX_ADMIN_API_KEY")

    print("=== HelixID Python SDK: Agent Delegation Demo ===")
    print(f"API: {api_url}\n")

    if not admin_api_key:
        print("HELIX_ADMIN_API_KEY is required: delegate_authority() hits the")
        print("admin-key gated /v1/agents/:did/delegate route.")
        return 1

    client = HelixClient(api_url, admin_api_key=admin_api_key)

    print("[Step 1] Onboard delegator agent (max_delegation_depth=1, scopes: read:orders, write:orders)")
    delegator = onboard_agent(api_url, client, "Delegator Agent", ["read:orders", "write:orders"], 1)
    print(f"  delegator DID: {delegator['agentDid']}")
    print(f"  delegator VC id: {delegator['vcId']}\n")

    print("[Step 2] Onboard sub-agent (no delegation authority of its own)")
    sub_agent = onboard_agent(api_url, client, "Sub-Agent", [], 0)
    print(f"  sub-agent DID: {sub_agent['agentDid']}\n")

    print("[Step 3] Delegator delegates 'read:orders' to sub-agent via delegate_authority()")
    print("  (the server holds the delegator key and signs -- nothing is signed locally)")
    delegated_vc = client.delegate_authority(
        delegator["agentDid"],
        sub_agent["agentDid"],
        ["read:orders"],
        3600,
        vc_id=delegator["vcId"],
    )
    subject = delegated_vc.get("credentialSubject") or {}
    print(f"  sub-agent VC id: {delegated_vc.get('id')}")
    print(f"  delegated scopes: {', '.join(subject.get('privilegeScopes') or [])}")
    print(f"  delegationDepth: {subject.get('delegationDepth')}\n")

    print("[Step 4] Sub-agent presents the delegated credential")
    # The sub-agent now holds two active credentials -- its own onboarding VC
    # and this delegated one -- so the VP pins which to present. The default
    # subject-only lookup rejects that ambiguity.
    vp = client.sign_vp(
        sub_agent["agentDid"],
        "https://api.example.invalid",
        vc_id=delegated_vc.get("id"),
    )
    result = client.verify_vp(vp)
    print(f"  valid: {result.get('valid')}")
    print(f"  effective scopes: {', '.join(result.get('effectiveScopes') or [])}")
    print(f"  delegation chain length: {len(result.get('delegationChain') or [])}\n")

    print("[Step 5] Sub-agent attempts to delegate further (should be blocked -- it has no delegation authority)")
    try:
        # No vc_id passed: the server resolves the sub-agent's own delegated
        # credential and finds it has no delegation budget left.
        client.delegate_authority(
            sub_agent["agentDid"],
            "did:key:z6MkSomeOtherAgentPlaceholder",
            ["read:orders"],
            3600,
        )
        print("  ERROR: unexpected success -- delegation should have been blocked")
        return 1
    except HelixError as error:
        # An agent with zero remaining delegation depth has an empty effective
        # delegable-scope set, so the API may report this as
        # SCOPE_ESCALATION_DENIED rather than MAX_DELEGATION_DEPTH_EXCEEDED.
        # Either is an acceptable "delegation blocked" outcome for this demo --
        # see the equivalent note in helixid's examples/delegation-demo.ts.
        # Which one the API *should* return for an exhausted-depth agent is
        # tracked separately, not fixed here.
        if error.code in (codes.MAX_DELEGATION_DEPTH_EXCEEDED, codes.SCOPE_ESCALATION_DENIED):
            print(f"  Expected failure: {error.code} -- delegation blocked as designed")
        else:
            raise

    print("\n=== Demo complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
