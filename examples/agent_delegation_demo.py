#!/usr/bin/env python3
# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Agent delegation demo -- BLOCKED, known gap from the server-custody
migration, not fixed here.

This demo previously onboarded a delegator and a sub-agent, each with a
local encrypted wallet and private key, then called delegate() to have the
delegator sign a delegation VC for the sub-agent (delegate() needs
wallet.sign() -- the delegator's real private key -- to authorize the API's
prepare/finalize payload).

Agent self-custody has been retired: HelixClient.onboard_agent() generates
and holds the private key server-side now, so no onboarding path produces
a wallet holding a real, signable key anymore. delegate() (in
helix_sdk.delegation) has nothing legitimate to call wallet.sign() with.

This is the same open question flagged in helix-core's
tests/live/agent-delegation.live.integration.test.ts and helix-sdk-js's
delegation.ts/renewal.ts: agent-to-agent delegation under server custody
needs its own design decision (something like a server-side
sign-delegation-VC capability) before this demo can be rewritten against
a real, working flow. Left as a stub rather than silently left calling
APIs (client.request_onboarding_challenge()/complete_onboarding()) that no
longer exist, or pretending the flow still works.
"""

from __future__ import annotations

import sys


def main() -> int:
    print("=== HelixID Python SDK: Agent Delegation Demo ===\n")
    print("BLOCKED: agent self-custody has been retired, and agent-to-agent")
    print("delegation under server custody has no design yet -- see this file's")
    print("module docstring for the full explanation and pointers.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
