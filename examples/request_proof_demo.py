#!/usr/bin/env python3
# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Per-request holder-of-key proof demo (KYA-OS story C-C), offline.

  1. An agent generates its own Ed25519 key (did:key); the private key stays
     in its environment, read by an EnvSigner at each signature.
  2. It signs one MCP tools/call with kyaos.with_request_proof(): the proof
     rides params._meta["org.kya-os/request-proof"], bound to this request's
     body and to the service's DID.
  3. The service verifies it in-process, in the SPEC-ENTITY-CARD section 11.2
     order (helix_sdk.verifier.verify_request_proof), from the agent's DID
     document alone: no Helix API call.
  4. The same proof a second time is a replay; the same proof over another
     body, or at another service, is refused with its own reason code.

The Helix VP (sign_vp, verify_vp, X-Helix-VP) is gone. Run it with no server:

    python examples/request_proof_demo.py
"""

from __future__ import annotations

import sys
import time

from helix_sdk import kyaos
from helix_sdk.agent_key import generate_agent_key, to_did_key
from helix_sdk.verifier import (
    REQUEST_PROOF_META_KEY,
    MemoryNonceStore,
    RequestProofOptions,
    RequestProofSeams,
    did_key_document,
    ed25519_keys_of,
    verify_request_proof,
)

SERVICE_DID = "did:web:orders.example.com"


def main() -> int:
    key = generate_agent_key()
    agent_did = to_did_key(key.public_key_hex)
    signer = kyaos.EnvSigner(agent_did, kid=agent_did.split(":")[-1], env_var="AGENT_KEY", env={"AGENT_KEY": key.private_key_hex})
    print(f"[Step 1] Agent {agent_did}: its key stays in its own environment")

    request = kyaos.with_request_proof({"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}}, signer, audience=SERVICE_DID)
    proof = request["params"]["_meta"][REQUEST_PROOF_META_KEY]
    print(f"[Step 2] Signed tools/call: requestHash {proof['requestHash']}, nonce {proof['nonce']}, expires in {proof['expires'] - proof['created']} s")

    seams = RequestProofSeams(
        resolve_did=did_key_document,
        resolve_did_keys=lambda did: ed25519_keys_of(did_key_document(did) or {}),
        nonce_store=MemoryNonceStore(),
        clock=lambda: int(time.time() * 1000),
    )
    here = RequestProofOptions(expected_audience=SERVICE_DID)
    verdict = verify_request_proof(proof, request, seams, here)
    print(f"[Step 3] Service verifies in-process: ok={verdict.ok}, agent={verdict.did}, assurance={verdict.assurance}")

    replay = verify_request_proof(proof, request, seams, here).reasons
    tampered = {"method": "tools/call", "params": {**request["params"], "arguments": {"orderId": "ORD-1002"}}}
    elsewhere = verify_request_proof(proof, request, seams, RequestProofOptions(expected_audience="did:web:other.example.com")).reasons
    print(f"[Step 4] replay -> {replay}; another body -> {verify_request_proof(proof, tampered, seams, here).reasons}; another service -> {elsewhere}")
    ok = verdict.ok and replay == ["nonce_replayed"] and elsewhere == ["audience_mismatch"]
    print("\n=== Demo complete ===" if ok else "\n=== Demo FAILED ===")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
