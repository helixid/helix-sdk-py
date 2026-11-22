# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The server's side of the KYA-OS detached response proof (story L2-A;
conformance L2.11, L2.12), mirroring helix-sdk-js's
mcp-middleware/src/kyaos/response-proof.ts. build_response_proof() signs the
RFC 8785 canonical JSON of the ProofMeta's claims (``iss``/``sub`` the
server DID, ``aud`` the audience, the rest by name) as an EdDSA compact JWS
through the service Signer, and returns ``{"jws", "meta"}``. The Signer is
the only thing that touches the private key: this module hands it bytes and
takes back a signature (self-custody invariant, stories rule 7).
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

from helix_sdk.crypto.jws import Signer, sign_jws
from helix_sdk.response_proof import RESPONSE_PROOF_META_KEY, outcome_has_response, proof_payload, validate_proof_meta


def build_response_proof(meta: Mapping[str, Any], signer: Signer) -> Dict[str, Any]:
    """Signs ``meta`` with ``signer``, whose DID and kid must be the ones
    ``meta`` names. ``responseHash`` must be present on ``allowed`` and
    ``needs_authorization`` and absent on ``denied`` and ``step_up_required``.
    Members whose value is None are left out."""
    validated = validate_proof_meta({k: v for k, v in meta.items() if v is not None})
    fragment = signer.kid[1:] if signer.kid.startswith("#") else signer.kid
    if validated["did"] != signer.did or validated["kid"] != f"{signer.did}#{fragment}":
        raise ValueError(f"build_response_proof: meta names {validated['did']} / {validated['kid']}, the signer is {signer.did}#{signer.kid}")
    outcome = validated.get("outcome") or "allowed"
    if outcome_has_response(outcome) and validated.get("responseHash") is None:
        raise ValueError(f"build_response_proof: a {outcome} proof must carry responseHash")
    if not outcome_has_response(outcome) and validated.get("responseHash") is not None:
        raise ValueError(f"build_response_proof: a {outcome} proof carries no response and so no responseHash")
    return {"jws": sign_jws(proof_payload(validated), signer), "meta": validated}


def attach_response_proof(result: Mapping[str, Any], proof: Mapping[str, Any]) -> Dict[str, Any]:
    """``result`` with ``proof`` at ``_meta["org.kya-os/response-proof"]``; other ``_meta`` members are kept."""
    existing = result.get("_meta")
    meta = dict(existing) if isinstance(existing, Mapping) else {}
    meta[RESPONSE_PROOF_META_KEY] = dict(proof)
    return {**result, "_meta": meta}
