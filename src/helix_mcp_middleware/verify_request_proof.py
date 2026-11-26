# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The request proof of one tool call alone, in the section 11.2 order (KYA-OS
story C-C), with a local verifier's seams: ported from helix-sdk-js's
mcp-middleware/src/verify-request-proof.ts."""

from __future__ import annotations

from typing import Any, Mapping, Optional

from helix_sdk.verifier import RequestProofOptions, RequestProofVerification, read_request_proof
from helix_sdk.verifier import verify_request_proof as _verify_request_proof

from .credentials import meta_mapping
from .verify_locally import LocalVerifier, request_of


def verify_request_proof(
    verifier: LocalVerifier,
    call: Mapping[str, Any],
    *,
    token_cnf_jkt: Optional[str] = None,
    skew_seconds: Optional[int] = None,
) -> RequestProofVerification:
    """Verifies the request proof of one tool call (``name``, ``input``, ``_meta``, optional
    ``request``) with ``verifier``'s seams; the audience is the verifier's service DID.
    ``token_cnf_jkt`` is the access token's ``cnf.jkt`` for the L3 fusion."""
    return _verify_request_proof(
        read_request_proof(meta_mapping(call.get("_meta"))),
        request_of(call),
        verifier.seams,
        RequestProofOptions(expected_audience=verifier.service_did, skew_seconds=skew_seconds, token_cnf_jkt=token_cnf_jkt),
    )
