# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The agent side of the per-request holder-of-key proof (KYA-OS story C-C,
SPEC-ENTITY-CARD.md section 8), the Python twin of helix-sdk-js
``kyaos/request-proof.ts``: every MCP call carries an ``org.kya-os/proof.v1``
signed by the agent's own Signer at ``_meta["org.kya-os/request-proof"]``,
with its delegation chain at ``_meta["org.kya-os/delegation-chain"]``.

    from helix_sdk import kyaos
    signer = kyaos.EnvSigner(did=agent_did)
    request = kyaos.with_request_proof(
        {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}},
        signer,
        audience="did:web:orders.example.com",
        chain=hops,
    )
    # send request["params"] as the MCP tools/call params

The Helix VP and its carriers (``X-Helix-VP``, ``_meta["x-helix-vp"]``) are
gone: there are no Helix-format presentations, and no request ever carries
private key material. The signer keeps the key wherever it lives.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .credentials import MAX_DELEGATION_DEPTH
from .crypto.jws import Signer
from .verifier.request_proof import (
    DELEGATION_CHAIN_META_KEY,
    MAX_PROOF_TTL_SECONDS,
    REQUEST_PROOF_META_KEY,
    request_hash_content_digest as _content_digest_of_request,
    sign_request_proof,
)

ProofCall = Mapping[str, Any]
"""What a proof can be minted for: a JSON-RPC ``{"method", "params"}``, or a tool
call ``{"name", "arguments"?, "_meta"?}``."""

_DID = re.compile(r"did:[a-z0-9]+:.+")
_NONCE = re.compile(r"[A-Za-z0-9_-]{22,}")
_JKT = re.compile(r"[A-Za-z0-9_-]{43}")


class RequestProofError(ValueError):
    """A call, option or chain no verifier would accept, refused before anything is signed."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def to_proof_request(call: Mapping[str, Any]) -> Dict[str, Any]:
    """A tool call as the JSON-RPC request it is sent as; a JSON-RPC request as is."""
    if not isinstance(call, Mapping):
        raise RequestProofError("a call is a mapping: {method, params} or {name, arguments}")
    if isinstance(call.get("method"), str):
        return dict(call)
    name = call.get("name")
    if not isinstance(name, str) or not name:
        raise RequestProofError("a tool call needs a name")
    params: Dict[str, Any] = {"name": name}
    if call.get("arguments") is not None:
        params["arguments"] = call["arguments"]
    if call.get("_meta") is not None:
        params["_meta"] = call["_meta"]
    return {"method": "tools/call", "params": params}


def request_hash_content_digest(call: Mapping[str, Any]) -> str:
    """``sha-256=:<base64>:`` over the JCS of the covered request: ``{method, params}``,
    ``params._meta`` removed (section 8.3)."""
    return _content_digest_of_request(to_proof_request(call))


def mint_request_proof(
    call: Mapping[str, Any],
    signer: Signer,
    *,
    audience: str,
    cnf_jkt: Optional[str] = None,
    now_ms: Optional[int] = None,
    ttl_seconds: int = MAX_PROOF_TTL_SECONDS,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Mints the ``org.kya-os/proof.v1`` for one call, signed by ``signer`` (a detached
    EdDSA JWS over the covered claims). One proof per call: the nonce is fresh and the
    verifier refuses it a second time.

    ``audience`` is the service's DID, from its Entity Card (or its ``/.well-known/mcp``
    ``serverDid``); ``cnf_jkt`` the RFC 7638 thumbprint of the signing key, carried as
    ``cnf.jkt`` for the section 8.6 fusion; ``ttl_seconds`` 1 to 60."""
    if not isinstance(audience, str) or _DID.fullmatch(audience) is None:
        raise RequestProofError("audience must be the service DID")
    if not _is_int(ttl_seconds) or ttl_seconds < 1 or ttl_seconds > MAX_PROOF_TTL_SECONDS:
        raise RequestProofError(f"ttl_seconds must be a whole number from 1 to {MAX_PROOF_TTL_SECONDS}")
    if nonce is not None and (not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None):
        raise RequestProofError("nonce must be base64url and at least 128 bits (22 characters)")
    if cnf_jkt is not None and (not isinstance(cnf_jkt, str) or _JKT.fullmatch(cnf_jkt) is None):
        raise RequestProofError("cnf_jkt must be an RFC 7638 SHA-256 thumbprint (43 base64url characters)")
    return sign_request_proof(
        to_proof_request(call),
        signer,
        audience=audience,
        now_ms=now_ms,
        ttl_seconds=ttl_seconds,
        nonce=nonce,
        cnf_jkt=cnf_jkt,
    )


def attach_chain(hops: Sequence[Any]) -> Dict[str, List[Any]]:
    """The ``_meta`` member carrying the delegation chain, root to leaf (section 10.5):
    ``{"org.kya-os/delegation-chain": hops}``. Refuses what every verifier would: an
    empty chain, one longer than 10 hops, or a hop without its own ``eddsa-jcs-2022``
    ``DataIntegrityProof`` for ``assertionMethod``."""
    if not isinstance(hops, (list, tuple)) or not hops:
        raise RequestProofError("a delegation chain is a non-empty list, root to leaf")
    if len(hops) > MAX_DELEGATION_DEPTH:
        raise RequestProofError(f"a carried chain has at most {MAX_DELEGATION_DEPTH} hops")
    for index, hop in enumerate(hops):
        proof = hop.get("proof") if isinstance(hop, Mapping) else None
        if (
            not isinstance(proof, Mapping)
            or proof.get("type") != "DataIntegrityProof"
            or proof.get("cryptosuite") != "eddsa-jcs-2022"
            or proof.get("proofPurpose") != "assertionMethod"
        ):
            raise RequestProofError(f"hop {index} carries no eddsa-jcs-2022 DataIntegrityProof for assertionMethod")
    return {DELEGATION_CHAIN_META_KEY: list(hops)}


def with_request_proof(
    call: Mapping[str, Any],
    signer: Signer,
    *,
    audience: str,
    chain: Optional[Sequence[Any]] = None,
    cnf_jkt: Optional[str] = None,
    now_ms: Optional[int] = None,
    ttl_seconds: int = MAX_PROOF_TTL_SECONDS,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """The call as it is sent: ``params._meta`` gains the proof (``org.kya-os/request-proof``)
    and, when given, the chain (``org.kya-os/delegation-chain``); every other ``_meta``
    member is kept."""
    request = to_proof_request(call)
    params = request.get("params")
    if params is not None and not isinstance(params, Mapping):
        raise RequestProofError("params must be an object to carry _meta")
    chain_meta = {} if chain is None else attach_chain(chain)
    # The request is signed as it is sent: absent params become {} once _meta rides in them (section 8.3 step 3).
    sent_params: Dict[str, Any] = dict(params or {})
    proof = mint_request_proof(
        {"method": request["method"], "params": sent_params},
        signer,
        audience=audience,
        cnf_jkt=cnf_jkt,
        now_ms=now_ms,
        ttl_seconds=ttl_seconds,
        nonce=nonce,
    )
    meta = sent_params.get("_meta")
    merged = dict(meta) if isinstance(meta, Mapping) else {}
    return {
        "method": request["method"],
        "params": {**sent_params, "_meta": {**merged, **chain_meta, REQUEST_PROOF_META_KEY: proof}},
    }


__all__ = [
    "DELEGATION_CHAIN_META_KEY",
    "REQUEST_PROOF_META_KEY",
    "ProofCall",
    "RequestProofError",
    "attach_chain",
    "mint_request_proof",
    "request_hash_content_digest",
    "to_proof_request",
    "with_request_proof",
]
