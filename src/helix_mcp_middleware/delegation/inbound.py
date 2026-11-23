"""Verifying a downstream call (KYA-OS story L3-D point 5, SPEC.md §8.1,
L3.27). Ported from helix-sdk-js's mcp-middleware/src/delegation/inbound.ts:
same order, same reason codes.

The receiving service derives everything from the two signed artifacts, the
chain in ``KYA-OS-Delegation-Credential`` and the forwarding service's
``KYA-OS-Delegation-Proof``, through its own local verifier (story F-2), with no
secret shared with the forwarder: the headers once each and the chain bounded;
the proof's signature, ``aud`` and window; ``sub`` = the root hop's issuer,
``delegation_id`` = the leaf, ``delegation_chain`` = the chain's string; the
chain's target is this service or an accepted forwarder; the forwarder is
bound to the chain; ``KYA-OS-Agent-DID`` is the agent the chain names; the
``jti`` once; then the chain root to leaf (cached by credential id unless the
tool demands L3). A forwarded call carries no request proof of the agent's,
so it comes to at most L2. ``KYA-OS-Delegation-Chain`` and
``KYA-OS-Granted-Scopes`` never enter the decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Union
from urllib.parse import unquote

from .headers import DELEGATION_HEADERS, decode_delegation_credential, header_values
from .proof_jwt import build_chain_string, delegation_id_of, scope_list, verify_delegation_proof_jwt


class InboundDelegationReasons:
    HEADERS_MISSING = "delegation_headers_missing"
    HEADER_DUPLICATED = "delegation_header_duplicated"
    CREDENTIAL_MALFORMED = "delegation_credential_malformed"
    CHAIN_TOO_LONG = "chain_too_long"
    PROOF_REPLAYED = "delegation_proof_replayed"
    SUBJECT_MISMATCH = "delegation_subject_mismatch"
    ID_MISMATCH = "delegation_id_mismatch"
    CHAIN_MISMATCH = "delegation_chain_mismatch"
    TARGET_NOT_ACCEPTED = "delegation_target_not_accepted"
    FORWARDER_UNBOUND = "delegation_forwarder_unbound"
    AGENT_DID_MISMATCH = "agent_did_mismatch"


@dataclass
class AdvisoryHeaders:
    chain: Optional[str] = None
    """``KYA-OS-Delegation-Chain``, when it agrees with the credential."""
    granted_scopes: Optional[List[str]] = None
    """``KYA-OS-Granted-Scopes``, when it agrees with the proof's ``scope``."""
    dropped: List[str] = field(default_factory=list)
    """The advisory headers that disagreed and were dropped: ``chain``, ``grantedScopes``."""


@dataclass
class InboundDelegationResult:
    ok: bool
    reasons: List[str] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)
    agent_did: Optional[str] = None
    forwarder: Optional[str] = None
    responsible_party: Optional[str] = None
    delegation_id: Optional[str] = None
    chain_string: Optional[str] = None
    chain: Optional[List[Any]] = None
    invocation_target: Optional[str] = None
    effective_scopes: List[str] = field(default_factory=list)
    level: str = "L1"
    fresh: bool = False
    cached: bool = False
    session_id: Optional[str] = None
    advisory: AdvisoryHeaders = field(default_factory=AdvisoryHeaders)
    claims: Optional[Dict[str, Any]] = None
    verification: Any = None


def host_of_did_web(did: str) -> Optional[str]:
    """The host a did:web DID names (``did:web:127.0.0.1%3A3000:services:ab`` → ``127.0.0.1:3000``), or None."""
    if not isinstance(did, str) or not did.startswith("did:web:"):
        return None
    segment = did[len("did:web:"):].split(":")[0]
    if not segment:
        return None
    try:
        return unquote(segment, errors="strict").lower()
    except UnicodeDecodeError:
        return None


def _subject_of(hop: Any) -> Dict[str, Any]:
    return hop["credentialSubject"] if isinstance(hop, dict) and isinstance(hop.get("credentialSubject"), dict) else {}


def _invoker_of(hop: Any) -> Optional[str]:
    subject = _subject_of(hop)
    invoker = subject.get("invoker", subject.get("controller"))
    return invoker if isinstance(invoker, str) else None


def agent_of_chain(chain: Sequence[Any], forwarder: str) -> Optional[str]:
    """The agent a chain names for ``forwarder``: its leaf delegate, unless the
    forwarder holds the leaf itself, in which case whoever first delegated to
    the forwarder (the forwarder itself when the root hop names it)."""
    leaf_invoker = _invoker_of(chain[-1]) if chain else None
    if leaf_invoker != forwarder:
        return leaf_invoker
    first = next(index for index, hop in enumerate(chain) if _invoker_of(hop) == forwarder)
    if first == 0:
        return forwarder
    hop = chain[first]
    return hop["issuer"] if isinstance(hop, dict) and isinstance(hop.get("issuer"), str) else None


def verify_inbound_delegation_headers(
    headers: Any,
    verifier: Any,
    *,
    audience: Union[None, str, Sequence[str]] = None,
    resource: Optional[str] = None,
    forwarders: Union[None, str, Sequence[str]] = None,
    cache: Any = None,
    live_status: bool = False,
    skew_seconds: Optional[int] = None,
    max_chain_length: int = 10,
) -> InboundDelegationResult:
    """Verifies the delegation headers of one downstream call with ``verifier``
    (this service's LocalVerifier). Never raises for a bad request: every
    refusal is a reason. ``forwarders`` is ``"*"`` or a list of DIDs whose own
    resource this service honours as a chain's target (default none)."""
    result = InboundDelegationResult(ok=False)

    def refuse(reason: str, message: str) -> InboundDelegationResult:
        result.ok = False
        result.reasons = [reason]
        result.messages = [message]
        result.effective_scopes = []
        result.level = "L1"
        result.fresh = False
        return result

    read = lambda name: header_values(headers, DELEGATION_HEADERS[name])  # noqa: E731
    credential_values, proof_values, agent_values = read("credential"), read("proof"), read("agent_did")
    for name, values in (("credential", credential_values), ("proof", proof_values), ("agent_did", agent_values)):
        if not values:
            return refuse(InboundDelegationReasons.HEADERS_MISSING, f"{DELEGATION_HEADERS[name]} is missing")
        if len(values) > 1:
            return refuse(InboundDelegationReasons.HEADER_DUPLICATED, f"{DELEGATION_HEADERS[name]} is sent more than once")
    session = read("session_id")
    if session:
        result.session_id = session[0]
    chain = decode_delegation_credential(credential_values[0])
    if chain is None:
        return refuse(InboundDelegationReasons.CREDENTIAL_MALFORMED, f"{DELEGATION_HEADERS['credential']} is not base64url JSON of a chain")
    if len(chain) > max_chain_length:
        return refuse(InboundDelegationReasons.CHAIN_TOO_LONG, f"the chain has {len(chain)} hops; at most {max_chain_length} are read")
    chain_string = build_chain_string(chain)
    delegation_id = delegation_id_of(chain)
    root = chain[0]
    responsible_party = root.get("issuer") if isinstance(root, dict) and isinstance(root.get("issuer"), str) else None
    target = _subject_of(chain[-1]).get("invocationTarget")
    invocation_target = target if isinstance(target, str) else None
    result.chain, result.chain_string, result.delegation_id = chain, chain_string, delegation_id
    result.responsible_party, result.invocation_target = responsible_party, invocation_target

    now = verifier.seams.clock()
    hosts = audience if audience is not None else host_of_did_web(verifier.service_did)
    if not hosts:
        return refuse("configuration_error", "verify_inbound_delegation_headers: no audience (this service's host) is configured")
    proof = verify_delegation_proof_jwt(proof_values[0], resolve_did=verifier.seams.resolve_did, audience=hosts, now_ms=now, skew_seconds=skew_seconds)
    if not proof.ok:
        result.forwarder = proof.iss
        return refuse(proof.reason, proof.message)  # type: ignore[arg-type]
    claims = proof.claims or {}
    forwarder = claims["iss"]
    result.forwarder, result.claims = forwarder, claims

    if responsible_party is None or claims["sub"] != responsible_party:
        return refuse(InboundDelegationReasons.SUBJECT_MISMATCH, f"sub {claims['sub']} is not the chain's root issuer {responsible_party}")
    if delegation_id is None or claims["delegation_id"] != delegation_id:
        return refuse(InboundDelegationReasons.ID_MISMATCH, f"delegation_id {claims['delegation_id']} is not the leaf capability {delegation_id}")
    if claims["delegation_chain"] != chain_string:
        return refuse(InboundDelegationReasons.CHAIN_MISMATCH, "delegation_chain is not the credential's chain string")

    own_resource = resource or verifier.service_did
    accepted = forwarders == "*" or (forwarders is not None and not isinstance(forwarders, str) and forwarder in forwarders)
    if invocation_target is None or (invocation_target != own_resource and not (invocation_target == forwarder and accepted)):
        return refuse(InboundDelegationReasons.TARGET_NOT_ACCEPTED, f"the chain targets {invocation_target}, which this service does not accept from {forwarder}")
    leaf_invoker = _invoker_of(chain[-1])
    if forwarder not in (invocation_target, leaf_invoker):
        return refuse(InboundDelegationReasons.FORWARDER_UNBOUND, f"{forwarder} is neither the chain's target nor its leaf delegate")
    agent_did = agent_of_chain(chain, forwarder)
    if agent_did is None or agent_values[0] != agent_did:
        return refuse(InboundDelegationReasons.AGENT_DID_MISMATCH, f"{DELEGATION_HEADERS['agent_did']} {agent_values[0]} is not the agent the chain names, {agent_did}")
    result.agent_did = agent_did

    skew = 5 if skew_seconds is None else skew_seconds
    if not verifier.seams.nonce_store.insert(claims["jti"], forwarder, (int(claims["exp"]) + skew + 1) * 1000):
        return refuse(InboundDelegationReasons.PROOF_REPLAYED, f"jti {claims['jti']} was already presented by {forwarder}")

    verification = None if live_status or cache is None else cache.get(chain)
    cached = verification is not None
    if verification is None:
        overrides: Dict[str, Any] = {"require_proof": False, "resource": invocation_target}
        if live_status:
            overrides["live_status"] = True
        verification = verifier.verify(None, chain=chain, **overrides)
        if verification.ok and not live_status and cache is not None:
            cache.set(chain, verification)
    result.verification = verification
    if not verification.ok:
        refuse(verification.reasons[0] if verification.reasons else "chain_invalid", "the chain was refused")
        result.reasons, result.messages = list(verification.reasons), list(verification.messages)
        return result

    signed = scope_list(claims["scope"])
    forwarded = set(signed)
    advisory = AdvisoryHeaders()
    stated_chain = read("chain")
    if stated_chain:
        if len(stated_chain) == 1 and stated_chain[0] == chain_string:
            advisory.chain = chain_string
        else:
            advisory.dropped.append("chain")
    stated_scopes = read("granted_scopes")
    if stated_scopes:
        stated = scope_list(stated_scopes[0]) if len(stated_scopes) == 1 else None
        if stated is not None and len(stated) == len(signed) and all(scope in forwarded for scope in stated):
            advisory.granted_scopes = stated
        else:
            advisory.dropped.append("grantedScopes")

    result.ok = True
    result.reasons, result.messages = [], []
    result.effective_scopes = [scope for scope in verification.effective_scopes if scope in forwarded]
    result.level = verification.level
    result.fresh = False if cached else verification.fresh
    result.cached = cached
    result.advisory = advisory
    return result
