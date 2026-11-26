# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The local verifier (KYA-OS story F-2), the Python port of helix-sdk-js
``kyaos.verifier.verify``: one pure module that verifies one shape, a
per-request holder-of-key proof (``org.kya-os/proof.v1``, SPEC-ENTITY-CARD.md
section 8) plus the delegation chain the request carries (section 10.5,
SPEC.md section 6.10), from the presented artifacts and what its seams
answer, and nothing else. Same seams, same order, same reason codes, same
results as the JavaScript reference, which the shared fixtures prove.

No network, no database, no global clock inside. A missing seam fails closed
with its own reason code; it never skips the check. Cross-border rule
(stories rule 4): the module never asks a Helix database anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Union

from ..credentials import (
    MAX_DELEGATION_DEPTH,
    TRUST_ALL_ISSUERS,
    DidResolver,
    TrustedIssuers,
    derive_conformance_level,
    derive_effective_scopes,
    validate_json_schema,
    verify_data_integrity,
)
from .attestation import CapabilityCheck, check_capabilities
from .card_schema import ENTITY_CARD_SCHEMA
from .chain import evaluate_delegation_chain_rules
from .codes import ReasonCodes
from .request_proof import DEFAULT_PROOF_SKEW_SECONDS, MAX_PROOF_TTL_SECONDS
from .revocation import RevocationChecker, RevocationContext, RevocationVerdict, check_chain_revocation, revocation_checker_of
from .status import FetchStatusList, StatusListRead
from .verify_request_proof import RequestProofOptions, verify_request_proof


class NonceStore:
    """The local replay store: one atomic conditional insert (the middleware's shape)."""

    def insert(self, nonce: str, agent_did: Optional[str], expires_at_ms: int) -> bool:  # pragma: no cover - protocol only
        raise NotImplementedError


class MemoryNonceStore(NonceStore):
    """Single-process store: a map of key to expiry, swept of expired entries on every insert."""

    def __init__(self, now_ms: Optional[Callable[[], int]] = None) -> None:
        self._entries: Dict[str, int] = {}
        self._now = now_ms or (lambda: int(__import__("time").time() * 1000))

    def insert(self, nonce: str, agent_did: Optional[str], expires_at_ms: int) -> bool:
        now = self._now()
        for key in [key for key, expiry in self._entries.items() if expiry <= now]:
            del self._entries[key]
        key = f"{agent_did or ''}|{nonce}"
        if key in self._entries:
            return False
        self._entries[key] = expires_at_ms
        return True


@dataclass
class VerifierSeams:
    resolve_did: Optional[DidResolver] = None
    resolve_did_keys: Optional[Callable[[str], Sequence[Mapping[str, Any]]]] = None
    fetch_status_list: Optional[FetchStatusList] = None
    #: The revocation check of one credential (story L3-C); default one over ``fetch_status_list``, no cache.
    check_revocation: Optional[RevocationChecker] = None
    resolve_card: Optional[Callable[[str], Any]] = None
    nonce_store: Optional[Any] = None
    clock: Optional[Callable[[], int]] = None
    trusted_issuers: TrustedIssuers = TRUST_ALL_ISSUERS


@dataclass
class VerifierOptions:
    expected_audience: str
    max_chain_length: int = MAX_DELEGATION_DEPTH
    skew_seconds: int = DEFAULT_PROOF_SKEW_SECONDS
    max_ttl_seconds: int = MAX_PROOF_TTL_SECONDS
    max_clock_skew_ms: Any = None
    resource: Optional[str] = None
    resource_owner: Optional[str] = None
    trusted_root_issuers: Optional[Sequence[str]] = None
    catalog: Optional[Sequence[str]] = None
    action: Optional[str] = None
    token_cnf_jkt: Optional[str] = None
    require_proof: bool = True
    """Default True: a call without a request proof is refused ``proof_missing``. False (story C-C):
    a call carrying a chain and no proof is verified on the chain alone, with the proof floor
    unmet, so its level is at most L2."""
    live_status: bool = False
    """Read every status list live, past the status cache (story L3-C with C-C's levels): a call to
    a tool whose minimum Card level is L3 needs fresh revocation status, which a cached read is not.
    Default False: the cache serves, and a cached read is not fresh, so at most L2."""
    allow_own_authority: bool = False
    """Own authority (the service's opt-in; default False): a call carrying no chain, from an agent
    whose card names no ``responsibleParty``, acts on what the agent is attested for, intersected
    with ``catalog`` (none without one). A card naming a ``responsibleParty`` still needs its chain
    (SPEC-ENTITY-CARD section 11.1 step 6), so it gets no scopes this way."""

    @classmethod
    def from_dict(cls, options: Mapping[str, Any]) -> "VerifierOptions":
        """The options as the shared fixtures write them (camelCase, as the JavaScript verifier takes them)."""
        names = {
            "expectedAudience": "expected_audience",
            "maxChainLength": "max_chain_length",
            "skewSeconds": "skew_seconds",
            "maxTtlSeconds": "max_ttl_seconds",
            "maxClockSkewMs": "max_clock_skew_ms",
            "resource": "resource",
            "resourceOwner": "resource_owner",
            "trustedRootIssuers": "trusted_root_issuers",
            "catalog": "catalog",
            "action": "action",
            "tokenCnfJkt": "token_cnf_jkt",
            "requireProof": "require_proof",
            "liveStatus": "live_status",
            "allowOwnAuthority": "allow_own_authority",
        }
        return cls(**{names[key]: value for key, value in options.items() if key in names})


@dataclass
class ChainSummary:
    depth: int = 0
    responsible_party: Optional[str] = None
    leaf_invoker: Optional[str] = None
    invocation_target: Optional[str] = None
    allowed_action: List[str] = field(default_factory=list)
    fresh: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """The camelCase form the shared fixtures record."""
        out: Dict[str, Any] = {"depth": self.depth}
        if self.responsible_party is not None:
            out["responsibleParty"] = self.responsible_party
        if self.leaf_invoker is not None:
            out["leafInvoker"] = self.leaf_invoker
        if self.invocation_target is not None:
            out["invocationTarget"] = self.invocation_target
        out["allowedAction"] = list(self.allowed_action)
        out["fresh"] = self.fresh
        return out


@dataclass
class VerifierResult:
    ok: bool
    level: str
    effective_scopes: List[str]
    reasons: List[str]
    messages: List[str]
    chain_summary: ChainSummary
    capabilities: CapabilityCheck
    fresh: bool
    warnings: List[str]
    proof_did: Optional[str] = None
    """The accountable principal, once its proof verified."""
    proof_assurance: Optional[str] = None
    """``L3`` on a full ``cnf`` fusion, ``L3-minus`` without a token ``cnf``; set once the proof verified."""
    agent_did: Optional[str] = None
    """Who the call is for: the proof's DID, or, on a call verified without a proof, the chain's
    leaf delegate (unproven). Set on success."""
    proof_floor: bool = False
    """True when a request proof verified: the section 9.4 proof floor."""

    def to_dict(self) -> Dict[str, Any]:
        """The comparable part of the result, as the shared fixtures record it."""
        return {
            "ok": self.ok,
            "level": self.level,
            "effectiveScopes": list(self.effective_scopes),
            "reasons": list(self.reasons),
            "chainSummary": self.chain_summary.to_dict(),
        }


class _Refusals:
    def __init__(self) -> None:
        self.reasons: List[str] = []
        self.messages: List[str] = []

    def add(self, code: str, message: str) -> None:
        self.reasons.append(code)
        self.messages.append(message)

    @property
    def any(self) -> bool:
        return bool(self.reasons)


def _refused(refusals: _Refusals, summary: ChainSummary, **extra: Any) -> VerifierResult:
    summary = ChainSummary(summary.depth, summary.responsible_party, summary.leaf_invoker, summary.invocation_target, [], False)
    result = VerifierResult(False, "L1", [], list(refusals.reasons), list(refusals.messages), summary, CapabilityCheck(), False, [])
    for name, value in extra.items():
        setattr(result, name, value)
    return result


def _missing_seams(seams: VerifierSeams, refusals: _Refusals) -> None:
    if not callable(seams.clock):
        refusals.add(ReasonCodes.CLOCK_SEAM_MISSING, "no clock seam: the verifier holds no clock of its own")
    if not callable(seams.resolve_did):
        refusals.add(ReasonCodes.DID_RESOLVER_MISSING, "no resolve_did seam: the signing key cannot be read")
    if not callable(seams.resolve_did_keys):
        refusals.add(ReasonCodes.DID_MEMBERSHIP_UNVERIFIABLE, "no resolve_did_keys seam: the key cannot be shown to belong to the DID")
    if seams.nonce_store is None or not callable(getattr(seams.nonce_store, "insert", None)):
        refusals.add(ReasonCodes.NONCE_SEAM_MISSING, "no nonce_store seam: there is no replay defense to run")


def _revocation_seam(seams: VerifierSeams, options: VerifierOptions) -> Optional[RevocationChecker]:
    """The revocation seam in force: the one given, else one over ``fetch_status_list``, else none."""
    if callable(seams.check_revocation):
        return seams.check_revocation
    return revocation_checker_of(seams.fetch_status_list, options.max_clock_skew_ms) if callable(seams.fetch_status_list) else None


def _request_scopes(options: VerifierOptions, allowed_action: Sequence[str]) -> Sequence[str]:
    """The scopes a request touches, which pick the status cache TTL: the invoked action, else what the leaf allows."""
    return list(allowed_action) if options.action is None else [options.action]


def validate_entity_card(value: Any) -> List[str]:
    """Every way ``value`` fails the strict card schema, as ``path: message``; empty when it is a card."""
    return [f"{violation.path}: {violation.message}" for violation in validate_json_schema(ENTITY_CARD_SCHEMA, value)]


def verify(
    proof: Any,
    seams: VerifierSeams,
    options: Union[VerifierOptions, Mapping[str, Any]],
    *,
    chain: Any = None,
    request: Optional[Mapping[str, Any]] = None,
    card: Any = None,
) -> VerifierResult:
    """Verifies the proof, the carried chain and the card with ``seams`` under ``options``; never raises for a bad input."""
    if isinstance(options, Mapping):
        options = VerifierOptions.from_dict(options)
    refusals = _Refusals()

    # 1. Seams and options, before anything is read.
    _missing_seams(seams, refusals)
    max_chain_length = options.max_chain_length
    if isinstance(max_chain_length, bool) or not isinstance(max_chain_length, int) or max_chain_length < 1:
        refusals.add(ReasonCodes.CONFIGURATION_ERROR, "maxChainLength must be a positive integer")
    if not isinstance(options.expected_audience, str) or not options.expected_audience.startswith("did:"):
        refusals.add(ReasonCodes.CONFIGURATION_ERROR, "expectedAudience must be this verifier's DID")
    if refusals.any:
        return _refused(refusals, ChainSummary())
    assert seams.clock is not None
    now = seams.clock()
    skew_seconds = options.skew_seconds

    # 2. The carried chain's length, bounded before any entry is parsed.
    hops: Optional[List[Any]] = None
    if chain is not None:
        if not isinstance(chain, list) or not chain:
            refusals.add(ReasonCodes.CHAIN_INVALID, "the carried chain is not a non-empty array")
            return _refused(refusals, ChainSummary())
        if len(chain) > max_chain_length:
            refusals.add(ReasonCodes.CHAIN_TOO_LONG, f"the carried chain has {len(chain)} hops; at most {max_chain_length} are read")
            return _refused(refusals, ChainSummary(depth=len(chain), fresh=False))
        hops = chain
    depth = len(hops) if hops is not None else 0
    no_chain = ChainSummary(depth=depth, fresh=False)

    # 3. The request proof, in the exact section 11.2 order (story C-C). A call that may go without
    #    one (require_proof=False) and carries a chain is verified on the chain alone, without the
    #    proof floor.
    proof_absent = proof is None
    proved: Dict[str, Any] = {}
    proof_did: Optional[str] = None
    if not proof_absent or options.require_proof or hops is None:
        verdict = verify_request_proof(
            proof,
            request,
            seams,
            RequestProofOptions(
                expected_audience=options.expected_audience,
                skew_seconds=skew_seconds,
                max_ttl_seconds=options.max_ttl_seconds,
                token_cnf_jkt=options.token_cnf_jkt,
            ),
        )
        if not verdict.ok:
            for index, code in enumerate(verdict.reasons):
                refusals.add(code, verdict.messages[index])
            return _refused(refusals, no_chain)
        proof_did = verdict.did
        # Every binding held: from here a refusal names the principal it refused.
        proved = {"proof_did": proof_did, "proof_assurance": verdict.assurance, "warnings": verdict.warnings, "proof_floor": True}

    # Lists read live for this verification: a second credential on the same list stays a live read.
    reads: Dict[str, StatusListRead] = {}

    # 6. The chain: local rules, the leaf join, trusted roots, the action, each hop's proof, each hop's status.
    summary = ChainSummary()
    leaf_allowed_action: List[str] = []
    chain_fresh = True
    if hops is not None:
        evaluation = evaluate_delegation_chain_rules(
            hops,
            now_ms=now,
            max_chain_length=max_chain_length,
            resource=options.resource,
            resource_owner=options.resource_owner,
            max_clock_skew_ms=options.max_clock_skew_ms,
        )
        summary = ChainSummary(evaluation.depth, evaluation.responsible_party, evaluation.leaf_invoker, evaluation.invocation_target, evaluation.allowed_action, False)
        if not evaluation.ok:
            for code, reason in evaluation.broken:
                refusals.add(code, reason)
            return _refused(refusals, summary, **proved)
        if proof_did is not None and evaluation.leaf_invoker != proof_did:
            refusals.add(ReasonCodes.LEAF_INVOKER_MISMATCH, f"the leaf delegate {evaluation.leaf_invoker} is not the proof's did {proof_did}")
            return _refused(refusals, summary, **proved)
        root = hops[0]
        if options.trusted_root_issuers is not None and root["issuer"] not in options.trusted_root_issuers:
            refusals.add(ReasonCodes.ISSUER_UNTRUSTED, f"root issuer {root['issuer']} is not a trusted root issuer")
            return _refused(refusals, summary, **proved)
        if options.action is not None and options.action not in evaluation.allowed_action:
            refusals.add(ReasonCodes.ACTION_NOT_DELEGATED, f"the leaf does not allow {options.action}")
            return _refused(refusals, summary, **proved)
        assert seams.resolve_did is not None
        for index, hop in enumerate(hops):
            verdict = verify_data_integrity(hop, seams.resolve_did)
            if not verdict.ok:
                refusals.add(ReasonCodes.HOP_PROOF_INVALID, f"hop {index}: {verdict.reason}: {verdict.message}")
                return _refused(refusals, summary, **proved)
        checker = _revocation_seam(seams, options)
        if checker is None:
            refusals.add(ReasonCodes.STATUS_SEAM_MISSING, "no fetch_status_list seam: the hops' status cannot be read")
            return _refused(refusals, summary, **proved)
        # Root to leaf, stopping at the first revoked or unresolvable hop (section 6.5 cascade, story L3-C point 4).
        revocation = check_chain_revocation(hops, checker, RevocationContext(now_ms=now, scopes=_request_scopes(options, evaluation.allowed_action), reads=reads, live=options.live_status))
        if revocation.revoked:
            refusals.add(revocation.code or ReasonCodes.STATUS_REVOKED, f"hop {revocation.index}: {revocation.message or 'revoked'}")
            return _refused(refusals, summary, **proved)
        chain_fresh = revocation.fresh
        summary.fresh = chain_fresh
        leaf_allowed_action = evaluation.allowed_action

    # 7. The card: its shape, the responsibleParty gate and its attestations. Without a proof the
    #    card is the leaf delegate's, which the chain names but nothing proves.
    agent_did = proof_did if proof_did is not None else summary.leaf_invoker
    assert agent_did is not None
    card_value = card
    if card_value is None and callable(seams.resolve_card):
        try:
            card_value = seams.resolve_card(agent_did)
        except Exception as exc:  # noqa: BLE001
            refusals.add(ReasonCodes.CARD_UNRESOLVABLE, f"the card of {agent_did} could not be read: {exc}")
            return _refused(refusals, summary, **proved)
    entity_card: Optional[Mapping[str, Any]] = None
    if card_value is not None:
        problems = validate_entity_card(card_value)
        if problems:
            refusals.add(ReasonCodes.CARD_MALFORMED, "; ".join(problems))
            return _refused(refusals, summary, **proved)
        entity_card = card_value
        if entity_card["id"] != agent_did:
            refusals.add(ReasonCodes.CARD_SUBJECT_MISMATCH, f"the card is {entity_card['id']}'s, not {agent_did}'s")
            return _refused(refusals, summary, **proved)
        responsible = entity_card.get("responsibleParty")
        if hops is not None and responsible is not None and responsible != summary.responsible_party:
            refusals.add(ReasonCodes.ROOT_NOT_RESPONSIBLE_PARTY, f"the root issuer {summary.responsible_party} is not the card's responsibleParty {responsible}")
            return _refused(refusals, summary, **proved)
    # The card's own revocation entry (SPEC-ENTITY-CARD section 10.3; Cleanup, Harish's pick A): a
    # revoked agent is refused. The list's keeper is the card's DID unless the configuration binds the
    # URL (status_list_issuers) to another issuer, as a Helix card's list is bound to Helix.
    card_fresh = True
    card_revocation = entity_card.get("revocation") if entity_card is not None else None
    if entity_card is not None and card_revocation is not None:
        card_checker = _revocation_seam(seams, options)
        if card_checker is None:
            refusals.add(ReasonCodes.STATUS_SEAM_MISSING, "no fetch_status_list seam: the card's revocation entry cannot be read")
            return _refused(refusals, summary, **proved)
        entry = {"type": "BitstringStatusListEntry", "statusPurpose": "revocation", **card_revocation}
        try:
            card_verdict = card_checker(
                {"issuer": entity_card["id"], "credentialStatus": entry},
                RevocationContext(now_ms=now, scopes=_request_scopes(options, leaf_allowed_action), reads=reads, live=options.live_status),
            )
        except Exception as exc:  # noqa: BLE001 - a checker that raises fails closed
            card_verdict = RevocationVerdict(True, False, ReasonCodes.STATUS_UNAVAILABLE, f"the revocation check failed: {exc}")
        if card_verdict.revoked:
            refusals.add(card_verdict.code or ReasonCodes.STATUS_REVOKED, f"the card's revocation entry: {card_verdict.message or 'revoked'}")
            return _refused(refusals, summary, **proved)
        card_fresh = card_verdict.fresh
    capabilities = CapabilityCheck()
    if entity_card is not None and isinstance(entity_card.get("capabilities"), list) and entity_card["capabilities"]:
        assert seams.resolve_did is not None
        capabilities = check_capabilities(
            entity_card["capabilities"],
            seams.resolve_did,
            subject_did=agent_did,
            now_ms=now,
            trusted_issuers=seams.trusted_issuers,
            max_clock_skew_ms=options.max_clock_skew_ms,
            fetch_status_list=seams.fetch_status_list,
            check_revocation=_revocation_seam(seams, options),
            scopes=_request_scopes(options, leaf_allowed_action),
            reads=reads,
            live_status=options.live_status,
        )

    # 8. Authority and level (story F-1 point 4; section 9.4): the proof floor holds only when a proof verified.
    # Own authority (allow_own_authority): no chain, a proven key and a card that names no responsible party.
    own_authority = options.allow_own_authority and hops is None and proof_did is not None and entity_card is not None and entity_card.get("responsibleParty") is None
    if own_authority:
        offered = list(options.catalog) if options.catalog is not None else []
        effective_scopes = derive_effective_scopes(capabilities.verified, offered, offered)
    else:
        catalog = options.catalog if options.catalog is not None else leaf_allowed_action
        effective_scopes = derive_effective_scopes(capabilities.verified, leaf_allowed_action, catalog)
    fresh = chain_fresh and capabilities.fresh and card_fresh
    proof_floor = proof_did is not None
    level = derive_conformance_level({"verified": capabilities.verified, "unverified": capabilities.unverified}, proof_floor, fresh)
    return VerifierResult(
        ok=True,
        level=level,
        effective_scopes=effective_scopes,
        reasons=[],
        messages=[],
        chain_summary=summary,
        capabilities=capabilities,
        fresh=fresh,
        warnings=list(proved.get("warnings", [])),
        proof_did=proof_did,
        proof_assurance=proved.get("proof_assurance"),
        agent_did=agent_did,
        proof_floor=proof_floor,
    )
