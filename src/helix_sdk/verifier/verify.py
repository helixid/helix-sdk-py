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
from ..crypto.jws import base64url_decode_strict, select_assertion_method, verification_method_to_jwk
from ..errors import InvalidJWSError
from .attestation import CapabilityCheck, check_capabilities
from .card_schema import ENTITY_CARD_SCHEMA
from .chain import evaluate_delegation_chain_rules
from .codes import ReasonCodes
from .request_proof import (
    DEFAULT_PROOF_SKEW_SECONDS,
    MAX_PROOF_TTL_SECONDS,
    did_of_kid,
    jwk_thumbprint,
    parse_request_proof,
    request_hash_content_digest,
    verify_detached_jws,
    window_problems,
)
from .status import FetchStatusList, check_status_entry


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
    proof_assurance: Optional[str] = None

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


def _resolve_signing_key(proof: Mapping[str, Any], seams: VerifierSeams, refusals: _Refusals) -> Optional[Dict[str, Any]]:
    assert seams.resolve_did is not None
    try:
        document = seams.resolve_did(proof["did"])
    except Exception as exc:  # noqa: BLE001 - a resolver that throws leaves the document unread
        refusals.add(ReasonCodes.DID_UNRESOLVED, f"could not resolve {proof['did']}: {exc}")
        return None
    if document is None:
        refusals.add(ReasonCodes.DID_UNRESOLVED, f"{proof['did']} did not resolve")
        return None
    try:
        jwk = verification_method_to_jwk(select_assertion_method(document, proof["did"], proof["kid"]))
    except InvalidJWSError as exc:
        refusals.add(ReasonCodes.KEY_UNRESOLVABLE, f"{exc.reason}: {exc}")
        return None
    raw = base64url_decode_strict(jwk["x"])
    assert raw is not None
    return {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"], "kid": proof["kid"]}, "public_key": raw}


def _assert_did_membership(proof: Mapping[str, Any], key: Mapping[str, Any], seams: VerifierSeams, refusals: _Refusals) -> None:
    assert seams.resolve_did_keys is not None
    try:
        published = list(seams.resolve_did_keys(proof["did"]))
    except Exception as exc:  # noqa: BLE001
        refusals.add(ReasonCodes.DID_KEYS_UNRESOLVABLE, f"could not list the keys of {proof['did']}: {exc}")
        return
    wanted = jwk_thumbprint(key["jwk"])
    thumbprints = []
    for jwk in published:
        try:
            thumbprints.append(jwk_thumbprint(jwk))
        except Exception:  # noqa: BLE001 - a key that is no JWK has no thumbprint
            thumbprints.append(None)
    if wanted not in thumbprints:
        refusals.add(ReasonCodes.KID_NOT_IN_DID_DOCUMENT, f"{proof['kid']} is not a key {proof['did']} publishes")


def _cnf_fusion(proof: Mapping[str, Any], key: Mapping[str, Any], options: VerifierOptions, refusals: _Refusals, warnings: List[str]) -> str:
    key_jkt = jwk_thumbprint(key["jwk"])
    cnf = proof.get("cnf")
    if cnf is not None and cnf["jkt"] != key_jkt:
        refusals.add(ReasonCodes.CNF_KEY_MISMATCH, "cnf.jkt is not the thumbprint of the signing key")
    if options.token_cnf_jkt is None:
        if cnf is not None:
            warnings.append("cnf_present_but_token_unfused")
        return "L3-minus"
    if cnf is None:
        refusals.add(ReasonCodes.CNF_REQUIRED_BY_TOKEN, "the token is sender-constrained but the proof carries no cnf")
        return "L3-minus"
    if cnf["jkt"] != options.token_cnf_jkt:
        refusals.add(ReasonCodes.CNF_TOKEN_MISMATCH, "cnf.jkt is not the token cnf.jkt")
        return "L3-minus"
    return "L3" if cnf["jkt"] == key_jkt else "L3-minus"


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
    warnings: List[str] = []

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
    now_seconds = now // 1000
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

    # 3. The proof's shape and its local bindings.
    if proof is None:
        refusals.add(ReasonCodes.PROOF_MISSING, "the request carries no org.kya-os/request-proof")
        return _refused(refusals, no_chain)
    parsed = parse_request_proof(proof)
    if parsed is None:
        refusals.add(ReasonCodes.MALFORMED_PROOF, "the request proof is not an org.kya-os/proof.v1 object")
        return _refused(refusals, no_chain)
    if did_of_kid(parsed["kid"]) != parsed["did"]:
        refusals.add(ReasonCodes.KID_DID_MISMATCH, "kid does not belong to did")
    if parsed["alg"] != "EdDSA":
        refusals.add(ReasonCodes.ALG_UNSUPPORTED, f"proof alg {parsed['alg']} is not EdDSA")
    if parsed["audience"] != options.expected_audience:
        refusals.add(ReasonCodes.AUDIENCE_MISMATCH, f"audience {parsed['audience']} is not this verifier ({options.expected_audience})")
    if request is None:
        refusals.add(ReasonCodes.REQUEST_MISSING, "no request to recompute requestHash from")
    else:
        try:
            computed: Optional[str] = request_hash_content_digest(request)
        except Exception:  # noqa: BLE001 - a request with no canonical form hashes to nothing
            computed = None
        if computed != parsed["requestHash"]:
            refusals.add(ReasonCodes.REQUEST_HASH_MISMATCH, "requestHash does not recompute from the request")
    for problem in window_problems(parsed, now_seconds, skew_seconds, options.max_ttl_seconds):
        refusals.add(problem, f"proof window: {problem}")
    if refusals.any:
        return _refused(refusals, no_chain)

    # 4. The signing key, its DID membership and the signature.
    key = _resolve_signing_key(parsed, seams, refusals)
    if key is None:
        return _refused(refusals, no_chain)
    _assert_did_membership(parsed, key, seams, refusals)
    if not verify_detached_jws(parsed, key["public_key"]):
        refusals.add(ReasonCodes.INVALID_SIGNATURE, "the detached JWS does not verify over the covered claims")
    proof_assurance = _cnf_fusion(parsed, key, options, refusals, warnings)
    if refusals.any:
        return _refused(refusals, no_chain, warnings=warnings)
    # The signature held: from here the refusal names the principal it refused.
    proved = {"proof_did": parsed["did"], "proof_assurance": proof_assurance, "warnings": warnings}

    # 5. The nonce, consumed only once every binding held.
    try:
        expires_at = (parsed["expires"] + skew_seconds + 1) * 1000
        if not seams.nonce_store.insert(parsed["nonce"], parsed["did"], expires_at):
            refusals.add(ReasonCodes.NONCE_REPLAYED, f"nonce {parsed['nonce']} was already used by {parsed['did']}")
    except Exception as exc:  # noqa: BLE001 - a store that cannot answer fails closed
        refusals.add(ReasonCodes.NONCE_STORE_UNAVAILABLE, f"the nonce store could not answer: {exc}")
    if refusals.any:
        return _refused(refusals, no_chain, **proved)

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
        if evaluation.leaf_invoker != parsed["did"]:
            refusals.add(ReasonCodes.LEAF_INVOKER_MISMATCH, f"the leaf delegate {evaluation.leaf_invoker} is not the proof's did {parsed['did']}")
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
        if not callable(seams.fetch_status_list):
            refusals.add(ReasonCodes.STATUS_SEAM_MISSING, "no fetch_status_list seam: the hops' status cannot be read")
            return _refused(refusals, summary, **proved)
        for index, hop in enumerate(hops):
            try:
                read = seams.fetch_status_list(hop["credentialStatus"]["statusListCredential"])
            except Exception as exc:  # noqa: BLE001
                refusals.add(ReasonCodes.STATUS_UNAVAILABLE, f"hop {index}: status list could not be read: {exc}")
                return _refused(refusals, summary, **proved)
            status = check_status_entry(hop["credentialStatus"], hop["issuer"], read, now_ms=now, max_clock_skew_ms=options.max_clock_skew_ms)
            if not status.ok:
                refusals.add(status.code or ReasonCodes.STATUS_UNAVAILABLE, f"hop {index}: {status.message}")
                return _refused(refusals, summary, **proved)
            chain_fresh = chain_fresh and status.fresh
        summary.fresh = chain_fresh
        leaf_allowed_action = evaluation.allowed_action

    # 7. The card: its shape, the responsibleParty gate and its attestations.
    card_value = card
    if card_value is None and callable(seams.resolve_card):
        try:
            card_value = seams.resolve_card(parsed["did"])
        except Exception as exc:  # noqa: BLE001
            refusals.add(ReasonCodes.CARD_UNRESOLVABLE, f"the card of {parsed['did']} could not be read: {exc}")
            return _refused(refusals, summary, **proved)
    entity_card: Optional[Mapping[str, Any]] = None
    if card_value is not None:
        problems = validate_entity_card(card_value)
        if problems:
            refusals.add(ReasonCodes.CARD_MALFORMED, "; ".join(problems))
            return _refused(refusals, summary, **proved)
        entity_card = card_value
        if entity_card["id"] != parsed["did"]:
            refusals.add(ReasonCodes.CARD_SUBJECT_MISMATCH, f"the card is {entity_card['id']}'s, not {parsed['did']}'s")
            return _refused(refusals, summary, **proved)
        responsible = entity_card.get("responsibleParty")
        if hops is not None and responsible is not None and responsible != summary.responsible_party:
            refusals.add(ReasonCodes.ROOT_NOT_RESPONSIBLE_PARTY, f"the root issuer {summary.responsible_party} is not the card's responsibleParty {responsible}")
            return _refused(refusals, summary, **proved)
    capabilities = CapabilityCheck()
    if entity_card is not None and isinstance(entity_card.get("capabilities"), list) and entity_card["capabilities"]:
        assert seams.resolve_did is not None
        capabilities = check_capabilities(
            entity_card["capabilities"],
            seams.resolve_did,
            subject_did=parsed["did"],
            now_ms=now,
            trusted_issuers=seams.trusted_issuers,
            max_clock_skew_ms=options.max_clock_skew_ms,
            fetch_status_list=seams.fetch_status_list,
        )

    # 8. Authority and level.
    catalog = options.catalog if options.catalog is not None else leaf_allowed_action
    effective_scopes = derive_effective_scopes(capabilities.verified, leaf_allowed_action, catalog)
    fresh = chain_fresh and capabilities.fresh
    level = derive_conformance_level({"verified": capabilities.verified, "unverified": capabilities.unverified}, True, fresh)
    return VerifierResult(
        ok=True,
        level=level,
        effective_scopes=effective_scopes,
        reasons=[],
        messages=[],
        chain_summary=summary,
        capabilities=capabilities,
        fresh=fresh,
        warnings=warnings,
        proof_did=parsed["did"],
        proof_assurance=proof_assurance,
    )
