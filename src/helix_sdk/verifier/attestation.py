# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Capability attestations and the Entity Card level as the local verifier
reads them (stories F-1, C-B; SPEC-ENTITY-CARD.md section 9): the status read
goes through the verifier's ``fetch_status_list`` seam. Mirrors helix-sdk-js
``verifier/attestation.ts``; the pure pieces come from ``helix_sdk.credentials``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..credentials import (
    TRUST_ALL_ISSUERS,
    DidResolver,
    TrustedIssuers,
    Verdict,
    _refused,
    describe_violations,
    is_trusted_issuer,
    validate_credential,
    verify_data_integrity,
    window_verdict,
)
from .codes import ReasonCodes
from .revocation import RevocationChecker, RevocationContext, revocation_checker_of
from .status import FetchStatusList, StatusListRead

__all__ = ["CapabilityCheck", "verify_capability_attestation", "check_capabilities", "capability_name"]


@dataclass
class CapabilityCheck:
    verified: List[str] = field(default_factory=list)
    unverified: List[str] = field(default_factory=list)
    fresh: bool = True
    refusals: Dict[str, str] = field(default_factory=dict)


def capability_name(capability: Any) -> str:
    return capability if isinstance(capability, str) else capability["name"]


def verify_capability_attestation(
    value: Any,
    resolve_did: DidResolver,
    *,
    now_ms: int,
    subject_did: Optional[str] = None,
    capability: Optional[str] = None,
    trusted_issuers: TrustedIssuers = TRUST_ALL_ISSUERS,
    max_clock_skew_ms: Any = None,
    fetch_status_list: Optional[FetchStatusList] = None,
    check_revocation: Optional[RevocationChecker] = None,
    scopes: Sequence[str] = (),
    reads: Optional[Dict[str, StatusListRead]] = None,
    live_status: bool = False,
) -> Verdict:
    """Schema, subject, capability, trusted issuer, window, proof and status, in that order; never raises."""
    violations = validate_credential("attestation", value)
    if violations:
        return _refused("schema_invalid", describe_violations(violations))
    subject = value["credentialSubject"]
    if subject_did is not None and subject["id"] != subject_did:
        return _refused("subject_mismatch", "credentialSubject.id is not the card id")
    if capability is not None and subject["capability"] != capability:
        return _refused("capability_mismatch", "credentialSubject.capability is not the declared capability")
    if not is_trusted_issuer(value["issuer"], trusted_issuers):
        return _refused(ReasonCodes.ISSUER_UNTRUSTED, f"{value['issuer']} is not a trusted issuer")
    window = window_verdict(value.get("validFrom"), value.get("validUntil"), now_ms, max_clock_skew_ms)
    if window != "inside":
        return _refused(f"credential_{window}", f"credential is {window.replace('_', ' ')}")
    proof = verify_data_integrity(value, resolve_did)
    if not proof.ok:
        return proof
    checker = check_revocation or (revocation_checker_of(fetch_status_list, max_clock_skew_ms) if fetch_status_list is not None else None)
    if checker is None:
        return _refused(ReasonCodes.STATUS_SEAM_MISSING, "no fetch_status_list seam to read the attestation status with")
    try:
        status = checker(value, RevocationContext(now_ms=now_ms, scopes=scopes, reads=reads, live=live_status))
    except Exception as exc:  # noqa: BLE001 - a checker that raises fails closed
        return _refused(ReasonCodes.STATUS_UNAVAILABLE, f"the revocation check failed: {exc}")
    if status.revoked:
        return _refused(status.code or ReasonCodes.STATUS_REVOKED, status.message or "revoked")
    return Verdict(True, details={"capability": subject["capability"], "issuer": value["issuer"], "fresh": status.fresh})


def check_capabilities(
    capabilities: Sequence[Any],
    resolve_did: DidResolver,
    *,
    subject_did: str,
    now_ms: int,
    trusted_issuers: TrustedIssuers = TRUST_ALL_ISSUERS,
    max_clock_skew_ms: Any = None,
    fetch_status_list: Optional[FetchStatusList] = None,
    check_revocation: Optional[RevocationChecker] = None,
    scopes: Sequence[str] = (),
    reads: Optional[Dict[str, StatusListRead]] = None,
    live_status: bool = False,
) -> CapabilityCheck:
    """Verified (at least one attestation holds) versus unverified capabilities of a card, with freshness."""
    check = CapabilityCheck()
    for capability in capabilities:
        if isinstance(capability, str):
            check.unverified.append(capability)
            continue
        holds = False
        for attestation in capability["attestations"]:
            verdict = verify_capability_attestation(
                attestation.get("vc") if isinstance(attestation, Mapping) else None,
                resolve_did,
                now_ms=now_ms,
                subject_did=subject_did,
                capability=capability["name"],
                trusted_issuers=trusted_issuers,
                max_clock_skew_ms=max_clock_skew_ms,
                fetch_status_list=fetch_status_list,
                check_revocation=check_revocation,
                scopes=scopes,
                reads=reads,
                live_status=live_status,
            )
            if verdict.ok:
                holds = True
                check.fresh = check.fresh and bool(verdict.details.get("fresh", True))
                break
            check.refusals.setdefault(capability["name"], verdict.reason or "")
        (check.verified if holds else check.unverified).append(capability["name"])
    return check
