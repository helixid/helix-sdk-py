# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The delegation chain as the local verifier evaluates it (KYA-OS story F-2).

``evaluate_delegation_chain_rules`` is ``helix_sdk.credentials.evaluate_delegation_chain``
(story F-1's evaluator, byte for byte the helix-core one) with each broken
rule carrying its finer code: an attenuation or continuity failure between
two hops is ``attenuation_violation``, which the verifier reports as such;
the plain evaluator folds it into ``chain_invalid``, the helix-core code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

import copy

from ..credentials import (
    DELEGATION_HOP_SCHEMA,
    MAX_DELEGATION_DEPTH,
    validate_json_schema,
    _now_ms,
    attenuation_reasons,
    clock_skew_ms,
    describe_violations,
    invoker_of,
    validate_credential,
    window_verdict,
)


def _hop_schema_any_proof() -> Any:
    schema = copy.deepcopy(DELEGATION_HOP_SCHEMA)
    schema["required"] = [member for member in schema["required"] if member != "proof"]
    schema["properties"]["proof"] = {"type": "object"}
    return schema


_HOP_SCHEMA_ANY_PROOF = _hop_schema_any_proof()


@dataclass
class ChainRules:
    ok: bool
    reasons: List[str]
    allowed_action: List[str]
    depth: int
    code: Optional[str] = None
    responsible_party: Optional[str] = None
    leaf_invoker: Optional[str] = None
    invocation_target: Optional[str] = None
    broken: List[Tuple[str, str]] = field(default_factory=list)


def _refused(code: str, reasons: List[str], depth: int) -> ChainRules:
    plain = "chain_invalid" if code == "attenuation_violation" else code
    return ChainRules(False, reasons, [], depth, plain, broken=[(code, reason) for reason in reasons])


def evaluate_delegation_chain_rules(
    hops: Any,
    *,
    resource: Optional[str] = None,
    resource_owner: Optional[str] = None,
    now_ms: Optional[int] = None,
    max_chain_length: int = MAX_DELEGATION_DEPTH,
    max_clock_skew_ms: Any = None,
    proof_shape: str = "data-integrity",
) -> ChainRules:
    """Pure evaluation root to leaf: length bound before parsing, schema, root, attenuation, windows.

    ``proof_shape="any"`` leaves the hop's ``proof`` shape unread, for a caller
    that checks no hop proof (the Entity Card vectors carry placeholder proofs).
    """
    if isinstance(max_chain_length, bool) or not isinstance(max_chain_length, int) or max_chain_length < 1:
        return _refused("configuration_error", ["maxChainLength must be a positive integer"], 0)
    if clock_skew_ms(max_clock_skew_ms) is None:
        return _refused("configuration_error", ["maxClockSkewMs must be a number of milliseconds from 0 to 600000"], 0)
    if not isinstance(hops, list) or not hops:
        return _refused("chain_invalid", ["empty delegation chain"], 0)
    if len(hops) > max_chain_length:
        return _refused("chain_invalid", [f"delegation chain depth {len(hops)} exceeds the maximum of {max_chain_length}"], len(hops))
    malformed = []
    for index, hop in enumerate(hops):
        violations = validate_json_schema(_HOP_SCHEMA_ANY_PROOF, hop) if proof_shape == "any" else validate_credential("hop", hop)
        if violations:
            malformed.append(f"hop {index}: {describe_violations(violations)}")
    if malformed:
        return _refused("delegation_malformed", malformed, len(hops))
    root, leaf = hops[0], hops[-1]
    broken: List[Tuple[str, str]] = []
    subject = root["credentialSubject"]
    if subject["parentCapability"] != subject["invocationTarget"]:
        broken.append(("chain_invalid", "root delegation: parentCapability must equal invocationTarget"))
    if resource is not None and subject["invocationTarget"] != resource:
        broken.append(("chain_invalid", "root invocationTarget is not the expected resource"))
    if resource_owner is not None and root["issuer"] != resource_owner:
        broken.append(("untrusted_root", "root issuer is not the resource owner"))
    for index in range(1, len(hops)):
        for reason in attenuation_reasons(hops[index - 1], hops[index]):
            broken.append(("attenuation_violation", f"hop {index}: {reason}"))
    now = now_ms if now_ms is not None else _now_ms()
    for index, hop in enumerate(hops):
        verdict = window_verdict(hop.get("validFrom"), hop.get("validUntil"), now, max_clock_skew_ms)
        if verdict == "malformed":
            broken.append(("delegation_malformed", f"hop {index}: validFrom/validUntil is not an RFC 3339 date-time with offset"))
        elif verdict == "expired":
            broken.append(("delegation_expired", f"hop {index}: expired (validUntil {hop.get('validUntil')} is in the past)"))
        elif verdict == "not_yet_valid":
            broken.append(("delegation_not_yet_valid", f"hop {index}: not yet valid (validFrom {hop.get('validFrom')} is in the future)"))
        for caveat in hop["credentialSubject"].get("caveats") or []:
            if caveat.get("type") != "ValidUntil":
                continue
            caveat_verdict = window_verdict(None, caveat.get("date"), now, max_clock_skew_ms)
            if caveat_verdict == "malformed":
                broken.append(("delegation_malformed", f"hop {index}: ValidUntil caveat date is not an RFC 3339 date-time with offset"))
            elif caveat_verdict == "expired":
                broken.append(("delegation_expired", f"hop {index}: expired caveat (ValidUntil {caveat.get('date')} is in the past)"))
    ok = not broken
    first = None if ok else ("chain_invalid" if broken[0][0] == "attenuation_violation" else broken[0][0])
    return ChainRules(
        ok=ok,
        reasons=[reason for _code, reason in broken],
        allowed_action=list(leaf["credentialSubject"]["allowedAction"]) if ok else [],
        depth=len(hops),
        code=first,
        responsible_party=root["issuer"],
        leaf_invoker=invoker_of(leaf),
        invocation_target=leaf["credentialSubject"]["invocationTarget"],
        broken=broken,
    )
