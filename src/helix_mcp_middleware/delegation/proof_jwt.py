"""The delegation proof JWT (KYA-OS story L3-D point 3, SPEC.md §8.2, L3.23)
and the chain string (§8.3, L3.24). Ported from helix-sdk-js's
mcp-middleware/src/delegation/proof-jwt.ts.

The forwarding service signs, with its own Signer (EdDSA, ``kid`` its DID's
key): ``iss`` its DID, ``sub`` the Responsible Party (the issuer of the
chain's root hop, whoever that is on this journey), ``aud`` the target host,
``iat``, ``exp`` = ``iat`` + 60 s, a fresh ``jti``, ``delegation_id`` (the
leaf capability's id), ``delegation_chain`` (the chain string) and ``scope``
(comma-separated).
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from helix_sdk.crypto.jws import JwsReasons, Signer, sign_jws, verify_jws_by_kid

DELEGATION_PROOF_TTL_SECONDS = 60
"""The proof's lifetime: §8.2 fixes ``exp`` at ``iat`` + 60 s."""
DELEGATION_PROOF_TYP = "JWT"


def mint_delegation_proof_jwt(
    signer: Signer,
    *,
    sub: str,
    aud: str,
    delegation_id: str,
    delegation_chain: str,
    scope: Union[str, Sequence[str]],
    iss: Optional[str] = None,
    jti: Optional[str] = None,
    now_ms: Optional[int] = None,
) -> str:
    """Mints the §8.2 delegation proof JWT, signed by the forwarding service's ``signer``."""
    issuer = iss if iss is not None else signer.did
    if issuer != signer.did:
        raise ValueError("mint_delegation_proof_jwt: iss must be the signer's DID")
    for name, value in (("sub", sub), ("aud", aud), ("delegation_id", delegation_id), ("delegation_chain", delegation_chain)):
        if not isinstance(value, str) or not value:
            raise ValueError(f"mint_delegation_proof_jwt: {name} must be a non-empty string")
    iat = int((now_ms if now_ms is not None else time.time() * 1000) // 1000)
    claims = {
        "iss": issuer,
        "sub": sub,
        "aud": aud,
        "iat": iat,
        "exp": iat + DELEGATION_PROOF_TTL_SECONDS,
        "jti": jti if jti is not None else f"urn:uuid:{uuid.uuid4()}",
        "delegation_id": delegation_id,
        "delegation_chain": delegation_chain,
        "scope": scope if isinstance(scope, str) else ",".join(scope),
    }
    return sign_jws(claims, signer, {"typ": DELEGATION_PROOF_TYP})


def chain_string_of(vc_id: Optional[str] = None, delegation_id: Optional[str] = None) -> str:
    """The §8.3 chain string of one delegation: ``<vcId>><delegationId>``, or the one id it has."""
    if not delegation_id and not vc_id:
        return ""
    if not vc_id:
        return delegation_id  # type: ignore[return-value]
    if not delegation_id:
        return vc_id
    return f"{vc_id}>{delegation_id}"


def build_chain_string(chain: Sequence[Any]) -> str:
    """The chain string of a Helix chain, root first: each hop's VC ``id`` and
    its capability id, the hops joined with ``>`` (L3.24)."""
    parts = []
    for hop in chain:
        if not isinstance(hop, dict):
            continue
        subject = hop.get("credentialSubject") if isinstance(hop.get("credentialSubject"), dict) else {}
        vc_id = hop.get("id") if isinstance(hop.get("id"), str) else None
        capability = subject.get("id") if isinstance(subject.get("id"), str) else None
        part = chain_string_of(vc_id, capability)
        if part:
            parts.append(part)
    return ">".join(parts)


def delegation_id_of(chain: Sequence[Any]) -> Optional[str]:
    """The leaf capability's id: the ``delegation_id`` the proof names."""
    leaf = chain[-1] if chain else None
    if not isinstance(leaf, dict) or not isinstance(leaf.get("credentialSubject"), dict):
        return None
    value = leaf["credentialSubject"].get("id")
    return value if isinstance(value, str) and value else None


@dataclass
class DelegationProofVerification:
    ok: bool
    claims: Optional[Dict[str, Any]] = None
    kid: Optional[str] = None
    reason: Optional[str] = None
    message: Optional[str] = None
    iss: Optional[str] = None


_CLAIM_STRINGS = ("iss", "sub", "aud", "jti", "delegation_id", "delegation_chain", "scope")


def _refused(reason: str, message: str, iss: Optional[str] = None) -> DelegationProofVerification:
    return DelegationProofVerification(False, reason=reason, message=message, iss=iss)


def verify_delegation_proof_jwt(
    jwt: str,
    *,
    resolve_did: Callable[[str], Any],
    audience: Union[str, Sequence[str]],
    now_ms: int,
    skew_seconds: Optional[int] = None,
) -> DelegationProofVerification:
    """Verifies a delegation proof JWT: EdDSA under the assertion key its
    ``kid`` names in the ``iss`` DID's document, ``aud`` one of this service's
    hosts, and the window (``iat`` not ahead, ``exp`` not past, both ± skew,
    ``exp - iat`` at most 60 s). The jti, ``sub`` and the chain claims are the
    caller's to hold against the chain and the replay store."""
    try:
        verified = verify_jws_by_kid(jwt, resolve_did)
    except Exception as error:  # noqa: BLE001 - every refusal is a reason
        reason = getattr(error, "reason", None)
        if reason in (JwsReasons.MALFORMED, JwsReasons.HEADER_INVALID):
            return _refused("delegation_proof_malformed", str(error))
        return _refused("delegation_proof_invalid", str(error))
    payload = verified.payload
    typ = verified.header.get("typ")
    if not isinstance(payload, dict) or (typ is not None and typ != DELEGATION_PROOF_TYP):
        return _refused("delegation_proof_malformed", "the proof is not a JWT with a JSON claims set")
    for name in _CLAIM_STRINGS:
        value = payload.get(name)
        if not isinstance(value, str) or (name != "scope" and not value):
            return _refused("delegation_proof_malformed", f"claim {name} is not a non-empty string", verified.did)
    for name in ("iat", "exp"):
        value = payload.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
            return _refused("delegation_proof_malformed", f"claim {name} is not an integer", verified.did)
    audiences = [audience] if isinstance(audience, str) else list(audience)
    if payload["aud"] not in audiences:
        return _refused("delegation_proof_audience", f"aud {payload['aud']} is not this service's host", payload["iss"])
    skew = 5 if skew_seconds is None else skew_seconds
    now = now_ms // 1000
    iat, exp = int(payload["iat"]), int(payload["exp"])
    if exp - iat > DELEGATION_PROOF_TTL_SECONDS or exp <= iat:
        return _refused("delegation_proof_lifetime", f"the proof lives {exp - iat} s; at most {DELEGATION_PROOF_TTL_SECONDS} s", payload["iss"])
    if now > exp + skew:
        return _refused("delegation_proof_expired", "the proof has expired", payload["iss"])
    if iat > now + skew:
        return _refused("delegation_proof_not_yet_valid", "the proof is issued in the future", payload["iss"])
    return DelegationProofVerification(True, claims=payload, kid=verified.kid)


def scope_list(scope: str) -> List[str]:
    """The scope claim as a list: comma-separated, trimmed, empty entries dropped."""
    return list(dict.fromkeys(entry.strip() for entry in scope.split(",") if entry.strip()))
