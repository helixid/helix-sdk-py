# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS story F-1 (credential split), the Python twin of helix-core's
``src/core/credentials/``:

* ``sign_data_integrity`` / ``verify_data_integrity``: W3C Data Integrity
  ``eddsa-jcs-2022`` (SHA-256 of the RFC 8785 proof options with the document
  ``@context``, then of the unsecured document, Ed25519 over the two,
  ``proofValue`` base58btc with a ``z`` prefix), the key read from the issuer's
  DID document through an injected resolver;
* builders for the identity credential, capability attestations, delegation
  hops (SPEC.md section 6.10) and the IdentityVerificationCredential;
* ``validate_credential``: the three JSON schemas helix-core publishes, read
  from a schema directory or the copies embedded here;
* ``evaluate_delegation_chain``: the attenuation invariants, pure;
* ``derive_effective_scopes``: attestations and leaf allowedAction and catalog;
* ``check_capabilities`` / ``derive_conformance_level``: the Entity Card floor
  (story C-B, SPEC-ENTITY-CARD.md section 9.4) and ``is_trusted_issuer``.

Cross-border rule (stories rule 4): a verifier here reads the artifacts it is
given and DID documents from its resolver, never a Helix database.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

import nacl.exceptions
import nacl.signing

from .crypto.jcs import canonicalize
from .crypto.jws import Signer, base64url_decode_strict, select_assertion_method, verification_method_to_jwk
from .errors import InvalidJWSError
from .vp_crypto import base58btc_decode, base58btc_encode

VC_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
ZCAP_CONTEXT = "https://w3id.org/security/zcap/v1"
KYA_OS_DELEGATION_CONTEXT = "https://kya-os.org/ns/delegation/v1"
HELIX_CONTEXT = "https://helixid.io/contexts/v1"
DELEGATION_HOP_CONTEXT = [VC_V2_CONTEXT, ZCAP_CONTEXT, KYA_OS_DELEGATION_CONTEXT]

IDENTITY_CREDENTIAL_TYPE = "AgentIdentityCredential"
CAPABILITY_ATTESTATION_TYPE = "CapabilityAttestationCredential"
DELEGATION_CREDENTIAL_TYPE = "DelegationCredential"
IDENTITY_VERIFICATION_TYPE = "IdentityVerificationCredential"

MAX_DELEGATION_DEPTH = 10
DEFAULT_CLOCK_SKEW_MS = 120_000
MAX_CLOCK_SKEW_MS = 600_000
TRUST_ALL_ISSUERS = "*"

DidResolver = Callable[[str], Optional[Mapping[str, Any]]]
TrustedIssuers = Union[str, Sequence[str]]


# -- dates ---------------------------------------------------------------------

_DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$")


def parse_date_time(value: Any) -> Optional[int]:
    """Milliseconds since the epoch of an RFC 3339 date-time with offset, else None."""
    if not isinstance(value, str) or not _DATE_TIME.match(value):
        return None
    text = value[:-1] + "+00:00" if value[-1] in "Zz" else value
    text = text.replace("t", "T", 1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return int(parsed.timestamp() * 1000)


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _iso_now() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


# -- JSON Schema subset --------------------------------------------------------

_KNOWN_KEYWORDS = {
    "$schema", "$id", "$defs", "title", "description", "examples", "type", "properties", "required",
    "additionalProperties", "items", "minItems", "contains", "enum", "const", "pattern", "minLength",
    "maxLength", "minimum", "maximum", "format", "allOf", "anyOf", "oneOf", "$ref",
}


class JsonSchemaError(ValueError):
    """A schema this evaluator cannot evaluate faithfully."""


@dataclass(frozen=True)
class SchemaViolation:
    path: str
    message: str


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _type_matches(expected: str, value: Any) -> bool:
    actual = _json_type(value)
    if expected == "number":
        return actual in ("number", "integer")
    return actual == expected


def _deep_equal(a: Any, b: Any) -> bool:
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def assert_supported_schema(schema: Mapping[str, Any], path: str = "#") -> None:
    for keyword in schema:
        if keyword not in _KNOWN_KEYWORDS:
            raise JsonSchemaError(f'Unsupported JSON Schema keyword "{keyword}" at {path}')

    def nested(value: Any, where: str) -> None:
        if isinstance(value, dict):
            assert_supported_schema(value, where)

    for key in ("$defs", "properties"):
        members = schema.get(key)
        if isinstance(members, dict):
            for name, sub in members.items():
                nested(sub, f"{path}/{key}/{name}")
    for key in ("items", "contains", "additionalProperties"):
        nested(schema.get(key), f"{path}/{key}")
    for key in ("allOf", "anyOf", "oneOf"):
        entries = schema.get(key)
        if isinstance(entries, list):
            for index, sub in enumerate(entries):
                nested(sub, f"{path}/{key}/{index}")


def _resolve_ref(root: Mapping[str, Any], ref: Any) -> Mapping[str, Any]:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise JsonSchemaError(f"Only local $ref values are supported, got {ref!r}")
    current: Any = root
    for segment in ref[2:].split("/"):
        if not isinstance(current, dict):
            raise JsonSchemaError(f"$ref {ref} does not resolve")
        current = current.get(segment)
    if not isinstance(current, dict):
        raise JsonSchemaError(f"$ref {ref} does not resolve")
    return current


def _count(root: Mapping[str, Any], schema: Mapping[str, Any], value: Any) -> int:
    out: List[SchemaViolation] = []
    _validate_at(root, schema, value, "$", out)
    return len(out)


def _validate_at(root: Mapping[str, Any], schema: Mapping[str, Any], value: Any, path: str, out: List[SchemaViolation]) -> None:
    if "$ref" in schema:
        _validate_at(root, _resolve_ref(root, schema["$ref"]), value, path, out)
    expected_type = schema.get("type")
    if expected_type is not None:
        allowed = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_type_matches(candidate, value) for candidate in allowed):
            out.append(SchemaViolation(path, f"expected type {' | '.join(allowed)}, got {_json_type(value)}"))
            return
    if "const" in schema and not _deep_equal(schema["const"], value):
        out.append(SchemaViolation(path, f"expected the constant {json.dumps(schema['const'])}"))
    allowed_values = schema.get("enum")
    if isinstance(allowed_values, list) and not any(_deep_equal(candidate, value) for candidate in allowed_values):
        out.append(SchemaViolation(path, f"expected one of {json.dumps(allowed_values)}"))
    if isinstance(value, str):
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(value) < min_length:
            out.append(SchemaViolation(path, f"expected at least {min_length} characters"))
        max_length = schema.get("maxLength")
        if isinstance(max_length, int) and len(value) > max_length:
            out.append(SchemaViolation(path, f"expected at most {max_length} characters"))
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            out.append(SchemaViolation(path, f"does not match pattern {pattern}"))
        if schema.get("format") == "date-time" and parse_date_time(value) is None:
            out.append(SchemaViolation(path, "is not an RFC 3339 date-time with offset"))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and value < minimum:
            out.append(SchemaViolation(path, f"expected at least {minimum}"))
        maximum = schema.get("maximum")
        if isinstance(maximum, (int, float)) and value > maximum:
            out.append(SchemaViolation(path, f"expected at most {maximum}"))
    if isinstance(value, list):
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(value) < min_items:
            out.append(SchemaViolation(path, f"expected at least {min_items} items"))
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                _validate_at(root, items, item, f"{path}[{index}]", out)
        contains = schema.get("contains")
        if isinstance(contains, dict) and not any(_count(root, contains, item) == 0 for item in value):
            out.append(SchemaViolation(path, f"no item satisfies {json.dumps(contains)}"))
    if isinstance(value, dict):
        required = schema.get("required")
        if isinstance(required, list):
            for name in required:
                if name not in value:
                    out.append(SchemaViolation(path, f'missing required member "{name}"'))
        properties = schema.get("properties") or {}
        for name, sub in properties.items():
            if name in value:
                _validate_at(root, sub, value[name], f"{path}.{name}", out)
        additional = schema.get("additionalProperties", True)
        if additional is not True:
            for name in value:
                if name in properties:
                    continue
                if additional is False:
                    out.append(SchemaViolation(f"{path}.{name}", "unknown member is not allowed"))
                else:
                    _validate_at(root, additional, value[name], f"{path}.{name}", out)
    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for sub in all_of:
            _validate_at(root, sub, value, path, out)
    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and not any(_count(root, sub, value) == 0 for sub in any_of):
        out.append(SchemaViolation(path, "matches none of the anyOf alternatives"))
    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        passing = sum(1 for sub in one_of if _count(root, sub, value) == 0)
        if passing != 1:
            out.append(SchemaViolation(path, f"matches {passing} oneOf alternatives, expected exactly one"))


def validate_json_schema(schema: Mapping[str, Any], value: Any) -> List[SchemaViolation]:
    """Every way ``value`` breaks ``schema``; empty when it conforms."""
    assert_supported_schema(schema)
    out: List[SchemaViolation] = []
    _validate_at(schema, schema, value, "$", out)
    return out


# -- the three schemas ---------------------------------------------------------

_STATUS_ENTRY_DEF = {
    "type": "object",
    "required": ["type", "statusPurpose", "statusListIndex", "statusListCredential"],
    "properties": {
        "id": {"type": "string"},
        "type": {"const": "BitstringStatusListEntry"},
        "statusPurpose": {"enum": ["revocation", "suspension"]},
        "statusListIndex": {"type": "string", "pattern": "^[0-9]+$"},
        "statusListCredential": {"type": "string", "minLength": 1},
        "statusSize": {"type": "integer"},
    },
    "additionalProperties": False,
}
_PROOF_DEF = {
    "type": "object",
    "required": ["type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "proofValue"],
    "properties": {
        "type": {"const": "DataIntegrityProof"},
        "cryptosuite": {"const": "eddsa-jcs-2022"},
        "created": {"type": "string", "format": "date-time"},
        "verificationMethod": {"type": "string", "pattern": "^did:.+#.+$"},
        "proofPurpose": {"const": "assertionMethod"},
        "proofValue": {"type": "string", "pattern": "^z[1-9A-HJ-NP-Za-km-z]+$"},
    },
    "additionalProperties": False,
}
_VC_CONTEXT_SCHEMA = {"type": "array", "minItems": 1, "items": {"type": "string"}, "contains": {"const": VC_V2_CONTEXT}}


def _type_schema(second: str) -> Dict[str, Any]:
    return {
        "type": "array",
        "minItems": 2,
        "items": {"type": "string"},
        "allOf": [{"contains": {"const": "VerifiableCredential"}}, {"contains": {"const": second}}],
    }


IDENTITY_CREDENTIAL_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://helixid.io/schemas/kya-os/identity-credential/v1",
    "title": "Helix Agent Identity Credential",
    "description": "KYA-OS story F-1: the agent's identity, issued by Helix. Agent DID, display name and the owner DID as responsibleParty. It carries no scopes: capability attestations do. Reissued only on key rotation or offboarding.",
    "type": "object",
    "required": ["@context", "id", "type", "issuer", "validFrom", "credentialSubject", "credentialStatus", "proof"],
    "properties": {
        "@context": _VC_CONTEXT_SCHEMA,
        "id": {"type": "string", "minLength": 1},
        "type": _type_schema(IDENTITY_CREDENTIAL_TYPE),
        "issuer": {"type": "string", "pattern": "^did:.+$"},
        "validFrom": {"type": "string", "format": "date-time"},
        "validUntil": {"type": "string", "format": "date-time"},
        "credentialSubject": {
            "type": "object",
            "required": ["id", "name", "responsibleParty"],
            "properties": {
                "id": {"type": "string", "pattern": "^did:.+$"},
                "name": {"type": "string", "minLength": 1},
                "responsibleParty": {"type": "string", "pattern": "^did:.+$"},
            },
            "additionalProperties": False,
        },
        "credentialStatus": {"$ref": "#/$defs/BitstringStatusListEntry"},
        "proof": {"$ref": "#/$defs/DataIntegrityProof"},
    },
    "additionalProperties": False,
    "$defs": {"BitstringStatusListEntry": _STATUS_ENTRY_DEF, "DataIntegrityProof": _PROOF_DEF},
}

CAPABILITY_ATTESTATION_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://helixid.io/schemas/kya-os/capability-attestation/v1",
    "title": "KYA-OS Capability Attestation Credential",
    "description": "KYA-OS story F-1 / C-B: one CapabilityAttestationCredential per capability (scope). credentialSubject.id is the agent DID (the card id), capability is the name a card's capabilities entry carries, validUntil bounds it, and a Bitstring status entry revokes it. Signed by the owner through the SDK or by the Helix issuer.",
    "type": "object",
    "required": ["@context", "id", "type", "issuer", "validFrom", "validUntil", "credentialSubject", "credentialStatus", "proof"],
    "properties": {
        "@context": _VC_CONTEXT_SCHEMA,
        "id": {"type": "string", "minLength": 1},
        "type": _type_schema(CAPABILITY_ATTESTATION_TYPE),
        "issuer": {"type": "string", "pattern": "^did:.+$"},
        "validFrom": {"type": "string", "format": "date-time"},
        "validUntil": {"type": "string", "format": "date-time"},
        "credentialSubject": {
            "type": "object",
            "required": ["id", "capability"],
            "properties": {"id": {"type": "string", "pattern": "^did:.+$"}, "capability": {"type": "string", "minLength": 1}},
            "additionalProperties": False,
        },
        "credentialStatus": {"$ref": "#/$defs/BitstringStatusListEntry"},
        "proof": {"$ref": "#/$defs/DataIntegrityProof"},
    },
    "additionalProperties": False,
    "$defs": {"BitstringStatusListEntry": _STATUS_ENTRY_DEF, "DataIntegrityProof": _PROOF_DEF},
}

DELEGATION_HOP_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://helixid.io/schemas/kya-os/delegation-hop/v1",
    "title": "KYA-OS Delegation Credential (one hop), Helix profile",
    "description": "KYA-OS SPEC.md section 6.10: a W3C VC 2.0 whose credentialSubject IS an attenuated ZCAP-LD capability, one credential per delegation hop, revoked through a Bitstring Status List entry and signed with a DataIntegrityProof eddsa-jcs-2022. This profile of schemas/card-delegation-credential.json (suite 1.10.0) closes the credentialSubject: a member it does not name is refused, the Core L3.5a rule against claim-contaminated subjects, and requires validUntil on every hop.",
    "type": "object",
    "required": ["@context", "id", "type", "issuer", "validUntil", "credentialSubject", "credentialStatus", "proof"],
    "properties": {
        "@context": {
            "type": "array",
            "minItems": 3,
            "items": {"type": "string"},
            "allOf": [
                {"contains": {"const": VC_V2_CONTEXT}},
                {"contains": {"const": ZCAP_CONTEXT}},
                {"contains": {"const": KYA_OS_DELEGATION_CONTEXT}},
            ],
        },
        "id": {"type": "string", "minLength": 1},
        "type": _type_schema(DELEGATION_CREDENTIAL_TYPE),
        "issuer": {"type": "string", "pattern": "^did:.+$"},
        "validFrom": {"type": "string", "format": "date-time"},
        "validUntil": {"type": "string", "format": "date-time"},
        "credentialSubject": {"$ref": "#/$defs/ZcapCapability"},
        "credentialStatus": {"$ref": "#/$defs/BitstringStatusListEntry"},
        "proof": {"$ref": "#/$defs/DataIntegrityProof"},
    },
    "additionalProperties": False,
    "$defs": {
        "ZcapCapability": {
            "type": "object",
            "required": ["id", "parentCapability", "invocationTarget", "allowedAction"],
            "anyOf": [{"required": ["invoker"]}, {"required": ["controller"]}],
            "properties": {
                "id": {"type": "string", "minLength": 1},
                "invoker": {"type": "string", "pattern": "^did:.+$"},
                "controller": {"type": "string", "pattern": "^did:.+$"},
                "parentCapability": {"type": "string", "minLength": 1},
                "invocationTarget": {"type": "string", "minLength": 1},
                "allowedAction": {"type": "array", "items": {"type": "string", "minLength": 1}},
                "caveats": {"type": "array", "items": {"$ref": "#/$defs/Caveat"}},
            },
            "additionalProperties": False,
        },
        "Caveat": {
            "type": "object",
            "required": ["type"],
            "properties": {
                "type": {"type": "string", "minLength": 1},
                "date": {"type": "string", "format": "date-time"},
                "limit": {"type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$"},
                "currency": {"type": "string", "minLength": 1},
            },
            "additionalProperties": True,
        },
        "BitstringStatusListEntry": _STATUS_ENTRY_DEF,
        "DataIntegrityProof": _PROOF_DEF,
    },
}

CREDENTIAL_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "identity": IDENTITY_CREDENTIAL_SCHEMA,
    "attestation": CAPABILITY_ATTESTATION_SCHEMA,
    "hop": DELEGATION_HOP_SCHEMA,
}


def validate_credential(kind: str, value: Any) -> List[SchemaViolation]:
    """Every schema violation of ``value`` as an ``identity``, ``attestation`` or ``hop``."""
    return validate_json_schema(CREDENTIAL_SCHEMAS[kind], value)


def describe_violations(violations: Sequence[SchemaViolation]) -> str:
    return "; ".join(f"{v.path}: {v.message}" for v in violations)


# -- Data Integrity eddsa-jcs-2022 ---------------------------------------------


class ProofReasons:
    PROOF_MISSING = "proof_missing"
    PROOF_UNSUPPORTED = "proof_unsupported"
    PROOF_PURPOSE_MISMATCH = "proof_purpose_mismatch"
    PROOF_VALUE_MALFORMED = "proof_value_malformed"
    PROOF_METHOD_MALFORMED = "proof_method_malformed"
    PROOF_ISSUER_MISMATCH = "proof_issuer_mismatch"
    PROOF_CONTEXT_MISMATCH = "proof_context_mismatch"
    DOCUMENT_NOT_CANONICAL = "document_not_canonical"
    DID_UNRESOLVED = "did_unresolved"
    KEY_REJECTED = "key_rejected"
    SIGNATURE_INVALID = "signature_invalid"


@dataclass(frozen=True)
class Verdict:
    """A verifier's answer: ``ok`` with details, or a refusal with ``reason``."""

    ok: bool
    reason: Optional[str] = None
    message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


def _refused(reason: str, message: str) -> Verdict:
    return Verdict(False, reason, message)


def issuer_of(issuer: Any) -> Optional[str]:
    if isinstance(issuer, str) and issuer.startswith("did:"):
        return issuer
    if isinstance(issuer, Mapping):
        candidate = issuer.get("id")
        if isinstance(candidate, str) and candidate.startswith("did:"):
            return candidate
    return None


def _digest(value: Any) -> bytes:
    return hashlib.sha256(canonicalize(value).encode("utf-8")).digest()


def hash_data(proof_options: Mapping[str, Any], unsecured: Mapping[str, Any]) -> bytes:
    """SHA-256(canonical proof options) || SHA-256(canonical unsecured document)."""
    return _digest(proof_options) + _digest(unsecured)


def sign_data_integrity(document: Mapping[str, Any], signer: Signer, created: Optional[str] = None) -> Dict[str, Any]:
    """Adds an ``eddsa-jcs-2022`` proof for ``assertionMethod``, signed by ``signer``, the document's issuer."""
    if "proof" in document:
        raise ValueError("document already carries a proof")
    issuer = issuer_of(document.get("issuer"))
    if issuer is None or issuer != signer.did:
        raise ValueError(f"signer {signer.did} is not the issuer of the document")
    fragment = signer.kid.lstrip("#")
    if not fragment or "#" in fragment:
        raise ValueError("signer kid must be a verification-method fragment")
    proof: Dict[str, Any] = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": created or _iso_now(),
        "verificationMethod": f"{signer.did}#{fragment}",
        "proofPurpose": "assertionMethod",
    }
    config = dict(proof)
    if "@context" in document:
        config["@context"] = document["@context"]
    signature = signer.sign(hash_data(config, document))
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise ValueError("signer did not return a 64-byte Ed25519 signature")
    return {**document, "proof": {**proof, "proofValue": "z" + base58btc_encode(bytes(signature))}}


def _contexts(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


def _is_prefix(whole: List[Any], prefix: List[Any]) -> bool:
    return len(prefix) <= len(whole) and all(canonicalize(a) == canonicalize(b) for a, b in zip(prefix, whole))


def verify_data_integrity(document: Mapping[str, Any], resolve_did: DidResolver, proof_purpose: str = "assertionMethod") -> Verdict:
    """The one ``eddsa-jcs-2022`` proof on ``document`` against the issuer's assertion key. Never raises for bad input."""
    proof = document.get("proof")
    if not isinstance(proof, Mapping):
        return _refused(ProofReasons.PROOF_MISSING, "document carries no single proof object")
    if proof.get("type") != "DataIntegrityProof" or proof.get("cryptosuite") != "eddsa-jcs-2022":
        return _refused(ProofReasons.PROOF_UNSUPPORTED, "proof is not DataIntegrityProof / eddsa-jcs-2022")
    if proof.get("proofPurpose") != proof_purpose:
        return _refused(ProofReasons.PROOF_PURPOSE_MISMATCH, f"proofPurpose is not {proof_purpose}")
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value.startswith("z") or len(proof_value) < 2:
        return _refused(ProofReasons.PROOF_VALUE_MALFORMED, "proofValue is not a base58btc multibase string")
    try:
        signature = base58btc_decode(proof_value[1:])
    except Exception:  # noqa: BLE001 - any decoding failure is one refusal
        return _refused(ProofReasons.PROOF_VALUE_MALFORMED, "proofValue is not base58btc")
    if len(signature) != 64:
        return _refused(ProofReasons.PROOF_VALUE_MALFORMED, "proofValue is not a 64-byte Ed25519 signature")
    method_id = proof.get("verificationMethod")
    if not isinstance(method_id, str) or "#" not in method_id:
        return _refused(ProofReasons.PROOF_METHOD_MALFORMED, "verificationMethod is not a DID URL")
    issuer = issuer_of(document.get("issuer"))
    did = method_id[: method_id.index("#")]
    if issuer is None or did != issuer:
        return _refused(ProofReasons.PROOF_ISSUER_MISMATCH, "verificationMethod does not belong to the issuer")
    unsecured = {k: v for k, v in document.items() if k != "proof"}
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    if "@context" in config:
        if not _is_prefix(_contexts(document.get("@context")), _contexts(config["@context"])):
            return _refused(ProofReasons.PROOF_CONTEXT_MISMATCH, "proof @context is not a prefix of the document @context")
        unsecured["@context"] = config["@context"]
    if "@context" in unsecured:
        config["@context"] = unsecured["@context"]
    try:
        resolved = resolve_did(did)
    except Exception as exc:  # noqa: BLE001 - a resolver that throws is one refusal
        return _refused(ProofReasons.DID_UNRESOLVED, f"could not resolve {did}: {exc}")
    if resolved is None:
        return _refused(ProofReasons.DID_UNRESOLVED, f"could not resolve {did}")
    try:
        method = select_assertion_method(resolved, did, method_id)
        public_key = base64url_decode_strict(verification_method_to_jwk(method)["x"])
    except InvalidJWSError as exc:
        return _refused(ProofReasons.KEY_REJECTED, f"{exc.reason}: {exc}")
    try:
        data = hash_data(config, unsecured)
    except Exception as exc:  # noqa: BLE001 - a document with no canonical form
        return _refused(ProofReasons.DOCUMENT_NOT_CANONICAL, str(exc))
    try:
        nacl.signing.VerifyKey(public_key).verify(data, signature)  # type: ignore[arg-type]
    except nacl.exceptions.BadSignatureError:
        return _refused(ProofReasons.SIGNATURE_INVALID, "proofValue does not verify")
    return Verdict(True, details={"issuer": issuer, "verificationMethod": method_id})


# -- windows -------------------------------------------------------------------


def clock_skew_ms(max_clock_skew_ms: Any) -> Optional[int]:
    if max_clock_skew_ms is None:
        return DEFAULT_CLOCK_SKEW_MS
    if isinstance(max_clock_skew_ms, bool) or not isinstance(max_clock_skew_ms, (int, float)):
        return None
    if max_clock_skew_ms < 0 or max_clock_skew_ms > MAX_CLOCK_SKEW_MS:
        return None
    return int(max_clock_skew_ms)


def window_verdict(valid_from: Any, valid_until: Any, now_ms: int, max_clock_skew_ms: Any = None) -> str:
    """'inside', 'expired', 'not_yet_valid', 'malformed' or 'skew_invalid'."""
    skew = clock_skew_ms(max_clock_skew_ms)
    if skew is None:
        return "skew_invalid"
    start = end = None
    if valid_from is not None:
        start = parse_date_time(valid_from)
        if start is None:
            return "malformed"
    if valid_until is not None:
        end = parse_date_time(valid_until)
        if end is None:
            return "malformed"
    if end is not None and now_ms > end + skew:
        return "expired"
    if start is not None and now_ms < start - skew:
        return "not_yet_valid"
    return "inside"


# -- builders ------------------------------------------------------------------


def _require_did(value: Any, what: str) -> None:
    if not isinstance(value, str) or not value.startswith("did:"):
        raise ValueError(f"{what} must be a DID")


def _require_capability(value: Any) -> None:
    if not isinstance(value, str) or not value.strip() or re.search(r"\s", value):
        raise ValueError("capability must be a non-empty string without whitespace")


def build_identity_credential(
    signer: Signer,
    agent_did: str,
    name: str,
    owner_did: str,
    status_entry: Mapping[str, Any],
    *,
    id: Optional[str] = None,
    valid_from: Optional[str] = None,
    valid_until: Optional[str] = None,
    proof_created: Optional[str] = None,
) -> Dict[str, Any]:
    _require_did(agent_did, "agent_did")
    _require_did(owner_did, "owner_did")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("name must be a non-empty string")
    credential: Dict[str, Any] = {
        "@context": [VC_V2_CONTEXT, HELIX_CONTEXT],
        "id": id or f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", IDENTITY_CREDENTIAL_TYPE],
        "issuer": signer.did,
        "validFrom": valid_from or _iso_now(),
    }
    if valid_until is not None:
        credential["validUntil"] = valid_until
    credential["credentialSubject"] = {"id": agent_did, "name": name, "responsibleParty": owner_did}
    credential["credentialStatus"] = dict(status_entry)
    return sign_data_integrity(credential, signer, proof_created)


def build_capability_attestation(
    signer: Signer,
    subject_did: str,
    capability: str,
    valid_until: str,
    status_entry: Mapping[str, Any],
    *,
    id: Optional[str] = None,
    valid_from: Optional[str] = None,
    proof_created: Optional[str] = None,
) -> Dict[str, Any]:
    _require_did(subject_did, "subject_did")
    _require_capability(capability)
    if not isinstance(valid_until, str):
        raise ValueError("valid_until is required")
    credential: Dict[str, Any] = {
        "@context": [VC_V2_CONTEXT, HELIX_CONTEXT],
        "id": id or f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", CAPABILITY_ATTESTATION_TYPE],
        "issuer": signer.did,
        "validFrom": valid_from or _iso_now(),
        "validUntil": valid_until,
        "credentialSubject": {"id": subject_did, "capability": capability},
        "credentialStatus": dict(status_entry),
    }
    return sign_data_integrity(credential, signer, proof_created)


def build_identity_verification_credential(
    signer: Signer,
    subject_did: str,
    subject_type: str,
    verification_level: str,
    valid_until: str,
    status_entry: Mapping[str, Any],
    *,
    provider: Optional[str] = None,
    id: Optional[str] = None,
    valid_from: Optional[str] = None,
    proof_created: Optional[str] = None,
) -> Dict[str, Any]:
    _require_did(subject_did, "subject_did")
    if verification_level not in ("basic", "enhanced", "loa3"):
        raise ValueError("verification_level must be one of basic, enhanced, loa3")
    if subject_type not in ("individual", "organization"):
        raise ValueError("subject_type must be individual or organization")
    subject: Dict[str, Any] = {"id": subject_did, "subjectType": subject_type, "verificationLevel": verification_level}
    if provider is not None:
        subject["provider"] = provider
    credential: Dict[str, Any] = {
        "@context": [VC_V2_CONTEXT, HELIX_CONTEXT],
        "id": id or f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", IDENTITY_VERIFICATION_TYPE],
        "issuer": signer.did,
        "validFrom": valid_from or _iso_now(),
        "validUntil": valid_until,
        "credentialSubject": subject,
        "credentialStatus": dict(status_entry),
    }
    return sign_data_integrity(credential, signer, proof_created)


def build_delegation_hop(
    signer: Signer,
    invoker: str,
    parent_capability: str,
    invocation_target: str,
    allowed_action: Sequence[str],
    valid_until: str,
    status_entry: Mapping[str, Any],
    *,
    caveats: Optional[Sequence[Mapping[str, Any]]] = None,
    id: Optional[str] = None,
    valid_from: Optional[str] = None,
    proof_created: Optional[str] = None,
) -> Dict[str, Any]:
    """One hop in the SPEC.md section 6.10 shape. For a root hop pass ``parent_capability=invocation_target``."""
    _require_did(invoker, "invoker")
    if not isinstance(parent_capability, str) or not parent_capability:
        raise ValueError("parent_capability is required")
    if not isinstance(invocation_target, str) or not invocation_target:
        raise ValueError("invocation_target is required")
    if not isinstance(allowed_action, (list, tuple)) or any(not isinstance(a, str) or not a for a in allowed_action):
        raise ValueError("allowed_action must be a list of non-empty strings")
    if not isinstance(valid_until, str):
        raise ValueError("valid_until is required")
    capability_id = id or f"urn:zcap:{uuid.uuid4()}"
    subject: Dict[str, Any] = {
        "id": capability_id,
        "invoker": invoker,
        "parentCapability": parent_capability,
        "invocationTarget": invocation_target,
        "allowedAction": list(allowed_action),
    }
    if caveats is not None:
        subject["caveats"] = [dict(c) for c in caveats]
    credential: Dict[str, Any] = {
        "@context": list(DELEGATION_HOP_CONTEXT),
        "id": capability_id,
        "type": ["VerifiableCredential", DELEGATION_CREDENTIAL_TYPE],
        "issuer": signer.did,
    }
    if valid_from is not None:
        credential["validFrom"] = valid_from
    credential["validUntil"] = valid_until
    credential["credentialSubject"] = subject
    credential["credentialStatus"] = dict(status_entry)
    return sign_data_integrity(credential, signer, proof_created)


# -- verifiers -----------------------------------------------------------------


def is_trusted_issuer(issuer_did: str, trusted_issuers: TrustedIssuers = TRUST_ALL_ISSUERS) -> bool:
    """``'*'`` trusts every issuer; a list trusts exactly those DIDs (stories rule 9)."""
    if trusted_issuers == TRUST_ALL_ISSUERS:
        return True
    if isinstance(trusted_issuers, str) or not isinstance(trusted_issuers, Sequence):
        return False
    return issuer_did in trusted_issuers


def is_revoked_in(status_entry: Mapping[str, Any], encoded_list: str) -> bool:
    """The credential's bit in an already-fetched Bitstring status list; True when revoked or unreadable."""
    import base64
    import gzip

    try:
        index = int(str(status_entry.get("statusListIndex")))
        if index < 0:
            return True
        padded = encoded_list + "=" * (-len(encoded_list) % 4)
        bits = gzip.decompress(base64.urlsafe_b64decode(padded))
        byte = bits[index // 8]
        return (byte >> (7 - index % 8)) & 1 == 1
    except Exception:  # noqa: BLE001 - fail closed
        return True


def _window_refusal(credential: Mapping[str, Any], now_ms: Optional[int], max_clock_skew_ms: Any) -> Optional[Verdict]:
    verdict = window_verdict(credential.get("validFrom"), credential.get("validUntil"), now_ms if now_ms is not None else _now_ms(), max_clock_skew_ms)
    if verdict != "inside":
        return _refused(f"credential_{verdict}", f"credential is {verdict.replace('_', ' ')}")
    return None


def verify_identity_credential(
    value: Any, resolve_did: DidResolver, *, agent_did: Optional[str] = None, now_ms: Optional[int] = None, max_clock_skew_ms: Any = None
) -> Verdict:
    violations = validate_credential("identity", value)
    if violations:
        return _refused("schema_invalid", describe_violations(violations))
    subject = value["credentialSubject"]
    if agent_did is not None and subject["id"] != agent_did:
        return _refused("subject_mismatch", "credentialSubject.id is not the expected agent")
    refusal = _window_refusal(value, now_ms, max_clock_skew_ms)
    if refusal is not None:
        return refusal
    proof = verify_data_integrity(value, resolve_did)
    if not proof.ok:
        return proof
    return Verdict(True, details={"agentDid": subject["id"], "responsibleParty": subject["responsibleParty"]})


def verify_capability_attestation(
    value: Any,
    resolve_did: DidResolver,
    *,
    subject_did: Optional[str] = None,
    capability: Optional[str] = None,
    trusted_issuers: TrustedIssuers = TRUST_ALL_ISSUERS,
    now_ms: Optional[int] = None,
    max_clock_skew_ms: Any = None,
    status_list: Optional[Mapping[str, Any]] = None,
) -> Verdict:
    """Schema, subject, capability, trusted issuer, window, proof and (given the list) revocation."""
    violations = validate_credential("attestation", value)
    if violations:
        return _refused("schema_invalid", describe_violations(violations))
    subject = value["credentialSubject"]
    if subject_did is not None and subject["id"] != subject_did:
        return _refused("subject_mismatch", "credentialSubject.id is not the card id")
    if capability is not None and subject["capability"] != capability:
        return _refused("capability_mismatch", "credentialSubject.capability is not the declared capability")
    if not is_trusted_issuer(value["issuer"], trusted_issuers):
        return _refused("issuer_untrusted", f"{value['issuer']} is not a trusted issuer")
    refusal = _window_refusal(value, now_ms, max_clock_skew_ms)
    if refusal is not None:
        return refusal
    proof = verify_data_integrity(value, resolve_did)
    if not proof.ok:
        return proof
    if status_list is not None and is_revoked_in(value["credentialStatus"], status_list["credentialSubject"]["encodedList"]):
        return _refused("credential_revoked", "the status list marks this credential revoked")
    return Verdict(True, details={"capability": subject["capability"], "issuer": value["issuer"]})


def verify_identity_verification_credential(
    value: Any, resolve_did: DidResolver, *, subject_did: Optional[str] = None, now_ms: Optional[int] = None, max_clock_skew_ms: Any = None
) -> Verdict:
    if not isinstance(value, Mapping):
        return _refused("schema_invalid", "not a credential")
    types = value.get("type")
    subject = value.get("credentialSubject")
    if (
        not isinstance(types, list)
        or IDENTITY_VERIFICATION_TYPE not in types
        or not isinstance(subject, Mapping)
        or not isinstance(subject.get("id"), str)
        or subject.get("verificationLevel") not in ("basic", "enhanced", "loa3")
    ):
        return _refused("schema_invalid", "not an IdentityVerificationCredential with a verification level")
    if subject_did is not None and subject["id"] != subject_did:
        return _refused("subject_mismatch", "credentialSubject.id is not the expected party")
    refusal = _window_refusal(value, now_ms, max_clock_skew_ms)
    if refusal is not None:
        return refusal
    proof = verify_data_integrity(value, resolve_did)
    if not proof.ok:
        return proof
    return Verdict(True, details={"verificationLevel": subject["verificationLevel"]})


def invoker_of(hop: Mapping[str, Any]) -> Optional[str]:
    subject = hop.get("credentialSubject") or {}
    delegate = subject.get("invoker", subject.get("controller"))
    return delegate if isinstance(delegate, str) else None


def verify_delegation_hop(value: Any, resolve_did: DidResolver) -> Verdict:
    """Shape (closed subject, Core L3.5a) and proof of one hop."""
    violations = validate_credential("hop", value)
    if violations:
        return _refused("schema_invalid", describe_violations(violations))
    proof = verify_data_integrity(value, resolve_did)
    if not proof.ok:
        return proof
    return Verdict(True, details={"issuer": value["issuer"], "invoker": invoker_of(value)})


def verify_delegation_chain_proofs(hops: Sequence[Any], resolve_did: DidResolver) -> Verdict:
    """Every hop's proof root to leaf, stopping at the first refusal."""
    for index, hop in enumerate(hops):
        verdict = verify_delegation_hop(hop, resolve_did)
        if not verdict.ok:
            return Verdict(False, "proof_invalid", f"hop {index}: {verdict.reason}: {verdict.message}")
    return Verdict(True)


# -- chain evaluation ----------------------------------------------------------


def _decimal(value: Any) -> Optional[Decimal]:
    if not isinstance(value, str) or re.fullmatch(r"\d+(?:\.\d+)?", value.strip()) is None:
        return None
    try:
        return Decimal(value.strip())
    except InvalidOperation:  # pragma: no cover - the regex already excludes this
        return None


def decimal_lte(child: Any, parent: Any) -> bool:
    """``child <= parent`` as exact decimals; any unparseable value is False."""
    c, p = _decimal(child), _decimal(parent)
    return c is not None and p is not None and c <= p


def _date_lte(child: Any, parent: Any) -> bool:
    c, p = parse_date_time(child), parse_date_time(parent)
    return c is not None and p is not None and c <= p


def caveat_narrows(parent: Mapping[str, Any], child: Mapping[str, Any]) -> bool:
    if parent.get("type") != child.get("type"):
        return False
    if parent.get("type") == "ValidUntil":
        return isinstance(parent.get("date"), str) and isinstance(child.get("date"), str) and _date_lte(child["date"], parent["date"])
    if parent.get("type") == "MaxAmount":
        currency_narrows = parent.get("currency") is None or parent.get("currency") == child.get("currency")
        return currency_narrows and isinstance(parent.get("limit"), str) and isinstance(child.get("limit"), str) and decimal_lte(child["limit"], parent["limit"])
    return _deep_equal(parent, child)


def attenuation_reasons(parent: Mapping[str, Any], child: Mapping[str, Any]) -> List[str]:
    p = parent["credentialSubject"]
    c = child["credentialSubject"]
    reasons: List[str] = []
    escalated = [action for action in c["allowedAction"] if action not in set(p["allowedAction"])]
    if escalated:
        reasons.append(f"allowedAction escalation: [{', '.join(escalated)}] not in parent")
    for parent_caveat in p.get("caveats") or []:
        if not any(caveat_narrows(parent_caveat, child_caveat) for child_caveat in c.get("caveats") or []):
            reasons.append(f'caveat "{parent_caveat.get("type")}" broadened or dropped by child')
    if not _date_lte(child.get("validUntil"), parent.get("validUntil")):
        reasons.append("validUntil broadened: child must expire no later than its parent")
    delegate = invoker_of(parent)
    if delegate is None or delegate != child.get("issuer"):
        reasons.append("broken continuity: parent invoker is not the child issuer")
    if c.get("parentCapability") != p.get("id"):
        reasons.append("broken continuity: child parentCapability is not the parent capability id")
    if c.get("invocationTarget") != p.get("invocationTarget"):
        reasons.append("invocationTarget drift: the resource must be constant along the chain")
    return reasons


@dataclass
class ChainEvaluation:
    ok: bool
    reasons: List[str]
    allowed_action: List[str]
    depth: int
    code: Optional[str] = None
    responsible_party: Optional[str] = None
    leaf_invoker: Optional[str] = None
    invocation_target: Optional[str] = None


def _refused_chain(code: str, reasons: List[str], depth: int) -> ChainEvaluation:
    return ChainEvaluation(False, reasons, [], depth, code)


def evaluate_delegation_chain(
    hops: Any,
    *,
    resource: Optional[str] = None,
    resource_owner: Optional[str] = None,
    now_ms: Optional[int] = None,
    max_chain_length: int = MAX_DELEGATION_DEPTH,
    max_clock_skew_ms: Any = None,
) -> ChainEvaluation:
    """Pure evaluation of a chain root to leaf: length bound before parsing, schema, root, attenuation, windows."""
    if isinstance(max_chain_length, bool) or not isinstance(max_chain_length, int) or max_chain_length < 1:
        return _refused_chain("configuration_error", ["maxChainLength must be a positive integer"], 0)
    if clock_skew_ms(max_clock_skew_ms) is None:
        return _refused_chain("configuration_error", ["maxClockSkewMs must be a number of milliseconds from 0 to 600000"], 0)
    if not isinstance(hops, list) or not hops:
        return _refused_chain("chain_invalid", ["empty delegation chain"], 0)
    if len(hops) > max_chain_length:
        return _refused_chain("chain_invalid", [f"delegation chain depth {len(hops)} exceeds the maximum of {max_chain_length}"], len(hops))
    malformed = []
    for index, hop in enumerate(hops):
        violations = validate_credential("hop", hop)
        if violations:
            malformed.append(f"hop {index}: {describe_violations(violations)}")
    if malformed:
        return _refused_chain("delegation_malformed", malformed, len(hops))
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
            broken.append(("chain_invalid", f"hop {index}: {reason}"))
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
    return ChainEvaluation(
        ok=ok,
        reasons=[reason for _code, reason in broken],
        allowed_action=list(leaf["credentialSubject"]["allowedAction"]) if ok else [],
        depth=len(hops),
        code=None if ok else broken[0][0],
        responsible_party=root["issuer"],
        leaf_invoker=invoker_of(leaf),
        invocation_target=leaf["credentialSubject"]["invocationTarget"],
    )


# -- effective scopes and card level -------------------------------------------


def attested_capabilities(attestations: Sequence[Any]) -> List[str]:
    names: List[str] = []
    for attestation in attestations:
        name = attestation if isinstance(attestation, str) else attestation["credentialSubject"]["capability"]
        if name not in names:
            names.append(name)
    return names


def derive_effective_scopes(attestations: Sequence[Any], leaf_allowed_action: Sequence[str], catalog: Sequence[str]) -> List[str]:
    """attestations and leaf allowedAction and the service catalog, in attestation order (story F-1 point 4)."""
    allowed, offered = set(leaf_allowed_action), set(catalog)
    return [scope for scope in attested_capabilities(attestations) if scope in allowed and scope in offered]


def capability_name(capability: Any) -> str:
    return capability if isinstance(capability, str) else capability["name"]


def attested_capability_entry(name: str, attestations: Sequence[Any]) -> Dict[str, Any]:
    return {"name": name, "attestations": [{"vc": vc} for vc in attestations]}


def check_capabilities(
    capabilities: Sequence[Any],
    resolve_did: DidResolver,
    *,
    subject_did: str,
    trusted_issuers: TrustedIssuers = TRUST_ALL_ISSUERS,
    now_ms: Optional[int] = None,
    max_clock_skew_ms: Any = None,
    status_lists: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> Dict[str, List[str]]:
    """Verified (at least one attestation holds) versus unverified capabilities of a card."""
    verified: List[str] = []
    unverified: List[str] = []
    for capability in capabilities:
        if isinstance(capability, str):
            unverified.append(capability)
            continue
        holds = False
        for attestation in capability["attestations"]:
            vc = attestation.get("vc")
            list_url = vc.get("credentialStatus", {}).get("statusListCredential") if isinstance(vc, Mapping) else None
            status_list = (status_lists or {}).get(list_url) if list_url is not None else None
            verdict = verify_capability_attestation(
                vc,
                resolve_did,
                subject_did=subject_did,
                capability=capability["name"],
                trusted_issuers=trusted_issuers,
                now_ms=now_ms,
                max_clock_skew_ms=max_clock_skew_ms,
                status_list=status_list,
            )
            if verdict.ok:
                holds = True
                break
        (verified if holds else unverified).append(capability["name"])
    return {"verified": verified, "unverified": unverified}


def derive_conformance_level(check: Mapping[str, Sequence[str]], proof_floor_ok: bool = False, revocation_fresh: bool = True) -> str:
    """SPEC-ENTITY-CARD.md section 9.4: L1 unless fully attested; L3 with the proof floor and a fresh status read; else L2."""
    all_attested = len(check["verified"]) > 0 and len(check["unverified"]) == 0
    if not all_attested:
        return "L1"
    if proof_floor_ok and revocation_fresh:
        return "L3"
    return "L2"
