# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
EdDSA compact JWS the KYA-OS way (conformance Core L1.3 to L1.5, SPEC 7.4),
byte-compatible with helix-core's src/core/crypto/jws.ts: same header member
order (alg, kid, then extras), base64url without padding, JSON payloads
written as JSON.stringify writes them.

- sign_jws(payload, signer): ``<header>.<payload>.<signature>`` with header
  ``{"alg": "EdDSA", "kid": "<did>#<fragment>"}``; the signature comes from a
  Signer, never from a key this module reads itself.
- verify_jws(jws, jwk): verifies against one Ed25519 public JWK. The three
  segments and the key's ``x`` are read exactly as RFC 7515 section 2 writes
  base64url: alphabet characters only, no padding, no white space.
- verify_jws_by_kid(jws, resolve_did): reads ``kid``, resolves its DID through
  the injected resolver, picks the one assertion method ``kid`` names, then
  verifies as verify_jws does.

Refusals raise InvalidJWSError with a ``reason`` from JwsReasons, the same
strings helix-core uses. Cross-border rule: the verify path reads only the
JWS, the key it is given, or the document the resolver returns.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Union

import nacl.exceptions
import nacl.signing

from ..errors import InvalidJWSError
from ..keys import _normalize_ed25519_private_key, derive_public_key, multibase_to_public_key_hex
from ..vp_crypto import base58btc_decode

JWS_ALG = "EdDSA"
DEFAULT_SIGNING_KEY_ENV_VAR = "HELIX_SIGNING_KEY"
DEFAULT_KID_FRAGMENT = "key-1"


class JwsReasons:
    """Why a JWS was refused; mirrors JwsReasons in helix-core."""

    MALFORMED = "jws_malformed"
    HEADER_INVALID = "jws_header_invalid"
    ALG_UNSUPPORTED = "jws_alg_unsupported"
    KID_MISSING = "jws_kid_missing"
    KID_MALFORMED = "jws_kid_malformed"
    KID_MISMATCH = "jws_kid_mismatch"
    KID_DID_MISMATCH = "jws_kid_did_mismatch"
    JWK_INVALID = "jws_jwk_invalid"
    SIGNATURE_INVALID = "jws_signature_invalid"
    DID_UNRESOLVED = "jws_did_unresolved"
    DID_DOCUMENT_MISMATCH = "jws_did_document_mismatch"
    KEY_NOT_FOUND = "jws_key_not_found"
    KEY_NOT_ASSERTION = "jws_key_not_assertion"
    KEY_AMBIGUOUS = "jws_key_ambiguous"
    KEY_FOREIGN_CONTROLLER = "jws_key_foreign_controller"
    KEY_UNSUPPORTED = "jws_key_unsupported"


JwsPayload = Union[bytes, bytearray, str, Dict[str, Any], List[Any]]
DidResolver = Callable[[str], Optional[Mapping[str, Any]]]


class Signer:
    """Whoever holds an Ed25519 private key and signs with it (structural; any
    object with ``did``, ``kid`` and ``sign(data: bytes) -> bytes`` will do).

    ``kid`` is the verification-method fragment without ``#``; the JWS header
    carries ``<did>#<kid>``. Signing code never reads the key itself, so no API
    request ever carries private key material (self-custody invariant)."""

    did: str
    kid: str

    def sign(self, data: bytes) -> bytes:  # pragma: no cover - protocol only
        raise NotImplementedError


class EnvSigner(Signer):
    """The only Signer for now: an Ed25519 private key (raw 32-byte hex or PKCS8
    DER seed hex, as HELIX_SIGNING_KEY already is) read from an environment
    variable at every sign() call. The instance never holds the key."""

    def __init__(
        self,
        did: str,
        kid: str = DEFAULT_KID_FRAGMENT,
        env_var: str = DEFAULT_SIGNING_KEY_ENV_VAR,
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        if not did.startswith("did:"):
            raise ValueError("EnvSigner: did must be a DID")
        fragment = kid[1:] if kid.startswith("#") else kid
        if not fragment or "#" in fragment:
            raise ValueError('EnvSigner: kid must be a verification-method fragment without "#"')
        self.did = did
        self.kid = fragment
        self._env_var = env_var
        # A closure, not the mapping itself: vars()/repr() of a signer show
        # the DID and kid and nothing of where the key lives.
        source = env if env is not None else os.environ
        self._read_secret = lambda: source.get(env_var)

    @property
    def verification_method_id(self) -> str:
        return f"{self.did}#{self.kid}"

    def sign(self, data: bytes) -> bytes:
        return nacl.signing.SigningKey(self._secret()).sign(bytes(data)).signature

    def public_key_hex(self) -> str:
        return derive_public_key(self._secret().hex())

    def _secret(self) -> bytes:
        value = self._read_secret()
        if value is None or value.strip() == "":
            raise ValueError(f"EnvSigner: environment variable {self._env_var} is not set")
        return _normalize_ed25519_private_key(value)

    def __repr__(self) -> str:
        return f"EnvSigner(did={self.did!r}, kid={self.kid!r})"


@dataclass(frozen=True)
class JwsVerification:
    header: Dict[str, Any]
    kid: str
    did: str
    payload_bytes: bytes
    payload: Any  # the payload parsed as JSON, or None when it is not JSON


# -- base64url, strictly -------------------------------------------------------

_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


def base64url_encode(data: Union[bytes, bytearray, str]) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def base64url_decode_strict(value: str) -> Optional[bytes]:
    """Bytes of a base64url string exactly as RFC 7515 section 2 writes one:
    alphabet characters only, no padding, no white space. None otherwise."""
    # fullmatch, not match with ``$``: ``$`` would pass a trailing newline.
    if not isinstance(value, str) or _BASE64URL.fullmatch(value) is None or len(value) % 4 == 1:
        return None
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


# -- keys ----------------------------------------------------------------------


def public_key_hex_to_jwk(public_key_hex: str, kid: Optional[str] = None) -> Dict[str, Any]:
    jwk: Dict[str, Any] = {"kty": "OKP", "crv": "Ed25519", "x": base64url_encode(bytes.fromhex(public_key_hex))}
    if kid is not None:
        jwk["kid"] = kid
    return jwk


def _jwk_public_key_bytes(jwk: Any) -> bytes:
    if (
        not isinstance(jwk, Mapping)
        or jwk.get("kty") != "OKP"
        or jwk.get("crv") != "Ed25519"
        or not isinstance(jwk.get("x"), str)
    ):
        raise InvalidJWSError(JwsReasons.JWK_INVALID, "Key is not an Ed25519 public JWK")
    key = base64url_decode_strict(jwk["x"])
    if key is None or len(key) != 32:
        raise InvalidJWSError(JwsReasons.JWK_INVALID, "JWK x is not a strict base64url 32-byte key")
    if "kid" in jwk and not isinstance(jwk["kid"], str):
        raise InvalidJWSError(JwsReasons.JWK_INVALID, "JWK kid must be a string")
    return key


def verification_method_to_jwk(method: Mapping[str, Any]) -> Dict[str, Any]:
    """The Ed25519 public JWK of a verification method, whichever key form it carries."""
    method_id = str(method.get("id"))
    if "publicKeyJwk" in method:
        return public_key_hex_to_jwk(_jwk_public_key_bytes(method["publicKeyJwk"]).hex(), method_id)
    try:
        if isinstance(method.get("publicKeyMultibase"), str):
            return public_key_hex_to_jwk(multibase_to_public_key_hex(method["publicKeyMultibase"]), method_id)
        if isinstance(method.get("publicKeyBase58"), str):
            return public_key_hex_to_jwk(base58btc_decode(method["publicKeyBase58"]).hex(), method_id)
    except Exception as exc:  # noqa: BLE001 - any decoding failure is one refusal
        raise InvalidJWSError(JwsReasons.KEY_UNSUPPORTED, f"Verification method {method_id} key is not decodable") from exc
    raise InvalidJWSError(JwsReasons.KEY_UNSUPPORTED, f"Verification method {method_id} carries no Ed25519 public key")


# -- parsing -------------------------------------------------------------------


def _kid_did(kid: str) -> str:
    hash_at = kid.find("#")
    if not kid.startswith("did:") or hash_at <= len("did:") or hash_at == len(kid) - 1:
        raise InvalidJWSError(JwsReasons.KID_MALFORMED, "JWS kid must be <did>#<fragment>")
    return kid[:hash_at]


@dataclass(frozen=True)
class _ParsedJws:
    header_segment: str
    payload_segment: str
    signature_segment: str
    header: Dict[str, Any]
    kid: str
    did: str


def _parse_jws(jws: Any) -> _ParsedJws:
    if not isinstance(jws, str):
        raise InvalidJWSError(JwsReasons.MALFORMED, "JWS must be a string")
    segments = jws.split(".")
    if len(segments) != 3 or any(len(segment) == 0 for segment in segments):
        raise InvalidJWSError(JwsReasons.MALFORMED, "Compact JWS must be header.payload.signature")
    for segment in segments:
        if base64url_decode_strict(segment) is None:
            raise InvalidJWSError(JwsReasons.MALFORMED, "JWS segment is not strict base64url")
    header_segment, payload_segment, signature_segment = segments
    try:
        header = json.loads(base64url_decode_strict(header_segment).decode("utf-8"))  # type: ignore[union-attr]
    except Exception as exc:  # noqa: BLE001
        raise InvalidJWSError(JwsReasons.HEADER_INVALID, "JWS header is not JSON") from exc
    if not isinstance(header, dict):
        raise InvalidJWSError(JwsReasons.HEADER_INVALID, "JWS header is not a JSON object")
    if header.get("alg") != JWS_ALG:
        raise InvalidJWSError(JwsReasons.ALG_UNSUPPORTED, f"JWS alg must be {JWS_ALG}")
    kid = header.get("kid")
    if kid is None:
        raise InvalidJWSError(JwsReasons.KID_MISSING, "JWS header has no kid")
    if not isinstance(kid, str):
        raise InvalidJWSError(JwsReasons.KID_MALFORMED, "JWS kid must be a string")
    return _ParsedJws(header_segment, payload_segment, signature_segment, header, kid, _kid_did(kid))


def read_jws_header(jws: str) -> Dict[str, Any]:
    """The protected header of a compact JWS, read strictly, without verifying anything else."""
    return _parse_jws(jws).header


# -- sign ----------------------------------------------------------------------


def _json_bytes(value: Any) -> bytes:
    # What JSON.stringify writes: no spaces, keys in insertion order, non-ASCII as is.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _payload_bytes(payload: JwsPayload) -> bytes:
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return _json_bytes(payload)


def sign_jws(payload: JwsPayload, signer: Signer, header: Optional[Mapping[str, Any]] = None) -> str:
    """Compact JWS over ``payload`` (bytes as given, str as UTF-8, anything else
    as JSON), header ``{alg, kid}`` then ``header`` extras, signed by ``signer``."""
    fragment = signer.kid[1:] if signer.kid.startswith("#") else signer.kid
    if not signer.did.startswith("did:") or not fragment or "#" in fragment:
        raise InvalidJWSError(JwsReasons.KID_MALFORMED, "Signer must have a DID and a fragment kid")
    protected: Dict[str, Any] = {"alg": JWS_ALG, "kid": f"{signer.did}#{fragment}"}
    for name, value in (header or {}).items():
        if name not in ("alg", "kid"):
            protected[name] = value
    signing_input = f"{base64url_encode(_json_bytes(protected))}.{base64url_encode(_payload_bytes(payload))}"
    signature = signer.sign(signing_input.encode("utf-8"))
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise InvalidJWSError(JwsReasons.SIGNATURE_INVALID, "Signer did not return a 64-byte Ed25519 signature")
    return f"{signing_input}.{base64url_encode(signature)}"


# -- verify --------------------------------------------------------------------


def _claimed_issuer(payload: Any) -> Optional[str]:
    if isinstance(payload, dict) and isinstance(payload.get("iss"), str):
        return payload["iss"]
    return None


def verify_jws(
    jws: str,
    jwk: Mapping[str, Any],
    expected_kid: Optional[str] = None,
    expected_did: Optional[str] = None,
) -> JwsVerification:
    """Verifies a compact EdDSA JWS against one Ed25519 public JWK.
    Raises InvalidJWSError (with a JwsReasons value) on any refusal."""
    parsed = _parse_jws(jws)
    public_key = _jwk_public_key_bytes(jwk)

    if "kid" in jwk and jwk["kid"] != parsed.kid:
        raise InvalidJWSError(JwsReasons.KID_MISMATCH, "JWS kid does not name the given key")
    if expected_kid is not None and expected_kid != parsed.kid:
        raise InvalidJWSError(JwsReasons.KID_MISMATCH, "JWS kid is not the expected kid")
    if expected_did is not None and expected_did != parsed.did:
        raise InvalidJWSError(JwsReasons.KID_DID_MISMATCH, "JWS kid belongs to a DID other than the expected signer")

    payload_bytes = base64url_decode_strict(parsed.payload_segment)
    assert payload_bytes is not None  # _parse_jws read every segment already
    try:
        payload: Any = json.loads(payload_bytes.decode("utf-8"))
    except Exception:  # noqa: BLE001 - a non-JSON payload is still a payload
        payload = None
    issuer = _claimed_issuer(payload)
    if issuer is not None and issuer != parsed.did:
        raise InvalidJWSError(JwsReasons.KID_DID_MISMATCH, "JWS kid belongs to a DID other than the iss claim")

    signature = base64url_decode_strict(parsed.signature_segment)
    signing_input = f"{parsed.header_segment}.{parsed.payload_segment}".encode("utf-8")
    valid = False
    if signature is not None and len(signature) == 64:
        try:
            nacl.signing.VerifyKey(public_key).verify(signing_input, signature)
            valid = True
        except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError, ValueError):
            valid = False
    if not valid:
        raise InvalidJWSError(JwsReasons.SIGNATURE_INVALID, "JWS signature does not verify")
    return JwsVerification(parsed.header, parsed.kid, parsed.did, payload_bytes, payload)


def _absolute_id(value: Any, did: str) -> str:
    text = str(value)
    return f"{did}{text}" if text.startswith("#") else text


def select_assertion_method(document: Any, did: str, kid: str) -> Mapping[str, Any]:
    """The one verification method ``kid`` names in ``document``: the document of
    ``did``, listing the method under assertionMethod (by reference or embedded)
    exactly once, controlled by ``did``."""
    if not isinstance(document, Mapping) or document.get("id") != did:
        raise InvalidJWSError(JwsReasons.DID_DOCUMENT_MISMATCH, f"Resolved document is not the document of {did}")
    methods = document.get("verificationMethod")
    published = [
        m for m in (methods if isinstance(methods, list) else [])
        if isinstance(m, Mapping) and _absolute_id(m.get("id"), did) == kid
    ]
    assertion = document.get("assertionMethod")
    entries = assertion if isinstance(assertion, list) else []
    referenced = any(isinstance(e, str) and _absolute_id(e, did) == kid for e in entries)
    embedded = [e for e in entries if isinstance(e, Mapping) and _absolute_id(e.get("id"), did) == kid]
    definitions = published + embedded
    if not definitions:
        raise InvalidJWSError(JwsReasons.KEY_NOT_FOUND, f"DID document {did} does not define {kid}")
    if len(definitions) > 1:
        raise InvalidJWSError(JwsReasons.KEY_AMBIGUOUS, f"DID document {did} defines {kid} more than once")
    if not referenced and not embedded:
        raise InvalidJWSError(JwsReasons.KEY_NOT_ASSERTION, f"{kid} is not an assertion method of {did}")
    method = definitions[0]
    if method.get("controller") != did:
        raise InvalidJWSError(JwsReasons.KEY_FOREIGN_CONTROLLER, f"{kid} is not controlled by {did}")
    return method


def verify_jws_by_kid(
    jws: str,
    resolve_did: DidResolver,
    expected_kid: Optional[str] = None,
    expected_did: Optional[str] = None,
) -> JwsVerification:
    """Reads ``kid``, resolves its DID through ``resolve_did``, picks the
    assertion method ``kid`` names, then verifies as verify_jws does."""
    parsed = _parse_jws(jws)
    if expected_did is not None and expected_did != parsed.did:
        raise InvalidJWSError(JwsReasons.KID_DID_MISMATCH, "JWS kid belongs to a DID other than the expected signer")
    document = resolve_did(parsed.did)
    if document is None:
        raise InvalidJWSError(JwsReasons.DID_UNRESOLVED, f"DID {parsed.did} did not resolve")
    method = select_assertion_method(document, parsed.did, parsed.kid)
    jwk = dict(verification_method_to_jwk(method))
    jwk["kid"] = parsed.kid
    return verify_jws(jws, jwk, expected_kid=expected_kid, expected_did=parsed.did)
