# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Custody preference at onboarding (KYA-OS story F-3), the Python side.

Two independent choices per agent, service and owner: key custody ``self``
(the key is generated and held client side, the SDK signs through its Signer)
or ``helix`` (Helix holds the key and signs through its signing endpoint);
DID hosting ``own`` (did:web on the owner's domain) or ``helix``.

- :func:`helix_init`: self-custody onboarding with an enrollment token. The
  key is generated here (:func:`generate_agent_key`), only the public JWK and
  a proof of possession are sent, ``did.json`` and ``card.json`` are written
  to an output directory, and with own hosting the documents must resolve
  from the owner's domain before the agent is activated.
- :class:`HelixCustodialSigner`: the Signer of a custodial agent. It holds no
  key; ``sign()`` asks the Helix API to sign. Application code takes a
  Signer (``EnvSigner`` or this one) and is the same in both modes.
- :func:`change_to_self_custody`: a custody change to self is a rotation;
  the new key is generated here and only its public half and a proof go out.

Every request body passes :func:`assert_no_private_material` before it is
sent (self-custody invariant). The proof messages are the bytes helix-core
checks (``fixtures/kya-os-helix/custody.json``).

Command line: ``helix-custody init|activate|custody take`` (``take`` alone
also works; or ``python -m helix_sdk.custody``), the same commands and report
as helix-sdk-js's ``helix init|activate|custody take``; ``--json`` prints the
result as JSON instead.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Sequence, TextIO, Tuple, TypedDict
from urllib.parse import quote

import nacl.signing

from .agent_key import AgentKey, assert_no_private_material, generate_agent_key, to_public_key_jwk
from .crypto.jws import DEFAULT_KID_FRAGMENT, DEFAULT_SIGNING_KEY_ENV_VAR, EnvSigner, Signer, default_kid_fragment
from .entity_card import FetchJson, resolve_entity_card, same_did
from .keys import _normalize_ed25519_private_key

ENROLLMENT_PROOF_PREFIX = "helix-enroll:v1"
ROTATION_PROOF_PREFIX = "helix-rotate:v1"
CUSTODY_LABEL_HELIX = "custody: helix"
CUSTODY_LABEL_SELF = "custody: self"

INIT_FILES = {
    "did_document": "did.json",
    "card": "card.json",
    "signing_key": "signing-key.env",
    "summary": "helix-agent.json",
}

# ------------------------------------------------------------------- types
# The shapes the custody endpoints answer with, as helix-sdk-js types them
# (core/custody/client.ts). The client returns plain dicts of these shapes.

KeyCustodyMode = Literal["self", "helix"]
DidHostingMode = Literal["own", "helix"]
CustodySubjectKind = Literal["agent", "service", "owner"]
CustodyLabel = Literal["custody: self", "custody: helix"]
CustodyStatus = Literal["pending_key", "pending_resolution", "active"]


class CustodyKeyView(TypedDict):
    kid: str
    location: KeyCustodyMode
    status: Literal["active", "retiring", "revoked"]
    createdAt: str
    retiresAt: Optional[str]
    revokedAt: Optional[str]


class CustodyView(TypedDict):
    did: str
    subjectType: CustodySubjectKind
    name: Optional[str]
    keyCustody: KeyCustodyMode
    didHosting: DidHostingMode
    label: CustodyLabel
    conformant: bool
    status: CustodyStatus
    kid: Optional[str]
    credentialVcId: Optional[str]
    keys: List[CustodyKeyView]


class PublishedDocuments(TypedDict):
    didDocument: Dict[str, Any]
    card: Dict[str, Any]
    didDocumentUrl: str
    cardUrl: str


class OnboardingResult(CustodyView, total=False):
    enrollmentToken: str
    enrollmentExpiresAt: str
    documents: PublishedDocuments
    publishRequired: bool
    vcId: str


class EnrollmentChallenge(TypedDict):
    did: str
    kid: str
    nonce: str
    keyCustody: Literal["self"]
    didHosting: DidHostingMode
    name: Optional[str]
    didDocumentUrl: str
    cardUrl: str


class SignResponse(TypedDict):
    did: str
    kid: str
    alg: Literal["EdDSA"]
    signature: str


class HopReissue(TypedDict, total=False):
    reissued: int
    pending: bool
    note: str


class ChangeCustodyResult(CustodyView, total=False):
    previousKid: str
    previousKeyShredded: bool
    retiresAt: str
    hopReissue: HopReissue
    documents: PublishedDocuments
    publishRequired: bool
    vcId: str


class ResolutionCheck(TypedDict, total=False):
    ok: bool
    reason: str


__all__ = [
    "ENROLLMENT_PROOF_PREFIX",
    "ROTATION_PROOF_PREFIX",
    "CUSTODY_LABEL_HELIX",
    "CUSTODY_LABEL_SELF",
    "DEFAULT_KID_FRAGMENT",
    "default_kid_fragment",
    "DEFAULT_SIGNING_KEY_ENV_VAR",
    "INIT_FILES",
    "ChangeCustodyResult",
    "CustodyApiError",
    "CustodyKeyView",
    "CustodyLabel",
    "CustodyStatus",
    "CustodySubjectKind",
    "CustodyView",
    "DidHostingMode",
    "EnrollmentChallenge",
    "EnvSigner",
    "HelixCustodialSigner",
    "HelixCustodyClient",
    "HelixInitResult",
    "KeyCustodyMode",
    "OnboardingResult",
    "PublishedDocuments",
    "ResolutionCheck",
    "SignResponse",
    "Signer",
    "activate_agent",
    "base64url_decode",
    "base64url_encode",
    "change_to_self_custody",
    "check_own_hosting",
    "enrollment_proof_message",
    "helix_init",
    "kid_fragment",
    "main",
    "rotation_proof",
    "rotation_proof_message",
    "verification_method_of",
]


# ----------------------------------------------------------------- encoding


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> Optional[bytes]:
    """Strict base64url without padding, or None."""
    if not isinstance(value, str) or len(value) % 4 == 1 or any(c not in _B64URL for c in value):
        return None
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


_B64URL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _message(parts: Sequence[str]) -> bytes:
    for part in parts:
        if not isinstance(part, str) or not part or any(ch.isspace() for ch in part):
            raise ValueError("proof message parts must be non-empty strings without whitespace")
    return ":".join(parts).encode("utf-8")


def enrollment_proof_message(did: str, kid: str, nonce: str) -> bytes:
    return _message([ENROLLMENT_PROOF_PREFIX, did, kid, nonce])


def rotation_proof_message(did: str, kid: str, issued_at: str) -> bytes:
    return _message([ROTATION_PROOF_PREFIX, did, kid, issued_at])


def kid_fragment(did: str, kid: Optional[str] = None) -> str:
    """``kid`` as a fragment: ``key-1``, ``#key-1`` or ``<did>#key-1`` (which must be this DID's).
    Default ``default_kid_fragment(did)``: the multibase value for a did:key, else ``key-1``."""
    if kid is None:
        kid = default_kid_fragment(did)
    fragment = kid[len(did) + 1:] if kid.startswith(f"{did}#") else kid
    fragment = fragment[1:] if fragment.startswith("#") else fragment
    if not fragment or "#" in fragment:
        raise ValueError(f"kid {kid} is not a verification-method fragment of {did}")
    return fragment


def verification_method_of(signer: Any) -> str:
    """``<did>#<kid>``, what a proof's verificationMethod or a JWS header names."""
    return f"{signer.did}#{str(signer.kid).lstrip('#')}"


def _base36(value: int) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while True:
        value, remainder = divmod(value, 36)
        out = digits[remainder] + out
        if value == 0:
            return out


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def rotation_proof(signer: Signer, did: str, kid: str, issued_at: Optional[str] = None) -> Dict[str, str]:
    """The proof a custody change to self carries: the new key's signature, made by its own Signer."""
    at = issued_at or _now_iso()
    return {"issuedAt": at, "signature": base64url_encode(signer.sign(rotation_proof_message(did, kid, at)))}


# ------------------------------------------------------------------- client

HttpCall = Callable[[str, str, Dict[str, str], Optional[str]], Tuple[int, Any]]


def _requests_call(method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, Any]:
    import requests

    response = requests.request(method, url, headers=headers, data=body, timeout=30)
    try:
        payload = response.json()
    except ValueError:
        payload = None
    return response.status_code, payload


class CustodyApiError(Exception):
    """A refusal from the custody API, with its error code and HTTP status."""

    def __init__(self, status: int, code: str, message: str, details: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = dict(details) if details else None


class HelixCustodyClient:
    """The custody endpoints of the Helix API. Bodies are checked for private
    key material before anything is sent."""

    def __init__(
        self,
        api_url: str,
        admin_api_key: Optional[str] = None,
        api_key: Optional[str] = None,
        http: Optional[HttpCall] = None,
    ) -> None:
        if not isinstance(api_url, str) or not api_url:
            raise ValueError("HelixCustodyClient: api_url is required")
        self._api_url = api_url.rstrip("/")
        if api_key:
            self._headers = {"authorization": f"Bearer {api_key}"}
        elif admin_api_key:
            self._headers = {"x-admin-api-key": admin_api_key}
        else:
            self._headers = {}
        self._http = http or _requests_call

    def request(self, method: str, path: str, body: Any = None) -> Any:
        if body is not None:
            assert_no_private_material(body)
        headers = dict(self._headers)
        if body is not None:
            headers["content-type"] = "application/json"
        status, payload = self._http(method, f"{self._api_url}{path}", headers, None if body is None else json.dumps(body))
        if status >= 400:
            error = payload.get("error", {}) if isinstance(payload, Mapping) else {}
            raise CustodyApiError(status, error.get("code", "HTTP_ERROR"), error.get("message", f"HTTP {status}"), error.get("details"))
        return payload

    @staticmethod
    def _subject(did: str, kind: str) -> str:
        if kind not in ("agent", "service", "owner"):
            raise ValueError("kind must be agent, service or owner")
        return f"/v1/{kind}s/{quote(did, safe='')}"

    def create_agent(self, **input: Any) -> OnboardingResult:
        """``POST /v1/agents``: name, scopes, keyCustody, didHosting, did, ownerDid,
        expiry, requestedDomains (bare hosts or http(s) URLs, published as
        ``#domain-N`` LinkedDomains entries) and maxDelegationDepth (0 to 5,
        default 0, written on the identity credential), passed as given."""
        return self.request("POST", "/v1/agents", input)

    def create_service(self, **input: Any) -> OnboardingResult:
        return self.request("POST", "/v1/services", input)

    def create_owner(self, **input: Any) -> OnboardingResult:
        return self.request("POST", "/v1/owners", input)

    def enrollment_challenge(self, enrollment_token: str) -> EnrollmentChallenge:
        return self.request("POST", "/v1/agents/enroll/challenge", {"enrollmentToken": enrollment_token})

    def enroll(self, enrollment_token: str, public_key_jwk: Mapping[str, Any], signature: str, kid: Optional[str] = None) -> OnboardingResult:
        body: Dict[str, Any] = {"enrollmentToken": enrollment_token, "publicKeyJwk": dict(public_key_jwk), "signature": signature}
        if kid is not None:
            body["kid"] = kid
        return self.request("POST", "/v1/agents/enroll", body)

    def activate(self, did: str, enrollment_token: Optional[str] = None, kind: str = "agent") -> OnboardingResult:
        return self.request("POST", f"{self._subject(did, kind)}/activate", {"enrollmentToken": enrollment_token} if enrollment_token else {})

    def sign(self, did: str, payload: bytes, kid: Optional[str] = None, kind: str = "agent") -> SignResponse:
        body: Dict[str, Any] = {"payload": base64url_encode(payload)}
        if kid is not None:
            body["kid"] = kid
        return self.request("POST", f"{self._subject(did, kind)}/sign", body)

    def get_custody(self, did: str, kind: str = "agent") -> CustodyView:
        return self.request("GET", f"{self._subject(did, kind)}/custody")

    def change_custody(self, did: str, kind: str = "agent", **input: Any) -> ChangeCustodyResult:
        return self.request("POST", f"{self._subject(did, kind)}/custody", input)

    def finalize_rotation(self, did: str, force: bool = False, kind: str = "agent") -> Dict[str, Any]:
        return self.request("POST", f"{self._subject(did, kind)}/custody/finalize", {"force": force})

    def defaults(self) -> Dict[str, Any]:
        return self.request("GET", "/v1/custody/defaults")

    def conformance_report(self) -> Dict[str, Any]:
        return self.request("GET", "/v1/conformance/report")


# ----------------------------------------------------------------- signers


class HelixCustodialSigner(Signer):
    """The Signer of a custodial (``keyCustody: helix``) agent, service or
    owner: holds no key, asks the Helix API to sign with the key Helix keeps
    in its KeyStore. Custodial subjects are labelled ``custody: helix`` and
    excluded from conformance claims (SPEC §4.5); their proofs still verify."""

    def __init__(
        self,
        did: str,
        api_url: Optional[str] = None,
        kid: Optional[str] = None,
        subject: str = "agent",
        admin_api_key: Optional[str] = None,
        api_key: Optional[str] = None,
        http: Optional[HttpCall] = None,
        client: Optional[HelixCustodyClient] = None,
    ) -> None:
        if not isinstance(did, str) or not did.startswith("did:"):
            raise ValueError("HelixCustodialSigner: did must be a DID")
        self.did = did
        self.kid = kid_fragment(did, kid)
        self._subject = subject
        if client is None and not api_url:
            raise ValueError("HelixCustodialSigner: api_url or client is required")
        self._client = client or HelixCustodyClient(api_url or "", admin_api_key=admin_api_key, api_key=api_key, http=http)

    @property
    def verification_method_id(self) -> str:
        return f"{self.did}#{self.kid}"

    def sign(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("HelixCustodialSigner: data to sign must be bytes")
        response = self._client.sign(self.did, bytes(data), kid=self.kid, kind=self._subject)
        if response.get("kid") != self.verification_method_id:
            raise ValueError(f"HelixCustodialSigner: Helix signed with {response.get('kid')}, not {self.verification_method_id}")
        signature = base64url_decode(response.get("signature", ""))
        if signature is None or len(signature) != 64:
            raise ValueError("HelixCustodialSigner: Helix did not return a 64-byte Ed25519 signature")
        return signature

    def __repr__(self) -> str:
        return f"HelixCustodialSigner(did={self.did!r}, kid={self.kid!r})"


# --------------------------------------------------------------- helix init


@dataclass
class HelixInitResult:
    did: str
    kid: str
    did_hosting: str
    status: str
    label: str
    public_key_jwk: Dict[str, Any]
    env_var: str
    files: Dict[str, str]
    did_document_url: str
    card_url: str
    key_custody: str = "self"
    resolution: Optional[Dict[str, Any]] = None
    vc_id: Optional[str] = None
    #: Own hosting, on activation: ``card.json`` was rewritten with what the
    #: agent's credentials put on its card (attestations, responsible party,
    #: revocation entry; F-3 parity). Republish it at ``card_url``.
    card_updated: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)


def check_own_hosting(did: str, kid: str, public_key_jwk: Mapping[str, Any], fetch_json: Optional[FetchJson] = None) -> Dict[str, Any]:
    """Whether ``did`` resolves from its own domain to a DID document listing
    ``kid`` with this key and an Entity Card carrying the same key."""
    try:
        resolved = resolve_entity_card(did, fetch_json)
    except Exception as error:  # noqa: BLE001 - every failure is a "not yet"
        return {"ok": False, "reason": str(error)}
    fragment = kid[kid.index("#"):]
    methods = (resolved.did_document or {}).get("verificationMethod") or []
    if not any(
        isinstance(method, Mapping)
        and method.get("id") in (kid, fragment)
        and isinstance(method.get("publicKeyJwk"), Mapping)
        and method["publicKeyJwk"].get("x") == public_key_jwk.get("x")
        for method in methods
    ):
        return {"ok": False, "reason": f"the DID document served for {did} does not list {kid} with this key"}
    card_key = resolved.card.get("publicKeyJwk")
    if isinstance(card_key, Mapping) and card_key.get("x") != public_key_jwk.get("x"):
        return {"ok": False, "reason": f"the card served for {did} carries another key"}
    return {"ok": True}


def _files(out_dir: Path) -> Dict[str, str]:
    return {name: str(out_dir / filename) for name, filename in INIT_FILES.items()}


def _write_json(path: str, value: Any) -> None:
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _write_signing_key(path: str, did: str, kid: str, fragment: str, env_var: str, seed: bytes) -> None:
    content = (
        f"# The private key of {did} ({kid}). Self-custody: it never leaves this host.\n"
        f"HELIX_AGENT_DID={did}\nHELIX_AGENT_KID={fragment}\n{env_var}={seed.hex()}\n"
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, 0o600)


def helix_init(
    api_url: str,
    enrollment_token: str,
    out_dir: str,
    did: Optional[str] = None,
    kid: Optional[str] = None,
    activate: bool = True,
    env_var: str = DEFAULT_SIGNING_KEY_ENV_VAR,
    http: Optional[HttpCall] = None,
    fetch_json: Optional[FetchJson] = None,
    generate_key: Optional[Callable[[], AgentKey]] = None,
) -> HelixInitResult:
    """``helix init``: self-custody onboarding with an enrollment token."""
    if not enrollment_token:
        raise ValueError("helix init: an enrollment token is required")
    if not out_dir:
        raise ValueError("helix init: an output directory is required")
    client = HelixCustodyClient(api_url, http=http)
    challenge = client.enrollment_challenge(enrollment_token)
    agent_did = challenge["did"]
    if did is not None and not same_did(did, agent_did):
        raise ValueError(f"helix init: this enrollment token is for {agent_did}, not {did}")
    fragment = kid_fragment(agent_did, kid or challenge["kid"])
    full_kid = f"{agent_did}#{fragment}"

    key = (generate_key or generate_agent_key)()
    seed = bytes(_normalize_ed25519_private_key(key.private_key_hex))
    public_key_jwk = to_public_key_jwk(key.public_key_hex)
    signature = base64url_encode(
        nacl.signing.SigningKey(seed).sign(enrollment_proof_message(agent_did, full_kid, challenge["nonce"])).signature
    )
    enrolled = client.enroll(enrollment_token, public_key_jwk, signature, kid=fragment)
    documents = enrolled.get("documents")
    if not isinstance(documents, Mapping):
        raise ValueError("helix init: Helix did not return the DID document and card")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = _files(out)
    _write_json(files["did_document"], documents["didDocument"])
    _write_json(files["card"], documents["card"])
    _write_signing_key(files["signing_key"], agent_did, full_kid, fragment, env_var, seed)
    _write_json(
        files["summary"],
        {
            "did": agent_did,
            "kid": full_kid,
            "keyCustody": "self",
            "didHosting": enrolled.get("didHosting"),
            "publicKeyJwk": public_key_jwk,
            "didDocumentUrl": documents["didDocumentUrl"],
            "cardUrl": documents["cardUrl"],
            "envVar": env_var,
        },
    )
    result = HelixInitResult(
        did=agent_did,
        kid=full_kid,
        did_hosting=enrolled.get("didHosting", ""),
        status=enrolled.get("status", ""),
        label=enrolled.get("label", CUSTODY_LABEL_SELF),
        public_key_jwk=public_key_jwk,
        env_var=env_var,
        files=files,
        did_document_url=documents["didDocumentUrl"],
        card_url=documents["cardUrl"],
        vc_id=enrolled.get("vcId"),
    )
    if result.status != "pending_resolution" or not activate:
        return result
    return _activate(result, enrollment_token, client, fetch_json)


def _activate(result: HelixInitResult, enrollment_token: str, client: HelixCustodyClient, fetch_json: Optional[FetchJson]) -> HelixInitResult:
    resolution = check_own_hosting(result.did, result.kid, result.public_key_jwk, fetch_json)
    result.resolution = resolution
    if not resolution["ok"]:
        return result
    active = client.activate(result.did, enrollment_token)
    result.status = active.get("status", result.status)
    result.vc_id = active.get("vcId") or result.vc_id
    # The card now carries the agent's attestations; the owner republishes it.
    card = (active.get("documents") or {}).get("card")
    if card is not None:
        _write_json(result.files["card"], card)
        result.card_updated = True
    return result


def activate_agent(
    api_url: str,
    enrollment_token: str,
    out_dir: str,
    http: Optional[HttpCall] = None,
    fetch_json: Optional[FetchJson] = None,
) -> HelixInitResult:
    """``helix activate``: once ``did.json`` and ``card.json`` are published on the owner's domain."""
    files = _files(Path(out_dir))
    summary = json.loads(Path(files["summary"]).read_text(encoding="utf-8"))
    result = HelixInitResult(
        did=summary["did"],
        kid=summary["kid"],
        did_hosting=summary["didHosting"],
        status="pending_resolution",
        label=CUSTODY_LABEL_SELF,
        public_key_jwk=summary["publicKeyJwk"],
        env_var=summary["envVar"],
        files=files,
        did_document_url=summary["didDocumentUrl"],
        card_url=summary["cardUrl"],
    )
    return _activate(result, enrollment_token, HelixCustodyClient(api_url, http=http), fetch_json)


def change_to_self_custody(
    client: HelixCustodyClient,
    did: str,
    out_dir: str,
    subject: str = "agent",
    kid: Optional[str] = None,
    overlap_seconds: Optional[int] = None,
    env_var: str = DEFAULT_SIGNING_KEY_ENV_VAR,
    generate_key: Optional[Callable[[], AgentKey]] = None,
) -> Dict[str, Any]:
    """A custody change from ``helix`` to ``self`` (a rotation): the new key is
    generated here; only its public half and a proof of possession go out."""
    fragment = kid_fragment(did, kid or f"key-{_base36(int(time.time() * 1000))}")
    full_kid = f"{did}#{fragment}"
    key = (generate_key or generate_agent_key)()
    seed = bytes(_normalize_ed25519_private_key(key.private_key_hex))
    public_key_jwk = to_public_key_jwk(key.public_key_hex)
    issued_at = _now_iso()
    signature = base64url_encode(nacl.signing.SigningKey(seed).sign(rotation_proof_message(did, full_kid, issued_at)).signature)
    body: Dict[str, Any] = {"keyCustody": "self", "publicKeyJwk": public_key_jwk, "kid": fragment, "proof": {"issuedAt": issued_at, "signature": signature}}
    if overlap_seconds is not None:
        body["overlapSeconds"] = overlap_seconds
    result = client.change_custody(did, subject, **body)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = _files(out)
    _write_signing_key(files["signing_key"], did, full_kid, fragment, env_var, seed)
    documents = result.get("documents") or {}
    _write_json(
        files["summary"],
        {
            "did": did,
            "kid": full_kid,
            "keyCustody": "self",
            "didHosting": result.get("didHosting"),
            "publicKeyJwk": public_key_jwk,
            "didDocumentUrl": documents.get("didDocumentUrl"),
            "cardUrl": documents.get("cardUrl"),
            "envVar": env_var,
        },
    )
    if result.get("publishRequired"):
        _write_json(files["did_document"], documents.get("didDocument"))
        _write_json(files["card"], documents.get("card"))
    return {"result": result, "files": files}


# ------------------------------------------------------------- command line


def _report(result: HelixInitResult, out: TextIO) -> None:
    out.write("\n")
    out.write(f"DID:        {result.did}\n")
    out.write(f"Key:        {result.kid} ({result.label}, generated here; only the public key was sent)\n")
    out.write(f"DID hosting: {result.did_hosting}\n")
    out.write(f"Status:     {result.status}\n")
    out.write(f"Files:      {result.files['did_document']}\n")
    out.write(f"            {result.files['card']}\n")
    out.write(f"            {result.files['signing_key']} (private key, mode 0600: keep it on this host)\n")
    out.write(f"            {result.files['summary']}\n")
    if result.vc_id:
        out.write(f"Credential: {result.vc_id}\n")


def _init_json(result: HelixInitResult) -> Dict[str, Any]:
    return {
        "did": result.did,
        "kid": result.kid,
        "label": result.label,
        "didHosting": result.did_hosting,
        "status": result.status,
        "files": result.files,
        "didDocumentUrl": result.did_document_url,
        "cardUrl": result.card_url,
        "resolution": result.resolution,
        **({"vcId": result.vc_id} if result.vc_id else {}),
        **({"cardUpdated": True} if result.card_updated else {}),
    }


def _print_init(result: HelixInitResult, out_dir: str, out: TextIO) -> None:
    """What ``helix init`` prints (helix-sdk-js cli/src/commands/init.ts)."""
    if result.status == "active":
        out.write(f"\u2713 Agent enrolled and active: {result.did}\n")
    else:
        out.write(f"\u26a0 Agent enrolled, waiting for its documents on your domain: {result.did}\n")
    _report(result, out)
    _print_republish(result, out)
    if result.status == "pending_resolution":
        out.write("\nPublish the two documents, then activate:\n")
        out.write(f"  {result.files['did_document']}  ->  {result.did_document_url}\n")
        out.write(f"  {result.files['card']}  ->  {result.card_url}\n")
        if result.resolution and not result.resolution.get("ok"):
            out.write(f"  (not resolving yet: {result.resolution.get('reason')})\n")
        out.write(f"  helix-custody activate --token <token> --out {out_dir}\n")


def _print_activate(result: HelixInitResult, out: TextIO) -> None:
    if result.status == "active":
        out.write(f"\u2713 Agent active: {result.did}\n")
    else:
        reason = (result.resolution or {}).get("reason") or "the documents do not resolve from your domain"
        out.write(f"\u26a0 Not active yet: {reason}\n")
    _print_republish(result, out)


def _print_republish(result: HelixInitResult, out: TextIO) -> None:
    """On activation Helix returns the card with the agent's attestations: say where to republish it."""
    if not result.card_updated:
        return
    out.write("\ncard.json now carries the attestations Helix issued; republish it:\n")
    out.write(f"  {result.files['card']}  ->  {result.card_url}\n")


def _print_take(did: str, out_dir: str, changed: Mapping[str, Any], out: TextIO) -> None:
    result = changed["result"]
    hops = result.get("hopReissue") or {}
    out.write(f"\u2713 {did} is now {result.get('label')}\n")
    out.write(f"New key:      {result.get('kid')} (generated here; private key in {changed['files']['signing_key']})\n")
    shredded = ", shredded in Helix" if result.get("previousKeyShredded") else ""
    out.write(f"Previous key: {result.get('previousKid')}, in the DID document until {result.get('retiresAt')}{shredded}\n")
    if hops.get("pending"):
        out.write(f"Hops:         not reissued ({hops.get('note') or 'story C-E'})\n")
    if result.get("publishRequired"):
        out.write(f"Publish the updated did.json and card.json from {out_dir} on your domain.\n")


def _take_arguments(take: argparse.ArgumentParser, default_api: str) -> None:
    take.add_argument("--did", required=True, help="the DID whose custody changes")
    take.add_argument("--out", required=True, help="directory for the new signing-key.env")
    take.add_argument("--api-url", default=default_api, help="Helix API base URL")
    take.add_argument("--api-key", default=os.environ.get("HELIX_API_KEY"), help="enterprise account API key")
    take.add_argument("--admin-key", default=os.environ.get("HELIX_ADMIN_API_KEY"), help="admin API key (self-hosted)")
    take.add_argument("--subject", default="agent", choices=["agent", "service", "owner"])
    take.add_argument("--overlap", type=int, help="how long both keys stay in the DID document, in seconds")
    take.add_argument("--json", action="store_true", help="print the result as JSON")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="helix-custody", description="HelixID custody commands (KYA-OS story F-3)")
    default_api = os.environ.get("HELIX_API_URL") or os.environ.get("API_BASE_URL") or "http://localhost:3000"
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="self-custody onboarding: generate the agent key here, register only its public half, write did.json and card.json")
    init.add_argument("--token", required=True, help="enrollment token from the console (POST /v1/agents with keyCustody self)")
    init.add_argument("--out", required=True, help="directory for did.json, card.json, signing-key.env and helix-agent.json")
    init.add_argument("--api-url", default=default_api, help="Helix API base URL")
    init.add_argument("--did", help="own hosting: the did:web you expect the token to be for")
    init.add_argument("--kid", help="verification-method fragment for the new key (default key-1)")
    init.add_argument("--no-activate", action="store_true", help="own hosting: do not check resolution or activate yet")
    init.add_argument("--env-var", default=DEFAULT_SIGNING_KEY_ENV_VAR, help="variable name signing-key.env sets")
    init.add_argument("--json", action="store_true", help="print the result as JSON")
    act = sub.add_parser("activate", help="own hosting: check the published documents resolve from your domain, then activate the agent")
    act.add_argument("--token", required=True, help="the enrollment token helix-custody init used")
    act.add_argument("--out", required=True, help="the directory helix-custody init wrote")
    act.add_argument("--api-url", default=default_api, help="Helix API base URL")
    act.add_argument("--json", action="store_true", help="print the result as JSON")
    custody = sub.add_parser("custody", help="custody commands")
    custody_sub = custody.add_subparsers(dest="custody_command", required=True)
    _take_arguments(custody_sub.add_parser("take", help="change a custodial agent, service or owner to self-custody (a key rotation; the new key is generated here)"), default_api)
    _take_arguments(sub.add_parser("take", help="same as custody take"), default_api)
    return parser


def main(argv: Optional[List[str]] = None, out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    """``helix-custody init|activate|custody take``: what helix-sdk-js's
    ``helix init|activate|custody take`` do and print. Exit 0 when the
    command ran (an agent still waiting for its documents included), 1 with
    the error on stderr when it failed."""
    args = _parser().parse_args(argv)
    stdout = out or sys.stdout
    stderr = err or sys.stderr
    try:
        if args.command == "init":
            result = helix_init(args.api_url, args.token, args.out, did=args.did, kid=args.kid, activate=not args.no_activate, env_var=args.env_var)
            if args.json:
                stdout.write(json.dumps(_init_json(result), indent=2) + "\n")
            else:
                _print_init(result, args.out, stdout)
        elif args.command == "activate":
            result = activate_agent(args.api_url, args.token, args.out)
            if args.json:
                stdout.write(json.dumps(_init_json(result), indent=2) + "\n")
            else:
                _print_activate(result, stdout)
        else:
            client = HelixCustodyClient(args.api_url, admin_api_key=args.admin_key, api_key=args.api_key)
            changed = change_to_self_custody(client, args.did, args.out, subject=args.subject, overlap_seconds=args.overlap)
            if args.json:
                result = changed["result"]
                stdout.write(json.dumps({"did": args.did, "label": result.get("label"), "kid": result.get("kid"), "previousKid": result.get("previousKid"), "files": changed["files"]}, indent=2) + "\n")
            else:
                _print_take(args.did, args.out, changed, stdout)
    except Exception as error:  # noqa: BLE001 - the command line reports every failure the same way
        stderr.write(f"{error}\n")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
