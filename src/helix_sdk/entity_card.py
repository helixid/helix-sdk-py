# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
KYA-OS Entity Cards (story C-A), the same answers helix-core's
``src/core/card/*`` and ``src/core/net/safe-fetch.ts`` give:

- ``resolve_entity_card(did)``: the two-step discovery of SPEC-ENTITY-CARD
  §6.5, ``did.json`` → the ``KyaOsEntityCard`` service entry → ``card.json``,
  the ``/.well-known/kya-os-card.json`` fallback for a bare host (the service
  entry wins when both exist), a did:key refused by discovery, the fetched
  card bound to the DID it was resolved for;
- ``safe_fetch(url)``: the SSRF-hardened read of §6.6: https only, public
  unicast addresses only (loopback, RFC 1918, link-local with the
  169.254.169.254 metadata endpoint, CGNAT, ULA, multicast and the transition
  ranges refused), the connection pinned to the checked address, same-origin
  redirects only (at most 3), a 1 MiB cap and a 5 s deadline;
- the strict card schema (§4): an unknown top-level field is refused, a
  ``conformanceLevel`` is read but never trusted;
- ``build_entity_card`` and the ``server.json`` projection, with its reverse.

Cross-border rule (stories, rule 4): this module reads public documents over
HTTPS and nothing else; ``fetch_json`` is its only seam.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote, unquote, urljoin, urlsplit

from .errors import HelixError

KYA_OS_CARD_SERVICE_TYPE = "KyaOsEntityCard"
KYA_OS_CARD_SERVICE_ID = "#kya-os-card"
KYA_OS_CARD_META_KEY = "org.kya-os/card"
KYA_OS_CARD_REF_KEY = "org.kya-os/cardRef"
KYA_OS_CARD_WELL_KNOWN_PATH = ".well-known/kya-os-card.json"
PROOF_PROFILE_V1 = "org.kya-os/proof.v1"
ENTITY_TYPES = ("mcp", "agent", "client", "verifier", "human")

SAFE_FETCH_MAX_BYTES = 1024 * 1024
SAFE_FETCH_TIMEOUT_SECONDS = 5.0
SAFE_FETCH_MAX_REDIRECTS = 3

FetchJson = Callable[[str], Any]


class EntityCardError(HelixError):
    """A card, a DID or a discovery step that is not what the spec asks for; ``reason`` codes it."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__("ENTITY_CARD_INVALID", message, 400, {"reason": reason})
        self.reason = reason


class SafeFetchRefusedError(HelixError):
    """SafeFetch refused or failed a read; ``reason`` codes why."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__("SAFE_FETCH_REFUSED", message, 502, {"reason": reason})
        self.reason = reason


# ── did:web ──────────────────────────────────────────────────────────────────

_SEGMENT_FORBIDDEN = re.compile(r"[/#?]")


def parse_did_web(did: Any) -> Optional[Tuple[str, List[str]]]:
    """``(host, decoded path segments)`` of a did:web, or None for anything else."""
    if not isinstance(did, str) or not did.startswith("did:web:"):
        return None
    parts = did[len("did:web:"):].split(":")
    if any(part == "" for part in parts):
        return None
    try:
        decoded = [unquote_strict(part) for part in parts]
    except ValueError:
        return None
    host, path = decoded[0], decoded[1:]
    if not host or _SEGMENT_FORBIDDEN.search(host):
        return None
    if any(seg == "" or _SEGMENT_FORBIDDEN.search(seg) or seg in (".", "..") for seg in path):
        return None
    return host, path


def unquote_strict(value: str) -> str:
    """``unquote`` that refuses a malformed percent-encoding (``ValueError``) instead of passing it through."""
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError(f"malformed percent-encoding in {value!r}")
    try:
        return unquote(value, errors="strict")
    except UnicodeDecodeError as err:
        raise ValueError(f"malformed percent-encoding in {value!r}") from err


def _require_did_web(did: str) -> Tuple[str, List[str]]:
    parsed = parse_did_web(did)
    if parsed is None:
        raise EntityCardError("malformed_did", f"{did} is not a did:web DID that names a URL")
    return parsed


def did_web_for(host: str, segments: Sequence[str] = ()) -> str:
    """``did:web:<host>:<seg>…`` with every segment percent-encoded and the host lowercased."""
    return ":".join(["did:web", quote(host.lower(), safe="")] + [quote(seg, safe="") for seg in segments])


def is_loopback_host(host: str) -> bool:
    """A loopback host (a local stack) serves plain http; SafeFetch admits it only in development mode."""
    hostname = re.sub(r":\d+$", "", host).strip("[]").lower()
    return hostname in ("localhost", "127.0.0.1", "::1")


def _scheme_for(host: str) -> str:
    return "http" if is_loopback_host(host) else "https"


def did_web_document_url(did: str) -> str:
    host, path = _require_did_web(did)
    if not path:
        return f"{_scheme_for(host)}://{host}/.well-known/did.json"
    return f"{_scheme_for(host)}://{host}/" + "/".join(quote(seg, safe="") for seg in path) + "/did.json"


def did_web_card_url(did: str) -> str:
    host, path = _require_did_web(did)
    if not path:
        return f"{_scheme_for(host)}://{host}/{KYA_OS_CARD_WELL_KNOWN_PATH}"
    return f"{_scheme_for(host)}://{host}/" + "/".join(quote(seg, safe="") for seg in path) + "/card.json"


def normalize_did(did: str) -> str:
    """One spelling for a did:web (host lowercased, segments decoded and re-encoded); any other DID as written."""
    if not did.startswith("did:web:"):
        return did
    parts = [unquote_strict(part) for part in did[len("did:web:"):].split(":")]
    host, path = (parts[0] if parts else "").lower(), parts[1:]
    return "did:web:" + ":".join(quote(part, safe="") for part in [host] + path)


def same_did(a: str, b: str) -> bool:
    try:
        return normalize_did(a) == normalize_did(b)
    except ValueError:
        return False


def card_endpoint_of(document: Any) -> Optional[str]:
    """The ``KyaOsEntityCard`` service endpoint a DID document anchors, or None."""
    services = document.get("service") if isinstance(document, Mapping) else None
    if not isinstance(services, list):
        return None
    for entry in services:
        if isinstance(entry, Mapping) and entry.get("type") == KYA_OS_CARD_SERVICE_TYPE and isinstance(entry.get("serviceEndpoint"), str):
            return entry["serviceEndpoint"]
    return None


def kya_os_card_service_entry(service_endpoint: str) -> Dict[str, str]:
    return {"id": KYA_OS_CARD_SERVICE_ID, "type": KYA_OS_CARD_SERVICE_TYPE, "serviceEndpoint": service_endpoint}


# ── The strict card schema ──────────────────────────────────────────────────

_DID_PATTERN = re.compile(r"^did:(?:key|web):(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$")
_CARD_MEMBERS = ("id", "entityType", "name", "kid", "publicKeyJwk", "createdAt", "capabilities", "conformanceLevel",
                 "responsibleParty", "principal", "delegationRef", "attestations", "didDocument", "proofProfile", "cimd", "revocation")


def _is_record(value: Any) -> bool:
    return isinstance(value, Mapping)


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0


def _strict_object(value: Any, path: str, allowed: Sequence[str], issues: List[str]) -> Optional[Mapping[str, Any]]:
    if not _is_record(value):
        issues.append(f"{path}: must be of type object")
        return None
    for member in value:
        if member not in allowed:
            issues.append(f"{path}/{member}: must NOT have additional properties")
    return value


def _check_did(value: Any, path: str, issues: List[str]) -> None:
    if not isinstance(value, str) or not _DID_PATTERN.match(value):
        issues.append(f"{path}: must be a did:key or did:web DID")


def _check_status_entry(value: Any, path: str, issues: List[str]) -> None:
    entry = _strict_object(value, path, ("statusListCredential", "statusListIndex", "statusSize", "statusMessage"), issues)
    if entry is None:
        return
    if not _non_empty_string(entry.get("statusListCredential")):
        issues.append(f"{path}/statusListCredential: must be a non-empty string")
    index = entry.get("statusListIndex")
    if not isinstance(index, str) or not re.fullmatch(r"[0-9]+", index):
        issues.append(f"{path}/statusListIndex: must match ^[0-9]+$")
    size = entry.get("statusSize")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 1):
        issues.append(f"{path}/statusSize: must be an integer of at least 1")
    messages = entry.get("statusMessage")
    if messages is not None:
        if not isinstance(messages, list):
            issues.append(f"{path}/statusMessage: must be an array")
        else:
            for i, message in enumerate(messages):
                if not _is_record(message) or not isinstance(message.get("status"), str) or not isinstance(message.get("message"), str):
                    issues.append(f"{path}/statusMessage/{i}: must have string status and message")


def _level2_capability_ok(capability: Any) -> bool:
    if not _is_record(capability) or any(member not in ("name", "attestations") for member in capability):
        return False
    attestations = capability.get("attestations")
    return (_non_empty_string(capability.get("name")) and isinstance(attestations, list) and len(attestations) > 0
            and all(_is_record(a) and (isinstance(a.get("vc"), str) or _is_record(a.get("vc"))) for a in attestations))


def validate_entity_card(value: Any) -> List[str]:
    """The issues ``value`` has against the strict card schema (empty: it is a card)."""
    issues: List[str] = []
    card = _strict_object(value, "", _CARD_MEMBERS, issues)
    if card is None:
        return issues
    for required in ("id", "entityType", "name"):
        if required not in card:
            issues.append(f": must have required property '{required}'")
    if "id" in card:
        _check_did(card["id"], "/id", issues)
    if "entityType" in card and card["entityType"] not in ENTITY_TYPES:
        issues.append(f"/entityType: must be one of {json.dumps(list(ENTITY_TYPES))}")
    if "name" in card and not _non_empty_string(card["name"]):
        issues.append("/name: must be a non-empty string")
    for member in ("kid", "delegationRef"):
        if card.get(member) is not None and not isinstance(card[member], str):
            issues.append(f"/{member}: must be of type string")
    if card.get("publicKeyJwk") is not None:
        jwk = _strict_object(card["publicKeyJwk"], "/publicKeyJwk", ("kty", "crv", "x", "kid", "use"), issues)
        if jwk is not None:
            if jwk.get("kty") != "OKP":
                issues.append('/publicKeyJwk/kty: must equal "OKP"')
            if jwk.get("crv") != "Ed25519":
                issues.append('/publicKeyJwk/crv: must equal "Ed25519"')
            if not isinstance(jwk.get("x"), str):
                issues.append("/publicKeyJwk/x: must be of type string")
            for member in ("kid", "use"):
                if jwk.get(member) is not None and not isinstance(jwk[member], str):
                    issues.append(f"/publicKeyJwk/{member}: must be of type string")
    created = card.get("createdAt")
    if created is not None and not (isinstance(created, str) and _RFC3339.match(created)):
        issues.append("/createdAt: must be an RFC 3339 date-time")
    capabilities = card.get("capabilities")
    if capabilities is not None:
        if not isinstance(capabilities, list):
            issues.append("/capabilities: must be of type array")
        else:
            for i, capability in enumerate(capabilities):
                if not _non_empty_string(capability) and not _level2_capability_ok(capability):
                    issues.append(f"/capabilities/{i}: must be a non-empty capability name or {{name, attestations[]}}")
    if card.get("conformanceLevel") is not None and card["conformanceLevel"] not in ("L1", "L2", "L3"):
        issues.append('/conformanceLevel: must be one of ["L1","L2","L3"]')
    for member in ("responsibleParty", "principal"):
        if card.get(member) is not None:
            _check_did(card[member], f"/{member}", issues)
    attestations = card.get("attestations")
    if attestations is not None:
        if not isinstance(attestations, list):
            issues.append("/attestations: must be of type array")
        else:
            for i, attestation in enumerate(attestations):
                entry = _strict_object(attestation, f"/attestations/{i}", ("type", "vc", "subject", "issuer"), issues)
                if entry is None:
                    continue
                if entry.get("type") not in ("IdentityVerification", "CapabilityAttestation"):
                    issues.append(f'/attestations/{i}/type: must be one of ["IdentityVerification","CapabilityAttestation"]')
                if not isinstance(entry.get("vc"), str) and not _is_record(entry.get("vc")):
                    issues.append(f"/attestations/{i}/vc: must be a string or an object")
                for member in ("subject", "issuer"):
                    if entry.get(member) is not None:
                        _check_did(entry[member], f"/attestations/{i}/{member}", issues)
    did_document = card.get("didDocument")
    if did_document is not None:
        split = urlsplit(did_document) if isinstance(did_document, str) else None
        if split is None or not split.scheme or not split.netloc:
            issues.append("/didDocument: must be a URI")
    if card.get("proofProfile") is not None and card["proofProfile"] not in ("org.kya-os/proof.v1", "org.kya-os/proof@1"):
        issues.append('/proofProfile: must be one of ["org.kya-os/proof.v1","org.kya-os/proof@1"]')
    if card.get("cimd") is not None:
        cimd = _strict_object(card["cimd"], "/cimd", ("clientId", "jwksUri"), issues)
        if cimd is not None:
            for member in ("clientId", "jwksUri"):
                if not _non_empty_string(cimd.get(member)):
                    issues.append(f"/cimd/{member}: must be a non-empty string")
    if card.get("revocation") is not None:
        _check_status_entry(card["revocation"], "/revocation", issues)
    return issues


def parse_entity_card(value: Any) -> Dict[str, Any]:
    """``parseCard``: the value as a card, or ``EntityCardError`` (reason ``card_invalid``) naming every issue."""
    issues = validate_entity_card(value)
    if issues:
        raise EntityCardError("card_invalid", "Entity Card is invalid: " + "; ".join(issues))
    return dict(value)


def capability_name(capability: Any) -> str:
    return capability if isinstance(capability, str) else capability["name"]


_INPUT_MEMBERS = ("id", "entityType", "name", "kid", "publicKeyJwk", "capabilities", "responsibleParty", "principal", "delegationRef",
                  "revocation", "didDocument", "createdAt", "attestations", "cimd", "proofProfile", "conformanceLevel")


def build_entity_card(input: Mapping[str, Any]) -> Dict[str, Any]:
    """``card.json`` for an entity: never a ``conformanceLevel`` (one on input is ignored), never a proof (one on
    input, or any unknown member, is refused), ``proofProfile`` v1 by default, the DID document URL derived for a did:web."""
    if not _is_record(input):
        raise EntityCardError("card_invalid", "build_entity_card needs an input mapping")
    foreign = [member for member in input if member not in _INPUT_MEMBERS]
    if foreign:
        raise EntityCardError("card_invalid", f"Entity Card input carries unknown members ({', '.join(foreign)}); a card never carries a proof or an unknown field")
    did = input["id"]
    jwk = input.get("publicKeyJwk")
    if jwk is not None:
        if not _is_record(jwk) or "d" in jwk:
            raise EntityCardError("card_invalid", "publicKeyJwk carries private material (d); only the public key is accepted")
        foreign_jwk = [member for member in jwk if member not in ("kty", "crv", "x", "kid")]
        if foreign_jwk:
            raise EntityCardError("card_invalid", f"publicKeyJwk carries unexpected members ({', '.join(foreign_jwk)})")
    kid = input.get("kid")
    if kid is not None:
        hash_at = kid.find("#")
        owner = did if hash_at == -1 else kid[:hash_at]
        fragment = kid if hash_at == -1 else kid[hash_at + 1:]
        if (hash_at > 0 and owner != did) or not fragment or "#" in fragment:
            raise EntityCardError("card_invalid", f"kid {kid} does not name one verification method of {did}")
        kid = f"{did}#{fragment}"
    public_key_jwk = None if jwk is None else {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"], **({"kid": kid} if kid else {})}
    did_document = input.get("didDocument")
    if did_document is None and parse_did_web(did) is not None:
        did_document = did_web_document_url(did)
    card: Dict[str, Any] = {"id": did, "entityType": input["entityType"], "name": input["name"]}
    if kid is not None:
        card["kid"] = kid
    if public_key_jwk is not None:
        card["publicKeyJwk"] = public_key_jwk
    if input.get("createdAt") is not None:
        card["createdAt"] = input["createdAt"]
    if input.get("capabilities") is not None:
        card["capabilities"] = list(input["capabilities"])
    for member in ("responsibleParty", "principal", "delegationRef"):
        if input.get(member) is not None:
            card[member] = input[member]
    if input.get("attestations") is not None:
        card["attestations"] = list(input["attestations"])
    if did_document is not None:
        card["didDocument"] = did_document
    card["proofProfile"] = input.get("proofProfile") or PROOF_PROFILE_V1
    if input.get("cimd") is not None:
        card["cimd"] = input["cimd"]
    if input.get("revocation") is not None:
        card["revocation"] = input["revocation"]
    return parse_entity_card(card)


# ── The server.json projection ───────────────────────────────────────────────

def entity_card_summary(card: Mapping[str, Any]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {"id": card["id"], "entityType": card["entityType"], "name": card["name"]}
    if card.get("capabilities") is not None:
        summary["capabilities"] = [capability_name(c) for c in card["capabilities"]]
    for member in ("responsibleParty", "delegationRef", "proofProfile", "revocation"):
        if card.get(member) is not None:
            summary[member] = card[member]
    return summary


def server_card_meta(card: Mapping[str, Any], card_url: Optional[str] = None, by_ref: bool = False) -> Dict[str, Any]:
    """``{"org.kya-os/card": {…summary, "org.kya-os/cardRef": url}}`` for ``server.json`` ``_meta``."""
    if card_url is None:
        if parse_did_web(card["id"]) is None:
            raise EntityCardError("card_invalid", "a did:key card has no card URL; pass card_url")
        card_url = did_web_card_url(card["id"])
    ref = {KYA_OS_CARD_REF_KEY: card_url}
    return {KYA_OS_CARD_META_KEY: ref if by_ref else {**entity_card_summary(card), **ref}}


# ── SafeFetch ────────────────────────────────────────────────────────────────

_NON_PUBLIC_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")]
_NON_PUBLIC_V6 = [ipaddress.ip_network(n) for n in (
    "::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32", "2002::/16",
    "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8")]


def is_public_unicast_address(address: str) -> bool:
    """True for a public unicast IPv4 or IPv6 address (an IPv4-mapped one judged by its IPv4)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_public_unicast_address(str(ip.ipv4_mapped))
        return not any(ip in net for net in _NON_PUBLIC_V6)
    return not any(ip in net for net in _NON_PUBLIC_V4)


def _is_local_name(hostname: str) -> bool:
    name = hostname.lower().rstrip(".")
    return name == "localhost" or name.endswith(".localhost")


def _ip_literal(hostname: str) -> Optional[str]:
    bare = hostname[1:-1] if hostname.startswith("[") and hostname.endswith("]") else hostname
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        return None
    return bare


@dataclass
class SafeFetchResponse:
    ok: bool
    status: int
    url: str
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    def text(self) -> str:
        return self.body.decode("utf-8")


Lookup = Callable[[str], List[str]]
# (url, headers, pinned address or None, remaining seconds, max bytes) -> (status, headers, body)
Transport = Callable[[str, Mapping[str, str], Optional[str], float, int], Tuple[int, Dict[str, str], bytes]]


def default_lookup(hostname: str) -> List[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)})


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS to the pinned address, the certificate still checked against the URL's host name."""

    def __init__(self, hostname: str, port: int, address: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(hostname, port, timeout=timeout, context=context)
        self._pinned_address = address

    def connect(self) -> None:  # pragma: no cover - exercised against the network only
        sock = socket.create_connection((self._pinned_address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, port: int, address: str, timeout: float) -> None:
        super().__init__(hostname, port, timeout=timeout)
        self._pinned_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_address, self.port), self.timeout)


def node_transport(url: str, headers: Mapping[str, str], address: Optional[str], timeout: float, max_bytes: int) -> Tuple[int, Dict[str, str], bytes]:
    """One hop over ``http.client``, connected to the pinned address; never follows a redirect."""
    split = urlsplit(url)
    hostname = split.hostname or ""
    secure = split.scheme == "https"
    port = split.port or (443 if secure else 80)
    target = address or hostname
    if secure:
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(hostname, port, target, timeout, ssl.create_default_context())
    else:
        connection = _PinnedHTTPConnection(hostname, port, target, timeout)
    try:
        path = split.path or "/"
        if split.query:
            path += "?" + split.query
        connection.request("GET", path, headers=dict(headers))
        response = connection.getresponse()
        response_headers = {name.lower(): value for name, value in response.getheaders()}
        declared = response_headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > max_bytes:
            raise SafeFetchRefusedError("too_large", f"SafeFetch: declared content-length {declared} exceeds the cap of {max_bytes} bytes")
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise SafeFetchRefusedError("too_large", f"SafeFetch: response body exceeds the cap of {max_bytes} bytes")
        return response.status, response_headers, body
    finally:
        connection.close()


_REDIRECTS = {301, 302, 303, 307, 308}


def create_safe_fetch(
    lookup: Optional[Lookup] = None,
    transport: Optional[Transport] = None,
    development: bool = False,
    max_bytes: int = SAFE_FETCH_MAX_BYTES,
    timeout: float = SAFE_FETCH_TIMEOUT_SECONDS,
    max_redirects: int = SAFE_FETCH_MAX_REDIRECTS,
) -> Callable[..., SafeFetchResponse]:
    """A SafeFetch. ``development`` admits http and non-public addresses (local stacks only)."""
    do_lookup = lookup or default_lookup
    do_transport = transport or node_transport

    def admit_scheme(split: Any) -> None:
        if split.scheme == "https" or (split.scheme == "http" and development):
            return
        raise SafeFetchRefusedError("scheme_refused", f"SafeFetch: only https is allowed (got {split.scheme}://{split.netloc})")

    def pin(split: Any) -> Optional[str]:
        if split.username or split.password:
            raise SafeFetchRefusedError("host_refused", "SafeFetch: a URL with credentials is refused")
        hostname = split.hostname or ""
        literal = _ip_literal(hostname)
        if literal is not None:
            if not development and not is_public_unicast_address(literal):
                raise SafeFetchRefusedError("host_refused", f"SafeFetch: {literal} is not a public unicast address")
            return None
        if _is_local_name(hostname):
            if not development:
                raise SafeFetchRefusedError("host_refused", f"SafeFetch: {hostname} is a local host name")
            return "127.0.0.1"
        try:
            addresses = do_lookup(hostname)
        except Exception as err:  # noqa: BLE001
            raise SafeFetchRefusedError("unresolved", f"SafeFetch: {hostname} did not resolve: {err}") from err
        if not addresses:
            raise SafeFetchRefusedError("unresolved", f"SafeFetch: {hostname} resolved to no address")
        if not development and any(not is_public_unicast_address(a) for a in addresses):
            raise SafeFetchRefusedError("host_refused", f"SafeFetch: {hostname} resolves to a non-public address")
        return addresses[0]

    def safe_fetch(url: str, headers: Optional[Mapping[str, str]] = None) -> SafeFetchResponse:
        try:
            origin = urlsplit(url)
            if not origin.scheme or (origin.scheme in ("http", "https") and not origin.netloc):
                raise ValueError("no scheme or host")
        except ValueError as err:
            raise SafeFetchRefusedError("invalid_url", f"SafeFetch: not a URL: {url}") from err
        admit_scheme(origin)
        deadline = time.monotonic() + timeout
        request_headers = {"accept": "application/json", **(headers or {})}
        current = url
        hop = 0
        while True:
            split = urlsplit(current)
            address = pin(split)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SafeFetchRefusedError("deadline_exceeded", f"SafeFetch: read of {url} exceeded {timeout} s")
            try:
                status, response_headers, body = do_transport(current, request_headers, address, remaining, max_bytes)
            except SafeFetchRefusedError:
                raise
            except (socket.timeout, TimeoutError) as err:
                raise SafeFetchRefusedError("deadline_exceeded", f"SafeFetch: read of {url} exceeded {timeout} s") from err
            except Exception as err:  # noqa: BLE001
                raise SafeFetchRefusedError("unavailable", f"SafeFetch: {current} could not be read: {err}") from err
            if status in _REDIRECTS:
                location = response_headers.get("location")
                if location is None:
                    raise SafeFetchRefusedError("unavailable", f"SafeFetch: {status} from {current} without a Location header")
                if hop >= max_redirects:
                    raise SafeFetchRefusedError("too_many_redirects", f"SafeFetch: more than {max_redirects} redirects from {url}")
                target = urlsplit(urljoin(current, location))
                if not target.netloc:
                    raise SafeFetchRefusedError("invalid_url", f"SafeFetch: redirect from {current} to a malformed location")
                if target.scheme != "https" and not (development and target.scheme == "http"):
                    raise SafeFetchRefusedError("scheme_refused", f"SafeFetch: redirect from {current} to a non-https target refused")
                if (target.scheme, target.netloc.lower()) != (origin.scheme, origin.netloc.lower()):
                    raise SafeFetchRefusedError("cross_origin_redirect", f"SafeFetch: cross-origin redirect from {origin.scheme}://{origin.netloc} refused")
                current = target.geturl()
                hop += 1
                continue
            return SafeFetchResponse(ok=200 <= status < 300, status=status, url=current, body=body)

    return safe_fetch


_default_safe_fetch: Optional[Callable[..., SafeFetchResponse]] = None


def default_outbound_fetch() -> Callable[..., SafeFetchResponse]:
    """The SDK's SafeFetch: strict unless ``HELIX_OUTBOUND_DEVELOPMENT=1`` (local stacks)."""
    global _default_safe_fetch
    if _default_safe_fetch is None:
        _default_safe_fetch = create_safe_fetch(development=os.environ.get("HELIX_OUTBOUND_DEVELOPMENT") == "1")
    return _default_safe_fetch


def _fetch_json_through_safe_fetch(url: str) -> Any:
    response = default_outbound_fetch()(url)
    if not response.ok:
        raise EntityCardError("unavailable", f"{url} answered HTTP {response.status}")
    return response.json()


# ── Resolution ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ResolvedEntityCard:
    did: str
    card: Dict[str, Any]
    card_url: str
    did_document: Optional[Dict[str, Any]] = None


def _read_json(url: str, fetch_json: Optional[FetchJson], what: str) -> Any:
    try:
        return (fetch_json or _fetch_json_through_safe_fetch)(url)
    except EntityCardError as err:
        if err.reason == "unavailable":
            raise EntityCardError(f"{what}_unavailable", f"{what} at {url} could not be read: {err}") from err
        raise
    except Exception as err:  # noqa: BLE001
        raise EntityCardError(f"{what}_unavailable", f"{what} at {url} could not be read: {err}") from err


def fetch_entity_card(url: str, fetch_json: Optional[FetchJson] = None, expected_did: Optional[str] = None) -> ResolvedEntityCard:
    """``card.json`` at ``url``, parsed and, when ``expected_did`` is known, bound to it."""
    card = parse_entity_card(_read_json(url, fetch_json, "card"))
    if expected_did is not None and not same_did(card["id"], expected_did):
        raise EntityCardError("card_mismatch", f"card at {url} is for {card['id']}, not {expected_did}")
    return ResolvedEntityCard(did=card["id"], card=card, card_url=url)


def resolve_entity_card(did: str, fetch_json: Optional[FetchJson] = None) -> ResolvedEntityCard:
    """Two-step resolution of a did:web: ``did.json`` → ``KyaOsEntityCard`` service → ``card.json``.
    ``fetch_json(url)`` replaces the SDK's SafeFetch (tests, local stacks)."""
    if not isinstance(did, str):
        raise EntityCardError("malformed_did", "did must be a string")
    if did.startswith("did:key:"):
        raise EntityCardError("did_key_not_resolvable", f"{did} has no web home: a did:key card is supplied directly, never discovered")
    parsed = parse_did_web(did)
    if parsed is None:
        raise EntityCardError("malformed_did", f"{did} is not a did:web DID that names a URL")
    document_url = did_web_document_url(did)
    document = _read_json(document_url, fetch_json, "did_document")
    served_id = document.get("id") if isinstance(document, Mapping) else None
    if not isinstance(served_id, str) or not same_did(served_id, did):
        raise EntityCardError("did_document_mismatch", f"DID document at {document_url} is not for {did}")
    endpoint = card_endpoint_of(document) or (did_web_card_url(did) if not parsed[1] else None)
    if endpoint is None:
        raise EntityCardError("no_card_service", f"DID document for {did} has no KyaOsEntityCard service entry")
    resolved = fetch_entity_card(endpoint, fetch_json, expected_did=did)
    return ResolvedEntityCard(did=did, card=resolved.card, card_url=endpoint, did_document=dict(document))


def resolve_entity_card_from_server_meta(server_meta: Any, did: Optional[str] = None, fetch_json: Optional[FetchJson] = None) -> ResolvedEntityCard:
    """A card from an MCP ``server.json`` ``_meta`` projection: a ``cardRef`` is fetched; an inline did:web summary
    is an index, so the canonical card is fetched and bound to its id; an inline did:key summary is parsed in place;
    a stripped projection falls back to the two-step resolution of ``did``."""
    entry = server_meta.get(KYA_OS_CARD_META_KEY) if isinstance(server_meta, Mapping) else None
    if entry is None:
        if did is not None:
            return resolve_entity_card(did, fetch_json)
        raise EntityCardError("no_projection", f"server metadata carries no {KYA_OS_CARD_META_KEY} and no DID is known")
    record = entry if isinstance(entry, Mapping) else {}
    ref = record.get(KYA_OS_CARD_REF_KEY)
    if isinstance(ref, str):
        expected = record["id"] if isinstance(record.get("id"), str) else did
        return fetch_entity_card(ref, fetch_json, expected_did=expected)
    identifier = record.get("id")
    if not isinstance(identifier, str):
        raise EntityCardError("no_projection", f"{KYA_OS_CARD_META_KEY} summary has no id and no cardRef")
    if identifier.startswith("did:web:"):
        return fetch_entity_card(did_web_card_url(identifier), fetch_json, expected_did=identifier)
    summary = {k: v for k, v in record.items() if k != KYA_OS_CARD_REF_KEY}
    card = parse_entity_card(summary)
    return ResolvedEntityCard(did=card["id"], card=card, card_url="")
