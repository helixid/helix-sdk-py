# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The client side of KYA-OS discovery (story L1-D; Core L1.10), the Python twin
of helix-sdk-js's ``kyaos.fetchWellKnownMcp`` / ``readWellKnownMcp``: a server
SHOULD serve ``/.well-known/mcp`` at its origin, and an agent reads its DID,
its skew window and its capabilities from there on first contact.

``fetch_well_known_mcp(origin)`` gets and checks the document;
``read_well_known_mcp(value)`` checks one already in hand. The checks mirror the
``well-known-mcpi.json`` schema (required members, patterns, the skew range),
and ``clockSkewSeconds`` comes back with the schema's default when the server
left it out, so a client can hand it straight to ``verify_response_proof`` and
to its own handshake timing:

    from helix_sdk import kyaos
    document = kyaos.fetch_well_known_mcp("https://mcp.example.com")
    request = kyaos.create_handshake_request(audience=document["serverDid"])
    kyaos.verify_response_proof(result, document["serverDid"], resolve_did, request=sent,
                                skew_seconds=document["clockSkewSeconds"])

The document keeps its own (camelCase) member names.
"""

from __future__ import annotations

import math
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import SplitResult, urljoin, urlsplit

from .handshake import DEFAULT_CLOCK_SKEW_SECONDS, MAX_CLOCK_SKEW_SECONDS, MIN_CLOCK_SKEW_SECONDS

WELL_KNOWN_MCP_PATH = "/.well-known/mcp"
WELL_KNOWN_MCP_INVALID = "WELL_KNOWN_MCP_INVALID"

_VERSION = re.compile(r"\d+\.\d+(\.\d+)?", re.ASCII)
_SERVER_DID = re.compile(r"did:(key|web):.+")
_SCHEME = re.compile(r"[a-z][a-z0-9+\-.]*", re.IGNORECASE | re.ASCII)
_FLAGS = ("proofs", "delegation", "statusList", "crisp")


class WellKnownMcpProblems:
    """Why a discovery document cannot be used (``WellKnownMcpError.reason``), the JS SDK's ``WellKnownMcpProblem``."""

    DOCUMENT_NOT_OBJECT = "document_not_object"
    VERSION_INVALID = "version_invalid"
    SERVER_DID_INVALID = "server_did_invalid"
    ENDPOINTS_INVALID = "endpoints_invalid"
    CLOCK_SKEW_INVALID = "clock_skew_invalid"
    CAPABILITIES_INVALID = "capabilities_invalid"
    STATUS_LIST_CREDENTIAL_INVALID = "status_list_credential_invalid"
    ADVISORY_LIST_INVALID = "advisory_list_invalid"
    FETCH_FAILED = "fetch_failed"
    NOT_JSON = "not_json"


class WellKnownMcpError(ValueError):
    """A discovery document that cannot be used; ``reason`` names what was wrong (``code`` ``WELL_KNOWN_MCP_INVALID``)."""

    code = WELL_KNOWN_MCP_INVALID

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(message)


def _refuse(reason: str, message: str) -> Any:
    raise WellKnownMcpError(reason, message)


def _origin(url: SplitResult) -> str:
    """WHATWG ``URL.origin``: scheme, lower-cased host, the port unless it is the scheme's default."""
    host = url.hostname or ""
    host = f"[{host}]" if ":" in host else host
    port = url.port
    default = {"https": 443, "http": 80}.get(url.scheme)
    return f"{url.scheme}://{host}" + ("" if port is None or port == default else f":{port}")


def _absolute(value: str) -> SplitResult:
    url = urlsplit(value)
    url.port  # noqa: B018 - raises on a bad port
    if not url.scheme or not url.netloc:
        raise ValueError(f"not an absolute URL: {value}")
    return url


def well_known_mcp_url(origin: str) -> str:
    """Where the document lives for a server at ``origin`` (a URL whose origin is used; any path is dropped)."""
    return f"{_origin(_absolute(origin))}{WELL_KNOWN_MCP_PATH}"


def _resolve(name: str, value: Any, origin: Optional[str]) -> str:
    if not isinstance(value, str):
        return _refuse(WellKnownMcpProblems.ENDPOINTS_INVALID, f"endpoints.{name} must be a string")
    if origin is None:
        return value
    try:
        urlsplit(value).port  # noqa: B018 - a malformed authority ("http://[bad") is refused here
        return urljoin(origin, value)
    except ValueError:
        return _refuse(WellKnownMcpProblems.ENDPOINTS_INVALID, f"endpoints.{name} is not a URI reference: {value}")


def _string_list(name: str, value: Any) -> Optional[List[str]]:
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return _refuse(WellKnownMcpProblems.ADVISORY_LIST_INVALID, f"{name} must be a list of strings")
    return value


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def read_well_known_mcp(value: Any, origin: Optional[str] = None) -> Dict[str, Any]:
    """Checks a discovery document the way ``well-known-mcpi.json`` describes it and returns it with
    ``clockSkewSeconds`` filled in and endpoints resolved against ``origin`` (the URL it was read from).
    Members the schema does not name are kept as they are."""
    if not isinstance(value, dict):
        return _refuse(WellKnownMcpProblems.DOCUMENT_NOT_OBJECT, "the discovery document must be a JSON object")
    base = f"{_origin(_absolute(origin))}/" if origin is not None else None

    version = value.get("version")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        return _refuse(WellKnownMcpProblems.VERSION_INVALID, "version must look like 1.0 or 1.0.0")
    server_did = value.get("serverDid")
    if not isinstance(server_did, str) or not _SERVER_DID.fullmatch(server_did):
        return _refuse(WellKnownMcpProblems.SERVER_DID_INVALID, "serverDid must be a did:web or did:key")

    raw_endpoints = value.get("endpoints")
    if not isinstance(raw_endpoints, dict):
        return _refuse(WellKnownMcpProblems.ENDPOINTS_INVALID, "endpoints must be an object")
    endpoints = {name: _resolve(name, reference, base) for name, reference in raw_endpoints.items()}

    skew = value.get("clockSkewSeconds")
    if skew is not None and (not _is_number(skew) or not MIN_CLOCK_SKEW_SECONDS <= skew <= MAX_CLOCK_SKEW_SECONDS):
        return _refuse(
            WellKnownMcpProblems.CLOCK_SKEW_INVALID,
            f"clockSkewSeconds must be a number from {MIN_CLOCK_SKEW_SECONDS} to {MAX_CLOCK_SKEW_SECONDS}",
        )

    capabilities = value.get("capabilities", {})
    if not isinstance(capabilities, dict):
        return _refuse(WellKnownMcpProblems.CAPABILITIES_INVALID, "capabilities must be an object")
    for flag in _FLAGS:
        if flag in capabilities and not isinstance(capabilities[flag], bool):
            return _refuse(WellKnownMcpProblems.CAPABILITIES_INVALID, f"capabilities.{flag} must be a boolean")

    status_list = value.get("statusListCredential")
    if status_list is not None:
        if not isinstance(status_list, str):
            return _refuse(WellKnownMcpProblems.STATUS_LIST_CREDENTIAL_INVALID, "statusListCredential must be a URL")
        scheme, colon, _rest = status_list.partition(":")
        if not colon or not _SCHEME.fullmatch(scheme):
            return _refuse(WellKnownMcpProblems.STATUS_LIST_CREDENTIAL_INVALID, f"statusListCredential is not an absolute URL: {status_list}")
    supported_did_methods = _string_list("supportedDidMethods", value.get("supportedDidMethods"))
    proof_algorithms = _string_list("proofAlgorithms", value.get("proofAlgorithms"))

    read: Dict[str, Any] = {
        **value,
        "version": version,
        "serverDid": server_did,
        "endpoints": endpoints,
        "clockSkewSeconds": skew if skew is not None else DEFAULT_CLOCK_SKEW_SECONDS,
        "capabilities": capabilities,
    }
    if supported_did_methods is not None:
        read["supportedDidMethods"] = supported_did_methods
    if proof_algorithms is not None:
        read["proofAlgorithms"] = proof_algorithms
    return read


Get = Callable[..., Any]
"""``requests.get``-shaped: ``get(url, headers=…, timeout=…)`` returning a response with ``status_code`` and ``json()``."""


def fetch_well_known_mcp(origin: str, get: Optional[Get] = None, timeout: float = 5.0) -> Dict[str, Any]:
    """GETs ``<origin>/.well-known/mcp`` and reads it. A non-200 answer or a non-JSON body is a ``WellKnownMcpError``."""
    url = well_known_mcp_url(origin)
    if get is None:
        import requests

        get = requests.get
    try:
        response = get(url, headers={"accept": "application/json"}, timeout=timeout)
    except Exception as error:  # noqa: BLE001 - any transport failure is "could not fetch"
        return _refuse(WellKnownMcpProblems.FETCH_FAILED, f"GET {url} failed: {error}")
    if response.status_code != 200:
        return _refuse(WellKnownMcpProblems.FETCH_FAILED, f"GET {url} answered {response.status_code}")
    try:
        body = response.json()
    except ValueError:
        return _refuse(WellKnownMcpProblems.NOT_JSON, f"GET {url} did not answer with JSON")
    return read_well_known_mcp(body, origin=url)
