# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""RFC 9728 protected resource metadata and HTTP auth responses, ported from
helix-sdk-js's mcp-middleware/src/metadata.ts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from . import errors as _errors


def protected_resource_metadata_url(resource: str) -> str:
    """Where RFC 9728 section 3.1 says the metadata lives:
    `/.well-known/oauth-protected-resource` inserted between the host and the
    resource's path."""
    url = urlsplit(resource)
    path = "" if url.path in ("", "/") else url.path
    return f"{url.scheme}://{url.netloc}/.well-known/oauth-protected-resource{path}"


def build_protected_resource_metadata(
    resource: str,
    authorization_servers: Optional[Sequence[str]] = None,
    scopes_supported: Optional[Sequence[str]] = None,
    resource_name: Optional[str] = None,
    resource_documentation: Optional[str] = None,
) -> Dict[str, Any]:
    """The JSON body to serve at protected_resource_metadata_url(resource)."""
    metadata: Dict[str, Any] = {"resource": resource}
    if authorization_servers:
        metadata["authorization_servers"] = list(authorization_servers)
    if scopes_supported:
        metadata["scopes_supported"] = list(scopes_supported)
    metadata["bearer_methods_supported"] = ["header"]
    if resource_name:
        metadata["resource_name"] = resource_name
    if resource_documentation:
        metadata["resource_documentation"] = resource_documentation
    return metadata


@dataclass
class HttpErrorResponse:
    status: int
    headers: Dict[str, str]
    """{'WWW-Authenticate': ...}"""
    body: Dict[str, str]
    """{'error': ..., 'error_description': ...}"""


# Only errors that describe the *caller's* credentials map to HTTP auth
# responses. Anything else (the middleware's own API key being rejected, the
# authorization server being down) is a server fault and must not be reported
# to the caller as a 401.
_MAPPED: Dict[str, Tuple[int, str]] = {
    "VP_MISSING": (401, ""),
    "VP_INVALID_STRUCTURE": (401, "invalid_token"),
    "VP_VERIFICATION_FAILED": (401, "invalid_token"),
    _errors.OAUTH_TOKEN_INVALID: (401, "invalid_token"),
    _errors.CREDENTIAL_CONFLICT: (400, "invalid_request"),
    "INSUFFICIENT_SCOPE": (403, "insufficient_scope"),
    _errors.TOOL_NOT_PERMITTED: (403, "insufficient_scope"),
}

# RFC 6750 section 3: error_description and scope are limited to %x20-21 / %x23-5B / %x5D-7E.
_NOT_ALLOWED = re.compile(r"[^\x20-\x21\x23-\x5B\x5D-\x7E]")


def _challenge(scheme: str, params: List[Tuple[str, str]]) -> str:
    return f"{scheme} " + ", ".join(f'{k}="{_NOT_ALLOWED.sub(" ", v)}"' for k, v in params)


def to_http_error_response(error: Any, resource_metadata_url: str) -> Optional[HttpErrorResponse]:
    """Turns an error raised by the middleware into an HTTP auth response: 401
    with `WWW-Authenticate` challenges for both `Bearer` and `HelixVP` (each
    pointing at the RFC 9728 metadata), 400 for ambiguous credentials, 403
    for scope failures. Returns None for errors that are not the caller's
    fault, so the host can answer 5xx."""
    code = getattr(error, "code", None)
    mapped = _MAPPED.get(code) if isinstance(code, str) else None
    if mapped is None:
        return None
    status, name = mapped
    message = str(error) if isinstance(error, Exception) and str(error) else "Unauthorized"
    required = getattr(error, "required_scopes", None)
    if not isinstance(required, (list, tuple)):
        single = getattr(error, "required_scope", None)
        required = [single] if isinstance(single, str) else []
    required = [s for s in required if isinstance(s, str)]
    params: List[Tuple[str, str]] = []
    if name:
        params += [("error", name), ("error_description", message)]
    # RFC 6750 section 3: the scopes the resource requires, so a client can ask its
    # authorization server for them and retry once. Only when the error names them.
    if name == "insufficient_scope" and required:
        params.append(("scope", " ".join(required)))
    params.append(("resource_metadata", resource_metadata_url))
    return HttpErrorResponse(
        status=status,
        headers={"WWW-Authenticate": f"{_challenge('Bearer', params)}, {_challenge('HelixVP', params)}"},
        body={"error": name or "unauthorized", "error_description": message},
    )
