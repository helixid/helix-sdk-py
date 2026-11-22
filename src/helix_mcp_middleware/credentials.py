"""Finds the caller's credential, ported from helix-sdk-js's
mcp-middleware/src/credentials.ts: a KYA-OS request proof (with the chain the
request carries) in ``_meta``, or an OAuth bearer token. Story F-2 retired the
Helix VP (``Authorization: HelixVP``, ``X-Helix-VP``, ``_meta["x-helix-vp"]``)
with no backward compatibility: those are no longer read."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Literal, Mapping, Optional, Sequence, Union

from helix_sdk.verifier import read_carried_chain, read_request_proof

from .errors import CREDENTIAL_CONFLICT, MCPAuthError

TrustedIssuers = Union[Literal["*"], Sequence[str]]
"""KYA-OS story C-B: which issuers' capability attestations a verifier counts.
``"*"`` trusts every issuer; a list trusts exactly those DIDs. Shipped as
allow-all (stories rule 9); the setting stays so a service can set a list.
See :func:`helix_mcp_middleware.trusted_issuers.is_trusted_issuer`."""

DEFAULT_TRUSTED_ISSUERS: TrustedIssuers = "*"

_AUTH = re.compile(r"^(\S+)\s+(\S+)$")


@dataclass(frozen=True)
class ExtractedCredential:
    kind: str
    """'proof' (a KYA-OS request proof, with the carried chain) or 'oauth' (a bearer token)."""
    token: Optional[str] = None
    """The bearer token, for 'oauth'."""
    proof: Any = None
    """The request proof as carried, for 'proof'."""
    chain: Any = None
    """The carried delegation chain, when the request has one."""


def _header_values(headers: Any, name: str) -> List[str]:
    """All values of a header, case-insensitively; empty values are dropped.
    Accepts a plain mapping (values may be lists), or a multi-value headers
    object with getlist() (Starlette, Werkzeug) or get_all() (http.client)."""
    if not headers:
        return []
    out: List[Any] = []
    getter = getattr(headers, "getlist", None) or getattr(headers, "get_all", None)
    if callable(getter):
        out.extend(getter(name) or [])
    elif isinstance(headers, Mapping):
        for key, value in headers.items():
            if not isinstance(key, str) or key.lower() != name or value is None:
                continue
            out.extend(value if isinstance(value, (list, tuple)) else [value])
    return [v.strip() for v in out if isinstance(v, str) and v.strip()]


def meta_mapping(meta: Any) -> Mapping[str, Any]:
    """`_meta` as a mapping. Accepts a dict or the MCP Python SDK's own
    RequestParams.Meta object (what a tool handler holds); anything else,
    including a string or list a client might send, is treated as absent."""
    if isinstance(meta, Mapping):
        return meta
    dump = getattr(meta, "model_dump", None)
    if callable(dump):
        dumped = dump(by_alias=True)
        return dumped if isinstance(dumped, Mapping) else {}
    return {}


def extract_credential(headers: Any = None, meta: Any = None) -> Optional[ExtractedCredential]:
    """The request proof at ``_meta["org.kya-os/request-proof"]`` (or the
    legacy ``org.kya-os/proof@1`` key, the canonical one winning when both are
    present), with the carried chain at ``_meta["org.kya-os/delegation-chain"]``;
    or ``Authorization: Bearer <token>`` for OAuth. Tool arguments are never read.

    Ambiguity is rejected, never resolved by picking one: two Authorization
    headers, or a proof together with a bearer token, raise CREDENTIAL_CONFLICT."""
    bearer: Optional[str] = None
    authorization = _header_values(headers, "authorization")
    if len(authorization) > 1:
        raise MCPAuthError(CREDENTIAL_CONFLICT, "Multiple Authorization headers were provided")
    if authorization:
        match = _AUTH.match(authorization[0])
        if not match:
            raise MCPAuthError(CREDENTIAL_CONFLICT, "Malformed Authorization header")
        if match.group(1).lower() == "bearer":
            bearer = match.group(2)
        # Any other scheme is not ours; treated as no credential.

    fields = meta_mapping(meta)
    proof = read_request_proof(fields)
    if proof is not None and bearer is not None:
        raise MCPAuthError(
            CREDENTIAL_CONFLICT, "Both a KYA-OS request proof and an OAuth bearer token were provided; send exactly one"
        )
    if proof is not None:
        return ExtractedCredential("proof", proof=proof, chain=read_carried_chain(fields))
    if bearer is not None:
        return ExtractedCredential("oauth", token=bearer)
    return None
