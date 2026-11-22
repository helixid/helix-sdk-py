# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The KYA-OS discovery document at ``/.well-known/mcp`` (story L1-D; Core L1.10,
RECOMMENDED), the Python twin of helix-sdk-js's ``mcp-middleware/src/well-known.ts``.
The service hosts it, not the agent: one document per MCP server, built once
from config, validated against the vendored ``well-known-mcpi.json`` schema at
startup and served as is.

Every URL in the document is external: it is built from ``public_origin``, the
origin agents connect to, never from the address the process binds (behind a
proxy the two differ). If MCP lives on ``mcp.example.com`` the document belongs
on that host. helix-sdk-js's ``mcp-middleware/docs/well-known.md`` has the
routing snippets for nginx, an ALB and API Gateway; they apply unchanged.

The document is the same, byte for byte, as the one the JS middleware serves
for the same configuration (members in the same order, serialised like
``JSON.stringify``). Validation is draft 2020-12 through ``jsonschema`` with the
``uri``, ``uri-reference`` and ``email`` formats checked by the regular
expressions ajv-formats uses, and ``pattern`` read with ECMA-262 anchors, so
both languages accept and refuse the same documents with the same problem
messages (``/version must match pattern "..."``).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any, Awaitable, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import SplitResult, urljoin, urlsplit

WELL_KNOWN_MCP_PATH = "/.well-known/mcp"
DEFAULT_WELL_KNOWN_VERSION = "1.0"
"""The protocol version the document advertises by default (the reference implementation's handshake says "1.0")."""
DEFAULT_SUPPORTED_DID_METHODS: Tuple[str, ...] = ("did:web", "did:key")
"""What the Helix verifier resolves: did:web and did:key (L1-A, C-A)."""
DEFAULT_PROOF_ALGORITHMS: Tuple[str, ...] = ("EdDSA",)
"""What the Helix verifier checks: EdDSA over Ed25519 (L1-C)."""
WELL_KNOWN_MCP_INVALID = "WELL_KNOWN_MCP_INVALID"

_CLOCK_SKEW_DEFAULT, _CLOCK_SKEW_MIN, _CLOCK_SKEW_MAX = 120, 30, 600
_SERVER_DID = re.compile(r"did:(key|web):.+")
_NOT_FOUND = b'{"error":"not_found"}'

Send = Callable[[Dict[str, Any]], Awaitable[None]]


class WellKnownMcpError(ValueError):
    """A configuration whose ``/.well-known/mcp`` document would not validate (``code`` ``WELL_KNOWN_MCP_INVALID``)."""

    code = WELL_KNOWN_MCP_INVALID

    def __init__(self, message: str, problems: Sequence[str] = ()) -> None:
        self.problems: Tuple[str, ...] = tuple(problems)
        super().__init__(f"{message}: {'; '.join(self.problems)}" if self.problems else message)


@dataclass(frozen=True)
class WellKnownMcpValidation:
    ok: bool
    problems: Tuple[str, ...] = ()
    """The schema's complaints, ajv style: ``<instance path> <message>``."""


# -- the schema and its validator ---------------------------------------------------------------

# ajv-formats 3.0.1 ("full" mode), extracted from its dist/formats.js: the same strings the JS middleware checks with.
_URI_SOURCE = "(?:[a-z][a-z0-9+\\-.]*:)(?:\\/?\\/(?:(?:[a-z0-9\\-._~!$&'()*+,;=:]|%[0-9a-f]{2})*@)?(?:\\[(?:(?:(?:(?:[0-9a-f]{1,4}:){6}|::(?:[0-9a-f]{1,4}:){5}|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}|(?:(?:[0-9a-f]{1,4}:){0,1}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}|(?:(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}|(?:(?:[0-9a-f]{1,4}:){0,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:|(?:(?:[0-9a-f]{1,4}:){0,4}[0-9a-f]{1,4})?::)(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?))|(?:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::)|[Vv][0-9a-f]+\\.[a-z0-9\\-._~!$&'()*+,;=:]+)\\]|(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)|(?:[a-z0-9\\-._~!$&'()*+,;=]|%[0-9a-f]{2})*)(?::\\d*)?(?:\\/(?:[a-z0-9\\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*|\\/(?:(?:[a-z0-9\\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:\\/(?:[a-z0-9\\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)?|(?:[a-z0-9\\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:\\/(?:[a-z0-9\\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)(?:\\?(?:[a-z0-9\\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?(?:#(?:[a-z0-9\\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?"  # noqa: E501
_URI_REFERENCE_SOURCE = '(?:[a-z][a-z0-9+\\-.]*:)?(?:\\/?\\/(?:(?:[a-z0-9\\-._~!$&\'()*+,;=:]|%[0-9a-f]{2})*@)?(?:\\[(?:(?:(?:(?:[0-9a-f]{1,4}:){6}|::(?:[0-9a-f]{1,4}:){5}|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}|(?:(?:[0-9a-f]{1,4}:){0,1}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}|(?:(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}|(?:(?:[0-9a-f]{1,4}:){0,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:|(?:(?:[0-9a-f]{1,4}:){0,4}[0-9a-f]{1,4})?::)(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?))|(?:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::)|[Vv][0-9a-f]+\\.[a-z0-9\\-._~!$&\'()*+,;=:]+)\\]|(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)|(?:[a-z0-9\\-._~!$&\'"()*+,;=]|%[0-9a-f]{2})*)(?::\\d*)?(?:\\/(?:[a-z0-9\\-._~!$&\'"()*+,;=:@]|%[0-9a-f]{2})*)*|\\/(?:(?:[a-z0-9\\-._~!$&\'"()*+,;=:@]|%[0-9a-f]{2})+(?:\\/(?:[a-z0-9\\-._~!$&\'"()*+,;=:@]|%[0-9a-f]{2})*)*)?|(?:[a-z0-9\\-._~!$&\'"()*+,;=:@]|%[0-9a-f]{2})+(?:\\/(?:[a-z0-9\\-._~!$&\'"()*+,;=:@]|%[0-9a-f]{2})*)*)?(?:\\?(?:[a-z0-9\\-._~!$&\'"()*+,;=:@/?]|%[0-9a-f]{2})*)?(?:#(?:[a-z0-9\\-._~!$&\'"()*+,;=:@/?]|%[0-9a-f]{2})*)?'  # noqa: E501
_EMAIL_SOURCE = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"  # noqa: E501


def _flags() -> int:
    # JS /i without the u flag: ASCII case folding, \d is [0-9].
    return re.IGNORECASE | re.ASCII


_URI = re.compile(_URI_SOURCE, _flags())
_URI_REFERENCE = re.compile(_URI_REFERENCE_SOURCE, _flags())
_EMAIL = re.compile(_EMAIL_SOURCE, _flags())
_NOT_URI_FRAGMENT = re.compile(r"/|:")


def _is_uri(value: str) -> bool:
    return bool(_NOT_URI_FRAGMENT.search(value)) and _URI.fullmatch(value) is not None


def _is_uri_reference(value: str) -> bool:
    return _URI_REFERENCE.fullmatch(value) is not None


def _is_email(value: str) -> bool:
    return _EMAIL.fullmatch(value) is not None


_FORMATS: Dict[str, Callable[[str], bool]] = {"uri": _is_uri, "uri-reference": _is_uri_reference, "email": _is_email}


def _ecma_pattern(pattern: str) -> "re.Pattern[str]":
    """A schema ``pattern`` read the ECMA-262 way: ``$`` is the end of the input (Python's also matches
    before a final newline), ``\\d`` is ASCII."""
    if pattern.endswith("$") and not pattern.endswith("\\$"):
        pattern = pattern[:-1] + r"\Z"
    return re.compile(pattern, re.ASCII)


def _schema_text() -> str:
    return resources.files("helix_mcp_middleware").joinpath("schemas/well-known-mcpi.json").read_text("utf-8")


@lru_cache(maxsize=1)
def _validator() -> Any:
    try:
        from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators
    except ImportError as error:  # pragma: no cover - installed with every extra that ships the middleware
        raise ImportError(
            "helix_mcp_middleware's /.well-known/mcp validation needs jsonschema: pip install 'helixid-sdk-py[mcp-middleware]'"
        ) from error

    checker = FormatChecker(formats=())
    for name, check in _FORMATS.items():
        checker.checks(name)(lambda value, check=check: not isinstance(value, str) or check(value))

    def pattern(validator: Any, value: str, instance: Any, schema: Any) -> Iterator[Any]:
        if validator.is_type(instance, "string") and not _ecma_pattern(value).search(instance):
            yield ValidationError(f"{instance!r} does not match {value!r}")

    cls = validators.extend(Draft202012Validator, {"pattern": pattern})
    return cls(json.loads(_schema_text()), format_checker=checker)


def _pointer(path: Sequence[Any]) -> str:
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in path)


def _ajv_message(error: Any) -> str:
    """The message ajv gives for the same failure, so the two languages report alike."""
    kind, value = error.validator, error.validator_value
    if kind == "required":
        missing = re.search(r"'(.*)' is a required property", error.message)
        return f"must have required property '{missing.group(1) if missing else value}'"
    if kind == "pattern":
        return f'must match pattern "{value}"'
    if kind == "format":
        return f'must match format "{value}"'
    if kind == "minimum":
        return f"must be >= {value}"
    if kind == "maximum":
        return f"must be <= {value}"
    if kind == "type":
        return "must be " + (",".join(value) if isinstance(value, list) else str(value))
    if kind == "const":
        return "must be equal to constant"
    if kind == "enum":
        return "must be equal to one of the allowed values"
    if kind == "additionalProperties":
        return "must NOT have additional properties"
    return str(error.message)


def validate_well_known_mcp(document: Any) -> WellKnownMcpValidation:
    """Validates any value against the vendored ``well-known-mcpi.json`` schema (story L1-D point 1)."""
    errors = list(_validator().iter_errors(document))
    if not errors:
        return WellKnownMcpValidation(ok=True)
    return WellKnownMcpValidation(ok=False, problems=tuple(f"{_pointer(e.absolute_path) or '/'} {_ajv_message(e)}" for e in errors))


def assert_well_known_mcp(document: Any) -> None:
    """``validate_well_known_mcp``, raising ``WellKnownMcpError`` instead."""
    result = validate_well_known_mcp(document)
    if not result.ok:
        raise WellKnownMcpError("the /.well-known/mcp document does not validate against well-known-mcpi.json", result.problems)


# -- building the document ----------------------------------------------------------------------


@dataclass
class WellKnownMcpConfig:
    enabled: bool = True
    """Default True. When False the route answers 404 and nothing is built or validated."""
    public_origin: Optional[str] = None
    """The origin agents connect to (``https://mcp.example.com``). Required while enabled; never the bind address."""
    server_did: Optional[str] = None
    """This server's DID (``did:web:…`` or ``did:key:…``). Required while enabled."""
    version: Optional[str] = None
    """Default ``DEFAULT_WELL_KNOWN_VERSION``."""
    tools_endpoint: Optional[str] = None
    """The MCP endpoint: a path at ``public_origin`` (default ``/mcp``) or an absolute URL whose origin is ``public_origin``."""
    kyaos: Optional[Mapping[str, Any]] = None
    """The KYA-OS layer's description (``describe_kyaos()`` or ``runtime.describe()``): proofs, the handshake and
    the skew. Without it there are no proofs and no handshake."""
    clock_skew_seconds: Optional[int] = None
    """Default 120; 30 to 600. With ``kyaos`` it must equal the runtime's skew (the handshake enforces that one)."""
    status_list_credential: Optional[str] = None
    """URL of this server's status list credential."""
    capabilities: Optional[Mapping[str, bool]] = None
    """``{"delegation": …, "statusList": …, "crisp": …}``, in the document's own names; each true only while that
    feature is enabled, default false. ``proofs`` comes from ``kyaos``."""
    supported_did_methods: Optional[Sequence[str]] = None
    """Default ``DEFAULT_SUPPORTED_DID_METHODS``."""
    proof_algorithms: Optional[Sequence[str]] = None
    """Default ``DEFAULT_PROOF_ALGORITHMS``."""


def _origin(url: SplitResult) -> str:
    """WHATWG ``URL.origin``: scheme, lower-cased host, the port unless it is the scheme's default."""
    host = url.hostname or ""
    host = f"[{host}]" if ":" in host else host
    port = url.port
    default = {"https": 443, "http": 80}.get(url.scheme)
    return f"{url.scheme}://{host}" + ("" if port is None or port == default else f":{port}")


def _href(url: SplitResult) -> str:
    """WHATWG ``URL.href`` for an http(s) URL: the origin, the path (``/`` when empty), the query and fragment."""
    query = f"?{url.query}" if url.query else ""
    fragment = f"#{url.fragment}" if url.fragment else ""
    return f"{_origin(url)}{url.path or '/'}{query}{fragment}"


def _split(value: str) -> Optional[SplitResult]:
    try:
        url = urlsplit(value)
        url.port  # noqa: B018 - raises on a bad port
    except ValueError:
        return None
    return url


def _origin_of(value: Optional[str], name: str) -> str:
    if not value:
        raise WellKnownMcpError(f"{name} is required for the /.well-known/mcp document (the origin agents connect to, e.g. https://mcp.example.com)")
    url = _split(value)
    if url is None or not url.scheme or not url.netloc:
        raise WellKnownMcpError(f"{name} must be an absolute URL, got {json.dumps(value)}")
    if url.scheme not in ("http", "https"):
        raise WellKnownMcpError(f"{name} must be http(s), got {json.dumps(value)}")
    if url.path not in ("", "/") or url.query or url.fragment:
        raise WellKnownMcpError(f"{name} must be an origin with no path, query or fragment, got {json.dumps(value)}; put the MCP path in tools_endpoint")
    return _origin(url)


def _tools_url(public_origin: str, endpoint: Optional[str]) -> str:
    reference = endpoint if endpoint is not None else "/mcp"
    joined = _split(urljoin(public_origin + "/", reference)) if _split(reference) is not None else None
    if joined is None or not joined.netloc:
        raise WellKnownMcpError(f"tools_endpoint must be a path or an absolute URL, got {json.dumps(reference)}")
    if _origin(joined) != public_origin:
        raise WellKnownMcpError(
            f"tools_endpoint {json.dumps(reference)} is not at public_origin {public_origin}: the document carries the URLs agents connect to"
        )
    return _href(joined)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _skew_of(config: WellKnownMcpConfig) -> int:
    configured = config.clock_skew_seconds
    runtime = config.kyaos.get("clockSkewSeconds") if config.kyaos is not None else None
    if configured is not None and (not _is_int(configured) or not _CLOCK_SKEW_MIN <= configured <= _CLOCK_SKEW_MAX):
        raise WellKnownMcpError(f"clock_skew_seconds must be an integer from {_CLOCK_SKEW_MIN} to {_CLOCK_SKEW_MAX}, got {configured!r}")
    if configured is not None and runtime is not None and configured != runtime:
        raise WellKnownMcpError(
            f"clock_skew_seconds {configured} differs from the KYA-OS runtime's {runtime}: the handshake enforces the runtime's, so advertise that one"
        )
    if configured is not None:
        return configured
    return runtime if runtime is not None else _CLOCK_SKEW_DEFAULT


def build_well_known_mcp(config: Optional[WellKnownMcpConfig] = None, **kwargs: Any) -> Dict[str, Any]:
    """Builds the document from config and validates it against the schema; a configuration that cannot
    produce a valid document raises ``WellKnownMcpError`` with the reason, so a misconfigured server fails at
    startup instead of advertising something no client can use."""
    config = config if config is not None else WellKnownMcpConfig(**kwargs)
    public_origin = _origin_of(config.public_origin, "public_origin")
    server_did = config.server_did
    if not server_did:
        raise WellKnownMcpError("server_did is required for the /.well-known/mcp document")
    if not isinstance(server_did, str) or not _SERVER_DID.fullmatch(server_did):
        raise WellKnownMcpError(f"server_did must be a did:web or did:key, got {json.dumps(server_did)}")
    tools = _tools_url(public_origin, config.tools_endpoint)
    kyaos = config.kyaos or {}
    # The handshake is a tool on the MCP endpoint: its reference is rebuilt on the public tools URL so a
    # runtime described with an internal endpoint never leaks that address.
    endpoints: Dict[str, str] = {"tools": tools}
    if (kyaos.get("endpoints") or {}).get("handshake") is not None:
        endpoints["handshake"] = f"{tools}#{kyaos['handshakeTool']}"
    requested = config.capabilities or {}
    document: Dict[str, Any] = {
        "version": config.version if config.version is not None else DEFAULT_WELL_KNOWN_VERSION,
        "serverDid": server_did,
        "endpoints": endpoints,
        "clockSkewSeconds": _skew_of(config),
        "capabilities": {
            "proofs": (kyaos.get("capabilities") or {}).get("proofs") is True,
            "delegation": requested.get("delegation") is True,
            "statusList": requested.get("statusList") is True,
            "crisp": requested.get("crisp") is True,
        },
    }
    if config.status_list_credential is not None:
        document["statusListCredential"] = config.status_list_credential
    document["supportedDidMethods"] = list(config.supported_did_methods if config.supported_did_methods is not None else DEFAULT_SUPPORTED_DID_METHODS)
    document["proofAlgorithms"] = list(config.proof_algorithms if config.proof_algorithms is not None else DEFAULT_PROOF_ALGORITHMS)
    assert_well_known_mcp(document)
    return document


# -- serving it ---------------------------------------------------------------------------------


def _to_json_bytes(value: Any) -> bytes:
    """``JSON.stringify(value)`` as UTF-8: the bytes the JS middleware serves."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class WellKnownMcpResponse:
    status: int
    headers: Dict[str, str]
    body: bytes


@dataclass
class WellKnownMcp:
    enabled: bool
    document: Optional[Dict[str, Any]]
    """The validated document, or None while disabled."""
    path: str = WELL_KNOWN_MCP_PATH
    _body: bytes = field(default=_NOT_FOUND, repr=False)

    def respond(self) -> WellKnownMcpResponse:
        """The HTTP answer for a GET of ``path``, for hosts that are not ASGI."""
        return WellKnownMcpResponse(
            status=200 if self.document is not None else 404,
            headers={"content-type": "application/json", "cache-control": "public, max-age=300" if self.document is not None else "no-store"},
            body=self._body,
        )

    async def handle(self, scope: Mapping[str, Any], receive: Any, send: Send) -> bool:
        """Answers a GET or HEAD of ``path`` (an ASGI response) and returns True; False, untouched, for anything else."""
        if scope.get("type") != "http" or scope.get("method") not in ("GET", "HEAD") or scope.get("path") != self.path:
            return False
        answer = self.respond()
        headers: List[Tuple[bytes, bytes]] = [(k.encode("ascii"), v.encode("ascii")) for k, v in answer.headers.items()]
        headers.append((b"content-length", str(len(answer.body)).encode("ascii")))
        await send({"type": "http.response.start", "status": answer.status, "headers": headers})
        await send({"type": "http.response.body", "body": b"" if scope.get("method") == "HEAD" else answer.body})
        return True


def create_well_known_mcp(config: Optional[WellKnownMcpConfig] = None, **kwargs: Any) -> WellKnownMcp:
    """The ``/.well-known/mcp`` route: on by default (L1.10 is RECOMMENDED), 404 when ``enabled=False``.
    Built and validated once, here, at startup."""
    config = config if config is not None else WellKnownMcpConfig(**kwargs)
    if not config.enabled:
        return WellKnownMcp(enabled=False, document=None)
    document = build_well_known_mcp(config)
    return WellKnownMcp(enabled=True, document=document, _body=_to_json_bytes(document))
