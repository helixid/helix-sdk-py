# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The middleware's default fetch for public resolution (KYA-OS stories F-2,
L3-C): DID documents, Entity Cards and status lists. Ported from
helix-sdk-js's mcp-middleware/src/resolution-fetch.ts. It applies the
SafeFetch rules that need no DNS control (story C-A, SPEC.md §6.6):

- ``https:`` only (an ``http:`` loopback URL only with
  ``allow_loopback_http``, in development);
- a host written as an IP address must be public unicast (no private,
  loopback, link-local, CGNAT, documentation, multicast or reserved ranges;
  IPv4-mapped IPv6 is unwrapped first), loopback only in development;
- same-origin redirects only, at most three;
- a 5 s timeout and a 1 MiB body cap.

What it cannot do is pin the address a host name resolves to: a public name
pointing at a private address is still connected to. helix-core's SafeFetch
(story C-A) pins the connection; a host that has one passes it as
``create_local_verifier(fetch=...)``, which replaces this default.
"""

from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

RESOLUTION_TIMEOUT_MS = 5_000
RESOLUTION_MAX_BYTES = 1024 * 1024
_MAX_REDIRECTS = 3
_ACCEPT = "application/json, application/did+json, */*;q=0.1"

ResolverFetch = Callable[[str], Any]
"""How DID documents, status lists and cards are read: ``url -> parsed JSON``;
raises when the URL does not answer with a document."""


class ResolutionRefusedError(ValueError):
    """A URL the resolution rules do not read, or an answer they do not accept."""


_NON_PUBLIC = [
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "64:ff9b::/96",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
]

_LOOPBACK_HOSTS = frozenset(("localhost", "127.0.0.1", "::1"))


def _ip(address: str) -> Optional[Any]:
    try:
        return ipaddress.ip_address(address)
    except ValueError:
        return None


def is_public_unicast_address(address: str) -> bool:
    """Whether ``address`` (an IP literal) is public unicast; IPv4-mapped IPv6 is judged by the IPv4 address it carries."""
    parsed = _ip(address)
    if parsed is None:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return not any(parsed.version == network.version and parsed in network for network in _NON_PUBLIC)


def resolution_target(url: str, allow_loopback_http: bool) -> str:
    """The URL to fetch for ``url`` under the rules above, or a raised :class:`ResolutionRefusedError`."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises on a malformed port
    except ValueError:
        raise ResolutionRefusedError(f"refusing to fetch {url}: not a URL") from None
    if not parts.netloc or host is None:
        raise ResolutionRefusedError(f"refusing to fetch {url}: not a URL")
    loopback = host in _LOOPBACK_HOSTS
    if parts.scheme == "http":
        if not (loopback and allow_loopback_http):
            raise ResolutionRefusedError(f"refusing to fetch {url}: only https: URLs are read")
    elif parts.scheme != "https":
        raise ResolutionRefusedError(f"refusing to fetch {url}: only https: URLs are read")
    if parts.username is not None or parts.password is not None:
        raise ResolutionRefusedError(f"refusing to fetch {url}: credentials in the URL")
    if loopback:
        if not allow_loopback_http:
            raise ResolutionRefusedError(f"refusing to fetch {url}: a loopback host")
        # Development: an https: loopback URL is read over http:, as the F-2 resolvers always did.
        return urlunsplit(parts._replace(scheme="http"))
    if _ip(host) is not None and not is_public_unicast_address(host):
        raise ResolutionRefusedError(f"refusing to fetch {url}: {host} is not a public unicast address")
    return url


def _origin(url: str) -> str:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme}://{(parts.hostname or '').lower()}:{port}"


@dataclass
class TransportResponse:
    """One HTTP answer: its status, its headers (lower-cased names) and its body, read up to the cap plus one byte."""

    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""


Transport = Callable[[str, float, int], TransportResponse]
"""``(url, timeout_seconds, max_bytes) -> TransportResponse``, redirects not followed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D102 - redirects are judged by the caller
        return None


def _read_capped(stream: Any, headers: Mapping[str, str], max_bytes: int) -> bytes:
    declared = headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > max_bytes:
        raise ResolutionRefusedError(f"the body is {declared} bytes; at most {max_bytes} are read")
    return stream.read(max_bytes + 1)


def urllib_transport(url: str, timeout_seconds: float, max_bytes: int) -> TransportResponse:
    """The default transport: urllib, redirects returned rather than followed."""
    opener = build_opener(_NoRedirect)
    request = Request(url, headers={"accept": _ACCEPT})
    try:
        with opener.open(request, timeout=timeout_seconds) as response:  # noqa: S310 - the URL passed resolution_target
            headers = {name.lower(): value for name, value in response.headers.items()}
            return TransportResponse(response.status, headers, _read_capped(response, headers, max_bytes))
    except HTTPError as error:
        headers = {name.lower(): value for name, value in (error.headers or {}).items()}
        return TransportResponse(error.code, headers, b"")


def create_resolution_fetch(
    allow_loopback_http: bool = False,
    transport: Optional[Transport] = None,
    timeout_ms: int = RESOLUTION_TIMEOUT_MS,
    max_bytes: int = RESOLUTION_MAX_BYTES,
) -> ResolverFetch:
    """A :data:`ResolverFetch` under the rules above: ``url -> parsed JSON``, raising on a refusal or a non-2xx answer."""
    send = transport or urllib_transport

    def fetch(url: str) -> Any:
        target = resolution_target(url, allow_loopback_http)
        origin = _origin(target)
        deadline = time.monotonic() + timeout_ms / 1000
        hop = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ResolutionRefusedError(f"{url}: timed out after {timeout_ms} ms")
            response = send(target, remaining, max_bytes)
            if 300 <= response.status < 400:
                location = response.headers.get("location")
                if location is None or hop >= _MAX_REDIRECTS:
                    raise ResolutionRefusedError(f"{url}: too many or empty redirects")
                following = urljoin(target, location)
                if _origin(following) != origin:
                    raise ResolutionRefusedError(f"{url}: redirect to another origin ({_origin(following)})")
                target = following
                hop += 1
                continue
            if not 200 <= response.status < 300:
                raise ValueError(f"{url} answered {response.status}")
            if len(response.body) > max_bytes:
                raise ResolutionRefusedError(f"the body exceeds {max_bytes} bytes")
            return json.loads(response.body.decode("utf-8"))

    return fetch


def status_list_http_fetch(fetch: ResolverFetch) -> Callable[[str], "tuple[int, Any]"]:
    """``fetch`` as :func:`helix_sdk.verifier.create_status_list_fetcher` takes it (``url -> (status, body)``); a raise reads as unavailable."""

    def fetch_list(url: str) -> "tuple[int, Any]":
        return 200, fetch(url)

    return fetch_list


__all__ = [
    "RESOLUTION_MAX_BYTES",
    "RESOLUTION_TIMEOUT_MS",
    "ResolutionRefusedError",
    "ResolverFetch",
    "Transport",
    "TransportResponse",
    "create_resolution_fetch",
    "is_public_unicast_address",
    "resolution_target",
    "status_list_http_fetch",
    "urllib_transport",
]
