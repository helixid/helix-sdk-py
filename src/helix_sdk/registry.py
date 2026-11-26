# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The Helix agent registry, and checking a service before calling it (registry v3, 2026-11-24).

The Python twin of sdk-js ``kyaos.registry``.

- **Agents** made discoverable at onboarding ("Make discoverable", on by
  default; ``discoverable`` when an agent is created through the API) are
  listed in the Helix registry at https://api.helixid.dev. Anyone can search
  it: ``find_agents(q)``, ``lookup(did)``.
- **Services** are not listed anywhere. An agent gets a service's URL from its
  user or its configuration, and ``resolve(url)`` checks the DID the service
  publishes at its own address (``/.well-known/mcp``): the DID document must
  be fetchable, else the service is refused.
- Nothing is public or private. Whether an agent or service can be reached is
  up to the network it is hosted on; a DID that can be fetched verifies::

    registry = kyaos.registry.create_registry_client()
    agent = registry.find_agents("travel")[0]
    resolved = registry.resolve("https://air.example.com")
    resolved["serviceDid"], resolved["toolsUrl"]

A discoverable self-custody agent registers itself with the Helix registry,
signed with its own key: ``publish(signer, helix_url)`` (the deployment it is
onboarded on, which the Helix registry asks whether it is discoverable). A
custodial agent's deployment does that for it.
"""

from __future__ import annotations

import os
import re
import time
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional
from urllib.parse import quote, unquote, urlsplit

from .crypto.jws import Signer, sign_jws
from .discovery import fetch_well_known_mcp

HELIX_REGISTRY_ORIGIN = "https://api.helixid.dev"
"""The Helix registry. Fixed."""
AGENT_REGISTRY_PATH = "/agent/registry"
REGISTRATION_TYP = "helix-registration+jwt"
REGISTRY_ERROR = "REGISTRY_ERROR"

# TEST ONLY: a local run stands a loopback deployment in for api.helixid.dev. Not configuration.
_TEST_ONLY_ORIGIN_ENV = "HELIX_TEST_ONLY_REGISTRY_ORIGIN"

Get = Callable[..., Any]
"""``requests.get``-shaped: ``get(url, headers=…, timeout=…)``."""
Post = Callable[..., Any]
"""``requests.post``-shaped: ``post(url, json=…, headers=…, timeout=…)``."""
ResolveDid = Callable[[str], Optional[Mapping[str, Any]]]

_LOOPBACK = {"127.0.0.1", "localhost", "[::1]"}
_DID_WEB = re.compile(r"^did:web:([^:]+)")


class RegistryProblems:
    NO_HELIX_LINK = "no_helix_link"
    FETCH_FAILED = "fetch_failed"
    REGISTRY_ERROR = "registry_error"
    NO_URL = "no_url"
    DID_UNRESOLVABLE = "did_unresolvable"
    DID_MISMATCH = "did_mismatch"
    PUBLISH_REFUSED = "publish_refused"


class RegistryError(Exception):
    """A registry step that failed; ``reason`` is one of ``RegistryProblems``."""

    code = REGISTRY_ERROR

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _origin(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"not an absolute http(s) URL: {url}")
    return f"{parts.scheme}://{parts.netloc}"


def helix_registry_origin() -> str:
    """The Helix registry's origin."""
    override = os.environ.get(_TEST_ONLY_ORIGIN_ENV)
    return _origin(override) if override else HELIX_REGISTRY_ORIGIN


def helix_origin_of_did(did: str) -> Optional[str]:
    """The deployment a did:web names (its %-decoded first segment): https, or http for a loopback host."""
    match = _DID_WEB.match(did)
    if not match:
        return None
    host = unquote(match.group(1))
    hostname = host[: host.index("]") + 1] if host.startswith("[") else host.split(":")[0]
    if not hostname or any(ch.isspace() for ch in host):
        return None
    return f"{'http' if hostname in _LOOPBACK else 'https'}://{host}"


def _get_json(get: Get, url: str, timeout: float) -> Any:
    """GET as JSON; None on 404."""
    try:
        response = get(url, headers={"accept": "application/json"}, timeout=timeout)
    except Exception as error:  # noqa: BLE001 - any transport failure is "could not fetch"
        raise RegistryError(RegistryProblems.FETCH_FAILED, f"GET {url} failed: {error}") from None
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise RegistryError(RegistryProblems.FETCH_FAILED, f"GET {url} answered {response.status_code}")
    try:
        return response.json()
    except ValueError:
        raise RegistryError(RegistryProblems.FETCH_FAILED, f"GET {url} did not answer with JSON") from None


def _default_get() -> Get:
    import requests

    return requests.get


class RegistryClient:
    """Reads the Helix agent registry and checks services by URL. Build it with ``create_registry_client``."""

    def __init__(self, get: Optional[Get] = None, resolve_did: Optional[ResolveDid] = None, timeout: float = 5.0) -> None:
        self.registry = helix_registry_origin()
        self._get = get
        self._resolve_did = resolve_did
        self._timeout = timeout

    def _did_resolver(self) -> ResolveDid:
        if self._resolve_did is not None:
            return self._resolve_did
        from .verifier.resolve import create_did_resolver

        return create_did_resolver()

    def find_agents(self, q: str) -> List[Dict[str, Any]]:
        """Discoverable agents matching ``q`` (any word of the name or owner, or an exact DID)."""
        url = f"{self.registry}{AGENT_REGISTRY_PATH}?q={quote(q, safe='')}"
        body = _get_json(self._get or _default_get(), url, self._timeout)
        listed = body.get("agents") if isinstance(body, dict) else None
        if not isinstance(listed, list):
            raise RegistryError(RegistryProblems.REGISTRY_ERROR, f"{url} did not answer an agents list")
        return [entry for entry in listed if isinstance(entry, dict) and isinstance(entry.get("agentDid"), str)]

    def lookup(self, agent_did: str) -> Optional[Dict[str, Any]]:
        """One discoverable agent, or None when the Helix registry does not list it."""
        body = _get_json(self._get or _default_get(), f"{self.registry}{AGENT_REGISTRY_PATH}/{quote(agent_did, safe='')}", self._timeout)
        agent = body.get("agent") if isinstance(body, dict) else None
        return agent if isinstance(agent, dict) and agent.get("agentDid") == agent_did else None

    def resolve(self, url: str, expected_did: Optional[str] = None) -> Dict[str, Any]:
        """The service at a URL, checked: its /.well-known/mcp names a DID whose document can be fetched.
        ``{serviceDid, toolsUrl, url, didDocument}``."""
        try:
            origin = _origin(url)
        except ValueError:
            raise RegistryError(RegistryProblems.NO_URL, f"Not a URL: {url}") from None
        document = fetch_well_known_mcp(origin, get=self._get, timeout=self._timeout)
        server_did = document["serverDid"]
        if expected_did is not None and server_did != expected_did:
            raise RegistryError(RegistryProblems.DID_MISMATCH, f"{origin} says it is {server_did}, not {expected_did}")
        try:
            did_document = self._did_resolver()(server_did)
        except Exception as error:  # noqa: BLE001 - any failure to fetch the document is "unresolvable"
            raise RegistryError(
                RegistryProblems.DID_UNRESOLVABLE, f"{server_did} (named by {origin}/.well-known/mcp) could not be resolved: {error}"
            ) from None
        if not did_document:
            raise RegistryError(RegistryProblems.DID_UNRESOLVABLE, f"{server_did} (named by {origin}/.well-known/mcp) could not be resolved")
        tools_url = document["endpoints"].get("tools")
        if not tools_url:
            raise RegistryError(RegistryProblems.NO_URL, f"{origin}/.well-known/mcp names no tools endpoint")
        return {"serviceDid": server_did, "toolsUrl": tools_url, "url": origin, "didDocument": dict(did_document)}


def create_registry_client(get: Optional[Get] = None, resolve_did: Optional[ResolveDid] = None, timeout: float = 5.0) -> RegistryClient:
    """A client for the Helix agent registry and the DID check of services (see the module docstring)."""
    return RegistryClient(get=get, resolve_did=resolve_did, timeout=timeout)


def publish(
    signer: Signer,
    helix_url: Optional[str] = None,
    post: Optional[Post] = None,
    timeout: float = 5.0,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Registers a discoverable, self-custody agent with the Helix registry, signed with its own key.
    ``helix_url`` is the deployment it is onboarded on (default: its did:web host)."""
    deployment = _origin(helix_url) if helix_url else helix_origin_of_did(signer.did)
    if not deployment:
        raise RegistryError(RegistryProblems.NO_HELIX_LINK, "Give a helix_url or sign with a did:web: there is no deployment for the Helix registry to ask")
    helix = helix_registry_origin()
    iat = int(now if now is not None else time.time())
    claims = {"iss": signer.did, "sub": signer.did, "aud": helix, "deployment": deployment, "iat": iat, "exp": iat + 300, "jti": str(uuid.uuid4())}
    registration = sign_jws(claims, signer, header={"typ": REGISTRATION_TYP})
    url = f"{helix}{AGENT_REGISTRY_PATH}"
    if post is None:
        import requests

        post = requests.post
    try:
        response = post(url, json={"registration": registration}, headers={"accept": "application/json"}, timeout=timeout)
    except Exception as error:  # noqa: BLE001 - any transport failure is "could not fetch"
        raise RegistryError(RegistryProblems.FETCH_FAILED, f"POST {url} failed: {error}") from None
    try:
        body = response.json()
    except ValueError:
        body = None
    entry = body.get("agent") if isinstance(body, dict) else None
    if response.status_code != 201 or not isinstance(entry, dict):
        error = body.get("error") if isinstance(body, dict) else None
        message = error.get("message") if isinstance(error, dict) else f"answered {response.status_code}"
        raise RegistryError(RegistryProblems.PUBLISH_REFUSED, f"The Helix registry refused the registration: {message}")
    return entry


__all__ = [
    "AGENT_REGISTRY_PATH",
    "HELIX_REGISTRY_ORIGIN",
    "REGISTRATION_TYP",
    "REGISTRY_ERROR",
    "RegistryClient",
    "RegistryError",
    "RegistryProblems",
    "create_registry_client",
    "helix_origin_of_did",
    "helix_registry_origin",
    "publish",
]
