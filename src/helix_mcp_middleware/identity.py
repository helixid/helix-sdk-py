# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The service's own KYA-OS identity, served from its origin (story C-A), ported
from helix-sdk-js's mcp-middleware/src/identity.ts: ``did.json`` and
``card.json`` at the paths its did:web derives, and the claim-minimal
projection of the card into MCP ``server.json`` under
``_meta["org.kya-os/card"]`` with the canonical ``cardRef``.

Hosting follows the L1-D cases: route ``/{path}/did.json`` and
``/{path}/card.json`` at the public origin to ``handle()`` (case 1, the proxy
forwards them; ``public_origin`` is what the documents name), mount
``handle()`` in whichever ASGI app serves the root (case 2), or write the two
documents out as static files (case 3: ``did_document`` and ``card`` are plain
JSON). A service whose documents ``helix init`` already wrote hands them in as
``documents`` and nothing is rebuilt.

Verifier side: ``resolve_server_card`` reads a ``server.json`` projection and,
when the projection was stripped, falls back to fetching the canonical card
through the SDK's SafeFetch.

``handle`` is the ASGI twin of the JS ``handle(pathname, res)``; ``body_for``
gives the bytes for any other framework. The JSON bytes are the ones the JS
middleware writes (``JSON.stringify``: no spaces, UTF-8, member order kept).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence
from urllib.parse import quote, urlsplit

from helix_sdk.entity_card import (
    FetchJson,
    ResolvedEntityCard,
    build_entity_card,
    did_web_card_url,
    did_web_document_url,
    did_web_for,
    kya_os_card_service_entry,
    parse_did_web,
    parse_entity_card,
    resolve_entity_card_from_server_meta,
    server_card_meta,
)

DID_CONTEXTS = ("https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1")

Send = Callable[[Dict[str, Any]], Awaitable[None]]


@dataclass
class ServeIdentityOptions:
    public_origin: str
    """The origin agents connect to, e.g. ``https://mcp.example.com``; behind a proxy the app's bind address is not it."""
    did: Optional[str] = None
    """This service's did:web. Derived from ``public_origin`` and ``path`` when omitted:
    ``did:web:<host>`` at the root, ``did:web:<host>:<seg>…`` under a path."""
    path: Optional[str] = None
    """Where under the origin the documents live (``/mcp`` → ``did:web:<host>:mcp``). Default: the origin's own path."""
    card: Optional[Mapping[str, Any]] = None
    """What the card says, in the card's own member names (``name``, ``kid``, ``publicKeyJwk``,
    ``capabilities``, ``responsibleParty``…); ``id`` and ``didDocument`` are filled in, ``entityType``
    defaults to ``mcp``."""
    also_known_as: Optional[Sequence[str]] = None
    """Other DIDs of this service (its did:key form, a did:hedera)."""
    service: Optional[Sequence[Any]] = None
    """Other DID-document services to keep beside the card entry."""
    documents: Optional[Mapping[str, Any]] = None
    """Documents ``helix init`` wrote, ``{"didDocument": …, "card": …}``: served as they are
    (the card is still checked against the schema)."""


def _segments_of(path: Optional[str]) -> List[str]:
    return [segment for segment in (path or "").split("/") if segment]


def _paths_for(segments: Sequence[str]) -> Dict[str, str]:
    if not segments:
        return {"did_document": "/.well-known/did.json", "card": "/.well-known/kya-os-card.json"}
    base = "/" + "/".join(quote(segment, safe="") for segment in segments)
    return {"did_document": f"{base}/did.json", "card": f"{base}/card.json"}


def _to_json_bytes(value: Any) -> bytes:
    """``JSON.stringify(value)`` as UTF-8: the bytes the JS middleware serves."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _origin_of(url: Any) -> str:
    """WHATWG ``URL.origin``: scheme, lower-cased host, the port unless it is the scheme's default."""
    host = url.hostname or ""
    host = f"[{host}]" if ":" in host else host
    default = {"https": 443, "http": 80}.get(url.scheme)
    port = url.port
    return f"{url.scheme}://{host}" + ("" if port is None or port == default else f":{port}")


@dataclass
class ServedIdentity:
    did: str
    did_document_url: str
    card_url: str
    paths: Dict[str, str]
    """The request paths ``handle`` answers: ``{"did_document": …, "card": …}``."""
    did_document: Dict[str, Any]
    card: Dict[str, Any]
    _bodies: Dict[str, bytes] = field(default_factory=dict, repr=False)

    def body_for(self, path: str) -> Optional[bytes]:
        """The JSON bytes served at ``path``, or None for any other path."""
        return self._bodies.get(path)

    async def handle(self, scope: Mapping[str, Any], receive: Any, send: Send) -> bool:
        """Answers a GET for one of the two paths with its JSON (an ASGI response); False for anything else."""
        if scope.get("type") != "http" or scope.get("method") != "GET":
            return False
        body = self.body_for(scope.get("path", ""))
        if body is None:
            return False
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"cache-control", b"public, max-age=300"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})
        return True

    def server_meta(self, by_ref: bool = False) -> Dict[str, Any]:
        """``{"org.kya-os/card": {…summary, "org.kya-os/cardRef": card_url}}`` to merge into ``server.json`` ``_meta``."""
        return server_card_meta(self.card, card_url=self.card_url, by_ref=by_ref)

    def project_server_json(self, server_json: Mapping[str, Any], by_ref: bool = False) -> Dict[str, Any]:
        """``server_json`` with the projection merged into its ``_meta``."""
        meta = server_json.get("_meta")
        return {**server_json, "_meta": {**(meta if isinstance(meta, Mapping) else {}), **self.server_meta(by_ref)}}


def serve_identity(options: Optional[ServeIdentityOptions] = None, **kwargs: Any) -> ServedIdentity:
    """The service's ``did.json`` and ``card.json``, built or handed in, ready to serve."""
    opts = options if options is not None else ServeIdentityOptions(**kwargs)
    try:
        origin = urlsplit(opts.public_origin)
    except (TypeError, ValueError):
        origin = None
    if origin is None or not origin.scheme or not origin.netloc:
        raise ValueError("serve_identity: public_origin must be an absolute URL such as https://mcp.example.com")
    if origin.scheme not in ("http", "https"):
        raise ValueError("serve_identity: public_origin must be an http(s) origin")
    public_base = _origin_of(origin)
    origin_host = public_base.split("://", 1)[1]
    segments = _segments_of(opts.path if opts.path is not None else ("" if origin.path in ("", "/") else origin.path))
    did = opts.did if opts.did is not None else did_web_for(origin_host, segments)
    parsed = parse_did_web(did)
    if parsed is None:
        raise ValueError(f"serve_identity: {did} is not a did:web DID")
    paths = _paths_for(parsed[1])
    canonical = origin.scheme == "https" and public_base == f"https://{parsed[0]}"
    did_document_url = did_web_document_url(did) if canonical else f"{public_base}{paths['did_document']}"
    card_url = did_web_card_url(did) if canonical else f"{public_base}{paths['card']}"

    if opts.documents is not None:
        card = parse_entity_card(opts.documents.get("card"))
        did_document = opts.documents.get("didDocument")
        if not isinstance(did_document, Mapping) or did_document.get("id") != did:
            served_id = did_document.get("id") if isinstance(did_document, Mapping) else None
            raise ValueError(f"serve_identity: the DID document is for {served_id}, not {did}")
        did_document = dict(did_document)
        if card["id"] != did:
            raise ValueError(f"serve_identity: the card is for {card['id']}, not {did}")
    else:
        given = dict(opts.card) if opts.card is not None else {"name": did}
        card = build_entity_card({**given, "entityType": given.get("entityType") or "mcp", "id": did, "didDocument": did_document_url})
        kid, jwk = card.get("kid"), card.get("publicKeyJwk")
        method = (
            [{"id": kid, "type": "Ed25519VerificationKey2020", "controller": did, "publicKeyJwk": {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"]}}]
            if kid is not None and jwk is not None
            else []
        )
        did_document = {"@context": list(DID_CONTEXTS), "id": did}
        if opts.also_known_as:
            did_document["alsoKnownAs"] = list(opts.also_known_as)
        did_document.update({
            "verificationMethod": method,
            "authentication": [entry["id"] for entry in method],
            "assertionMethod": [entry["id"] for entry in method],
            "service": [*(opts.service or []), kya_os_card_service_entry(card_url)],
        })

    bodies = {paths["did_document"]: _to_json_bytes(did_document), paths["card"]: _to_json_bytes(card)}
    return ServedIdentity(did=did, did_document_url=did_document_url, card_url=card_url, paths=paths, did_document=did_document, card=card, _bodies=bodies)


def resolve_server_card(server_json: Optional[Mapping[str, Any]], did: Optional[str] = None, fetch_json: Optional[FetchJson] = None) -> ResolvedEntityCard:
    """The card an MCP ``server.json`` advertises: the inline summary or ``cardRef`` under
    ``_meta["org.kya-os/card"]``, dereferenced to the canonical card; a stripped projection falls back to
    the two-step resolution of ``did``."""
    meta = server_json.get("_meta") if isinstance(server_json, Mapping) else None
    return resolve_entity_card_from_server_meta(meta, did=did, fetch_json=fetch_json)
