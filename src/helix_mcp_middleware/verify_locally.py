# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""In-process verification of every tool call (KYA-OS story F-2), ported
from helix-sdk-js's mcp-middleware/src/verify-locally.ts.

The middleware runs :func:`helix_sdk.verifier.verify` on the request proof
and the carried chain, with seams built from local config and public
resolution only:

- the middleware's replay store (story L2-A: a ``NonceStore`` such as the
  memory, Redis or DynamoDB one ``nonce_store_from_env`` picks, shared with
  the handshake and the response proofs; default one in memory, this process
  only);
- DID documents over HTTPS (did:web) or offline (did:key), through an
  injected ``fetch`` where the host has one of its own;
- status lists over HTTPS, each list's own proof verified before any bit is
  read, through a revocation checker that fails closed and a
  :class:`helix_sdk.verifier.StatusCache` (story L3-C: ``status_cache_ttl``,
  ``high_privilege_scopes`` held to at most 60 s, cached reads reported
  ``fresh=False``), which a :class:`RevocationSignalClient` invalidates at once
  on a revocation signal; in multi-instance mode the cache lives in the
  shared Redis (:class:`RedisStatusCacheStore`);
- Entity Cards over HTTPS, through the same fetch: by default
  :func:`create_resolution_fetch` (https only, public IP literals only,
  same-origin redirects, 5 s, 1 MiB);
- ``trusted_issuers`` (default ``"*"``) and ``max_chain_length`` (default 10).

The Helix API is never asked: a call verifies with the API down, and a
credential issued by any Helix deployment verifies here from the presented
artifacts and public resolution alone (stories rule 4). Each verification is
handed to ``report_verification``, the hook story A-1's audit trail
connects; until it is, the default says once that verifications go
unrecorded.
"""

from __future__ import annotations

import asyncio
import inspect
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit

from helix_sdk.verifier import (
    StatusCache,
    VerifierOptions,
    VerifierResult,
    VerifierSeams,
    create_did_keys_resolver,
    RotationSequenceGuard,
    create_did_resolver,
    create_revocation_checker,
    create_status_list_fetcher,
    read_carried_chain,
    read_request_proof,
    verify,
)

from .credentials import meta_mapping
from .kyaos.nonce_store import MemoryNonceStore
from .resolution_fetch import ResolverFetch, create_resolution_fetch, status_list_http_fetch

KYA_OS_CARD_SERVICE_TYPE = "KyaOsEntityCard"

VerificationReport = Dict[str, Any]
"""What ``report_verification`` receives for every local verification. Keys
match the JS report: timestamp, serviceDid, toolName, agentDid, ok, level,
proofAssurance, proofFloor, l3Minus, cnfDiagnostics (story C-C),
effectiveScopes, reasons, fresh, chainDepth."""

ReportVerification = Callable[[VerificationReport], Any]

_LOOPBACK = ("127.0.0.1", "localhost", "::1")


@dataclass
class LocalVerifierOptions:
    """The local verifier's settings. Inside :class:`MCPMiddlewareOptions`
    ``service_did`` may be left out: it defaults to the middleware's own."""

    service_did: Optional[str] = None
    """This service's DID: the proof's audience and, unless ``resource`` is set, the chain's resource."""
    resource: Optional[str] = None
    """The ``invocationTarget`` every carried chain must name; default ``service_did``."""
    resource_owner: Optional[str] = None
    """When set, the root hop's issuer must be this DID."""
    trusted_root_issuers: Optional[Sequence[str]] = None
    """When set, the root hop's issuer must be one of these DIDs."""
    trusted_issuers: Any = "*"
    """``"*"`` (default) trusts every attestation issuer; a list trusts those DIDs only (stories rule 9)."""
    max_chain_length: Optional[int] = None
    """The longest carried chain parsed; default 10."""
    skew_seconds: Optional[int] = None
    """Clock skew on the proof window, seconds; default 5."""
    max_clock_skew_ms: Any = None
    """Clock tolerance on credential and status-list windows, ms; default 120,000."""
    catalog: Optional[Sequence[str]] = None
    """The scopes this service offers; ``effectiveScopes`` is intersected with it."""
    allow_own_authority: bool = True
    """Own authority (default True): a call with no chain, from an agent whose card names no
    ``responsibleParty``, gets its attested capabilities that are in ``catalog``. The middleware
    passes the scopes its ``tool_scopes``, ``resource_scopes`` and ``prompt_scopes`` name as the catalog.
    A tool that needs the user's consent sets ``require_delegation``; ``False`` here makes every scoped
    call need a chain."""
    nonce_store: Any = None
    """The middleware's replay store, a :class:`helix_mcp_middleware.NonceStore`
    (``insert(nonce, agent_did, expires_at)``, Unix seconds, answering a bool
    or an awaitable): share the KYA-OS runtime's store across the handshake,
    the response proofs and the request proofs. Default one in memory, this process only."""
    fetch: Optional[ResolverFetch] = None
    """``url -> parsed JSON``: the host's SafeFetch (story C-A). Default: :func:`create_resolution_fetch`
    (https only, public IP literals only, same-origin redirects, 5 s, 1 MiB)."""
    allow_loopback_http: bool = False
    """Development only: also read ``http:`` URLs on loopback hosts (a did:web on ``127.0.0.1``, say)."""
    resolve_did: Optional[Callable[[str], Any]] = None
    """A DID resolver of the host's own, in place of the built-in did:key / did:web one."""
    rotation_sequence_store: Any = None
    """Story C-E point 2: where the default resolver keeps the highest DID document ``rotationSequence`` it
    has seen, refusing a lower one. Default: in memory for this verifier; pass a ``RedisRotationSequenceStore``
    (next to the nonce store) so every instance refuses the same replay."""
    resolve_did_keys: Optional[Callable[[str], Any]] = None
    """Default: every Ed25519 key the resolved document publishes."""
    fetch_status_list: Optional[Callable[[str], Any]] = None
    """Default: fetch the list at its URL, verify its proof, then decode it (story L3-C)."""
    check_revocation: Optional[Callable[..., Any]] = None
    """The revocation seam; default: a checker over ``fetch_status_list`` with ``status_cache``."""
    status_cache: Any = None
    """A :class:`helix_sdk.verifier.StatusCache`, or a dict of its options (story L3-C point 6). Default: one in
    memory with ``status_cache_ttl`` 300 s; pass ``store=RedisStatusCacheStore(...)`` to share it between instances."""
    status_list_issuers: Optional[Mapping[str, Sequence[str]]] = None
    """Issuer DID to the status-list URLs or ``https:`` origins bound to it (SPEC.md §6.6 keeper rules 1 and 2)."""
    cards: Optional[Mapping[str, Any]] = None
    """Entity Cards by agent DID, from local config, read before ``resolve_card``."""
    resolve_card: Optional[Callable[[str], Any]] = None
    """Default: the ``KyaOsEntityCard`` service of the agent's DID document, fetched."""
    report_verification: Optional[ReportVerification] = None
    """Story A-1's hook; default: says once that verifications are unrecorded."""
    on_report_error: Optional[Callable[[BaseException], Any]] = None
    """Called when ``report_verification`` raises; reporting never blocks a call."""
    clock: Optional[Callable[[], int]] = None
    """Milliseconds since the epoch; default the system clock."""
    log: Optional[Callable[[str], Any]] = None
    """Where the default report hook writes; default stderr."""


MiddlewareVerifierOptions = LocalVerifierOptions
"""The verifier settings :class:`MCPMiddlewareOptions` takes (``service_did`` optional there)."""


def resolution_url(url: str, allow_loopback_http: bool) -> Optional[str]:
    """``https://`` only, unless the host is loopback and ``allow_loopback_http`` is set, where ``http://`` is used."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return None
    if not parts.netloc or host is None:
        return None
    loopback = host in _LOOPBACK
    if parts.scheme == "https":
        return urlunsplit(parts._replace(scheme="http")) if loopback and allow_loopback_http else url
    if parts.scheme == "http" and loopback and allow_loopback_http:
        return url
    return None


def card_endpoint_of(document: Any) -> Optional[str]:
    """The URL the ``KyaOsEntityCard`` service of a DID document names, or None."""
    if not isinstance(document, Mapping) or not isinstance(document.get("service"), list):
        return None
    for service in document["service"]:
        if not isinstance(service, Mapping):
            continue
        kind = service.get("type")
        kinds = kind if isinstance(kind, list) else [kind]
        if KYA_OS_CARD_SERVICE_TYPE in kinds and isinstance(service.get("serviceEndpoint"), str):
            return service["serviceEndpoint"]
    return None


def _stderr(message: str) -> None:
    print(message, file=sys.stderr)


def unrecorded_reporter(log: Optional[Callable[[str], Any]] = None) -> ReportVerification:
    """The default ``report_verification``: says once that verifications go unrecorded until story A-1 connects the trail."""
    write = log or _stderr
    said = [False]

    def report(_entry: VerificationReport) -> None:
        if said[0]:
            return
        said[0] = True
        write("[kya-os] local verifications are unrecorded: no report_verification hook is set (story A-1 connects the audit trail)")

    return report


async def _awaited(value: Any) -> Any:
    return await value


def _settle(value: Any) -> Any:
    """An answer of the replay store, awaited when it is awaitable: on the event
    loop of the async gate that called us (an asyncio client is bound to it),
    or, with no gate loop, on a loop of its own in this thread."""
    if not inspect.isawaitable(value):
        return value
    from .middleware import _LOOP  # the async gate's loop, set around its worker thread

    loop = _LOOP.get()
    if loop is not None:
        return asyncio.run_coroutine_threadsafe(_awaited(value), loop).result()
    return asyncio.run(_awaited(value))


class _ReplaySeam:
    """helix_sdk.verifier's replay seam over the middleware's NonceStore: the
    verifier's millisecond expiry in the store's Unix seconds, and only a real
    ``True`` counts as fresh (an unresolved answer would otherwise pass every replay)."""

    def __init__(self, store: Any) -> None:
        self._store = store

    def insert(self, nonce: str, agent_did: Optional[str], expires_at_ms: int) -> bool:
        return _settle(self._store.insert(nonce, agent_did, expires_at_ms / 1000)) is True


def request_of(call: Mapping[str, Any]) -> Dict[str, Any]:
    """The JSON-RPC request the proof's ``requestHash`` covers: ``call["request"]`` as received,
    else ``tools/call`` rebuilt from ``name``, ``input`` and ``_meta``."""
    request = call.get("request")
    if request is not None:
        return request  # type: ignore[no-any-return]
    params: Dict[str, Any] = {}
    if call.get("name") is not None:
        params["name"] = call["name"]
    if call.get("input") is not None:
        params["arguments"] = call["input"]
    if call.get("_meta") is not None:
        params["_meta"] = dict(meta_mapping(call["_meta"]))
    return {"method": "tools/call", "params": params}


class LocalVerifier:
    """Verifies tool calls in-process. Build it with :func:`create_local_verifier`."""

    def __init__(self, options: LocalVerifierOptions) -> None:
        service_did = options.service_did
        if not isinstance(service_did, str) or not service_did.startswith("did:"):
            raise ValueError("create_local_verifier: service_did must be a DID")
        self.service_did: str = service_did
        self._options = options
        clock = options.clock or (lambda: int(datetime.now(timezone.utc).timestamp() * 1000))
        self._clock = clock
        self.nonce_store = options.nonce_store if options.nonce_store is not None else MemoryNonceStore(now=lambda: clock() / 1000)
        allow = options.allow_loopback_http
        host_fetch = options.fetch
        if host_fetch is None:
            fetch_json: ResolverFetch = create_resolution_fetch(allow_loopback_http=allow)
        else:
            # A host's own fetch (its SafeFetch) is held to the URL policy here; the default applies it itself.
            def fetch_json(url: str) -> Any:
                target = resolution_url(url, allow)
                if target is None:
                    raise ValueError(f"refusing to fetch {url}: only https: URLs are read")
                return host_fetch(target)

        # A URL that is not read is refused inside fetch_json; the verifier reports the DID unresolved.
        guard = RotationSequenceGuard(options.rotation_sequence_store) if options.rotation_sequence_store is not None else None
        resolve_did = options.resolve_did or create_did_resolver(fetch_json, sequence_guard=guard)
        resolve_did_keys = options.resolve_did_keys or create_did_keys_resolver(resolve_did)

        # Every list's proof is verified, by its issuer's assertionMethod key, before any bit is read (story L3-C point 2).
        fetch_status_list = options.fetch_status_list or create_status_list_fetcher(status_list_http_fetch(fetch_json), resolve_did)
        # A cache the host built (duck-typed), else one from the options.
        given = options.status_cache
        if given is not None and callable(getattr(given, "invalidate", None)) and callable(getattr(given, "get_list", None)):
            self.status_cache = given
        else:
            settings = {"clock": clock, **(dict(given) if given is not None else {})}
            if options.max_clock_skew_ms is not None:
                settings["max_clock_skew_ms"] = options.max_clock_skew_ms
            self.status_cache = StatusCache(**settings)
        check_revocation = options.check_revocation or create_revocation_checker(
            fetch_status_list,
            cache=self.status_cache,
            max_clock_skew_ms=options.max_clock_skew_ms,
            status_list_issuers={issuer: list(urls) for issuer, urls in options.status_list_issuers.items()} if options.status_list_issuers is not None else None,
            trusted_root_issuer=options.resource_owner,
        )

        def resolve_card(did: str) -> Any:
            configured = (options.cards or {}).get(did)
            if configured is not None:
                return configured
            if options.resolve_card is not None:
                return options.resolve_card(did)
            endpoint = card_endpoint_of(resolve_did(did))
            return None if endpoint is None else fetch_json(endpoint)

        self._report = options.report_verification or unrecorded_reporter(options.log)
        self.seams = VerifierSeams(
            resolve_did=resolve_did,
            resolve_did_keys=resolve_did_keys,
            fetch_status_list=fetch_status_list,
            check_revocation=check_revocation,
            resolve_card=resolve_card,
            nonce_store=_ReplaySeam(self.nonce_store),
            clock=clock,
            trusted_issuers=options.trusted_issuers if options.trusted_issuers is not None else "*",
        )
        base: Dict[str, Any] = {"expected_audience": service_did, "resource": options.resource or service_did}
        for name in ("resource_owner", "trusted_root_issuers", "max_chain_length", "skew_seconds", "max_clock_skew_ms", "catalog"):
            value = getattr(options, name)
            if value is not None:
                base[name] = value
        if options.allow_own_authority:
            base["allow_own_authority"] = True
        self.allow_own_authority = options.allow_own_authority
        self._has_catalog = options.catalog is not None
        self._base = base

    def verify(self, proof: Any, *, chain: Any = None, request: Any = None, card: Any = None, **overrides: Any) -> VerifierResult:
        """The verifier on explicit input, with this service's seams and options (``overrides`` are VerifierOptions fields)."""
        return verify(proof, self.seams, VerifierOptions(**{**self._base, **overrides}), chain=chain, request=request, card=card)

    def verify_call(self, call: Mapping[str, Any]) -> Optional[VerifierResult]:
        """Verifies one tool call (``name``, ``input``, ``_meta``, optional ``request``) from its
        ``_meta``; None when it carries neither a request proof nor a chain. ``token_cnf_jkt`` is
        the bearer token's ``cnf.jkt`` for the L3 fusion; ``require_proof=False`` (story C-C) lets
        a chain without a proof verify, at L2 at most; ``live_status=True`` reads every status list
        live, past the status cache (the guard sets it for a tool whose minimum level is L3, story L3-C)."""
        meta = meta_mapping(call.get("_meta"))
        proof = read_request_proof(meta)
        chain = read_carried_chain(meta)
        if proof is None and chain is None:
            return None
        name = call.get("name")
        overrides: Dict[str, Any] = {}
        if call.get("token_cnf_jkt") is not None:
            overrides["token_cnf_jkt"] = call["token_cnf_jkt"]
        if call.get("require_proof") is not None:
            overrides["require_proof"] = call["require_proof"]
        if call.get("live_status") is True:
            overrides["live_status"] = True
        if call.get("catalog") is not None and not self._has_catalog:
            overrides["catalog"] = list(call["catalog"])
        if call.get("own_authority_catalog") is not None and not self._has_catalog:
            overrides["own_authority_catalog"] = list(call["own_authority_catalog"])
        result = self.verify(proof, chain=chain, request=request_of(call), **overrides)
        entry: VerificationReport = {
            "timestamp": datetime.fromtimestamp(self._clock() / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "serviceDid": self.service_did,
            "toolName": name if isinstance(name, str) else None,
            "agentDid": result.agent_did if result.agent_did is not None else result.proof_did,
            "ok": result.ok,
            "level": result.level,
            "proofAssurance": result.proof_assurance,
            "proofFloor": result.proof_floor,
            "l3Minus": result.level == "L3" and result.proof_assurance == "L3-minus",
            "cnfDiagnostics": [warning for warning in result.warnings if warning.startswith("cnf_")],
            "effectiveScopes": list(result.effective_scopes),
            "reasons": list(result.reasons),
            "fresh": result.fresh,
            "chainDepth": result.chain_summary.depth,
        }
        try:
            outcome = self._report(entry)
            if inspect.isawaitable(outcome):
                close = getattr(outcome, "close", None)
                if callable(close):
                    close()
                raise TypeError("report_verification returned an awaitable; pass a sync hook, or use async_helixid_mcp_middleware")
        except Exception as exc:  # noqa: BLE001 - reporting never blocks a call
            if self._options.on_report_error is not None:
                self._options.on_report_error(exc)
        return result


def create_local_verifier(options: Optional[LocalVerifierOptions] = None, **settings: Any) -> LocalVerifier:
    """A :class:`LocalVerifier` from :class:`LocalVerifierOptions`, or from its fields as keywords."""
    if options is None:
        options = LocalVerifierOptions(**settings)
    elif settings:
        raise TypeError("create_local_verifier: pass LocalVerifierOptions or keywords, not both")
    return LocalVerifier(options)
