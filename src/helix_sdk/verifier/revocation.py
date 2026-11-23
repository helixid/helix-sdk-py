# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Revocation checking (KYA-OS story L3-C points 2, 4 and 6).

A :data:`RevocationChecker` answers ``RevocationVerdict(revoked, fresh)`` per
credential, fail-closed; ``fresh`` only for a live read made for this
verification. :func:`create_revocation_checker` builds one over a
``fetch_status_list`` seam, the keeper configuration and an optional
:class:`StatusCache`; :func:`check_chain_revocation` walks a chain root to
leaf and stops at the first revoked or unresolvable hop. Mirrors helix-sdk-js
``verifier/revocation.ts``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from .codes import ReasonCodes
from .keeper import NO_STATUS_CONFIGURATION, StatusConfiguration, keeper, may_omit_list_id, status_configuration
from .status import FetchStatusList, StatusListRead, check_status_entry, parse_status_list_index
from .status_cache import CachedVerdict, StatusCache, VerdictKey
from .status_list_reader import StatusListError


@dataclass(frozen=True)
class RevocationVerdict:
    revoked: bool
    fresh: bool
    code: Optional[str] = None
    message: Optional[str] = None


@dataclass
class RevocationContext:
    now_ms: int
    scopes: Sequence[str] = ()
    #: The chain's root (``{"issuer", "statusListCredential"}``), for keeper rule 3.
    root: Optional[Mapping[str, Any]] = None
    #: The lists read live during this one verification, by URL.
    reads: Optional[Dict[str, StatusListRead]] = None
    #: Read every list live, past any cached verdict or list: a request that must be fresh (a tool
    #: whose minimum Card level is L3). A live read still refreshes the cache for other requests.
    live: bool = False


#: ``checker(credential, context)``: never raises for a bad list; every failure is ``revoked=True``.
RevocationChecker = Callable[[Mapping[str, Any], RevocationContext], RevocationVerdict]


def _revoked(code: str, message: str) -> RevocationVerdict:
    return RevocationVerdict(True, False, code, message)


def _with_root(base: StatusConfiguration, pinned_root: Optional[str], root: Optional[Mapping[str, Any]]) -> StatusConfiguration:
    if pinned_root is None or root is None or root.get("issuer") != pinned_root or root.get("statusListCredential") is None:
        return base
    return replace(base, root=pinned_root, root_list=root.get("statusListCredential"))


def create_revocation_checker(
    fetch_status_list: FetchStatusList,
    cache: Optional[StatusCache] = None,
    max_clock_skew_ms: Any = None,
    status_list_issuers: Optional[Mapping[str, List[str]]] = None,
    trusted_root_issuer: Optional[str] = None,
) -> RevocationChecker:
    """A checker over ``fetch_status_list``: entry, keeper, cached verdict, cached or live list, entry against list, verdict cached."""
    base = (
        NO_STATUS_CONFIGURATION
        if status_list_issuers is None and trusted_root_issuer is None
        else status_configuration({"statusListIssuers": status_list_issuers, "trustedRootIssuer": trusted_root_issuer})
    )

    def check(credential: Mapping[str, Any], context: RevocationContext) -> RevocationVerdict:
        entry = credential.get("credentialStatus")
        if not isinstance(entry, Mapping) or not isinstance(entry.get("statusListCredential"), str):
            return _revoked(ReasonCodes.STATUS_ENTRY_MALFORMED, "the credential has no usable credentialStatus")
        size = entry.get("statusSize")
        if size is not None and (isinstance(size, bool) or size != 1):
            return _revoked(ReasonCodes.STATUS_ENTRY_MALFORMED, "statusSize must be 1 for a revocation entry")
        if parse_status_list_index(entry.get("statusListIndex")) is None:
            return _revoked(ReasonCodes.STATUS_ENTRY_MALFORMED, "statusListIndex is not a non-negative decimal string")
        url = entry["statusListCredential"]
        issuer = credential.get("issuer")
        config = _with_root(base, trusted_root_issuer, context.root)
        kept, _ = keeper(url, issuer, config)
        credential_id = credential.get("id")
        verdict_key = (
            VerdictKey(credential_id, url, entry.get("statusListIndex"), entry.get("statusPurpose"), issuer, kept)
            if cache is not None and isinstance(credential_id, str) and credential_id
            else None
        )
        if verdict_key is not None and not context.live:
            cached = cache.get_verdict(verdict_key, context.scopes)  # type: ignore[union-attr]
            if cached is not None:
                if cached.revoked:
                    return _revoked(cached.code or ReasonCodes.STATUS_REVOKED, cached.message or "cached: revoked")
                return RevocationVerdict(False, False)

        read = (context.reads or {}).get(url)
        if read is None and cache is not None and not context.live:
            read = cache.get_list(url, context.scopes)
        if read is None:
            try:
                read = fetch_status_list(url)
            except StatusListError as exc:
                return _revoked(exc.code, f"status list could not be read: {exc}")
            except Exception as exc:  # noqa: BLE001 - a seam that cannot answer fails closed
                return _revoked(ReasonCodes.STATUS_UNAVAILABLE, f"status list could not be read: {exc}")
            if read is not None:
                if context.reads is not None:
                    context.reads[url] = read
                if cache is not None:
                    cache.set_list(url, read)
        status = check_status_entry(
            entry,
            issuer,
            read,
            now_ms=context.now_ms,
            max_clock_skew_ms=max_clock_skew_ms,
            keeper=kept,
            may_omit_id=may_omit_list_id(url, issuer, config),
            check_window=read is None or read.fresh is not False,
        )
        verdict = RevocationVerdict(False, status.fresh) if status.ok else _revoked(status.code or ReasonCodes.STATUS_UNAVAILABLE, status.message or "")
        decided = status.ok or status.code == ReasonCodes.STATUS_REVOKED
        if verdict_key is not None and (read is None or read.fresh is not False) and decided:
            cache.set_verdict(verdict_key, CachedVerdict(verdict.revoked, verdict.code, verdict.message))  # type: ignore[union-attr]
        return verdict

    return check


def revocation_checker_of(fetch_status_list: FetchStatusList, max_clock_skew_ms: Any = None) -> RevocationChecker:
    """F-2's plain reading as a checker: no cache, no bindings, every read live."""
    return create_revocation_checker(fetch_status_list, max_clock_skew_ms=max_clock_skew_ms)


@dataclass(frozen=True)
class ChainRevocationResult:
    revoked: bool
    fresh: bool
    index: Optional[int] = None
    code: Optional[str] = None
    message: Optional[str] = None


def check_chain_revocation(hops: Sequence[Mapping[str, Any]], checker: RevocationChecker, context: RevocationContext) -> ChainRevocationResult:
    """Root to leaf, stopping at the first revoked or unresolvable hop; ``fresh`` is the AND of every read."""
    if hops:
        status = hops[0].get("credentialStatus")
        context = replace(
            context,
            root={"issuer": hops[0].get("issuer"), "statusListCredential": status.get("statusListCredential") if isinstance(status, Mapping) else None},
        )
    fresh = True
    for index, hop in enumerate(hops):
        try:
            verdict = checker(hop, context)
        except Exception as exc:  # noqa: BLE001 - a checker that raises fails closed
            verdict = _revoked(ReasonCodes.STATUS_UNAVAILABLE, f"the revocation check failed: {exc}")
        if verdict.revoked:
            return ChainRevocationResult(True, False, index, verdict.code or ReasonCodes.STATUS_REVOKED, verdict.message)
        fresh = fresh and verdict.fresh
    return ChainRevocationResult(False, fresh)
