# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
#
# The keeper rules follow the KYA-OS suite's independent reading
# (decentralized-identity/kya-os-mcp, conformance/status_list.py at a4d7f61,
# MIT licensed, Copyright (c) 2026 KYA-OS).
"""Who keeps a status-list URL (SPEC.md section 6.6; KYA-OS stories F-2, L3-C).

Every ``statusListCredential`` URL has exactly one keeper, decided before the
list is fetched, from the verifier's configuration and the signed
credentials, never from the list: (1) the issuer the configuration binds the
exact URL to; (2) the issuer it binds the URL's ``https:`` origin to; (3) the
pinned root, when its own credential names the same URL; (4) the
credential's own issuer. Comparisons are on the bytes as written. Mirrors
helix-sdk-js ``verifier/keeper.ts``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

_ORIGIN = re.compile(r"^https://[a-z0-9.-]+(:[0-9]{1,5})?$")
_ORIGIN_IN_ANY_FORM = re.compile(r"^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(/?)$")


@dataclass(frozen=True)
class StatusConfiguration:
    root: Optional[str] = None
    root_list: Optional[str] = None
    services: Mapping[str, List[str]] = field(default_factory=dict)


NO_STATUS_CONFIGURATION = StatusConfiguration()


def mistaken_binding(binding: str) -> Optional[str]:
    """The words a binding section 6.6 says is mistaken is refused in, or None."""
    written = _ORIGIN_IN_ANY_FORM.match(binding)
    if written is not None and written.group(1) == "/":
        return 'statusListIssuers binds an origin followed by "/"'
    if written is not None and re.search(r"[A-Z]", binding):
        return "statusListIssuers binds an origin whose host is not in lower case"
    if binding.endswith("/"):
        return 'statusListIssuers binds a URL that ends in "/"'
    return None


def status_configuration(value: Mapping[str, Any]) -> StatusConfiguration:
    """The configuration an input states (``trustedRootIssuer``, ``trustedRootStatusList``, ``statusListIssuers``); raises ``ValueError`` when not well formed."""
    for member in ("trustedRootIssuer", "trustedRootStatusList"):
        stated = value.get(member)
        if stated is not None and (not isinstance(stated, str) or not stated):
            raise ValueError(f"{member} is not a non-empty string")
    services = value.get("statusListIssuers") or {}
    if not isinstance(services, Mapping):
        raise ValueError("statusListIssuers does not map issuers to lists of URLs")
    bound: Dict[str, str] = {}
    for did, bindings in services.items():
        if did == "" or not isinstance(bindings, list):
            raise ValueError("statusListIssuers does not map issuers to lists of URLs")
        for binding in bindings:
            if not isinstance(binding, str) or re.match(r"^https?://", binding) is None:
                raise ValueError("statusListIssuers does not map issuers to lists of URLs")
            mistaken = mistaken_binding(binding)
            if mistaken is not None:
                raise ValueError(mistaken)
            if bound.get(binding, did) != did:
                raise ValueError("statusListIssuers binds one URL to two issuers")
            bound[binding] = did
    return StatusConfiguration(value.get("trustedRootIssuer"), value.get("trustedRootStatusList"), dict(services))


def keeper(url: str, owner: str, config: StatusConfiguration) -> Tuple[str, bool]:
    """The one issuer whose list is read at ``url`` for ``owner``'s credential, and whether no binding names it."""
    for did, bindings in config.services.items():
        if url in bindings:
            return did, False
    for did, bindings in config.services.items():
        for binding in bindings:
            if _ORIGIN.match(binding) and any(url.startswith(binding + mark) for mark in ("/", "?", "#")):
                return did, False
    if config.root is not None and config.root_list == url:
        return config.root, True
    return owner, True


def may_omit_list_id(url: str, owner: str, config: StatusConfiguration) -> bool:
    """Whether a list stating no ``id`` may be read at ``url`` for ``owner``'s credential."""
    did, unbound = keeper(url, owner, config)
    if not unbound or did != owner:
        return False
    if config.root is not None and config.root != owner:
        return False
    return all(issuer == owner for issuer in config.services)
