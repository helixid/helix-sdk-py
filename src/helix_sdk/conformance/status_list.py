# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
#
# The keeper and acceptance rules follow the KYA-OS suite's independent reading
# (decentralized-identity/kya-os-mcp, conformance/status_list.py at a4d7f61,
# MIT licensed, Copyright (c) 2026 KYA-OS).
"""A status list held to SPEC.md section 6.6 for a section 6.2 credential (the
``status-list`` vector category, stories F-2 and L3-C), judged by the code the
verifier's revocation checker runs: the keeper (``helix_sdk.verifier.keeper``),
the list read by ``read_status_list_credential`` (shape, its proof, then its
bits; Bitstring Status List v1.0 or StatusList2021) and ``check_status_entry``.
Mirrors helix-sdk-js ``conformance/status-list.ts``.
"""

from __future__ import annotations

import time
from typing import Any, Mapping, Optional

from ..verifier.keeper import keeper, may_omit_list_id, mistaken_binding, status_configuration
from ..verifier.status import check_status_entry
from ..verifier.status_list_reader import StatusListError, read_status_list_credential
from .legacy import issuer_did, verify_legacy_proof

__all__ = ["keeper", "mistaken_binding", "status_configuration", "status_list_refusal"]


def status_list_refusal(value: Mapping[str, Any], now_ms: Optional[float] = None) -> Optional[str]:
    """None when the credential is active, else why it is refused: the production path (story L3-C).

    The credential's own section 6.2 proof, then the keeper, then
    ``read_status_list_credential`` (shape, the list's proof, then its bits)
    and ``check_status_entry`` (keeper, id, purpose, window, entry, bit), as
    the verifier's revocation checker runs them."""
    now = time.time() * 1000 if now_ms is None else now_ms
    try:
        credential = value["credential"]
        entry = credential.get("credentialStatus")
        if not isinstance(entry, dict):
            return "the credential has no credentialStatus"
        url = entry.get("statusListCredential")
        if not isinstance(url, str):
            return "the entry names no list"
        purpose = entry.get("statusPurpose")
        config = status_configuration(value)
        owner = issuer_did(credential.get("issuer"))
        if not isinstance(purpose, str) or owner is None:
            return "the entry names no purpose or the credential no issuer"
        credential_proof = verify_legacy_proof(credential, value["didDocuments"])
        if credential_proof is not None:
            return "credential: " + credential_proof
        document = value["statusLists"].get(url)
        if document is None:
            return f"status_unavailable: no list at {url}"
        documents = value["didDocuments"]
        read = read_status_list_credential(document, lambda did: documents.get(did))
        kept, _ = keeper(url, owner, config)
        verdict = check_status_entry(entry, owner, read, now_ms=int(now), keeper=kept, may_omit_id=may_omit_list_id(url, owner, config))
        return None if verdict.ok else f"{verdict.code}: {verdict.message}"
    except StatusListError as exc:
        return f"{exc.code}: {exc}"
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OSError, EOFError) as exc:
        return f"unreadable: {exc}"
