# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Domain-separated digests (AUDITABILITY.md, Cryptographic suites): the
SHA-256 of ``UTF8(<domain>) || 0x00 || UTF8(JCS(value))``, written in the
``sha256:<hex>`` form of SPEC section 7.3. JCS is ``helix_sdk.crypto.jcs``;
the audit-integrity vectors fix the event digest and
``fixtures/kya-os-helix/audit-events.json`` fixes the rest. Ported from
helix-core's ``src/core/audit/digest.ts``.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from ..crypto.jcs import canonicalize
from .types import AUDIT_DIGEST_DOMAINS, AuditProducerEvent


def digest_bytes(data: bytes) -> str:
    """``sha256:<hex>`` of raw bytes (evidence ciphertext, authenticated data)."""
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


def utf16_units(text: str) -> str:
    """``text`` with every high+low surrogate pair joined into one code point,
    so a string built from UTF-16 units reads as JavaScript reads it. A lone
    surrogate stays a lone surrogate."""
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def utf16_length(text: str) -> int:
    """The length JavaScript reports: UTF-16 code units, the unit of every schema bound."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def wtf8_bytes(text: str) -> bytes:
    """The bytes of a string as UTF-8, or WTF-8 when it is not well-formed: a
    surrogate without its pair is written in three bytes as a code point of
    the same value (SPEC section 7.8), so every string has bytes to digest."""
    return utf16_units(text).encode("utf-8", "surrogatepass")


def digest_text(text: str) -> str:
    """``sha256:<hex>`` of a string's UTF-8 (WTF-8 for a lone surrogate) bytes: how an overlong or malformed reference is recorded."""
    return digest_bytes(wtf8_bytes(text))


def audit_digest(domain: str, value: Any) -> str:
    """The domain-separated digest of a JSON value. Raises ``CanonicalJsonError`` for a value with no RFC 8785 form."""
    if not domain or "\0" in domain:
        raise TypeError("Audit digest domain must be non-empty and cannot contain NUL")
    return digest_bytes(domain.encode("utf-8") + b"\0" + canonicalize(value).encode("utf-8"))


def audit_event_digest(event: AuditProducerEvent) -> str:
    """The event digest: domain ``org.kya-os.audit.event.v1`` over the event's canonical form."""
    return audit_digest(AUDIT_DIGEST_DOMAINS["event"], event)


def keyed_commitment_value(key: bytes, value: Any) -> str:
    """A keyed commitment value: HMAC-SHA256 under a tenant key over the JCS
    of ``value``, so an index over low-entropy identifiers (an account id, an
    email) cannot be reversed by dictionary without the key."""
    return "sha256:" + hmac.new(bytes(key), canonicalize(value).encode("utf-8"), hashlib.sha256).hexdigest()
