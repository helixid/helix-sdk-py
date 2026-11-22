# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Caller-presented references and delegation evidence, ported from
helix-core's ``src/core/audit/references.ts``.

A reference a caller presents (a credential id, a grant, consent, scope or
policy reference, a correlation id, a tool name) is untrusted. One that is
empty, over the schema bound, not well-formed UTF-16, or that holds a
character that does not print is recorded as the ``sha256:`` digest of its
bytes (AUDITABILITY.md, Event and privacy model): the digest always fits,
prints as itself in a log line, and, unlike cutting, keeps two long ids with
one beginning apart.

A delegation credential is recorded by the ``delegationRef`` SPEC section
7.8 defines and digested over its signed form, so an event and a proof that
name the credential carry one string, and an auditor holding the
per-credential digests recomputes the chain digest without the credentials.
Lengths are counted in UTF-16 code units, as the JavaScript reference does.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..crypto.jcs import CanonicalJsonError
from .digest import audit_digest, digest_text, utf16_length, utf16_units
from .schema import DIGEST_PATTERN
from .types import AUDIT_DIGEST_DOMAINS

MAX_REFERENCE_LENGTH = 256
"""The schema bound on a reference, in UTF-16 code units."""
MAX_CHAIN_DIGESTS = 256
"""SPEC section 7.8: a chain of more than this many credentials is not listed."""
MAX_CREDENTIAL_NESTING = 64
"""SPEC section 7.8: a credential whose arrays and objects nest deeper has no signed form."""

UNSEEN_CODE_POINT_RANGES: Tuple[Tuple[int, int], ...] = (
    (0x0000, 0x001F),
    (0x007F, 0x009F),
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
"""The code points a reader does not see (SPEC section 7.8; vendored at
``fixtures/kya-os/conformance/unseen-code-points.json``): Unicode 16.0/17.0
general categories Cc, Cf, Zl, Zp and Default_Ignorable_Code_Point. Frozen
here, not taken from the runtime's Unicode tables, so every implementation
hashes the same ids."""

UNKNOWN_DELEGATION_REF = "unknown"
"""What a delegation event names a credential that shows no id (AUDITABILITY.md)."""

_JWS_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
_BASE64_ALPHANUMERIC = re.compile(r"[A-Za-z0-9]")
_BASE64_VALUE: Dict[str, int] = {
    ch: index for index, ch in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
}
_BASE64_VALUE.update({"+": 62, "-": 62, "/": 63, "_": 63})
_ASCII_WHITESPACE = frozenset(" \t\n\r\f")


def _is_unseen_code_point(code: int) -> bool:
    for first, last in UNSEEN_CODE_POINT_RANGES:
        if code < first:
            return False
        if code <= last:
            return True
    return False


def has_unprintable_character(text: str) -> bool:
    """True when ``text`` holds a character that does not print, or a surrogate without its pair."""
    for ch in utf16_units(text):
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF or _is_unseen_code_point(code):
            return True
    return False


def sanitize_reference(value: str, max_length: int = MAX_REFERENCE_LENGTH) -> str:
    """A caller-presented reference as the event records it: verbatim when it
    is non-empty, within ``max_length`` UTF-16 code units and prints as
    itself, otherwise the ``sha256:`` digest of its UTF-8 (WTF-8) bytes."""
    length = utf16_length(value)
    if 0 < length <= max_length and not has_unprintable_character(value):
        return value
    return digest_text(value)


def delegation_reference(id: str) -> str:  # noqa: A002 - the SPEC's name
    """SPEC section 7.8 step 2: the reference for a credential id. The id
    itself, unless it is overlong, holds a character that does not print or a
    lone surrogate, already reads as a ``sha256:`` digest, or is the word
    ``unknown``: then the digest of its bytes, so a reference of digest form
    always stands for the digest of an id and ``unknown`` never stands for a
    credential."""
    length = utf16_length(id)
    if (
        length == 0
        or length > MAX_REFERENCE_LENGTH
        or has_unprintable_character(id)
        or DIGEST_PATTERN.fullmatch(id) is not None
        or id == UNKNOWN_DELEGATION_REF
    ):
        return digest_text(id)
    return id


def _non_empty_string(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def json_text_nesting_depth(text: str, limit: int = MAX_CREDENTIAL_NESTING) -> int:
    """The nesting depth of a JSON text's arrays and objects, counted before
    it is parsed (a depth past ``limit`` returns ``limit + 1`` at once), so a
    value nested to any depth is answered without recursion."""
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > deepest:
                deepest = depth
                if deepest > limit:
                    return limit + 1
        elif ch in "}]":
            depth -= 1
    return deepest


def value_nesting_depth(value: Any, limit: int = MAX_CREDENTIAL_NESTING) -> int:
    """The nesting depth of a parsed value, iteratively: the value itself is level 1."""
    if not isinstance(value, (dict, list, tuple)):
        return 0
    deepest = 0
    stack: List[Tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > deepest:
            deepest = depth
            if deepest > limit:
                return limit + 1
        children = current if isinstance(current, (list, tuple)) else current.values()
        for child in children:
            if isinstance(child, (dict, list, tuple)):
                stack.append((child, depth + 1))
    return deepest


def read_signature_base64(text: str, url_only: bool) -> Optional[bytes]:
    """Base64 bytes read as SPEC section 7.8 step 1 reads them. ``url_only``
    is the JWS reading (base64url alphabet, ``=`` completing the last group
    only); otherwise the looser ``proofValue`` reading (either alphabet,
    ``=`` in any number after the last character). None when the string is
    not a signature under that reading."""
    out = bytearray()
    buffer = 0
    bits = 0
    count = 0
    padding = 0
    for ch in text:
        if ch in _ASCII_WHITESPACE:
            continue
        if ch == "=":
            padding += 1
            continue
        if padding > 0:
            return None
        if url_only and not (ch in "-_" or _BASE64_ALPHANUMERIC.fullmatch(ch)):
            return None
        value = _BASE64_VALUE.get(ch)
        if value is None:
            return None
        count += 1
        buffer = (buffer << 6) | value
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
            buffer &= (1 << bits) - 1
    if count == 0 or count % 4 == 1:
        return None
    if url_only and padding > 0 and padding != (4 - count % 4) % 4:
        return None
    return bytes(out)


def _base64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _signature_from_proof_value(proof: Dict[str, Any]) -> Optional[bytes]:
    proof_value = _non_empty_string(proof.get("proofValue"))
    # The SPEC's loose reading, whatever `proof.type` says: a multibase or
    # base58 value is read by the same rule, so every implementation digests
    # one string to one value.
    return None if proof_value is None else read_signature_base64(proof_value, False)


def credential_signed_form(credential: Any) -> Optional[Dict[str, Any]]:
    """SPEC section 7.8 step 1: the signed form of a credential, ``{jwt,
    signature}`` for a compact VC-JWT and ``{credential, signature}`` for a
    credential object, or None when the value has none."""
    if isinstance(credential, str):
        segments = credential.split(".")
        if len(segments) != 3:
            return None
        header, payload, signature = segments
        if _JWS_SEGMENT.fullmatch(header) is None or _JWS_SEGMENT.fullmatch(payload) is None:
            return None
        data = read_signature_base64(signature, True)
        if not data:
            return None
        return {"jwt": f"{header}.{payload}", "signature": _base64url_no_pad(data)}
    if not isinstance(credential, dict):
        return None
    if value_nesting_depth(credential) > MAX_CREDENTIAL_NESTING:
        return None
    proof = credential.get("proof")
    if not isinstance(proof, dict):
        return None
    data = _signature_from_proof_value(proof)
    if not data:
        return None
    rest = {name: value for name, value in credential.items() if name != "proof"}
    return {"credential": rest, "signature": _base64url_no_pad(data)}


def credential_digest(credential: Any) -> Optional[str]:
    """SPEC section 7.8 step 2: the digest over a credential's signed form, or None when it has none."""
    signed_form = credential_signed_form(credential)
    if signed_form is None:
        return None
    try:
        return audit_digest(AUDIT_DIGEST_DOMAINS["delegationCredential"], signed_form)
    except CanonicalJsonError:
        return None


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _decode_base64url_segment(segment: str) -> bytes:
    """A JWS segment's bytes as Node's lenient base64url decoder reads them:
    padding supplied, a trailing lone sextet dropped."""
    if len(segment) % 4 == 1:
        segment = segment[:-1]
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _read_jwt_payload(jwt: str) -> Optional[Dict[str, Any]]:
    segments = jwt.split(".")
    if len(segments) != 3:
        return None
    payload = segments[1]
    if _JWS_SEGMENT.fullmatch(payload) is None:
        return None
    try:
        text = _decode_base64url_segment(payload).decode("utf-8")
    except (UnicodeDecodeError, binascii.Error):
        return None
    if text.startswith("﻿"):
        return None
    if json_text_nesting_depth(text) > MAX_CREDENTIAL_NESTING:
        return None
    try:
        parsed = json.loads(text, parse_constant=_reject_constant)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _delegation_id_of(obj: Dict[str, Any]) -> Optional[str]:
    subject = obj.get("credentialSubject")
    if not isinstance(subject, dict):
        return None
    delegation = subject.get("delegation")
    return _non_empty_string(delegation.get("id")) if isinstance(delegation, dict) else None


def credential_shown_id(credential: Any) -> Optional[str]:
    """SPEC section 7.8 step 1: the id a credential shows in the form it was presented in, or None."""
    if isinstance(credential, str):
        payload = _read_jwt_payload(credential)
        if payload is None:
            return None
        vc = payload.get("vc")
        if not isinstance(vc, dict):
            return None
        return _non_empty_string(vc.get("id")) or _non_empty_string(payload.get("jti")) or _delegation_id_of(vc)
    if not isinstance(credential, dict):
        return None
    return _non_empty_string(credential.get("id")) or _delegation_id_of(credential)


def delegation_ref(credential: Any) -> Optional[str]:
    """SPEC section 7.8: the ``delegationRef`` of a credential, or None when it shows no id."""
    shown = credential_shown_id(credential)
    return None if shown is None else delegation_reference(shown)


def delegation_chain_digests(chain_root_first: Sequence[Any]) -> Optional[List[str]]:
    """One digest per credential of a chain, root first, as
    ``delegationChainDigests`` lists them; None when a credential has no
    signed form or the chain is longer than 256 (SPEC section 7.8: the events
    then carry the presented credential's digest only)."""
    if len(chain_root_first) == 0 or len(chain_root_first) > MAX_CHAIN_DIGESTS:
        return None
    digests: List[str] = []
    for credential in chain_root_first:
        digest = credential_digest(credential)
        if digest is None:
            return None
        digests.append(digest)
    return digests


def delegation_chain_digest(digests: Sequence[str]) -> str:
    """SPEC section 7.8 step 3: the chain digest over the array of credential digests, root first."""
    return audit_digest(AUDIT_DIGEST_DOMAINS["delegationChain"], list(digests))
