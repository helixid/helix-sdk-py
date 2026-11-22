# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""SPEC.md section 7.8 delegation binding (KYA-OS story F-2): a credential's
signed form, the credential and chain digests, the id a credential shows and
the reference it goes by. The Python twin of helix-sdk-js
``kyaos/conformance/delegation-binding.ts``; every reading is the one the
SDK's audit trail records a delegation by.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from ..crypto.jcs import CanonicalJsonError, canonicalize

MAX_CREDENTIAL_NESTING = 64
MAX_REFERENCE_LENGTH = 256
CREDENTIAL_DIGEST_DOMAIN = "org.kya-os.delegation.credential.v1"
CHAIN_DIGEST_DOMAIN = "org.kya-os.delegation.chain.v1"
_DIGEST_FORM = re.compile(r"sha256:[0-9a-f]{64}")

UNSEEN_CODE_POINT_RANGES = (
    (0x0000, 0x001F), (0x007F, 0x009F), (0x00AD, 0x00AD), (0x034F, 0x034F), (0x0600, 0x0605), (0x061C, 0x061C),
    (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x2028, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
_DOES_NOT_PRINT = re.compile(
    "[" + "".join(f"\\U{first:08x}-\\U{last:08x}" for first, last in UNSEEN_CODE_POINT_RANGES + ((0xD800, 0xDFFF),)) + "]"
)

_BASE64_VALUE = {character: value for value, character in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")}
_BASE64_EITHER = {**_BASE64_VALUE, "+": 62, "/": 63}


def read_signature_base64(text: str, url_only: bool) -> Optional[bytes]:
    """Base64 read as section 7.8 step 1 reads it; None when ``text`` is not one.

    ``url_only``: a VC-JWT segment (base64url only, ``=`` completing the last
    group alone). Otherwise a ``proofValue`` (either alphabet, ``=`` in any
    number after the last character). ASCII whitespace is passed over and
    bits short of a byte are dropped.
    """
    if not isinstance(text, str):
        return None
    alphabet = _BASE64_VALUE if url_only else _BASE64_EITHER
    out = bytearray()
    buffer = bits = count = padding = 0
    for character in text:
        if character in " \t\n\r\f":
            continue
        if character == "=":
            padding += 1
            continue
        value = None if padding else alphabet.get(character)
        if value is None:
            return None
        count += 1
        buffer = (buffer << 6) | value
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
            buffer &= (1 << bits) - 1
    if url_only:
        last_group = count % 4
        if last_group == 1 or (padding and (last_group == 0 or padding != 4 - last_group)):
            return None
    return bytes(out)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def domain_digest(domain: str, value: Any) -> str:
    """``sha256:`` of ``UTF8(domain) || 0x00 || UTF8(JCS(value))``; raises CanonicalJsonError for no JCS form."""
    return sha256_digest(domain.encode("utf-8") + b"\x00" + canonicalize(value).encode("utf-8"))


def json_text_nesting_depth(text: str, limit: int = MAX_CREDENTIAL_NESTING) -> int:
    depth = deepest = 0
    in_string = escaped = False
    for character in text:
        if escaped:
            escaped = False
        elif in_string:
            if character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            deepest = max(deepest, depth)
            if deepest > limit:
                return limit + 1
        elif character in "]}":
            depth -= 1
    return deepest


def value_nesting_depth(value: Any, limit: int = MAX_CREDENTIAL_NESTING) -> int:
    if not isinstance(value, (list, dict)):
        return 0
    deepest = 0
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        deepest = max(deepest, depth)
        if deepest > limit:
            return limit + 1
        for child in item.values() if isinstance(item, dict) else item:
            if isinstance(child, (list, dict)):
                stack.append((child, depth + 1))
    return deepest


def _json_int(literal: str) -> Any:
    """An integer literal read as JSON.parse reads it: exactly up to 640 digits, past that as an infinite double."""
    return int(literal) if len(literal) <= 640 else float(literal)


def read_json(text: str) -> Any:
    """JSON as JSON.parse reads it: the last of members that share a name kept, no NaN or Infinity, numbers of any length."""
    def refuse(constant: str) -> Any:
        raise ValueError(f"{constant} is not JSON")

    return json.loads(text, parse_constant=refuse, parse_int=_json_int)


def credential_signed_form(credential: Any) -> Optional[Dict[str, Any]]:
    """Section 7.8 step 1: the signed form of a credential, or None when it has none."""
    if isinstance(credential, str):
        segments = credential.split(".")
        if len(segments) != 3 or not segments[0] or not segments[1]:
            return None
        signature = read_signature_base64(segments[2], True)
        if not signature:
            return None
        return {"jwt": f"{segments[0]}.{segments[1]}", "signature": _b64url(signature)}
    if not isinstance(credential, dict):
        return None
    proof = credential.get("proof")
    if not isinstance(proof, dict):
        return None
    if value_nesting_depth(credential) > MAX_CREDENTIAL_NESTING:
        return None
    signature = read_signature_base64(proof.get("proofValue"), False) if isinstance(proof.get("proofValue"), str) else None
    if not signature:
        return None
    return {"credential": {key: value for key, value in credential.items() if key != "proof"}, "signature": _b64url(signature)}


def credential_digest(credential: Any) -> Optional[str]:
    form = credential_signed_form(credential)
    if form is None:
        return None
    try:
        return domain_digest(CREDENTIAL_DIGEST_DOMAIN, form)
    except CanonicalJsonError:
        return None


def chain_digest(chain: Any) -> Optional[str]:
    """Section 7.8 step 3: over the credentials' digests root first; None when one has no signed form."""
    if not isinstance(chain, list) or not chain:
        return None
    digests: List[str] = []
    for credential in chain:
        digest = credential_digest(credential)
        if digest is None:
            return None
        digests.append(digest)
    return domain_digest(CHAIN_DIGEST_DOMAIN, digests)


def _non_empty(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _delegation_id(value: Dict[str, Any]) -> Optional[str]:
    subject = value.get("credentialSubject")
    delegation = subject.get("delegation") if isinstance(subject, dict) else None
    return _non_empty(delegation.get("id")) if isinstance(delegation, dict) else None


def credential_shown_id(credential: Any) -> Optional[str]:
    """Section 7.8 step 1: the id a credential shows in the form it was presented in, or None."""
    if isinstance(credential, str):
        segments = credential.split(".")
        if len(segments) != 3:
            return None
        payload_bytes = read_signature_base64(segments[1], True)
        if payload_bytes is None:
            return None
        try:
            text = payload_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if text.startswith("﻿") or json_text_nesting_depth(text) > MAX_CREDENTIAL_NESTING:
            return None
        try:
            claims = read_json(text)
        except ValueError:
            return None
        vc = claims.get("vc") if isinstance(claims, dict) else None
        if not isinstance(vc, dict):
            return None
        return _non_empty(vc.get("id")) or _non_empty(claims.get("jti")) or _delegation_id(vc)
    if not isinstance(credential, dict):
        return None
    return _non_empty(credential.get("id")) or _delegation_id(credential)


def delegation_reference(identifier: str) -> str:
    """Section 7.8 step 2: the id itself, or the SHA-256 of its UTF-8 (WTF-8) bytes."""
    code_units = identifier.encode("utf-16-le", "surrogatepass")
    as_read = code_units.decode("utf-16-le", "surrogatepass")
    verbatim = (
        len(code_units) // 2 <= MAX_REFERENCE_LENGTH
        and not _DOES_NOT_PRINT.search(as_read)
        and not _DIGEST_FORM.fullmatch(as_read)
        and as_read != "unknown"
    )
    return as_read if verbatim else sha256_digest(as_read.encode("utf-8", "surrogatepass"))


def delegation_ref(credential: Any) -> Optional[str]:
    identifier = credential_shown_id(credential)
    return None if identifier is None else delegation_reference(identifier)
