# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Canonical JSON, SHA-256 hashing, and Ed25519 sign/verify over hash bytes,
ported from helix-sdk-js's src/core/vp-crypto.ts.

toCanonicalJson/hashCanonicalPayload/signBytes are three of the four
local-signing carveouts from docs/proposal-sdk-api-only.md (the fourth is
VPBuilder.sign() itself, in vp_builder.py, which calls these).

Verified byte-for-byte against fixtures/golden-vectors/canonical-json.json
and signing.json -- see tests/test_golden_vectors.py. json.dumps with
separators=(",", ":") and sort_keys applied recursively (not json.dumps'
own sort_keys, which does not recurse into nested containers reliably
across dict/list mixes the way this hand-rolled sort does) reproduces
JSON.stringify(sortValue(x)) exactly for every vector, including nested
objects, arrays, unicode, and numeric edge cases.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import nacl.signing

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _sort_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_sort_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _sort_value(value[key]) for key in sorted(value.keys())}
    return value


def to_canonical_json(value: Any) -> str:
    return json.dumps(_sort_value(value), separators=(",", ":"), ensure_ascii=False)


def hash_canonical_payload(payload: Any) -> bytes:
    canonical = to_canonical_json(payload)
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def sign_bytes(hash_bytes: bytes, private_key_hex: str) -> str:
    # Local import to avoid a circular import with keys.py at module load time.
    from .keys import _normalize_ed25519_private_key

    signing_key = nacl.signing.SigningKey(_normalize_ed25519_private_key(private_key_hex))
    return signing_key.sign(hash_bytes).signature.hex()


def verify_signature(hash_bytes: bytes, signature_hex: str, public_key_hex: str) -> bool:
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(public_key_hex))
        verify_key.verify(hash_bytes, bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False


def base58btc_encode(data: bytes) -> str:
    if len(data) == 0:
        return ""
    digits = [0]
    for byte in data:
        carry = byte
        for i in range(len(digits)):
            x = digits[i] * 256 + carry
            digits[i] = x % 58
            carry = x // 58
        while carry > 0:
            digits.append(carry % 58)
            carry //= 58
    result = ""
    for byte in data:
        if byte == 0:
            result += _ALPHABET[0]
        else:
            break
    for digit in reversed(digits):
        result += _ALPHABET[digit]
    return result


def base58btc_decode(value: str) -> bytes:
    if len(value) == 0:
        return b""
    byte_list = [0]
    for char in value:
        index = _ALPHABET.find(char)
        if index < 0:
            raise ValueError("Invalid base58 string")
        carry = index
        for j in range(len(byte_list)):
            x = byte_list[j] * 58 + carry
            byte_list[j] = x & 0xFF
            carry = x >> 8
        while carry > 0:
            byte_list.append(carry & 0xFF)
            carry >>= 8
    leading_zeroes = 0
    while leading_zeroes < len(value) and value[leading_zeroes] == _ALPHABET[0]:
        leading_zeroes += 1
    decoded = bytearray(leading_zeroes + len(byte_list))
    for i, b in enumerate(byte_list):
        decoded[len(decoded) - 1 - i] = b
    return bytes(decoded)
