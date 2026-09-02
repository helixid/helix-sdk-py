# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Local Ed25519 signing primitives, ported from helix-sdk-js's
src/core/keys.ts. This is one of the explicit local-signing carveouts from
docs/proposal-sdk-api-only.md -- private keys never leave this process, so
keygen/sign/derive have no API equivalent to call instead.

Verified byte-for-byte against fixtures/golden-vectors/signing.json (see
tests/test_golden_vectors.py): same private key + same payload produces the
identical hex-encoded public key and signature as helix-sdk-js and
helix-core, because standard Ed25519 (RFC 8032) key derivation and signing
are both deterministic.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional, Union

import nacl.signing

_ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_PKCS8_DER_PREFIX = "302e020100300506032b657004220420"

_RAW_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True)
class KeyPair:
    private_key: str
    public_key: str


def generate_key_pair() -> KeyPair:
    private_key_bytes = os.urandom(32)
    signing_key = nacl.signing.SigningKey(private_key_bytes)
    public_key_bytes = bytes(signing_key.verify_key)
    return KeyPair(private_key=private_key_bytes.hex(), public_key=public_key_bytes.hex())


def derive_public_key(private_key_hex: str) -> str:
    signing_key = nacl.signing.SigningKey(_normalize_ed25519_private_key(private_key_hex))
    return bytes(signing_key.verify_key).hex()


def sign_data(data: Union[str, bytes], private_key_hex: str) -> str:
    message = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    signing_key = nacl.signing.SigningKey(_normalize_ed25519_private_key(private_key_hex))
    return signing_key.sign(message).signature.hex()


def verify_signature(message: bytes, signature_hex: str, public_key_hex: str) -> bool:
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(public_key_hex))
        verify_key.verify(message, bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False


def public_key_to_multibase(public_key_hex: str) -> str:
    public_key_bytes = bytes.fromhex(public_key_hex)
    prefixed = _ED25519_MULTICODEC_PREFIX + public_key_bytes
    return f"z{_base58btc_encode(prefixed)}"


def multibase_to_public_key_hex(multibase: str) -> str:
    if not multibase.startswith("z"):
        raise ValueError("Only base58btc multibase values are supported")
    decoded = _base58btc_decode(multibase[1:])
    return decoded[len(_ED25519_MULTICODEC_PREFIX) :].hex()


def is_supported_ed25519_private_key_hex(private_key_hex: str) -> bool:
    return normalize_ed25519_private_key_hex(private_key_hex) is not None


def normalize_ed25519_private_key_hex(private_key_hex: str) -> Optional[str]:
    value = private_key_hex.strip()
    if _RAW_HEX_RE.match(value):
        return value.lower()
    if (
        len(value) == 96
        and value.lower().startswith(_ED25519_PKCS8_DER_PREFIX)
        and _HEX_RE.match(value)
    ):
        return value[len(_ED25519_PKCS8_DER_PREFIX) :].lower()
    return None


def _normalize_ed25519_private_key(private_key_hex: str) -> bytes:
    normalized = normalize_ed25519_private_key_hex(private_key_hex)
    if normalized is None:
        raise ValueError("Ed25519 private key must be raw 32-byte hex or PKCS8 DER seed hex")
    return bytes.fromhex(normalized)


def _base58btc_encode(data: bytes) -> str:
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
            result += _BASE58_ALPHABET[0]
        else:
            break
    for digit in reversed(digits):
        result += _BASE58_ALPHABET[digit]
    return result


def _base58btc_decode(value: str) -> bytes:
    if len(value) == 0:
        return b""
    byte_list = [0]
    for char in value:
        index = _BASE58_ALPHABET.find(char)
        if index < 0:
            raise ValueError(f"Invalid base58 character: {char}")
        carry = index
        for j in range(len(byte_list)):
            x = byte_list[j] * 58 + carry
            byte_list[j] = x & 0xFF
            carry = x >> 8
        while carry > 0:
            byte_list.append(carry & 0xFF)
            carry >>= 8
    leading_zeroes = 0
    while leading_zeroes < len(value) and value[leading_zeroes] == _BASE58_ALPHABET[0]:
        leading_zeroes += 1
    decoded = bytearray(leading_zeroes + len(byte_list))
    for i, b in enumerate(byte_list):
        decoded[len(decoded) - 1 - i] = b
    return bytes(decoded)
