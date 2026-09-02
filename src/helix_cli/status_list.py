# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Bitstring status list encoding, ported from helix-sdk-js's
cli/src/core/status-list-schema.ts, itself duplicated verbatim from
helix-core's status-list/schema.ts (see docs/proposal-retire-core-package.md).
Used by the CLI's local/offline issuer-ops flow -- no API call involved.
"""

from __future__ import annotations

import base64
import gzip


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_status_list(size: int = 131072) -> str:
    buffer = bytes(-(-size // 8))  # ceil(size / 8) zero bytes
    compressed = gzip.compress(buffer)
    return _base64url_encode(compressed)


def set_bit(encoded_list: str, index: int, value: int) -> str:
    compressed = _base64url_decode(encoded_list)
    buffer = bytearray(gzip.decompress(compressed))

    byte_index = index // 8
    bit_index = index % 8
    if byte_index >= len(buffer):
        raise ValueError("Status list index out of bounds")

    if value == 1:
        buffer[byte_index] |= 1 << (7 - bit_index)
    else:
        buffer[byte_index] &= ~(1 << (7 - bit_index)) & 0xFF

    new_compressed = gzip.compress(bytes(buffer))
    return _base64url_encode(new_compressed)


def get_bit(encoded_list: str, index: int) -> int:
    compressed = _base64url_decode(encoded_list)
    buffer = gzip.decompress(compressed)

    byte_index = index // 8
    bit_index = index % 8
    if byte_index >= len(buffer):
        raise ValueError("Status list index out of bounds")

    return (buffer[byte_index] >> (7 - bit_index)) & 1


def get_status_list_length(encoded_list: str) -> int:
    compressed = _base64url_decode(encoded_list)
    buffer = gzip.decompress(compressed)
    return len(buffer) * 8
