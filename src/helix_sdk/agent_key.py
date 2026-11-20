# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The agent's own key (KYA-OS story L1-A), byte-compatible with helix-sdk-js's
src/core/agent-key.ts and helix-core's src/core/did/document.ts: generated
here, on the client, and never sent anywhere. What leaves the process is the
public half only, as an OKP JWK ({"kty": "OKP", "crv": "Ed25519", "x": ...})
that Helix publishes in the agent's did:web document, and the did:key form
of the same key.

- generate_agent_key(): a fresh Ed25519 key. ``private_key_hex`` is the
  32-byte seed, the value to put in the environment secret a Signer reads
  (HELIX_SIGNING_KEY for EnvSigner); ``public_key_hex`` the public key.
- to_public_key_jwk(): the public key as RFC 8037 writes it (L1.8).
- to_did_key(): ``did:key:z6Mk...``, multicodec 0xed01 then base58btc (L1.1).
- agent_key_registration(): the body of POST /v1/agents/{did}/keys, checked
  to carry no private material (self-custody invariant, rule 7).
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Union

import nacl.signing

from .keys import _normalize_ed25519_private_key

DEFAULT_AGENT_KEY_ID = "key-1"

_ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])
_ED25519_PUBLIC_KEY_LENGTH = 32
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: i for i, char in enumerate(_BASE58_ALPHABET)}
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
# Member names that only ever carry private material.
_PRIVATE_MATERIAL_MEMBERS = frozenset(["d", "privateKey", "privateKeyHex", "private_key", "seed", "secret"])


@dataclass(frozen=True)
class AgentKey:
    """The 32-byte seed (keep it in the Signer's secret; never send it) and the public key, hex."""

    private_key_hex: str
    public_key_hex: str


def generate_agent_key() -> AgentKey:
    """A fresh Ed25519 key, generated in this process."""
    seed = os.urandom(32)
    public_key = bytes(nacl.signing.SigningKey(seed).verify_key)
    return AgentKey(private_key_hex=seed.hex(), public_key_hex=public_key.hex())


def agent_public_key(private_key_hex: str) -> bytes:
    """The public key of a seed (raw 32-byte hex, or the PKCS8 seed hex the environment may hold)."""
    return bytes(nacl.signing.SigningKey(_normalize_ed25519_private_key(private_key_hex)).verify_key)


def _public_key_bytes(public_key: Union[str, bytes, bytearray]) -> bytes:
    if isinstance(public_key, str):
        if _HEX64.match(public_key) is None:
            raise ValueError("An Ed25519 public key is 32 bytes (64 hex characters)")
        return bytes.fromhex(public_key)
    raw = bytes(public_key)
    if len(raw) != _ED25519_PUBLIC_KEY_LENGTH:
        raise ValueError("An Ed25519 public key is 32 bytes (64 hex characters)")
    return raw


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def to_public_key_jwk(public_key: Union[str, bytes, bytearray], kid: Optional[str] = None) -> Dict[str, Any]:
    """{"kty": "OKP", "crv": "Ed25519", "x": ...} of the public key; ``kid`` only when given."""
    jwk: Dict[str, Any] = {"kty": "OKP", "crv": "Ed25519", "x": base64url_encode(_public_key_bytes(public_key))}
    if kid is not None:
        jwk["kid"] = kid
    return jwk


def to_did_key(public_key: Union[str, bytes, bytearray]) -> str:
    """``did:key:z6Mk...``: multicodec 0xed01 plus the key, base58btc, multibase ``z``."""
    return "did:key:z" + encode_base58btc(_ED25519_MULTICODEC_PREFIX + _public_key_bytes(public_key))


def public_key_from_did_key(did: str) -> Optional[bytes]:
    """The raw public key a did:key names, or None when it is not an Ed25519 did:key that decodes."""
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        return None
    try:
        decoded = decode_base58btc(did[len("did:key:z"):])
    except ValueError:
        return None
    if len(decoded) != len(_ED25519_MULTICODEC_PREFIX) + _ED25519_PUBLIC_KEY_LENGTH:
        return None
    if decoded[: len(_ED25519_MULTICODEC_PREFIX)] != _ED25519_MULTICODEC_PREFIX:
        return None
    return decoded[len(_ED25519_MULTICODEC_PREFIX):]


def assert_no_private_material(value: Any, path: str = "") -> None:
    """Raises ValueError when ``value``, at any depth, has a member that only ever
    carries private material (``d``, ``privateKey``, ``seed``, ...). What the SDK
    sends to the API goes through this first."""
    if isinstance(value, Mapping):
        for name, member in value.items():
            here = f"{path}.{name}" if path else str(name)
            if name in _PRIVATE_MATERIAL_MEMBERS:
                raise ValueError(f"Private key material must never leave the client (found {here})")
            assert_no_private_material(member, here)
    elif isinstance(value, (list, tuple)):
        for index, member in enumerate(value):
            assert_no_private_material(member, f"{path}.{index}" if path else str(index))


def public_key_jwk_bytes(jwk: Any) -> bytes:
    """The 32 raw bytes of a public Ed25519 JWK; raises ValueError for anything else, a ``d`` member above all."""
    if not isinstance(jwk, Mapping):
        raise ValueError("publicKeyJwk must be a JSON object")
    assert_no_private_material(jwk)
    foreign = [name for name in jwk if name not in ("kty", "crv", "x", "kid")]
    if foreign:
        raise ValueError(
            f"publicKeyJwk carries unexpected members ({', '.join(foreign)}); only kty, crv, x and kid are allowed"
        )
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("publicKeyJwk must be an OKP key on the Ed25519 curve")
    if "kid" in jwk and not isinstance(jwk["kid"], str):
        raise ValueError("publicKeyJwk kid must be a string")
    x = jwk.get("x")
    if not isinstance(x, str) or _BASE64URL.fullmatch(x) is None or len(x) % 4 == 1:
        raise ValueError("publicKeyJwk x must be strict base64url")
    raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    if len(raw) != _ED25519_PUBLIC_KEY_LENGTH:
        raise ValueError("publicKeyJwk x must be a 32-byte Ed25519 public key")
    return raw


def agent_key_registration(
    public_key: Union[str, bytes, bytearray, Mapping[str, Any]], kid: Optional[str] = None
) -> Dict[str, Any]:
    """The body of POST /v1/agents/{did}/keys: the public JWK (kty, crv, x, nothing
    else) and the verification-method fragment. Takes the public key as hex,
    bytes or JWK; a JWK with ``d`` or any other member is refused."""
    raw = public_key_jwk_bytes(public_key) if isinstance(public_key, Mapping) else _public_key_bytes(public_key)
    fragment = DEFAULT_AGENT_KEY_ID if kid is None else kid
    if not isinstance(fragment, str) or not fragment:
        raise ValueError("kid must be a non-empty verification-method fragment")
    body = {"publicKeyJwk": to_public_key_jwk(raw), "kid": fragment}
    assert_no_private_material(body)
    return body


# -- base58btc (conformance L1.9) ----------------------------------------------


def encode_base58btc(data: bytes) -> str:
    """base58btc: every leading zero byte is one leading ``1``, the rest the number in base 58."""
    zeros = 0
    while zeros < len(data) and data[zeros] == 0:
        zeros += 1
    n = int.from_bytes(data[zeros:], "big") if len(data) > zeros else 0
    digits = ""
    while n > 0:
        n, remainder = divmod(n, 58)
        digits = _BASE58_ALPHABET[remainder] + digits
    return _BASE58_ALPHABET[0] * zeros + digits


def decode_base58btc(value: str) -> bytes:
    zeros = 0
    while zeros < len(value) and value[zeros] == _BASE58_ALPHABET[0]:
        zeros += 1
    n = 0
    for char in value[zeros:]:
        digit = _BASE58_INDEX.get(char)
        if digit is None:
            raise ValueError(f"Invalid base58 character: {char}")
        n = n * 58 + digit
    rest = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    return b"\x00" * zeros + rest
