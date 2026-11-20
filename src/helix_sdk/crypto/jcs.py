# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""RFC 8785 (JSON Canonicalization Scheme) and the KYA-OS hash format.

``canonicalize(value)`` writes a JSON value the one way RFC 8785 allows:
object members sorted by the UTF-16 code units of their names, no
whitespace, numbers as ECMAScript ``Number::toString`` writes them, strings
escaped as ``JSON.stringify`` escapes them. ``hash_json(value)`` is the
SHA-256 of the UTF-8 bytes of that text, written ``sha256:<64 lowercase
hex>``, the form KYA-OS compares everywhere a hash travels (SPEC 7.3,
CONFORMANCE L1.2).

This is the twin of helix-core's ``src/core/crypto/jcs.ts`` and produces the
same bytes for the same JSON value; ``helix-core/fixtures/kya-os-helix/jcs.json``
is the contract between them. Like the JS side it is strict: a value with no
single JSON form (a non-finite float, an integer beyond 2**53 - 1, a lone
surrogate, a non-str key, a cycle, or any type that is not None, bool, int,
float, str, list, tuple or dict) raises ``CanonicalJsonError`` instead of
being coerced. Where it differs from a plain ``json.dumps`` is number
formatting: Python's ``repr`` yields the same shortest round-trip digits as
ECMAScript but lays them out differently (``1e-07`` against ``1e-7``,
``1e+16`` against ``10000000000000000``), so the digits are re-laid out per
ECMA-262 Number::toString.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, List, Set

__all__ = ["CanonicalJsonError", "canonicalize", "hash_json"]

_MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalJsonError(TypeError):
    """Raised for a value that has no RFC 8785 canonical form."""

    def __init__(self, problem: str, path: str) -> None:
        super().__init__(f"Cannot canonicalize {problem} at {path}")


def _write_string(text: str, path: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonicalJsonError("a string with a lone surrogate", path) from None
    # json.dumps escapes exactly what JSON.stringify escapes: the quote, the
    # backslash, \b \f \n \r \t, and every other control character below
    # U+0020 as a lowercase \u00XX. Everything else, including U+007F and
    # U+2028, is written as itself.
    return json.dumps(text, ensure_ascii=False)


def _es_number_layout(digits: str, n: int) -> str:
    """ECMA-262 Number::toString step 6 onward, for digits ``s`` (no leading or
    trailing zeros) and decimal exponent ``n`` such that the value is
    ``0.<digits> * 10**n``. Every admitted magnitude is below 2**53, so
    ``n <= 16``: the ``n > 21`` case, and with it a positive exponent, never
    arises."""
    k = len(digits)
    if k <= n:
        return digits + "0" * (n - k)
    if n > 0:
        return digits[:n] + "." + digits[n:]
    if n > -6:
        return "0." + "0" * (-n) + digits
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{mantissa}e-{1 - n}"


def _write_float(value: float, path: str) -> str:
    if math.isnan(value) or math.isinf(value):
        raise CanonicalJsonError(f"a non-finite number ({value!r})", path)
    if value.is_integer() and abs(value) > _MAX_SAFE_INTEGER:
        raise CanonicalJsonError(f"an integer outside the safe range ({value!r})", path)
    if value == 0.0:
        return "0"  # -0.0 included: Number::toString writes -0 as 0.
    sign = "-" if value < 0 else ""
    # repr gives the shortest digit string that round-trips, the same digits
    # ECMAScript picks (and the same tie-break: the candidate closest to the
    # true value). Only the layout is redone.
    mantissa, _, exponent_text = repr(abs(value)).partition("e")
    exponent = int(exponent_text) if exponent_text else 0
    integer_part, _, fraction_part = mantissa.partition(".")
    all_digits = integer_part + fraction_part
    point = len(integer_part) + exponent  # position of the decimal point within all_digits
    without_leading = all_digits.lstrip("0")
    digits = without_leading.rstrip("0")
    n = point - (len(all_digits) - len(without_leading))
    return sign + _es_number_layout(digits, n)


def _write_int(value: int, path: str) -> str:
    if abs(value) > _MAX_SAFE_INTEGER:
        raise CanonicalJsonError(f"an integer outside the safe range ({value})", path)
    return str(value)


def _write(value: Any, path: str, ancestors: Set[int]) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _write_string(value, path)
    if isinstance(value, int):
        return _write_int(value, path)
    if isinstance(value, float):
        return _write_float(value, path)
    if isinstance(value, (list, tuple)):
        return _write_array(value, path, ancestors)
    if isinstance(value, dict):
        return _write_object(value, path, ancestors)
    raise CanonicalJsonError(f"a {type(value).__name__}", path)


def _enter(container: Any, path: str, ancestors: Set[int]) -> None:
    if id(container) in ancestors:
        raise CanonicalJsonError("a cyclic reference", path)
    ancestors.add(id(container))


def _write_array(array: Any, path: str, ancestors: Set[int]) -> str:
    _enter(array, path, ancestors)
    try:
        parts: List[str] = [_write(item, f"{path}[{index}]", ancestors) for index, item in enumerate(array)]
    finally:
        ancestors.discard(id(array))
    return "[" + ",".join(parts) + "]"


def _write_object(obj: dict, path: str, ancestors: Set[int]) -> str:
    _enter(obj, path, ancestors)
    try:
        for key in obj:
            if not isinstance(key, str):
                raise CanonicalJsonError(f"a non-string member name ({key!r})", path)
        # RFC 8785 3.2.3: member names sorted by UTF-16 code units, so a
        # non-BMP name (two surrogates) sorts before a BMP name above U+D7FF.
        parts = []
        for key in sorted(obj, key=lambda name: name.encode("utf-16-be", "surrogatepass")):
            member_path = f"{path}.{key}"
            parts.append(_write_string(key, member_path) + ":" + _write(obj[key], member_path, ancestors))
    finally:
        ancestors.discard(id(obj))
    return "{" + ",".join(parts) + "}"


def canonicalize(value: Any) -> str:
    """The RFC 8785 canonical JSON text of ``value``.

    Raises ``CanonicalJsonError`` for a value that has none.
    """
    return _write(value, "$", set())


def hash_json(value: Any) -> str:
    """SHA-256 over the UTF-8 bytes of ``canonicalize(value)``, as
    ``sha256:<64 lowercase hex>`` (KYA-OS SPEC 7.3)."""
    return "sha256:" + hashlib.sha256(canonicalize(value).encode("utf-8")).hexdigest()
