# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""parse_duration(), ported from helix-sdk-js's cli/src/lib/duration.ts."""

from __future__ import annotations

import re

_DURATION_RE = re.compile(r"^(\d+)([smhd])$")
_MULTIPLIER_MS = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}


def parse_duration(value: str) -> int:
    match = _DURATION_RE.match(value)
    if not match:
        raise ValueError("expires must use s, m, h, or d suffix (e.g. 90d, 24h)")
    amount = int(match.group(1))
    unit = match.group(2)
    return amount * _MULTIPLIER_MS[unit]
