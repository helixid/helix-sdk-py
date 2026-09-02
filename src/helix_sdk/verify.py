# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
verify_vp(), ported from helix-sdk-js's src/verify.ts.

Verifies a VP via the API's /v1/vp/verify endpoint (see
docs/proposal-sdk-api-only.md) -- signature check, delegation-chain walk,
expiry, target service, and revocation all happen server-side, with
VP_VERIFIED/VP_REJECTED audit logging handled there too. There is no local
fallback: unlike VPBuilder.sign(), verification was decided to move to the
API for every SDK, without exception, so a HelixClient is required.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .client import HelixClient


def verify_vp(
    vp: Dict[str, Any],
    client: HelixClient,
    expected_target_service: Optional[str] = None,
    allow_self_signed: Optional[bool] = None,
) -> Dict[str, Any]:
    return client.verify_vp(vp, expected_target_service=expected_target_service, allow_self_signed=allow_self_signed)
