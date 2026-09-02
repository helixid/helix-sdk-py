# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""check_scope() / require_scope(), ported from helix-sdk-js's src/scope.ts."""

from __future__ import annotations

from typing import Any, Dict

from .errors import InsufficientScopeError


def check_scope(result: Dict[str, Any], required_scope: str) -> bool:
    # Enforcement reads effectiveScopes: identical to privilegeScopes when
    # no consent grant is in the VP, the grant intersection when one is.
    return required_scope in result.get("effectiveScopes", [])


def require_scope(result: Dict[str, Any], required_scope: str) -> None:
    if not check_scope(result, required_scope):
        raise InsufficientScopeError(required_scope)
