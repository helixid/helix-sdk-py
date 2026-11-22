# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Sync-or-async seams: an injected store, client or callback may answer with
a value or an awaitable (redis-py and redis.asyncio, boto3 and aioboto3)."""

from __future__ import annotations

import inspect
from typing import Awaitable, Callable, TypeVar, Union

T = TypeVar("T")
U = TypeVar("U")

MaybeAwaitable = Union[T, Awaitable[T]]


async def resolve(value: MaybeAwaitable[T]) -> T:
    """``value``, awaited when it is awaitable."""
    if inspect.isawaitable(value):
        return await value  # type: ignore[no-any-return]
    return value  # type: ignore[return-value]


def then(value: MaybeAwaitable[T], apply: Callable[[T], U]) -> MaybeAwaitable[U]:
    """``apply(value)``, after awaiting it when it is awaitable: a sync client
    gets a sync answer, an async client an awaitable one."""
    if inspect.isawaitable(value):

        async def later() -> U:
            return apply(await value)  # type: ignore[misc]

        return later()
    return apply(value)  # type: ignore[arg-type]
