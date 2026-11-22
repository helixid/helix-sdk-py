# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The resume-token store chosen by the same environment variables as the replay
store (story L3-E on L2-A's ``KYAOS_NONCE_STORE``), the twin of helix-sdk-js's
mcp-middleware/src/resume-token-store-env.ts: a service that shares its replay
store across instances shares its resume tokens the same way, with no
further setting.

==================  =================================================================
KYAOS_NONCE_STORE   Resume-token store
==================  =================================================================
memory (default)    MemoryResumeTokenStore, this process only
redis               RedisResumeTokenStore on KYAOS_REDIS_URL, key prefix
                    KYAOS_RESUME_KEY_PREFIX (default ``kyaos:resume:``)
dynamo              MemoryResumeTokenStore, with a warning: there is no DynamoDB
                    resume-token store yet
==================  =================================================================

Memory under a multi-instance deployment fails closed: a token is known only
to the instance that issued it, so a retry that lands elsewhere is refused
(``resume_token_unknown``), never accepted twice. Redis uses the same optional
extra as the replay store (``pip install 'helixid-sdk-py[redis]'``, through
redis.asyncio, so the store answers awaitables: use it behind
async_helixid_mcp_middleware). A bad setting or a missing package raises
NonceStoreConfigError at startup, never a silent fall back to memory. One
secret-free startup line names the store; the text is the same as JS's.
"""

from __future__ import annotations

import importlib
import logging
import os
import time
from typing import Any, Callable, Mapping, Optional

from .kyaos.nonce_store_env import (
    LOGGER,
    Importer,
    NonceStoreConfig,
    _load,
    _LoopBoundRedis,
    read_nonce_store_config,
    redact_url,
)
from .resume_token_store import DEFAULT_RESUME_KEY_PREFIX, MemoryResumeTokenStore, RedisResumeTokenStore, ResumeTokenStore


class _LoopBoundResumeRedis(_LoopBoundRedis):
    """L2-A's loop-bound redis.asyncio client, with the GETDEL the resume store needs."""

    async def getdel(self, name: str) -> Any:
        return await self._client().getdel(name)


def describe_resume_token_store(config: NonceStoreConfig, key_prefix: str = DEFAULT_RESUME_KEY_PREFIX) -> str:
    """One secret-free line naming the resume-token store ``config`` leads to; the same text as helix-sdk-js."""
    if config.kind == "redis":
        return f"KYA-OS resume-token store: redis {redact_url(config.url or '')} (key prefix {key_prefix})"
    return "KYA-OS resume-token store: memory (this process only)"


def _announce(config: NonceStoreConfig, key_prefix: str, logger: logging.Logger) -> None:
    logger.info(describe_resume_token_store(config, key_prefix))
    if config.kind == "dynamo":
        logger.warning(
            "KYA-OS resume-token store: there is no DynamoDB resume-token store; tokens stay in this process, "
            "so a retry must reach the instance that issued the challenge"
        )


def resume_token_store_from_config(
    config: NonceStoreConfig,
    now: Callable[[], float] = time.time,
    key_prefix: str = DEFAULT_RESUME_KEY_PREFIX,
    importer: Optional[Importer] = None,
) -> ResumeTokenStore:
    """Builds the store ``config`` leads to, importing redis for redis. Does not log; see resume_token_store_from_env()."""
    if config.kind != "redis":
        return MemoryResumeTokenStore(now=now)
    load = importer if importer is not None else importlib.import_module
    redis_asyncio = _load(load, "redis.asyncio", "redis", "redis")
    url = config.url
    return RedisResumeTokenStore(_LoopBoundResumeRedis(lambda: redis_asyncio.Redis.from_url(url)), key_prefix=key_prefix, now=now)


def resume_token_store_from_env(
    env: Optional[Mapping[str, str]] = None,
    now: Callable[[], float] = time.time,
    logger: Optional[logging.Logger] = None,
    importer: Optional[Importer] = None,
) -> ResumeTokenStore:
    """The resume-token store the environment names (``os.environ`` by
    default), built and announced: reads the replay store settings, logs one
    secret-free line naming the store (and the dynamo warning), and imports
    redis for redis. Raises NonceStoreConfigError for a bad setting or a
    missing package."""
    env = os.environ if env is None else env
    config = read_nonce_store_config(env)
    key_prefix = (env.get("KYAOS_RESUME_KEY_PREFIX") or "").strip() or DEFAULT_RESUME_KEY_PREFIX
    _announce(config, key_prefix, logger if logger is not None else LOGGER)
    return resume_token_store_from_config(config, now=now, key_prefix=key_prefix, importer=importer)


__all__ = ["describe_resume_token_store", "resume_token_store_from_config", "resume_token_store_from_env"]
