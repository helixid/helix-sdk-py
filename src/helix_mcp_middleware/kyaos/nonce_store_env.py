# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The replay store chosen by environment variables (story L2-A), the twin of
helix-sdk-js's nonceStoreFromEnv():

==============================  ==========================================  ===================
Variable                        Values                                      Default
==============================  ==========================================  ===================
KYAOS_NONCE_STORE               memory, redis, dynamo                       memory
KYAOS_REDIS_URL                 redis:// or rediss:// URL; for redis
KYAOS_NONCE_KEY_PREFIX          Redis key prefix                            kyaos:nonce:
KYAOS_DYNAMO_TABLE              table name; for dynamo
KYAOS_DYNAMO_KEY_ATTRIBUTE      partition key attribute                     pk
KYAOS_DYNAMO_TTL_ATTRIBUTE      TTL attribute (Unix seconds)                expiresAt
KYAOS_DYNAMO_REGION             AWS region                                  boto3's own
KYAOS_DYNAMO_ENDPOINT           endpoint URL, for DynamoDB Local            boto3's own
==============================  ==========================================  ===================

AWS credentials come from boto3's standard chain, never from these
variables. The clients are optional extras, imported only when chosen:
``pip install 'helixid-sdk-py[redis]'`` (redis-py, used through
redis.asyncio) and ``pip install 'helixid-sdk-py[dynamo]'`` (boto3, whose
calls run in a worker thread so the event loop stays free).

Fail closed: an unknown store, a missing required variable or a missing
package raises NonceStoreConfigError at startup, never a silent fall back to
memory. One startup line names the store in use, without secrets; memory
with ``ENV`` or ``NODE_ENV`` = ``production`` also warns that it covers one
process only.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import os
import time
import weakref
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit

from .nonce_store import DynamoNonceStore, MemoryNonceStore, NonceStore, RedisNonceStore

NONCE_STORE_KINDS = ("memory", "redis", "dynamo")
DEFAULT_NONCE_KEY_PREFIX = "kyaos:nonce:"
DEFAULT_DYNAMO_KEY_ATTRIBUTE = "pk"
DEFAULT_DYNAMO_TTL_ATTRIBUTE = "expiresAt"

LOGGER = logging.getLogger("helix_mcp_middleware.kyaos")


class NonceStoreConfigError(ValueError):
    """A replay store setting that cannot work: an unknown store, a missing variable or a missing package."""


@dataclass(frozen=True)
class NonceStoreConfig:
    kind: str
    url: Optional[str] = None
    key_prefix: str = DEFAULT_NONCE_KEY_PREFIX
    table: Optional[str] = None
    key_attribute: str = DEFAULT_DYNAMO_KEY_ATTRIBUTE
    ttl_attribute: str = DEFAULT_DYNAMO_TTL_ATTRIBUTE
    region: Optional[str] = None
    endpoint: Optional[str] = None


def _value(env: Mapping[str, str], name: str) -> Optional[str]:
    raw = (env.get(name) or "").strip()
    return raw or None


def _required(env: Mapping[str, str], name: str, kind: str) -> str:
    found = _value(env, name)
    if found is None:
        raise NonceStoreConfigError(f"KYAOS_NONCE_STORE={kind} needs {name}")
    return found


def _check_url(raw: str, name: str, schemes: tuple) -> None:
    try:
        parts = urlsplit(raw)
    except ValueError:  # pragma: no cover - urlsplit refuses very little
        raise NonceStoreConfigError(f"{name} is not a URL") from None
    if not parts.scheme or not parts.netloc:
        raise NonceStoreConfigError(f"{name} is not a URL")
    if parts.scheme not in schemes:
        raise NonceStoreConfigError(f"{name} must be a {' or '.join(f'{s}://' for s in schemes)} URL")


def read_nonce_store_config(env: Optional[Mapping[str, str]] = None) -> NonceStoreConfig:
    """Reads and checks the replay store settings (``os.environ`` by default);
    raises NonceStoreConfigError for an unknown store or a missing or
    malformed required variable. Nothing is imported or connected here."""
    env = os.environ if env is None else env
    kind = (_value(env, "KYAOS_NONCE_STORE") or "memory").lower()
    if kind == "memory":
        return NonceStoreConfig(kind="memory")
    if kind == "redis":
        url = _required(env, "KYAOS_REDIS_URL", "redis")
        _check_url(url, "KYAOS_REDIS_URL", ("redis", "rediss"))
        return NonceStoreConfig(kind="redis", url=url, key_prefix=env.get("KYAOS_NONCE_KEY_PREFIX") or DEFAULT_NONCE_KEY_PREFIX)
    if kind == "dynamo":
        endpoint = _value(env, "KYAOS_DYNAMO_ENDPOINT")
        if endpoint is not None:
            _check_url(endpoint, "KYAOS_DYNAMO_ENDPOINT", ("http", "https"))
        return NonceStoreConfig(
            kind="dynamo",
            table=_required(env, "KYAOS_DYNAMO_TABLE", "dynamo"),
            key_attribute=_value(env, "KYAOS_DYNAMO_KEY_ATTRIBUTE") or DEFAULT_DYNAMO_KEY_ATTRIBUTE,
            ttl_attribute=_value(env, "KYAOS_DYNAMO_TTL_ATTRIBUTE") or DEFAULT_DYNAMO_TTL_ATTRIBUTE,
            region=_value(env, "KYAOS_DYNAMO_REGION"),
            endpoint=endpoint,
        )
    raise NonceStoreConfigError(f"KYAOS_NONCE_STORE must be one of {', '.join(NONCE_STORE_KINDS)}; got {kind!r}")


def redact_url(raw: str) -> str:
    """A URL without its password (the username kept), for logs."""
    parts = urlsplit(raw)
    if parts.password is None:
        return raw
    user = parts.username or ""
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{user}:***@{host}" + (f":{parts.port}" if parts.port is not None else "")
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def describe_nonce_store(config: NonceStoreConfig) -> str:
    """One secret-free line naming the store; the same text as helix-sdk-js."""
    if config.kind == "redis":
        return f"KYA-OS replay store: redis {redact_url(config.url or '')} (key prefix {config.key_prefix})"
    if config.kind == "dynamo":
        extra = (f", region {config.region}" if config.region else "") + (f", endpoint {redact_url(config.endpoint)}" if config.endpoint else "")
        return f"KYA-OS replay store: dynamo table {config.table} (key {config.key_attribute}, ttl {config.ttl_attribute}{extra})"
    return "KYA-OS replay store: memory (this process only)"


def _announce(config: NonceStoreConfig, env: Mapping[str, str], logger: logging.Logger) -> None:
    logger.info(describe_nonce_store(config))
    if config.kind != "memory":
        return
    if any((env.get(name) or "").strip().lower() == "production" for name in ("ENV", "NODE_ENV")):
        logger.warning(
            "KYA-OS replay store: memory in production covers this process only; a nonce replayed at another instance is not refused. "
            "Set KYAOS_NONCE_STORE=redis or dynamo when more than one instance serves this DID."
        )
    for name in ("KYAOS_REDIS_URL", "KYAOS_DYNAMO_TABLE"):
        if _value(env, name) is not None:
            logger.warning(f"KYA-OS replay store: {name} is set but KYAOS_NONCE_STORE is memory; set KYAOS_NONCE_STORE to use it for replays")


Importer = Callable[[str], Any]


def _load(importer: Importer, module: str, kind: str, extra: str) -> Any:
    try:
        return importer(module)
    except ImportError as error:
        missing = getattr(error, "name", None) or ""
        if missing == module or module.startswith(f"{missing}.") or not missing:
            raise NonceStoreConfigError(f"KYAOS_NONCE_STORE={kind} needs the optional package {module.split('.')[0]}: pip install 'helixid-sdk-py[{extra}]'") from None
        raise


class _LoopBoundRedis:
    """A redis.asyncio client made on first use, inside the running event loop,
    one per loop: an asyncio client belongs to the loop it was made on, and a
    runtime is usually built before the server's loop starts."""

    def __init__(self, make: Callable[[], Any]) -> None:
        self._make = make
        self._clients: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Any]" = weakref.WeakKeyDictionary()

    def _client(self) -> Any:
        loop = asyncio.get_running_loop()
        client = self._clients.get(loop)
        if client is None:
            client = self._make()
            self._clients[loop] = client
        return client

    async def set(self, *args: Any, **kwargs: Any) -> Any:
        return await self._client().set(*args, **kwargs)

    async def aclose(self) -> None:
        """Closes the client of the running loop, if it made one."""
        client = self._clients.pop(asyncio.get_running_loop(), None)
        if client is not None:
            await client.aclose()


class _ThreadedDynamoClient:
    """A boto3 client whose ``put_item`` runs in a worker thread: DynamoNonceStore awaits it, the event loop stays free."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def put_item(self, **request: Any) -> Any:
        return asyncio.to_thread(self._client.put_item, **request)


def nonce_store_from_config(
    config: NonceStoreConfig, now: Callable[[], float] = time.time, importer: Optional[Importer] = None
) -> NonceStore:
    """Builds the store ``config`` names, importing its client package. Does not log; see nonce_store_from_env()."""
    load = importer if importer is not None else importlib.import_module
    if config.kind == "redis":
        redis_asyncio = _load(load, "redis.asyncio", "redis", "redis")
        url = config.url
        return RedisNonceStore(_LoopBoundRedis(lambda: redis_asyncio.Redis.from_url(url)), key_prefix=config.key_prefix, now=now)
    if config.kind == "dynamo":
        boto3 = _load(load, "boto3", "dynamo", "dynamo")
        # Credentials: boto3's standard chain. Only where to connect is ours.
        options = {**({"region_name": config.region} if config.region else {}), **({"endpoint_url": config.endpoint} if config.endpoint else {})}
        try:
            client = boto3.client("dynamodb", **options)
        except Exception as error:  # noqa: BLE001 - botocore's NoRegionError, said in our terms
            if type(error).__name__ == "NoRegionError":
                raise NonceStoreConfigError("KYAOS_NONCE_STORE=dynamo needs a region: set KYAOS_DYNAMO_REGION or AWS_REGION") from None
            raise
        return DynamoNonceStore(
            _ThreadedDynamoClient(client), config.table or "", key_attribute=config.key_attribute, ttl_attribute=config.ttl_attribute
        )
    return MemoryNonceStore(now=now)


def nonce_store_from_env(
    env: Optional[Mapping[str, str]] = None,
    now: Callable[[], float] = time.time,
    logger: Optional[logging.Logger] = None,
    importer: Optional[Importer] = None,
) -> NonceStore:
    """The replay store the environment names, built and announced: reads the
    settings, logs one secret-free line naming the store and any warning, and
    imports the client package for redis or dynamo. Raises
    NonceStoreConfigError for an unknown store, a missing variable or a
    missing package."""
    env = os.environ if env is None else env
    config = read_nonce_store_config(env)
    _announce(config, env, logger if logger is not None else LOGGER)
    return nonce_store_from_config(config, now=now, importer=importer)
