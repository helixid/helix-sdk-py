# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The one Redis command RedisNonceStore needs (``SET key value PX ms NX``),
spoken over RESP2 on an asyncio connection, so the sample can share its
replay store between instances (KYA-OS story L2-A) without a client library.
The call shape is redis.asyncio's (``await client.set(name, value, px=, nx=)``,
True when set, None when NX refused it), so a production server hands the
store a ``redis.asyncio.Redis`` instead. Deliberately tiny: one connection,
commands sent one at a time, no auth, no TLS, reconnect on the next command
after the server hangs up. The twin of the JS sample's src/redis-client.ts."""

from __future__ import annotations

import asyncio
from typing import List, Optional
from urllib.parse import urlsplit


class RedisClient:
    def __init__(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme != "redis":
            raise ValueError(f"redis client: expected a redis:// URL, got {url}")
        self._host = parsed.hostname or "127.0.0.1"
        self._port = parsed.port or 6379
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._lock: Optional[asyncio.Lock] = None  # made on first use, on the loop that uses it

    async def set(self, name: str, value: str, px: Optional[int] = None, nx: bool = False) -> Optional[bool]:
        parts = ["SET", name, value] + (["PX", str(px)] if px is not None else []) + (["NX"] if nx else [])
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            reply = await self._send(parts)
        return True if reply == "OK" else None

    async def _send(self, parts: List[str]) -> Optional[str]:
        if self._writer is None or self._writer.is_closing():
            self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
        reader, writer = self._reader, self._writer
        assert reader is not None
        payload = f"*{len(parts)}\r\n" + "".join(f"${len(p.encode())}\r\n{p}\r\n" for p in parts)
        writer.write(payload.encode())
        await writer.drain()
        line = (await reader.readline()).decode()
        if not line:
            await self.close()
            raise ConnectionError("redis: connection closed before a reply")
        if line == "+OK\r\n":
            return "OK"
        if line in ("$-1\r\n", "_\r\n"):
            return None
        if line.startswith("-"):
            raise RuntimeError(f"redis: {line[1:].strip()}")
        raise RuntimeError(f"redis: unexpected reply {line!r}")

    async def close(self) -> None:
        writer, self._reader, self._writer = self._writer, None, None
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):  # pragma: no cover - already gone
                pass
