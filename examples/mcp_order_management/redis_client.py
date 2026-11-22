# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""The Redis commands the sample's shared status cache needs (KYA-OS story
L3-C), spoken over RESP2 on a plain socket: ``GET``, ``SET key value PX ms``,
``DEL``, ``INCR``. Ported from the JS sample's redis-client.ts, so the
sample shares its cache between instances without a client library.

A production server would hand :class:`RedisStatusCacheStore` a redis-py
client instead; this is deliberately tiny: one connection, commands sent one
at a time under a lock, no auth, no TLS, no reconnect beyond opening the
socket again on the next command.
"""

from __future__ import annotations

import socket
import threading
from typing import Optional, Union
from urllib.parse import urlsplit

Reply = Union[str, int, None, Exception]


class RedisError(Exception):
    """An error reply, or a connection that closed before a reply."""


def parse_reply(buffer: bytes) -> "tuple[Optional[Reply], int]":
    """One RESP2 reply from the start of ``buffer`` and the bytes it took, or ``(None, 0)`` while it is incomplete.
    An error reply is returned as a :class:`RedisError`, a null as ``None`` with a non-zero length."""
    end = buffer.find(b"\r\n")
    if end == -1:
        return None, 0
    kind, head = buffer[:1], buffer[1:end].decode("utf-8")
    if kind == b"+":
        return head, end + 2
    if kind == b"-":
        return RedisError(f"redis: {head.strip()}"), end + 2
    if kind == b":":
        return int(head), end + 2
    if kind == b"_":
        return None, end + 2
    if kind == b"$":
        length = int(head)
        if length < 0:
            return None, end + 2
        if len(buffer) < end + 2 + length + 2:
            return None, 0
        return buffer[end + 2 : end + 2 + length].decode("utf-8"), end + 2 + length + 2
    return RedisError(f"redis: unexpected reply {buffer!r}"), len(buffer)


class RedisClient:
    """``get``/``set(px=)``/``delete``/``incr``, as :class:`helix_mcp_middleware.RedisStatusCacheStore` calls them."""

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        parts = urlsplit(url)
        if parts.scheme != "redis":
            raise ValueError(f"redis client: expected a redis:// URL, got {url}")
        self._address = (parts.hostname or "127.0.0.1", parts.port or 6379)
        self._timeout = timeout
        self._socket: Optional[socket.socket] = None
        self._lock = threading.Lock()

    def _command(self, *parts: str) -> Reply:
        payload = f"*{len(parts)}\r\n".encode() + b"".join(f"${len(p.encode())}\r\n".encode() + p.encode() + b"\r\n" for p in parts)
        with self._lock:
            if self._socket is None:
                self._socket = socket.create_connection(self._address, timeout=self._timeout)
            sock = self._socket
            try:
                sock.sendall(payload)
                buffered = b""
                while True:
                    reply, used = parse_reply(buffered)
                    if used:
                        break
                    chunk = sock.recv(65536)
                    if not chunk:
                        raise RedisError("redis: connection closed before a reply")
                    buffered += chunk
            except (OSError, RedisError):
                self.close_locked()
                raise
        if isinstance(reply, Exception):
            raise reply
        return reply

    def get(self, key: str) -> Optional[str]:
        reply = self._command("GET", key)
        return None if reply is None else str(reply)

    def set(self, key: str, value: str, px: int) -> Reply:
        return self._command("SET", key, value, "PX", str(px))

    def delete(self, key: str) -> int:
        return int(self._command("DEL", key) or 0)

    def incr(self, key: str) -> int:
        return int(self._command("INCR", key) or 0)

    def close_locked(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None

    def close(self) -> None:
        with self._lock:
            self.close_locked()
