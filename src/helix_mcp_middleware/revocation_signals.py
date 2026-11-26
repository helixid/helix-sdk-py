# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The revocation signal, received (KYA-OS story L3-C point 7; SPEC.md
§6.5.2 "honor explicit revocation signals immediately"). Ported from
helix-sdk-js's mcp-middleware/src/revocation-signals.ts.

Helix emits one Security Event Token (RFC 8417) per revoked credential,
carrying only the credential id. The middleware receives them either way:

- **SSE (default)**: one outbound connection per instance to Helix's
  ``GET /v1/events/revocations``, kept on a background thread, reconnecting
  on drop with backoff and ``Last-Event-ID``, so nothing inbound is opened
  and nothing is polled;
- **webhook push (RFC 8935)**, for services that prefer inbound: mount
  :meth:`RevocationSignalClient.asgi_webhook` (or call
  :meth:`RevocationSignalClient.handle_push` from any framework) at the URL
  registered with Helix; it answers 202, or 400 with ``{err, description}``.

Each SET is verified (an issuer on ``trusted_issuers``, checked before any
resolution, and its signature under that issuer's ``assertionMethod`` key);
a valid one deletes the cached verdict and status entry for the credential
(``StatusCache.invalidate``). A signal with a bad signature or from an
unknown issuer is ignored and reported through ``on_signal``; it never
revokes anything. The signal is a cache hint only: the next call is judged
by the chain and the list, read live.
"""

from __future__ import annotations

import json
import re
import socket
import sys
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence
from urllib.request import Request, urlopen

from helix_sdk.verifier import SECEVENT_JWT_MEDIA_TYPE, SignalReasons, verify_revocation_signal

from .delegation.verification_cache import revocation_invalidation

#: RFC 8935 §2.3 error codes.
PUSH_ERRORS: Dict[str, str] = {
    SignalReasons.MALFORMED: "invalid_request",
    SignalReasons.WRONG_EVENT: "invalid_request",
    SignalReasons.STALE: "invalid_request",
    SignalReasons.UNKNOWN_ISSUER: "invalid_issuer",
    SignalReasons.BAD_SIGNATURE: "invalid_key",
}

MAX_PUSH_BYTES = 64 * 1024
_SEEN_LIMIT = 1000


@dataclass
class SignalReport:
    """Every signal handled, accepted or ignored: what ``on_signal`` receives. :meth:`to_dict` gives the JS report's keys."""

    timestamp: str
    via: str
    accepted: bool
    credential_id: Optional[str] = None
    jti: Optional[str] = None
    issuer: Optional[str] = None
    invalidated: Optional[str] = None
    """What the cache dropped: ``'credential'`` (its entries) or ``'all-lists'`` (a credential it held nothing for)."""
    reason: Optional[str] = None
    """Why the signal was ignored (``signal_unknown_issuer``, ``signal_bad_signature``, ...)."""
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        keys = {"credential_id": "credentialId"}
        return {keys.get(name, name): value for name, value in self.__dict__.items() if value is not None}


@dataclass(frozen=True)
class SignalOutcome:
    accepted: bool
    credential_id: Optional[str] = None
    invalidated: Optional[str] = None
    reason: Optional[str] = None
    message: Optional[str] = None


@dataclass(frozen=True)
class PushResponse:
    """What an RFC 8935 receiver answers: a status, an optional JSON body, extra headers."""

    status: int
    body: Optional[Dict[str, str]] = None
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass
class SseEvent:
    event: str
    data: str
    id: Optional[str] = None


_LINE_BREAK = re.compile(r"\r\n|\r|\n")


class SseParser:
    """Splits an SSE text stream into events (WHATWG HTML §9.2), calling ``on_event`` per dispatched event."""

    def __init__(self, on_event: Callable[[SseEvent], Any]) -> None:
        self._on_event = on_event
        self._buffer = ""
        self._data: List[str] = []
        self._event = ""
        self._id: Optional[str] = None
        self.retry: Optional[int] = None
        """The last ``retry:`` value the stream set, ms."""

    def push(self, chunk: str) -> None:
        self._buffer += chunk
        while True:
            match = _LINE_BREAK.search(self._buffer)
            if match is None:
                return
            # A lone "\r" at the end may be the first half of "\r\n": wait for more.
            if match.group(0) == "\r" and match.start() == len(self._buffer) - 1:
                return
            line = self._buffer[: match.start()]
            self._buffer = self._buffer[match.end() :]
            self._line(line)

    def _line(self, line: str) -> None:
        if line == "":
            if self._data:
                event = SseEvent(id=self._id, event=self._event or "message", data="\n".join(self._data))
                self._data = []
                self._event = ""
                self._on_event(event)
            else:
                self._event = ""
            return
        if line.startswith(":"):
            return
        name, colon, value = line.partition(":")
        if colon and value.startswith(" "):
            value = value[1:]
        if name == "data":
            self._data.append(value)
        elif name == "event":
            self._event = value
        elif name == "id" and "\0" not in value:
            self._id = value
        elif name == "retry" and value.isdigit():
            self.retry = int(value)


class SseStream:
    """One open SSE answer, as :class:`RevocationSignalClient` reads it: status, content type, body chunks, and a ``close`` that unblocks a read."""

    def __init__(self, status: int, content_type: str, chunks: Iterator[bytes], close: Callable[[], None] = lambda: None) -> None:
        self.status = status
        self.content_type = content_type
        self.chunks = chunks
        self._close = close

    def close(self) -> None:
        self._close()


OpenStream = Callable[[str, Mapping[str, str]], SseStream]
"""``(url, headers) -> SseStream``: how the SSE request is made; default urllib."""


def urllib_open_stream(url: str, headers: Mapping[str, str]) -> SseStream:
    """The default :data:`OpenStream`: a streaming urllib request; ``close`` shuts the socket down, so a blocked read returns."""
    response = urlopen(Request(url, headers=dict(headers)), timeout=60)  # noqa: S310 - the operator configures this URL
    raw = getattr(getattr(response, "fp", None), "raw", None)
    sock = getattr(raw, "_sock", None)

    closed = threading.Event()

    def chunks() -> Iterator[bytes]:
        try:
            while True:
                try:
                    chunk = response.read1(65536)
                except (OSError, ValueError, AttributeError):
                    # A read cut short by close() (from another thread) is the end of the stream, not an error.
                    if closed.is_set():
                        return
                    raise
                if not chunk:
                    return
                yield chunk
        finally:
            response.close()

    def close() -> None:
        closed.set()
        if isinstance(sock, socket.socket):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        try:
            response.close()
        except Exception:  # noqa: BLE001 - closing from another thread may race the reader
            pass

    return SseStream(response.status, response.headers.get("content-type", ""), chunks(), close)


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class RevocationSignalClient:
    """Receives Helix's revocation signals and invalidates the status cache on each valid one."""

    def __init__(
        self,
        trusted_issuers: Sequence[str],
        resolve_did: Callable[[str], Any],
        cache: Any,
        events_url: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        open_stream: Optional[OpenStream] = None,
        reconnect_delay_ms: int = 1_000,
        max_reconnect_delay_ms: int = 30_000,
        on_signal: Optional[Callable[[SignalReport], Any]] = None,
        on_connection_change: Optional[Callable[[bool, Optional[BaseException]], Any]] = None,
        clock: Optional[Callable[[], int]] = None,
        log: Optional[Callable[[str], Any]] = None,
    ) -> None:
        """
        ``trusted_issuers``: the issuer DIDs whose signals are honoured (the Helix issuer of the deployment this
        service listens to). ``resolve_did``: how a trusted issuer's DID resolves (the local verifier's
        ``seams.resolve_did``). ``cache``: what a valid signal invalidates (the local verifier's ``status_cache``).
        ``events_url``: Helix's SSE endpoint (``<api>/v1/events/revocations``); without it only the webhook
        receives signals. ``headers``: sent on the SSE request (an API key, say). ``reconnect_delay_ms`` doubles per
        failure up to ``max_reconnect_delay_ms``. ``on_signal``: the audit hook (default: ignored signals logged).
        """
        if isinstance(trusted_issuers, str) or not trusted_issuers:
            raise ValueError("RevocationSignalClient: trusted_issuers must name the issuer whose signals are honoured")
        self.trusted_issuers = list(trusted_issuers)
        self._resolve_did = resolve_did
        self._cache = cache
        self.events_url = events_url
        self._headers = dict(headers or {})
        self._open_stream = open_stream or urllib_open_stream
        self._initial_delay = reconnect_delay_ms
        self._max_delay = max_reconnect_delay_ms
        self._clock = clock or _now_ms
        write = log or (lambda message: print(message, file=sys.stderr))

        def default_on_signal(report: SignalReport) -> None:
            if not report.accepted:
                write(f"[kya-os] revocation signal ignored ({report.via}): {report.reason}: {report.message}")

        self._on_signal = on_signal or default_on_signal
        self._on_connection_change = on_connection_change
        self._seen: "OrderedDict[str, None]" = OrderedDict()
        self._lock = threading.Lock()
        self._running = False
        self._connected = False
        self._last_event_id: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._stream: Optional[SseStream] = None
        self._wake = threading.Event()

    @property
    def connected(self) -> bool:
        """True while the SSE stream is open."""
        return self._connected

    @property
    def last_event_id(self) -> Optional[str]:
        """The id of the last SSE event received, sent as ``Last-Event-ID`` on reconnect."""
        return self._last_event_id

    def handle(self, set_jwt: Any, via: str = "sse") -> SignalOutcome:
        """Verifies one SET and, when it holds, invalidates the cache for its credential. Never raises."""
        now = self._clock()
        timestamp = _iso(now)
        verdict = verify_revocation_signal(set_jwt, self.trusted_issuers, self._resolve_did, now_ms=now)
        if not verdict.ok or verdict.signal is None:
            reason, message = verdict.reason or SignalReasons.MALFORMED, verdict.message or "the signal was refused"
            outcome = SignalOutcome(accepted=False, reason=reason, message=message)
            report = SignalReport(timestamp, via, False, reason=reason, message=message)
        else:
            signal = verdict.signal
            try:
                # A duplicate (the same jti over SSE and webhook, or replayed after a reconnect) deletes again: harmless.
                invalidated = self._cache.invalidate(signal.credential_id)
                self._remember(signal.jti)
                outcome = SignalOutcome(accepted=True, credential_id=signal.credential_id, invalidated=invalidated)
                report = SignalReport(timestamp, via, True, credential_id=signal.credential_id, jti=signal.jti, issuer=signal.iss, invalidated=invalidated)
            except Exception as exc:  # noqa: BLE001 - a cache that cannot be reached is reported, not raised
                outcome = SignalOutcome(accepted=False, reason="cache_unavailable", message=str(exc))
                report = SignalReport(
                    timestamp, via, False, credential_id=signal.credential_id, jti=signal.jti, issuer=signal.iss, reason="cache_unavailable", message=str(exc)
                )
        try:
            self._on_signal(report)
        except Exception:  # noqa: BLE001 - reporting never blocks the invalidation
            pass
        return outcome

    def has_seen(self, jti: str) -> bool:
        """Whether a signal with this ``jti`` was accepted recently (for diagnostics; duplicates are handled again regardless)."""
        with self._lock:
            return jti in self._seen

    def _remember(self, jti: str) -> None:
        with self._lock:
            self._seen[jti] = None
            if len(self._seen) > _SEEN_LIMIT:
                self._seen.popitem(last=False)

    # -- SSE ----------------------------------------------------------------

    def start(self) -> None:
        """Opens the SSE stream on a background thread and keeps it open, reconnecting on drop, until :meth:`stop`."""
        if self._running:
            return
        if self.events_url is None:
            raise ValueError("RevocationSignalClient: start() needs events_url (SSE); use handle_push() or asgi_webhook() for push")
        self._running = True
        self._wake.clear()
        self._thread = threading.Thread(target=self._run, name="kyaos-revocation-signals", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Closes the stream and stops reconnecting."""
        self._running = False
        self._wake.set()
        stream = self._stream
        if stream is not None:
            stream.close()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    def _set_connected(self, connected: bool, error: Optional[BaseException] = None) -> None:
        if self._connected == connected and error is None:
            return
        self._connected = connected
        if self._on_connection_change is not None:
            try:
                self._on_connection_change(connected, error)
            except Exception:  # noqa: BLE001 - a health hook never stops the stream
                pass

    def _run(self) -> None:
        delay = self._initial_delay
        while self._running:
            parser: Optional[SseParser] = None
            opened = [False]
            try:
                parser = self._read_stream(opened)
                self._set_connected(False)
            except Exception as exc:  # noqa: BLE001 - every failure reconnects
                self._set_connected(False, exc if self._running else None)
            if opened[0]:
                delay = self._initial_delay
            if not self._running:
                break
            self._wake.wait((parser.retry if parser is not None and parser.retry is not None else delay) / 1000)
            delay = min(delay * 2, self._max_delay)
        self._set_connected(False)

    def _read_stream(self, opened: List[bool]) -> SseParser:
        headers = {"accept": "text/event-stream", "cache-control": "no-cache", **self._headers}
        if self._last_event_id is not None:
            headers["last-event-id"] = self._last_event_id
        stream = self._open_stream(str(self.events_url), headers)
        self._stream = stream
        try:
            if not 200 <= stream.status < 300:
                raise ConnectionError(f"revocation events answered {stream.status}")
            if not stream.content_type.startswith("text/event-stream"):
                raise ConnectionError(f"revocation events answered {stream.content_type or 'no content type'}, not text/event-stream")
            self._set_connected(True)
            opened[0] = True

            def on_event(event: SseEvent) -> None:
                if event.id is not None:
                    self._last_event_id = event.id
                if event.event == "revocation":
                    self.handle(event.data, "sse")

            parser = SseParser(on_event)
            pending = b""
            for chunk in stream.chunks:
                if not self._running:
                    break
                pending += chunk
                try:
                    text, pending = pending.decode("utf-8"), b""
                except UnicodeDecodeError as exc:
                    # A multi-byte character split across chunks: keep its first bytes for the next chunk.
                    text, pending = pending[: exc.start].decode("utf-8"), pending[exc.start :]
                parser.push(text)
            return parser
        finally:
            self._stream = None
            stream.close()

    # -- webhook push (RFC 8935) --------------------------------------------

    def handle_push(self, method: str, content_type: Optional[str], body: bytes) -> PushResponse:
        """An RFC 8935 receiver, framework-neutral: ``POST`` with ``Content-Type: application/secevent+jwt`` and the
        SET as the body; 202 when it verified, 400 ``{err, description}`` when it did not, 405/413/415 otherwise."""
        if method.upper() != "POST":
            return PushResponse(405, {"err": "invalid_request", "description": "POST a SET"}, {"allow": "POST"})
        kind = (content_type or "").split(";")[0].strip().lower()
        if kind != SECEVENT_JWT_MEDIA_TYPE:
            return PushResponse(415, {"err": "invalid_request", "description": f"Content-Type must be {SECEVENT_JWT_MEDIA_TYPE}"})
        if len(body) > MAX_PUSH_BYTES:
            return PushResponse(400, {"err": "invalid_request", "description": f"the SET exceeds {MAX_PUSH_BYTES} bytes"})
        try:
            text = body.decode("utf-8").strip()
        except UnicodeDecodeError:
            return PushResponse(400, {"err": "invalid_request", "description": "the SET is not UTF-8"})
        outcome = self.handle(text, "webhook")
        if outcome.accepted:
            return PushResponse(202)
        status = 503 if outcome.reason == "cache_unavailable" else 400
        return PushResponse(status, {"err": PUSH_ERRORS.get(str(outcome.reason), "invalid_request"), "description": str(outcome.message)})

    def asgi_webhook(self) -> Callable[[Any, Any, Any], Any]:
        """:meth:`handle_push` as a bare ASGI app, to mount at the path registered with Helix."""

        async def app(scope: Any, receive: Any, send: Any) -> None:
            content_type: Optional[str] = None
            for name, value in scope.get("headers") or []:
                if name.lower() == b"content-type":
                    content_type = value.decode("latin-1")
            body, more = b"", True
            while more and len(body) <= MAX_PUSH_BYTES:
                message = await receive()
                if message["type"] != "http.request":
                    return  # client went away
                body += message.get("body", b"")
                more = message.get("more_body", False)
            answer = self.handle_push(scope.get("method", "GET"), content_type, body)
            payload = b"" if answer.body is None else json.dumps(answer.body).encode("utf-8")
            headers = [(name.encode("latin-1"), value.encode("latin-1")) for name, value in answer.headers.items()]
            if answer.body is not None:
                headers.append((b"content-type", b"application/json"))
            await send({"type": "http.response.start", "status": answer.status, "headers": headers})
            await send({"type": "http.response.body", "body": payload})

        return app


def create_revocation_signal_client(verifier: Any, trusted_issuers: Sequence[str], **options: Any) -> RevocationSignalClient:
    """A :class:`RevocationSignalClient` for a local verifier: its resolver (``seams.resolve_did``), its ``status_cache``."""
    resolve_did = options.pop("resolve_did", None) or getattr(verifier.seams, "resolve_did", None)
    if resolve_did is None:
        raise ValueError("create_revocation_signal_client: the verifier has no resolve_did seam")
    # Story L3-D: the default also drops the verdicts of every verification cache linked to the status cache.
    cache = options.pop("cache", None) or revocation_invalidation(verifier.status_cache)
    return RevocationSignalClient(trusted_issuers, resolve_did, cache, **options)
