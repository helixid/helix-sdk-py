# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""KYA-OS story L3-C in the Python middleware, ported from helix-sdk-js's
mcp-middleware/tests/revocation.test.ts: signed status lists read through
the local verifier, the shared status cache (two instances, one store), the
revocation signal over SSE and webhook push, and the resolution fetch guard.
"""

from __future__ import annotations

import asyncio
import base64
import http.server
import json
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pytest

from helix_sdk.credentials import sign_data_integrity
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.verifier import MemoryNonceStore, MemoryStatusCacheStore, RevocationContext, StatusCache, sign_revocation_signal

from helix_mcp_middleware import (
    LocalVerifierOptions,
    MCPMiddlewareOptions,
    ProofError,
    helixid_mcp_middleware,
    RedisStatusCacheStore,
    ResolutionRefusedError,
    RevocationSignalClient,
    SignalReport,
    SseParser,
    create_local_verifier,
    create_resolution_fetch,
    create_revocation_signal_client,
    is_public_unicast_address,
    resolution_target,
)
from helix_mcp_middleware.resolution_fetch import TransportResponse, urllib_transport
from helix_mcp_middleware.revocation_signals import SseStream, urllib_open_stream
from mcp_proof_helpers import NOW_MS, fixture_signer, have_verifier_fixtures, load_cases, load_environment, proof_meta
from mcp_revocation_helpers import encoded_bits

needs_fixtures = pytest.mark.skipif(not have_verifier_fixtures(), reason="helix-core fixtures/verifier not found")


# ── a tiny HTTP server per test ──────────────────────────────────────────────

Handler = Callable[[http.server.BaseHTTPRequestHandler], None]


class _Server:
    def __init__(self, handler: Handler) -> None:
        outer = handler

        class RequestHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802 - http.server's naming
                outer(self)

            do_POST = do_GET  # noqa: N815

            def log_message(self, *args: Any) -> None:
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RequestHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def listen() -> Iterator[Callable[[Handler], str]]:
    servers: List[_Server] = []

    def start(handler: Handler) -> str:
        server = _Server(handler)
        servers.append(server)
        return server.url

    yield start
    for server in servers:
        server.close()


def respond(request: http.server.BaseHTTPRequestHandler, status: int, body: bytes = b"", headers: Optional[Dict[str, str]] = None) -> None:
    request.send_response(status)
    for name, value in (headers or {}).items():
        request.send_header(name, value)
    if "content-length" not in {name.lower() for name in (headers or {})}:
        request.send_header("content-length", str(len(body)))
    request.end_headers()
    if body:
        request.wfile.write(body)


def wait_for(condition: Callable[[], bool], timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        time.sleep(0.01)


def jti_of(set_jwt: str) -> str:
    segment = set_jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))["jti"]


# ── the fixture world ────────────────────────────────────────────────────────


class FixtureLists:
    """The Helix side of the fixture world: every fixture status list, signed by its issuer's TEST-ONLY key, with bits that can be set."""

    def __init__(self, env: Dict[str, Any]) -> None:
        self.env = env
        self.revoked: Dict[str, List[int]] = {}
        self.asked: List[str] = []

    def _signed(self, url: str) -> Optional[Dict[str, Any]]:
        listed = self.env["status_lists"].get(url)
        if not listed or not listed.get("issuer"):
            return None
        key = next(entry for entry in self.env["keys"].values() if entry["did"] == listed["issuer"])
        document = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": listed["id"],
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": listed["issuer"],
            "validFrom": listed["valid_from"],
            "validUntil": listed["valid_until"],
            "credentialSubject": {"id": f"{url}#list", "type": "BitstringStatusList", "statusPurpose": listed["status_purpose"], "encodedList": encoded_bits(16, self.revoked.get(url, []))},
        }
        # The fixture documents publish #key-1 for these did:keys: sign under the fixture's own kid.
        signer = EnvSigner(listed["issuer"], kid="key-1", env_var="K", env={"K": key["private_key_hex"]})
        return sign_data_integrity(document, signer, created="2026-01-01T00:00:00Z")

    def revoke(self, url: str, index: int) -> None:
        self.revoked.setdefault(url, []).append(index)

    def fetch(self, url: str) -> Any:
        self.asked.append(url)
        body = self._signed(url)
        if body is None:
            raise LookupError(f"{url} answered 404")
        return body


@pytest.fixture
def world() -> Dict[str, Any]:
    env = load_environment()
    valid = next(case for case in load_cases()["valid"] if case["name"] == "two_hop_chain")
    return {
        "env": env,
        "service": env["keys"]["service"]["did"],
        "chain": valid["input"]["chain"],
        "helix": fixture_signer(env, "helix"),
        "resolve_did": lambda did: env["did_documents"].get(did),
    }


def instance(world: Dict[str, Any], lists: FixtureLists, store: Any, clock: Callable[[], int], **options: Any) -> Any:
    env = world["env"]
    settings: Dict[str, Any] = {
        "service_did": world["service"],
        "fetch": lists.fetch,
        "resolve_did": world["resolve_did"],
        "cards": {env["keys"]["agent"]["did"]: env["cards"]["attested"]},
        "status_cache": {"store": store, "status_cache_ttl": 120, "clock": clock},
        "nonce_store": MemoryNonceStore(now_ms=clock),
        "clock": clock,
        "report_verification": lambda entry: None,
        **options,
    }
    return create_local_verifier(LocalVerifierOptions(**settings))


CALL_INPUT = {"orderId": "ORD-1001"}


def present(world: Dict[str, Any], verifier: Any, now: int) -> Any:
    meta = proof_meta(fixture_signer(world["env"], "agent"), world["service"], "lookup_order", CALL_INPUT, world["chain"], now_ms=now)
    return verifier.verify_call({"name": "lookup_order", "input": CALL_INPUT, "_meta": meta})


@needs_fixtures
def test_verifies_every_list_proof_live_then_serves_the_second_instance_from_the_shared_cache(world: Dict[str, Any]) -> None:
    lists = FixtureLists(world["env"])
    store = MemoryStatusCacheStore(lambda: NOW_MS)
    a = instance(world, lists, store, lambda: NOW_MS)
    b = instance(world, lists, store, lambda: NOW_MS)
    first = present(world, a, NOW_MS)
    assert (first.ok, first.level, first.fresh) == (True, "L3", True)
    asked = len(lists.asked)
    second = present(world, b, NOW_MS)
    assert (second.ok, second.level, second.fresh) == (True, "L2", False)
    assert len(lists.asked) == asked


@needs_fixtures
def test_revoke_a_parent_hop_refused_on_both_instances_once_the_signal_reaches_one(world: Dict[str, Any]) -> None:
    lists = FixtureLists(world["env"])
    store = MemoryStatusCacheStore(lambda: NOW_MS)
    a = instance(world, lists, store, lambda: NOW_MS)
    b = instance(world, lists, store, lambda: NOW_MS)
    assert present(world, a, NOW_MS).ok and present(world, b, NOW_MS).ok
    # Helix revokes the root hop (the child's parent): its bit flips on the owner's list.
    root = world["chain"][0]
    lists.revoke(root["credentialStatus"]["statusListCredential"], int(root["credentialStatus"]["statusListIndex"]))
    # Inside the TTL, with no signal yet, both still read the cached verdict.
    assert present(world, a, NOW_MS).ok
    reports: List[SignalReport] = []
    helix = world["helix"]
    client = create_revocation_signal_client(a, [helix.did], resolve_did=world["resolve_did"], on_signal=reports.append, clock=lambda: NOW_MS)
    set_jwt = sign_revocation_signal(root["id"], helix, iat=NOW_MS // 1000)
    outcome = client.handle(set_jwt)
    assert (outcome.accepted, outcome.credential_id, outcome.invalidated) == (True, root["id"], "credential")
    assert reports[0].to_dict() == {
        "timestamp": "2026-06-01T00:00:00.000Z",
        "via": "sse",
        "accepted": True,
        "credentialId": root["id"],
        "jti": jti_of(set_jwt),
        "issuer": helix.did,
        "invalidated": "credential",
    }
    assert client.has_seen(jti_of(set_jwt))
    # The signal reached instance A only; B shares the store, so both refuse.
    for verifier in (a, b):
        result = present(world, verifier, NOW_MS)
        assert (result.ok, list(result.reasons)) == (False, ["status_revoked"])


def _guarded(world: Dict[str, Any], verifier: Any) -> Callable[[str], Any]:
    """A guard whose tools demand L3 by default, with ``list_orders`` set to L2; returns ``authorize`` by tool name."""
    gate = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier, tools={"list_orders": {"minimum_level": "L2"}}))

    def at(name: str) -> Any:
        meta = proof_meta(fixture_signer(world["env"], "agent"), world["service"], name, CALL_INPUT, world["chain"], now_ms=NOW_MS)
        return gate.authorize({"name": name, "input": CALL_INPUT, "_meta": meta})  # type: ignore[attr-defined]

    return at


@needs_fixtures
def test_a_tool_that_demands_l3_reads_its_lists_live_on_every_call_and_a_tool_set_to_l2_uses_the_cache(world: Dict[str, Any]) -> None:
    lists = FixtureLists(world["env"])
    verifier = instance(world, lists, MemoryStatusCacheStore(lambda: NOW_MS), lambda: NOW_MS)
    at = _guarded(world, verifier)
    first = at("lookup_order")
    assert (first.level, first.fresh) == ("L3", True)
    asked = len(lists.asked)
    # The default minimum is L3: the same call again, inside the TTL, reads every list live and stays L3.
    again = at("lookup_order")
    assert (again.level, again.fresh) == ("L3", True)
    assert len(lists.asked) > asked
    asked = len(lists.asked)
    # A tool set to L2 takes the cached verdicts: no list is read, and the call is L2, not fresh.
    cached = at("list_orders")
    assert (cached.level, cached.fresh) == ("L2", False)
    assert len(lists.asked) == asked
    # The root hop is revoked. The L3 tool sees it at once (live), and its live read refreshed the cache for the L2 tool.
    root = world["chain"][0]
    lists.revoke(root["credentialStatus"]["statusListCredential"], int(root["credentialStatus"]["statusListIndex"]))
    for name in ("lookup_order", "list_orders"):
        with pytest.raises(ProofError) as refused:
            at(name)
        assert list(refused.value.reasons) == ["status_revoked"]


@needs_fixtures
def test_without_a_live_read_an_l2_tool_keeps_the_cached_verdict_until_the_signal_drops_it(world: Dict[str, Any]) -> None:
    lists = FixtureLists(world["env"])
    verifier = instance(world, lists, MemoryStatusCacheStore(lambda: NOW_MS), lambda: NOW_MS)
    at = _guarded(world, verifier)
    first = at("list_orders")
    assert (first.level, first.fresh) == ("L3", True)
    root = world["chain"][0]
    lists.revoke(root["credentialStatus"]["statusListCredential"], int(root["credentialStatus"]["statusListIndex"]))
    # Inside the TTL, with no signal, the L2 tool still reads the cached "not revoked".
    cached = at("list_orders")
    assert (cached.level, cached.fresh) == ("L2", False)
    helix = world["helix"]
    client = create_revocation_signal_client(verifier, trusted_issuers=[helix.did], resolve_did=world["resolve_did"], clock=lambda: NOW_MS)
    assert client.handle(sign_revocation_signal(root["id"], helix, iat=NOW_MS // 1000)).accepted
    with pytest.raises(ProofError) as refused:
        at("list_orders")
    assert list(refused.value.reasons) == ["status_revoked"]


@needs_fixtures
def test_with_the_signal_channel_down_a_revoked_hop_is_refused_no_later_than_status_cache_ttl(world: Dict[str, Any]) -> None:
    lists = FixtureLists(world["env"])
    now = [NOW_MS]
    store = MemoryStatusCacheStore(lambda: now[0])
    a = instance(world, lists, store, lambda: now[0])
    assert present(world, a, now[0]).ok
    leaf = world["chain"][1]
    lists.revoke(leaf["credentialStatus"]["statusListCredential"], int(leaf["credentialStatus"]["statusListIndex"]))
    now[0] += 60_000
    assert present(world, a, now[0]).ok
    now[0] += 61_000
    result = present(world, a, now[0])
    assert (result.ok, list(result.reasons)) == (False, ["status_revoked"])


@needs_fixtures
def test_a_bad_signature_or_unknown_issuer_is_ignored_and_reported_and_revokes_nothing(world: Dict[str, Any]) -> None:
    lists = FixtureLists(world["env"])
    a = instance(world, lists, MemoryStatusCacheStore(lambda: NOW_MS), lambda: NOW_MS)
    assert present(world, a, NOW_MS).ok
    logged: List[str] = []
    helix = world["helix"]
    client = create_revocation_signal_client(a, [helix.did], resolve_did=world["resolve_did"], log=logged.append, clock=lambda: NOW_MS)
    stranger = fixture_signer(world["env"], "stranger")
    foreign = sign_revocation_signal(world["chain"][0]["id"], stranger, iat=NOW_MS // 1000)
    assert client.handle(foreign, "webhook").reason == "signal_unknown_issuer"
    forged_signer = EnvSigner(helix.did, kid="key-1", env_var="K", env={"K": world["env"]["keys"]["stranger"]["private_key_hex"]})
    forged = sign_revocation_signal(world["chain"][0]["id"], forged_signer, iat=NOW_MS // 1000)
    assert client.handle(forged).reason == "signal_bad_signature"
    assert len(logged) == 2
    assert "ignored (webhook): signal_unknown_issuer" in logged[0]
    # The cached verdict is untouched: the next call is still served from the cache.
    result = present(world, a, NOW_MS)
    assert (result.ok, result.fresh) == (True, False)


@needs_fixtures
def test_reports_a_cache_that_cannot_be_reached_and_a_report_hook_that_raises_never_blocks(world: Dict[str, Any]) -> None:
    class Down:
        def invalidate(self, credential_id: str) -> str:
            raise ConnectionError("redis down")

    def hook(report: SignalReport) -> None:
        raise RuntimeError("report hook down")

    helix = world["helix"]
    failing = RevocationSignalClient([helix.did], world["resolve_did"], Down(), on_signal=hook, clock=lambda: NOW_MS)
    outcome = failing.handle(sign_revocation_signal("urn:uuid:x", helix, iat=NOW_MS // 1000))
    assert (outcome.accepted, outcome.reason, outcome.message) == (False, "cache_unavailable", "redis down")
    with pytest.raises(ValueError, match="trusted_issuers"):
        RevocationSignalClient([], world["resolve_did"], Down())
    with pytest.raises(ValueError, match="trusted_issuers"):
        RevocationSignalClient(helix.did, world["resolve_did"], Down())
    with pytest.raises(ValueError, match="events_url"):
        failing.start()

    class NoSeams:
        seams = type("Seams", (), {"resolve_did": None})()
        status_cache = StatusCache()

    with pytest.raises(ValueError, match="resolve_did"):
        create_revocation_signal_client(NoSeams(), [helix.did])


def _asgi_call(app: Any, method: str, body: bytes, content_type: Optional[str] = None, chunk: Optional[int] = None) -> Tuple[int, Dict[str, str], bytes]:
    headers = [] if content_type is None else [(b"content-type", content_type.encode())]
    parts = [body[i : i + chunk] for i in range(0, len(body), chunk)] if chunk else [body]
    messages = [{"type": "http.request", "body": part, "more_body": index < len(parts) - 1} for index, part in enumerate(parts)]
    sent: List[Dict[str, Any]] = []

    async def receive() -> Dict[str, Any]:
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(app({"type": "http", "method": method, "headers": headers}, receive, send))
    if not sent:
        return 0, {}, b""
    return sent[0]["status"], {k.decode(): v.decode() for k, v in sent[0]["headers"]}, sent[1]["body"]


@needs_fixtures
def test_receives_sets_pushed_to_its_webhook_rfc_8935(world: Dict[str, Any]) -> None:
    a = instance(world, FixtureLists(world["env"]), MemoryStatusCacheStore(), lambda: NOW_MS)
    helix = world["helix"]
    client = create_revocation_signal_client(a, [helix.did], resolve_did=world["resolve_did"], log=lambda message: None, clock=lambda: NOW_MS)
    app = client.asgi_webhook()
    set_jwt = sign_revocation_signal(world["chain"][0]["id"], helix, iat=NOW_MS // 1000)
    assert _asgi_call(app, "POST", set_jwt.encode(), "application/secevent+jwt")[0] == 202
    assert _asgi_call(app, "POST", set_jwt.encode(), "application/secevent+jwt; charset=utf-8", chunk=40)[0] == 202
    foreign = sign_revocation_signal("x", fixture_signer(world["env"], "stranger"), iat=NOW_MS // 1000)
    status, headers, body = _asgi_call(app, "POST", foreign.encode(), "application/secevent+jwt")
    assert (status, headers["content-type"], json.loads(body)["err"]) == (400, "application/json", "invalid_issuer")
    assert json.loads(_asgi_call(app, "POST", b"not.a.set", "application/secevent+jwt")[2])["err"] == "invalid_request"
    assert _asgi_call(app, "POST", set_jwt.encode(), "application/json")[0] == 415
    status, headers, _ = _asgi_call(app, "GET", b"")
    assert (status, headers["allow"]) == (405, "POST")
    assert _asgi_call(app, "POST", b"x" * (70 * 1024), "application/secevent+jwt", chunk=16 * 1024)[0] == 400
    assert client.handle_push("POST", "application/secevent+jwt", b"\xff\xfe").status == 400

    class Down:
        def invalidate(self, credential_id: str) -> str:
            raise ConnectionError("down")

    down = RevocationSignalClient([helix.did], world["resolve_did"], Down(), log=lambda message: None, clock=lambda: NOW_MS)
    assert down.handle_push("POST", "application/secevent+jwt", set_jwt.encode()).status == 503


@needs_fixtures
def test_webhook_stops_reading_when_the_client_goes_away(world: Dict[str, Any]) -> None:
    client = RevocationSignalClient([world["helix"].did], world["resolve_did"], StatusCache(), log=lambda message: None)
    sent: List[Any] = []

    async def receive() -> Dict[str, Any]:
        return {"type": "http.disconnect"}

    async def send(message: Any) -> None:
        sent.append(message)

    asyncio.run(client.asgi_webhook()({"type": "http", "method": "POST", "headers": []}, receive, send))
    assert sent == []


@needs_fixtures
def test_keeps_one_sse_connection_open_invalidates_on_each_event_and_reconnects_with_last_event_id(world: Dict[str, Any], listen: Any) -> None:
    a = instance(world, FixtureLists(world["env"]), MemoryStatusCacheStore(), lambda: NOW_MS)
    helix = world["helix"]
    first = sign_revocation_signal("urn:uuid:first", helix, iat=NOW_MS // 1000, jti="j1")
    second = sign_revocation_signal("urn:uuid:second", helix, iat=NOW_MS // 1000, jti="j2")
    last_event_ids: List[Optional[str]] = []
    api_keys: List[Optional[str]] = []
    connections = [0]
    hold = threading.Event()

    def handler(request: http.server.BaseHTTPRequestHandler) -> None:
        connections[0] += 1
        last_event_ids.append(request.headers.get("last-event-id"))
        api_keys.append(request.headers.get("x-api-key"))
        if connections[0] == 1:
            body = f": keep-alive\n\nretry: 10\nid: 1\nevent: revocation\ndata: {first}\n\nevent: other\ndata: ignored\n\n".encode()
            respond(request, 200, body, {"content-type": "text/event-stream", "connection": "close"})
            return
        if connections[0] == 2:
            respond(request, 503, b"", {"connection": "close"})
            return
        request.send_response(200)
        request.send_header("content-type", "text/event-stream; charset=utf-8")
        request.send_header("connection", "close")
        request.end_headers()
        # One event split mid-character (a two-byte "é" in a comment) and mid-line, then the stream stays open.
        payload = f": café\r\nid: 2\r\nevent: revocation\r\ndata: {second}\r\n\r\n".encode()
        split = payload.index(b"\xc3") + 1
        request.wfile.write(payload[:split])
        request.wfile.flush()
        time.sleep(0.05)
        request.wfile.write(payload[split:])
        request.wfile.flush()
        hold.wait(5)

    url = listen(handler)
    reports: List[SignalReport] = []
    states: List[bool] = []
    client = create_revocation_signal_client(
        a,
        [helix.did],
        resolve_did=world["resolve_did"],
        events_url=f"{url}/v1/events/revocations",
        reconnect_delay_ms=5,
        max_reconnect_delay_ms=20,
        on_signal=reports.append,
        on_connection_change=lambda connected, error: states.append(connected),
        headers={"x-api-key": "k"},
        clock=lambda: NOW_MS,
    )
    client.start()
    client.start()
    wait_for(lambda: [report.credential_id for report in reports] == ["urn:uuid:first", "urn:uuid:second"])
    assert client.connected is True
    assert client.last_event_id == "2"
    assert last_event_ids[:3] == [None, "1", "1"]
    assert api_keys[0] == "k"
    client.stop()
    hold.set()
    assert client.connected is False
    assert True in states and states[-1] is False


@needs_fixtures
def test_logs_ignored_signals_by_default_bounds_what_it_remembers_and_refuses_an_answer_with_no_content_type(
    world: Dict[str, Any], listen: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    helix = world["helix"]

    class Hits:
        def invalidate(self, credential_id: str) -> str:
            return "credential"

    quiet = RevocationSignalClient([helix.did], world["resolve_did"], Hits(), clock=lambda: NOW_MS)
    assert quiet.handle("not.a.set", "webhook").reason == "signal_malformed"
    assert "revocation signal ignored (webhook): signal_malformed" in capsys.readouterr().err
    for index in range(1002):
        quiet.handle(sign_revocation_signal(f"urn:uuid:{index}", helix, iat=NOW_MS // 1000, jti=f"j-{index}"))
    assert not quiet.has_seen("j-0")
    assert quiet.has_seen("j-1001")
    calls = [0]

    def handler(request: http.server.BaseHTTPRequestHandler) -> None:
        calls[0] += 1
        request.send_response(200)
        request.send_header("content-length", "0")
        request.end_headers()

    url = listen(handler)
    errors: List[Optional[BaseException]] = []
    client = RevocationSignalClient([helix.did], world["resolve_did"], Hits(), events_url=url, reconnect_delay_ms=5, on_connection_change=lambda c, error: errors.append(error))
    client.start()
    wait_for(lambda: calls[0] >= 1)
    wait_for(lambda: any(error is not None for error in errors))
    client.stop()
    assert "no content type" in str(next(error for error in errors if error is not None))


@needs_fixtures
def test_refuses_a_non_sse_answer_and_keeps_retrying_until_stopped(world: Dict[str, Any], listen: Any) -> None:
    a = instance(world, FixtureLists(world["env"]), MemoryStatusCacheStore(), lambda: NOW_MS)
    calls = [0]

    def handler(request: http.server.BaseHTTPRequestHandler) -> None:
        calls[0] += 1
        respond(request, 200, b"{}", {"content-type": "application/json"})

    url = listen(handler)
    errors: List[Optional[BaseException]] = []
    client = create_revocation_signal_client(a, [world["helix"].did], events_url=url, reconnect_delay_ms=5, on_connection_change=lambda c, error: errors.append(error))
    client.start()
    wait_for(lambda: calls[0] >= 2)
    client.stop()
    assert "not text/event-stream" in str(next(error for error in errors if error is not None))


def test_stop_unblocks_a_stream_that_sends_nothing_and_a_failing_health_hook_never_stops_it() -> None:
    blocked = threading.Event()
    closed = threading.Event()

    def chunks() -> Iterator[bytes]:
        blocked.wait(5)
        if False:  # pragma: no cover - a generator that yields nothing until closed
            yield b""

    def open_stream(url: str, headers: Any) -> SseStream:
        return SseStream(200, "text/event-stream", chunks(), lambda: (closed.set(), blocked.set()))

    def hook(connected: bool, error: Optional[BaseException]) -> None:
        raise RuntimeError("health hook down")

    client = RevocationSignalClient(["did:web:helix.example"], lambda did: None, StatusCache(), events_url="https://helix.example/v1/events/revocations", open_stream=open_stream, on_connection_change=hook)
    client.start()
    wait_for(lambda: client.connected)
    client.stop()
    assert closed.is_set() and client.connected is False


def test_the_default_sse_transport_streams_and_close_unblocks_a_read(listen: Any) -> None:
    hold = threading.Event()

    def handler(request: http.server.BaseHTTPRequestHandler) -> None:
        request.send_response(200)
        request.send_header("content-type", "text/event-stream")
        request.end_headers()
        request.wfile.write(b"data: one\n\n")
        request.wfile.flush()
        hold.wait(5)

    url = listen(handler)
    stream = urllib_open_stream(url, {"accept": "text/event-stream"})
    assert (stream.status, stream.content_type) == (200, "text/event-stream")
    assert next(stream.chunks) == b"data: one\n\n"
    timer = threading.Timer(0.1, stream.close)
    timer.start()
    assert list(stream.chunks) == []
    stream.close()
    hold.set()


# ── the SSE parser ───────────────────────────────────────────────────────────


def test_sse_parser_dispatches_events_per_the_whatwg_rules() -> None:
    events: List[Any] = []
    parser = SseParser(events.append)
    parser.push("data: a\ndata: b\n\n")
    parser.push("id: 7\nevent: x\ndata\n\r")
    parser.push("\n")
    parser.push("id: a\0b\nretry: nope\nretry: 25\nfield-without-colon\n\nevent: dropped\n\n")
    assert [(event.id, event.event, event.data) for event in events] == [(None, "message", "a\nb"), ("7", "x", "")]
    assert parser.retry == 25


# ── the Redis store ──────────────────────────────────────────────────────────


def test_redis_status_cache_store_speaks_get_set_px_del_and_incr() -> None:
    class Client:
        def __init__(self) -> None:
            self.data: Dict[str, Any] = {}
            self.calls: List[Any] = []

        def get(self, key: str) -> Any:
            return self.data.get(key)

        def set(self, key: str, value: str, px: int) -> str:
            self.calls.append(("set", key, px))
            self.data[key] = value.encode()  # redis-py answers bytes unless decode_responses is set
            return "OK"

        def delete(self, key: str) -> int:
            return 1 if self.data.pop(key, None) is not None else 0

        def incr(self, key: str) -> int:
            self.data[key] = int(self.data.get(key, 0)) + 1
            return self.data[key]

    client = Client()
    store = RedisStatusCacheStore(client)
    store.set("k", "v", 0.4)
    assert client.calls[0] == ("set", "k", 1)
    assert store.get("k") == "v"
    assert store.get("missing") is None
    client.data["n"] = 7
    assert store.get("n") == "7"
    store.delete("k")
    assert store.get("k") is None
    assert (store.increment("g"), store.increment("g")) == (1, 2)


# ── the resolution fetch ─────────────────────────────────────────────────────


def test_knows_public_unicast_from_everything_else() -> None:
    for address in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.0.1", "100.64.0.1", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1", "::ffff:a00:1", "0.0.0.0", "not-an-ip"):
        assert not is_public_unicast_address(address), address
    for address in ("8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8", "::ffff:808:808"):
        assert is_public_unicast_address(address), address
    assert not is_public_unicast_address("::ffff:zz:1")


def test_refuses_http_credentials_loopback_outside_development_and_private_ip_literals() -> None:
    for url, development in (
        ("http://example.com/l", False),
        ("ftp://example.com/l", False),
        ("not a url", False),
        ("https://user:pw@example.com/l", False),
        ("https://127.0.0.1/l", False),
        ("https://10.0.0.1/l", True),
        ("https://[fd00::1]/l", True),
        ("http://10.0.0.1/l", True),
        ("https://example.com:notaport/l", False),
        ("https://[bad/l", False),
    ):
        with pytest.raises(ResolutionRefusedError):
            resolution_target(url, development)
    assert resolution_target("https://127.0.0.1:4000/l", True) == "http://127.0.0.1:4000/l"
    assert resolution_target("http://localhost:4000/l", True) == "http://localhost:4000/l"
    assert resolution_target("https://8.8.8.8/l", False) == "https://8.8.8.8/l"


def test_follows_same_origin_redirects_only_bounds_the_body_and_times_out(listen: Any) -> None:
    big = b"x" * 2048

    def handler(request: http.server.BaseHTTPRequestHandler) -> None:
        path = request.path
        if path == "/hop":
            respond(request, 302, headers={"location": "/list"})
        elif path == "/list":
            respond(request, 200, b'{"ok":true}', {"content-type": "application/json"})
        elif path == "/away":
            respond(request, 302, headers={"location": "http://localhost:1/elsewhere"})
        elif path == "/loop":
            respond(request, 302, headers={"location": "/loop"})
        elif path == "/nowhere":
            respond(request, 302)
        elif path == "/declared":
            respond(request, 200, big)
        elif path == "/chunked":
            request.send_response(200)
            request.send_header("connection", "close")
            request.end_headers()
            request.wfile.write(big)
        elif path == "/slow":
            time.sleep(0.5)
            respond(request, 200, b"{}")
        else:
            respond(request, 404)

    url = listen(handler)
    fetcher = create_resolution_fetch(allow_loopback_http=True, max_bytes=1024, timeout_ms=150)
    assert fetcher(f"{url}/hop") == {"ok": True}
    with pytest.raises(ValueError, match="answered 404"):
        fetcher(f"{url}/missing")
    for path, words in (("/away", "another origin"), ("/loop", "too many"), ("/nowhere", "empty redirects"), ("/declared", "at most 1024"), ("/chunked", "exceeds 1024")):
        with pytest.raises(ResolutionRefusedError, match=words):
            fetcher(f"{url}{path}")
    with pytest.raises(Exception):
        fetcher(f"{url}/slow")
    with pytest.raises(ResolutionRefusedError, match="only https"):
        create_resolution_fetch()(f"{url}/list")
    with pytest.raises(ResolutionRefusedError, match="a loopback host"):
        create_resolution_fetch()(url.replace("http:", "https:"))
    empty = create_resolution_fetch(allow_loopback_http=True, transport=lambda target, timeout, cap: TransportResponse(200, {}, b""))
    with pytest.raises(ValueError):
        empty(f"{url}/x")
    expired = create_resolution_fetch(allow_loopback_http=True, timeout_ms=0, transport=lambda target, timeout, cap: TransportResponse(200, {}, b"{}"))
    with pytest.raises(ResolutionRefusedError, match="timed out"):
        expired(f"{url}/x")
    assert urllib_transport(f"{url}/hop", 2, 1024).status == 302


def test_a_list_at_a_private_address_is_refused_before_anything_is_fetched_and_reads_as_revoked() -> None:
    fetched: List[str] = []

    def transport(url: str, timeout: float, cap: int) -> TransportResponse:  # pragma: no cover - must never be reached
        fetched.append(url)
        return TransportResponse(200, {}, b"{}")

    verifier = create_local_verifier(LocalVerifierOptions(service_did="did:web:svc.example", resolve_did=lambda did: None, clock=lambda: NOW_MS, report_verification=lambda entry: None))
    credential = {
        "id": "urn:uuid:c",
        "issuer": "did:web:issuer.example",
        "credentialStatus": {"type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": "1", "statusListCredential": "https://10.0.0.1/status/1"},
    }
    verdict = verifier.seams.check_revocation(credential, RevocationContext(now_ms=NOW_MS))
    assert (verdict.revoked, verdict.code) == (True, "status_unavailable")
    assert "not a public unicast address" in str(verdict.message)
    assert fetched == []
    cached = create_local_verifier(LocalVerifierOptions(service_did="did:web:svc.example", status_cache=verifier.status_cache, report_verification=lambda entry: None))
    assert cached.status_cache is verifier.status_cache

    class Foreign:
        def invalidate(self, credential_id: str) -> str:
            return "credential"

        def get_list(self, url: str, scopes: Any = ()) -> None:
            return None

    foreign = Foreign()
    assert create_local_verifier(LocalVerifierOptions(service_did="did:web:svc.example", status_cache=foreign, report_verification=lambda entry: None)).status_cache is foreign
    tuned = create_local_verifier(LocalVerifierOptions(service_did="did:web:svc.example", status_cache={"status_cache_ttl": 30}, max_clock_skew_ms=0, report_verification=lambda entry: None))
    assert tuned.status_cache.status_cache_ttl == 30


def test_a_host_fetch_is_held_to_the_url_policy_and_fails_closed() -> None:
    asked: List[str] = []

    def host_fetch(url: str) -> Any:
        asked.append(url)
        raise LookupError(f"{url} answered 404")

    verifier = create_local_verifier(
        LocalVerifierOptions(
            service_did="did:web:svc.example",
            fetch=host_fetch,
            resolve_did=lambda did: None,
            status_list_issuers={"did:web:issuer.example": ["https://lists.example"]},
            clock=lambda: NOW_MS,
            report_verification=lambda entry: None,
        )
    )
    entry = {"type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": "1"}
    bound = verifier.seams.check_revocation(
        {"id": "urn:uuid:b", "issuer": "did:web:issuer.example", "credentialStatus": {**entry, "statusListCredential": "https://lists.example/l"}}, RevocationContext(now_ms=NOW_MS)
    )
    assert (bound.revoked, bound.code) == (True, "status_unavailable")
    assert asked == ["https://lists.example/l"]
    # An http: list never reaches the host's fetch, and reads as revoked.
    plain = verifier.seams.check_revocation(
        {"id": "urn:uuid:c", "issuer": "did:web:issuer.example", "credentialStatus": {**entry, "statusListCredential": "http://lists.example/l"}}, RevocationContext(now_ms=NOW_MS)
    )
    assert (plain.revoked, plain.code) == (True, "status_unavailable")
    assert "only https" in str(plain.message)
    assert asked == ["https://lists.example/l"]
