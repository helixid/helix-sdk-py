# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0
"""KYA-OS story L3-C in the Python sample: the revocation settings read from
the environment (status cache and its redis-py client, signal client,
verification log), the webhook route, and the store shared by two instances.
Mirrors the JS sample's main.ts settings."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

pytest.importorskip("mcp")
pytest.importorskip("starlette")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from starlette.testclient import TestClient  # noqa: E402

from helix_mcp_middleware import MCPMiddlewareOptions, RedisStatusCacheStore, create_local_verifier  # noqa: E402
from helix_sdk.verifier import MemoryStatusCacheStore, sign_revocation_signal  # noqa: E402
from mcp_order_management import __main__ as sample  # noqa: E402
from mcp_order_management.app import create_order_app  # noqa: E402
from mcp_proof_helpers import NOW_MS, fixture_signer, have_verifier_fixtures, load_environment  # noqa: E402

SERVICE = "did:web:orders.example"
HELIX = "did:web:helix.example"


def exits(fn: Any, *args: Any) -> str:
    with pytest.raises(SystemExit):
        fn(*args)
    return ""


# ── the settings ─────────────────────────────────────────────────────────────


def test_reads_seconds_and_json_settings_and_refuses_bad_values(capsys: pytest.CaptureFixture[str]) -> None:
    assert sample.seconds_from_env({}, "X") is None
    assert sample.seconds_from_env({"X": "1.5"}, "X") == 1.5
    assert sample.seconds_from_env({"X": "0"}, "X") == 0
    for value, positive in (("0", True), ("-1", False), ("nope", False), ("inf", False), ("nan", False)):
        exits(sample.seconds_from_env, {"X": value}, "X", positive)
    assert sample.json_object_from_env({}, "J") is None
    assert sample.json_object_from_env({"J": '{"did:web:a": ["https://a"]}'}, "J") == {"did:web:a": ["https://a"]}
    exits(sample.json_object_from_env, {"J": "{"}, "J")
    exits(sample.json_object_from_env, {"J": "[]"}, "J")
    assert "must be a positive number" in capsys.readouterr().err


def test_builds_the_status_cache_from_the_environment_on_memory_or_redis() -> None:
    cache = sample.status_cache_from_env(
        {"KYAOS_STATUS_CACHE_TTL": "120", "KYAOS_HIGH_PRIVILEGE_SCOPES": "orders:admin, ,orders:refund", "KYAOS_HIGH_PRIVILEGE_TTL": "30", "KYAOS_MAX_STALE_SECONDS": "5"},
        None,
    )
    assert (cache.status_cache_ttl, cache.high_privilege_ttl, cache.max_stale_seconds) == (120, 30, 5)
    assert cache.high_privilege_scopes == frozenset({"orders:admin", "orders:refund"})
    assert isinstance(cache._store, MemoryStatusCacheStore)
    shared = sample.status_cache_from_env({}, object())
    assert isinstance(shared._store, RedisStatusCacheStore)
    # SPEC.md §6.5.2: a high-privilege read is cached at most 60 s.
    exits(sample.status_cache_from_env, {"KYAOS_HIGH_PRIVILEGE_TTL": "61"}, None)


def test_logs_each_event_as_a_json_line_on_stdout_or_to_a_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert sample.event_logger({}) is None
    sample.event_logger({"KYAOS_VERIFICATION_LOG": "1"})("verification", {"ok": True})  # type: ignore[misc]
    assert capsys.readouterr().out == '[kya-os] verification {"ok": true}\n'
    target = tmp_path / "events.jsonl"
    log = sample.event_logger({"KYAOS_VERIFICATION_LOG": str(target)})
    assert log is not None
    log("verification", {"ok": True, "level": "L3"})
    log("revocation-events", {"connected": False})
    assert [json.loads(line) for line in target.read_text().splitlines()] == [
        {"kind": "verification", "ok": True, "level": "L3"},
        {"kind": "revocation-events", "connected": False},
    ]


def test_verifier_settings_carry_the_cache_the_keeper_bindings_and_the_log(tmp_path: Path) -> None:
    target = tmp_path / "v.jsonl"
    options = sample.verifier_from_env(
        {"KYAOS_STATUS_CACHE_TTL": "90", "KYAOS_STATUS_LIST_ISSUERS": '{"did:web:i": ["https://i"]}', "KYAOS_VERIFICATION_LOG": str(target)},
        SERVICE,
    )
    assert options.status_cache.status_cache_ttl == 90
    assert options.status_list_issuers == {"did:web:i": ["https://i"]}
    assert options.report_verification is not None
    options.report_verification({"ok": False})
    assert json.loads(target.read_text()) == {"kind": "verification", "ok": False}
    assert sample.verifier_from_env({}, SERVICE).report_verification is None
    exits(sample.verifier_from_env, {"KYAOS_REDIS_URL": "http://not-redis"}, SERVICE)


def test_the_status_cache_gets_a_redis_py_client_only_when_kyaos_redis_url_is_set(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    assert sample.status_cache_redis_from_env({}) is None
    redis = pytest.importorskip("redis")
    # A client is made, not connected: redis-py connects at the first command.
    client = sample.status_cache_redis_from_env({"KYAOS_REDIS_URL": "redis://127.0.0.1:1/0"})
    assert isinstance(client, redis.Redis)
    monkeypatch.setitem(sys.modules, "redis", None)  # as if the extra were not installed
    exits(sample.status_cache_redis_from_env, {"KYAOS_REDIS_URL": "redis://127.0.0.1:6380"})
    assert "pip install 'helixid-sdk-py[redis]'" in capsys.readouterr().err


def test_builds_the_signal_client_only_with_its_issuers_and_a_channel(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    verifier = create_local_verifier(service_did=SERVICE, resolve_did=lambda did: None, report_verification=lambda entry: None)
    assert sample.revocation_signals_from_env({}, verifier, None) == (None, None)
    exits(sample.revocation_signals_from_env, {"KYAOS_SIGNAL_ISSUERS": HELIX}, verifier, None)
    exits(sample.revocation_signals_from_env, {"KYAOS_REVOCATION_EVENTS_URL": "https://helix.example/v1/events/revocations"}, verifier, None)
    exits(sample.revocation_signals_from_env, {"KYAOS_SIGNAL_ISSUERS": HELIX, "KYAOS_REVOCATION_WEBHOOK_PATH": "relative"}, verifier, None)
    target = tmp_path / "s.jsonl"
    log = sample.event_logger({"KYAOS_VERIFICATION_LOG": str(target)})
    client, path = sample.revocation_signals_from_env(
        {"KYAOS_SIGNAL_ISSUERS": HELIX, "KYAOS_REVOCATION_EVENTS_URL": "https://helix.example/v1/events/revocations", "KYAOS_REVOCATION_WEBHOOK_PATH": "/revocation-signals"},
        verifier,
        log,
    )
    assert client is not None and path == "/revocation-signals"
    assert (client.events_url, client.trusted_issuers) == ("https://helix.example/v1/events/revocations", [HELIX])
    # Every signal is one line on stdout and in the log; so is every connection change.
    client.handle("not.a.set", "webhook")
    client._on_connection_change(True, None)  # type: ignore[misc]
    client._on_connection_change(False, ConnectionError("dropped"))  # type: ignore[misc]
    out = capsys.readouterr().out
    assert '[kya-os] revocation-signal {"timestamp"' in out and "revocation-events connected" in out and "disconnected: dropped" in out
    kinds = [json.loads(line) for line in target.read_text().splitlines()]
    assert [entry["kind"] for entry in kinds] == ["revocation-signal", "revocation-events", "revocation-events"]
    assert kinds[0]["reason"] == "signal_malformed" and kinds[2] == {"kind": "revocation-events", "connected": False, "error": "dropped"}
    quiet, _ = sample.revocation_signals_from_env({"KYAOS_SIGNAL_ISSUERS": HELIX, "KYAOS_REVOCATION_WEBHOOK_PATH": "/hook"}, verifier, None)
    assert quiet is not None and quiet.events_url is None
    quiet.handle("not.a.set", "webhook")
    quiet._on_connection_change(True, None)  # type: ignore[misc]


@pytest.mark.skipif(not have_verifier_fixtures(), reason="helix-core fixtures/verifier not found")
def test_the_sample_mounts_the_webhook_route_and_the_signal_reaches_the_cache() -> None:
    env = load_environment()
    helix = fixture_signer(env, "helix")
    verifier = create_local_verifier(service_did=SERVICE, resolve_did=lambda did: env["did_documents"].get(did), report_verification=lambda entry: None, clock=lambda: NOW_MS)
    client, path = sample.revocation_signals_from_env({"KYAOS_SIGNAL_ISSUERS": helix.did, "KYAOS_REVOCATION_WEBHOOK_PATH": "/revocation-signals"}, verifier, None)
    assert client is not None and path is not None
    client._clock = lambda: NOW_MS  # type: ignore[attr-defined]
    app = create_order_app("http://127.0.0.1:3700/mcp", MCPMiddlewareOptions(verifier=verifier, service_did=SERVICE), revocation_webhook=(path, client.asgi_webhook()))
    with TestClient(app, base_url="http://127.0.0.1:3700") as http:
        set_jwt = sign_revocation_signal("urn:uuid:revoked", helix, iat=NOW_MS // 1000)
        accepted = http.post("/revocation-signals", content=set_jwt, headers={"content-type": "application/secevent+jwt"})
        assert accepted.status_code == 202
        refused = http.post("/revocation-signals", content="not.a.set", headers={"content-type": "application/secevent+jwt"})
        assert (refused.status_code, refused.json()["err"]) == (400, "invalid_request")
        assert http.get("/elsewhere").status_code == 404


def test_main_refuses_revocation_settings_without_a_service_did(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sample.os, "environ", {"DEMO_MODE": "1", "KYAOS_STATUS_CACHE_TTL": "60"})
    exits(sample.main)
    assert "revocation settings need SERVICE_DID" in capsys.readouterr().err


def test_main_starts_and_stops_the_signal_stream_around_the_server(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    pytest.importorskip("redis")
    started: List[str] = []

    def fake_run(app: Any, host: str, port: int, log_level: str) -> None:
        started.append(f"{host}:{port}")
        raise KeyboardInterrupt

    monkeypatch.setattr(sample.uvicorn, "run", fake_run)
    monkeypatch.setattr(sample.RevocationSignalClient, "start", lambda self: started.append("start"))
    monkeypatch.setattr(sample.RevocationSignalClient, "stop", lambda self, timeout=5.0: started.append("stop"))
    monkeypatch.setattr(
        sample.os,
        "environ",
        {
            "SERVICE_DID": SERVICE,
            "KYAOS_SIGNAL_ISSUERS": HELIX,
            "KYAOS_REVOCATION_EVENTS_URL": "https://helix.example/v1/events/revocations",
            "KYAOS_REVOCATION_WEBHOOK_PATH": "/revocation-signals",
            "KYAOS_REDIS_URL": "redis://127.0.0.1:6380",
        },
    )
    with pytest.raises(KeyboardInterrupt):
        sample.main()
    assert started == ["start", "127.0.0.1:3700", "stop"]
    out = capsys.readouterr().out
    assert "Revocation:  list proofs verified, cache redis redis://127.0.0.1:6380, signals SSE https://helix.example/v1/events/revocations + webhook /revocation-signals" in out


def test_main_without_signals_says_so(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sample.uvicorn, "run", lambda app, host, port, log_level: None)
    monkeypatch.setattr(sample.os, "environ", {"SERVICE_DID": SERVICE})
    sample.main()
    assert "cache in memory, signals off" in capsys.readouterr().out


# ── the shared store ─────────────────────────────────────────────────────────


def test_the_store_and_client_share_a_cache_between_two_instances_over_redis() -> None:
    """Both stores talk to the same scripted Redis: what one writes, the other reads."""
    values: Dict[str, str] = {}

    class Memory:
        def get(self, key: str) -> Optional[str]:
            return values.get(key)

        def set(self, key: str, value: str, px: int) -> str:
            values[key] = value
            return "OK"

        def delete(self, key: str) -> int:
            return 1 if values.pop(key, None) is not None else 0

        def incr(self, key: str) -> int:
            values[key] = str(int(values.get(key, "0")) + 1)
            return int(values[key])

    one, two = RedisStatusCacheStore(Memory()), RedisStatusCacheStore(Memory())
    one.set("kyaos:status:verdict:x", '{"url": "u"}', 1000)
    assert two.get("kyaos:status:verdict:x") == '{"url": "u"}'
    assert two.increment("kyaos:status:generation") == 1
