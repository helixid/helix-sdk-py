# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""KYA-OS story F-2: the gate verifies every request proof in-process with the
local verifier; the Helix API is never asked. The same cases as helix-sdk-js's
mcp-middleware tests/verify-locally.test.ts and tests/middleware.test.ts
(proof path), over the shared helix-core fixtures."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.keys import derive_public_key, public_key_to_multibase
from helix_sdk.verifier import StatusListError, sign_request_proof
from helix_mcp_middleware import (
    LocalVerifierOptions,
    MemoryNonceStore,
    MCPMiddlewareOptions,
    ProofError,
    async_helixid_mcp_middleware,
    card_endpoint_of,
    create_local_verifier,
    helixid_mcp_middleware,
    resolution_url,
    unrecorded_reporter,
)
import helix_mcp_middleware.verify_locally as verify_locally_module
import helix_mcp_middleware.resolution_fetch as resolution_fetch_module
from helix_mcp_middleware.resolution_fetch import TransportResponse

from mcp_revocation_helpers import ListIssuer, bitstring_list, well_known_did_url
from mcp_proof_helpers import (
    NOW_MS,
    fixture_signer,
    fixture_verifier_options,
    have_verifier_fixtures,
    load_cases,
    load_environment,
    make_agent,
    proof_meta,
    valid_chain,
)

SERVICE = "did:web:orders.helix.test"
AGENT = "did:web:127.0.0.1%3A4000:agents:a1"
_KEY = "11" * 32
SIGNER = EnvSigner(AGENT, env_var="K", env={"K": _KEY})
DOCUMENT: Dict[str, Any] = {
    **__import__("helix_sdk.did", fromlist=["build_did_document"]).build_did_document(AGENT, derive_public_key(_KEY)),
    "service": [{"id": "#kya-os-card", "type": "KyaOsEntityCard", "serviceEndpoint": "https://127.0.0.1:4000/agents/a1/card.json"}],
}
# The same document without the card service: no card is fetched for it.
PLAIN_DOCUMENT: Dict[str, Any] = {key: value for key, value in DOCUMENT.items() if key != "service"}
CARD = {"id": AGENT, "entityType": "agent", "name": "a1", "capabilities": ["read:orders"]}
LIST_ISSUER = ListIssuer("did:web:issuer.example")
STATUS_LIST = bitstring_list("https://issuer.example/status/1", LIST_ISSUER)


def static_fetch(served: Dict[str, Any], asked: List[str]) -> Any:
    def fetch(url: str) -> Any:
        asked.append(url)
        if url not in served:
            raise LookupError(f"{url} answered 404")
        return served[url]

    return fetch


def quiet(**settings: Any) -> Any:
    return create_local_verifier(LocalVerifierOptions(**{"service_did": SERVICE, "clock": lambda: NOW_MS, "report_verification": lambda entry: None, **settings}))


# ── resolution URLs and card endpoints ───────────────────────────────────────


def test_reads_https_only_and_http_on_loopback_only_in_development() -> None:
    assert resolution_url("https://example.com/did.json", False) == "https://example.com/did.json"
    assert resolution_url("http://example.com/did.json", False) is None
    assert resolution_url("http://example.com/did.json", True) is None
    assert resolution_url("https://127.0.0.1:4000/x", True) == "http://127.0.0.1:4000/x"
    assert resolution_url("http://localhost:4000/x", True) == "http://localhost:4000/x"
    assert resolution_url("https://[::1]:4000/x", True) == "http://[::1]:4000/x"
    assert resolution_url("https://127.0.0.1:4000/x", False) == "https://127.0.0.1:4000/x"
    assert resolution_url("not a url", True) is None
    assert resolution_url("ftp://127.0.0.1/x", True) is None
    assert resolution_url("https://[bad/x", True) is None


def test_finds_the_kya_os_entity_card_service() -> None:
    assert card_endpoint_of(DOCUMENT) == "https://127.0.0.1:4000/agents/a1/card.json"
    assert card_endpoint_of({"service": [{"type": ["Other", "KyaOsEntityCard"], "serviceEndpoint": "https://x"}, "junk"]}) == "https://x"
    assert card_endpoint_of({"service": [{"type": "KyaOsEntityCard", "serviceEndpoint": {"nested": True}}]}) is None
    assert card_endpoint_of({}) is None
    assert card_endpoint_of(None) is None


# ── create_local_verifier defaults ───────────────────────────────────────────


def test_resolves_did_web_the_card_and_status_lists_over_the_injected_fetch_and_verifies_a_call() -> None:
    asked: List[str] = []
    served = {
        "http://127.0.0.1:4000/agents/a1/did.json": DOCUMENT,
        "http://127.0.0.1:4000/agents/a1/card.json": CARD,
        "https://issuer.example/status/1": STATUS_LIST,
        "https://issuer.example/status/unsigned": bitstring_list("https://issuer.example/status/unsigned", LIST_ISSUER, unsigned=True),
        well_known_did_url(LIST_ISSUER.did): LIST_ISSUER.document,
    }
    verifier = quiet(fetch=static_fetch(served, asked), allow_loopback_http=True)
    result = verifier.verify_call({"name": "t", "_meta": proof_meta(SIGNER, SERVICE, "t")})
    assert (result.ok, result.level, result.proof_did) == (True, "L1", AGENT)
    assert asked[-1] == "http://127.0.0.1:4000/agents/a1/card.json"
    assert set(asked) == {"http://127.0.0.1:4000/agents/a1/did.json", "http://127.0.0.1:4000/agents/a1/card.json"}
    read = verifier.seams.fetch_status_list("https://issuer.example/status/1")
    assert (read.issuer, read.id, read.fresh, read.proof_verified) == ("did:web:issuer.example", "https://issuer.example/status/1", True, True)
    # The list's own proof is verified before any bit is read (story L3-C).
    with pytest.raises(StatusListError) as unsigned:
        verifier.seams.fetch_status_list("https://issuer.example/status/unsigned")
    assert unsigned.value.code == "status_list_proof_invalid"
    with pytest.raises(StatusListError, match="404"):
        verifier.seams.fetch_status_list("https://issuer.example/status/missing")
    with pytest.raises(StatusListError, match="only https"):
        verifier.seams.fetch_status_list("http://issuer.example/status/1")
    assert isinstance(verifier.nonce_store, MemoryNonceStore)
    assert verifier.verify_call({"name": "t", "_meta": {}}) is None
    assert verifier.verify_call({"name": "t"}) is None


def test_refuses_http_resolution_outside_development_and_resolves_did_key_offline() -> None:
    asked: List[str] = []
    verifier = quiet(fetch=static_fetch({}, asked))
    result = verifier.verify_call({"name": "t", "_meta": proof_meta(SIGNER, SERVICE, "t")})
    assert result.reasons == ["did_unresolved"]
    # Outside development the loopback did:web is read over https, where nothing answers.
    assert set(asked) == {"https://127.0.0.1:4000/agents/a1/did.json"}
    asked.clear()
    key = "22" * 32
    multibase = public_key_to_multibase(derive_public_key(key))
    did = f"did:key:{multibase}"
    offline = verifier.verify_call({"name": "t", "_meta": proof_meta(EnvSigner(did, kid=multibase, env_var="K", env={"K": key}), SERVICE, "t")})
    assert (offline.ok, offline.proof_did) == (True, did)
    assert asked == []


def test_takes_cards_from_local_config_before_the_resolver_and_a_resolve_card_seam_of_the_host() -> None:
    configured = quiet(resolve_did=lambda did: DOCUMENT, cards={AGENT: CARD})
    assert configured.seams.resolve_card(AGENT) is CARD
    hosted = quiet(resolve_did=lambda did: DOCUMENT, resolve_card=lambda did: {**CARD, "name": "hosted"})
    assert hosted.seams.resolve_card(AGENT)["name"] == "hosted"
    none = quiet(resolve_did=lambda did: {"id": AGENT})
    assert none.seams.resolve_card(AGENT) is None


def test_passes_the_service_settings_through_to_the_verifier() -> None:
    verifier = quiet(
        resource="did:web:resource",
        resource_owner="did:web:owner",
        trusted_root_issuers=["did:web:owner"],
        trusted_issuers=["did:web:helix"],
        max_chain_length=3,
        skew_seconds=10,
        max_clock_skew_ms=1000,
        catalog=["read:orders"],
        resolve_did=lambda did: PLAIN_DOCUMENT,
    )
    assert verifier.seams.trusted_issuers == ["did:web:helix"]
    meta = proof_meta(SIGNER, SERVICE, "t", chain=[1, 2, 3, 4])
    assert verifier.verify_call({"name": "t", "_meta": meta}).reasons == ["chain_too_long"]
    direct = verifier.verify(meta["org.kya-os/request-proof"], request={"method": "tools/call", "params": {"name": "t"}}, expected_audience="did:web:elsewhere")
    assert direct.reasons == ["audience_mismatch"]
    with pytest.raises(ValueError, match="service_did must be a DID"):
        create_local_verifier(service_did="nope")
    with pytest.raises(TypeError):
        create_local_verifier(LocalVerifierOptions(service_did=SERVICE), clock=lambda: 0)
    assert create_local_verifier(service_did=SERVICE).service_did == SERVICE


def test_says_once_that_verifications_are_unrecorded_without_a_report_hook(capsys: pytest.CaptureFixture) -> None:
    logged: List[str] = []
    verifier = create_local_verifier(service_did=SERVICE, resolve_did=lambda did: PLAIN_DOCUMENT, clock=lambda: NOW_MS, log=logged.append)
    verifier.verify_call({"name": "t", "_meta": proof_meta(SIGNER, SERVICE, "t")})
    verifier.verify_call({"name": "t", "_meta": proof_meta(SIGNER, SERVICE, "t")})
    assert len(logged) == 1 and "unrecorded" in logged[0]
    unrecorded_reporter()({"ok": True})
    assert "unrecorded" in capsys.readouterr().err


def test_reports_every_verification_and_survives_a_hook_that_raises_or_is_async() -> None:
    reports: List[Dict[str, Any]] = []
    verifier = quiet(resolve_did=lambda did: PLAIN_DOCUMENT, report_verification=reports.append)
    verifier.verify_call({"name": "t", "_meta": proof_meta(SIGNER, SERVICE, "t")})
    assert reports[0] == {
        "timestamp": "2026-06-01T00:00:00.000Z", "serviceDid": SERVICE, "toolName": "t", "agentDid": AGENT, "ok": True,
        "level": "L1", "proofAssurance": "L3-minus", "proofFloor": True, "l3Minus": False, "cnfDiagnostics": [],
        "effectiveScopes": [], "reasons": [], "fresh": True, "chainDepth": 0,
    }
    errors: List[BaseException] = []

    def boom(entry: Dict[str, Any]) -> None:
        raise RuntimeError("trail down")

    async def later(entry: Dict[str, Any]) -> None: ...

    for hook in (boom, later):
        failing = quiet(resolve_did=lambda did: PLAIN_DOCUMENT, report_verification=hook, on_report_error=errors.append)
        assert failing.verify_call({"name": "t", "_meta": proof_meta(SIGNER, SERVICE, "t")}).ok
    assert [type(e) for e in errors] == [RuntimeError, TypeError]
    quiet(resolve_did=lambda did: PLAIN_DOCUMENT, report_verification=boom).verify_call({"name": "t", "_meta": proof_meta(SIGNER, SERVICE, "t")})


def test_fetches_over_http_when_no_fetch_is_injected(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: List[str] = []

    def fake_transport(url: str, timeout: float, max_bytes: int) -> TransportResponse:
        asked.append(url)
        return TransportResponse(200, {}, json.dumps(DOCUMENT).encode())

    # The default fetch is create_resolution_fetch over urllib (story L3-C).
    monkeypatch.setattr(resolution_fetch_module, "urllib_transport", fake_transport)
    verifier = quiet(allow_loopback_http=True)
    assert verifier.verify_call({"name": "t", "_meta": proof_meta(SIGNER, SERVICE, "t")}).proof_did == AGENT
    assert asked[0] == "http://127.0.0.1:4000/agents/a1/did.json"


# ── the gate's proof path ────────────────────────────────────────────────────

AGENT_OWN = make_agent()


def gate(**options: Any) -> Any:
    # Levels are not the subject here (story C-C's gate is in test_mcp_levels.py): every level is accepted.
    options.setdefault("minimum_level", "L1")
    return helixid_mcp_middleware(MCPMiddlewareOptions(**options))


def own_verifier(**settings: Any) -> Any:
    return create_local_verifier(fixture_verifier_options(SERVICE, documents={AGENT_OWN["did"]: AGENT_OWN["document"]}, **settings))


def refusal(fn: Any) -> Any:
    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        fn()
    return excinfo.value


def test_proof_missing_and_arguments_never_read() -> None:
    mw = gate(verifier=own_verifier())
    err = refusal(lambda: mw({"name": "orders.lookup", "input": {}}))
    assert (err.code, err.status_code if hasattr(err, "status_code") else 401) == ("PROOF_MISSING", 401)
    assert refusal(lambda: mw({"name": "orders.lookup", "input": {"org.kya-os/request-proof": {"x": 1}}})).code == "PROOF_MISSING"


def test_a_valid_proof_from_an_agent_whose_document_resolves_is_l1_with_no_scopes() -> None:
    verifier = own_verifier()
    mw = gate(verifier=verifier, required_scopes=[])
    call = {"name": "orders.lookup", "input": {"orderId": "ORD-1"}, "_meta": proof_meta(AGENT_OWN["signer"], SERVICE, "orders.lookup", {"orderId": "ORD-1"})}
    assert mw(call) is call
    assert mw.verifier is verifier


def test_refuses_a_replay_a_proof_for_another_service_and_a_tampered_request_naming_the_reason() -> None:
    mw = gate(verifier=own_verifier(), required_scopes=[])
    signer = AGENT_OWN["signer"]
    meta = proof_meta(signer, SERVICE, "t", {"a": 1})
    assert mw({"name": "t", "input": {"a": 1}, "_meta": meta})
    replay = refusal(lambda: mw({"name": "t", "input": {"a": 1}, "_meta": meta}))
    assert isinstance(replay, ProofError) and (replay.code, replay.reasons) == ("PROOF_INVALID", ("nonce_replayed",))
    assert refusal(lambda: mw({"name": "t", "input": {"a": 2}, "_meta": proof_meta(signer, SERVICE, "t", {"a": 1})})).reasons == ("request_hash_mismatch",)
    assert refusal(lambda: mw({"name": "t", "input": {"a": 1}, "_meta": proof_meta(signer, "did:web:other", "t", {"a": 1})})).reasons == ("audience_mismatch",)


def test_hashes_the_json_rpc_request_the_host_hands_over_as_received() -> None:
    mw = gate(verifier=own_verifier(), required_scopes=[])
    request = {"method": "tools/call", "params": {"name": "t", "arguments": {"a": 1}, "extra": "member"}}
    meta = {"org.kya-os/request-proof": sign_request_proof(request, AGENT_OWN["signer"], audience=SERVICE, now_ms=NOW_MS)}
    # Rebuilt from name and input, the extra member is missing and the hash differs.
    assert refusal(lambda: mw({"name": "t", "input": {"a": 1}, "_meta": meta})).reasons == ("request_hash_mismatch",)
    assert mw({"name": "t", "input": {"a": 1}, "_meta": meta, "request": {**request, "params": {**request["params"], "_meta": meta}}})


def test_reads_the_proof_under_the_legacy_key_for_one_major_version() -> None:
    mw = gate(verifier=own_verifier(), required_scopes=[])
    call = {"name": "t", "_meta": proof_meta(AGENT_OWN["signer"], SERVICE, "t", legacy_key=True)}
    assert mw(call) is call


def test_audits_a_granted_proof_and_a_refused_one_whose_signer_was_identified() -> None:
    events: List[Dict[str, Any]] = []
    mw = gate(verifier=own_verifier(), audit_sink=events.append, service_did=SERVICE)
    meta = proof_meta(AGENT_OWN["signer"], SERVICE, "t")
    mw({"name": "t", "_meta": meta})
    # Section 11.2 refuses a replay before the signature (story C-C): no principal is proven, so it is not audited.
    assert refusal(lambda: mw({"name": "t", "_meta": meta})).reasons == ("nonce_replayed",)
    # A proof that verified, under a chain that does not: the refusal names the proven signer.
    broken_chain = proof_meta(AGENT_OWN["signer"], SERVICE, "t", chain=[{"type": ["VerifiableCredential"]}])
    refusal(lambda: mw({"name": "t", "_meta": broken_chain}))
    assert len(events) == 2
    assert {k: events[0][k] for k in ("event", "authMethod", "agentDid", "level", "fresh", "serviceDid", "proofAssurance", "l3Minus")} == {
        "event": "AUTHZ_GRANTED", "authMethod": "kyaos", "agentDid": AGENT_OWN["did"], "level": "L1", "fresh": True, "serviceDid": SERVICE,
        "proofAssurance": "L3-minus", "l3Minus": False,
    }
    assert (events[1]["event"], events[1]["agentDid"]) == ("AUTHZ_DENIED", AGENT_OWN["did"]) and events[1]["reason"]


def test_builds_the_verifier_from_settings_with_the_service_did_and_the_tool_scopes_as_the_catalog() -> None:
    mw = gate(
        service_did=SERVICE,
        tool_scopes={"t": ["read:orders"]},
        verifier=LocalVerifierOptions(clock=lambda: NOW_MS, resolve_did=lambda did: AGENT_OWN["document"], report_verification=lambda e: None),
    )
    assert mw.verifier.service_did == SERVICE
    assert refusal(lambda: mw({"name": "t", "_meta": proof_meta(AGENT_OWN["signer"], SERVICE, "t")})).code == "INSUFFICIENT_SCOPE"


def test_the_async_gate_awaits_an_async_report_hook_on_the_loop() -> None:
    import asyncio

    reports: List[Dict[str, Any]] = []

    async def report(entry: Dict[str, Any]) -> None:
        await asyncio.sleep(0)
        reports.append(entry)

    options = fixture_verifier_options(SERVICE, documents={AGENT_OWN["did"]: AGENT_OWN["document"]}, report_verification=report)
    mw = async_helixid_mcp_middleware(MCPMiddlewareOptions(minimum_level="L1", verifier=options, required_scopes=[]))
    call = {"name": "t", "_meta": proof_meta(AGENT_OWN["signer"], SERVICE, "t")}
    assert asyncio.run(mw(call)) is call
    assert [r["ok"] for r in reports] == [True]
    assert mw.verifier.service_did == SERVICE


def test_the_middleware_imports_no_helix_client_and_no_api_urls() -> None:
    package = Path(verify_locally_module.__file__).parent
    for name in ("middleware.py", "verify_locally.py", "credentials.py", "types.py", "__init__.py", "resolution_fetch.py", "revocation_signals.py", "kyaos/status_cache_store.py"):
        content = (package / name).read_text("utf-8")
        assert "HelixClient" not in content, name
        assert "localhost:3000" not in content, name
        assert "vp_transport" not in content and "verify_vp" not in content, name


# ── over the shared fixtures: a signed chain and an attested card ────────────

needs_fixtures = pytest.mark.skipif(not have_verifier_fixtures(), reason="helix-core fixtures/verifier not found")


@needs_fixtures
def test_authorises_a_tool_from_attestations_leaf_actions_and_tool_scopes_at_l3() -> None:
    env = load_environment()
    service, agent = env["keys"]["service"]["did"], env["keys"]["agent"]["did"]
    signer, chain = fixture_signer(env, "agent"), valid_chain()
    reports: List[Dict[str, Any]] = []
    events: List[Dict[str, Any]] = []
    verifier = create_local_verifier(fixture_verifier_options(service, env=env, cards={agent: env["cards"]["attested"]}, report_verification=reports.append))
    mw = gate(verifier=verifier, tool_scopes={"lookup_order": ["read:orders"], "refund_order": ["refund:orders"]}, audit_sink=events.append)
    mw({"name": "lookup_order", "input": {"orderId": "ORD-1001"}, "_meta": proof_meta(signer, service, "lookup_order", {"orderId": "ORD-1001"}, chain)})
    assert (events[0]["authMethod"], events[0]["agentDid"], events[0]["level"], events[0]["fresh"], events[0]["effectiveScopes"]) == (
        "kyaos", agent, "L3", True, ["read:orders", "write:orders"]
    )
    assert {k: reports[0][k] for k in ("ok", "level", "toolName", "chainDepth", "serviceDid", "reasons")} == {
        "ok": True, "level": "L3", "toolName": "lookup_order", "chainDepth": 2, "serviceDid": service, "reasons": [],
    }
    assert refusal(lambda: mw({"name": "refund_order", "input": {}, "_meta": proof_meta(signer, service, "refund_order", {}, chain)})).code == "INSUFFICIENT_SCOPE"


@needs_fixtures
def test_refuses_every_refused_chain_and_status_fixture_with_its_reasons_and_never_falls_back() -> None:
    env = load_environment()
    service, agent = env["keys"]["service"]["did"], env["keys"]["agent"]["did"]
    signer = fixture_signer(env, "agent")
    lookups: List[str] = []
    verifier = create_local_verifier(
        fixture_verifier_options(service, env=env, cards={agent: env["cards"]["attested"]}, resolve_card=lambda did: lookups.append(did))
    )
    mw = gate(verifier=verifier, required_scopes=[])
    # Cases about the case's own card: this gate always presents the configured attested card.
    skip = {"root_not_responsible_party", "card_malformed", "card_subject_mismatch", "card_unresolvable", "revoked_card", "card_list_not_kept_by_card"}
    cases = [
        case
        for case in [*load_cases()["chain"], *load_cases()["status"]]
        if not case["expected"]["ok"]
        and case["input"].get("proof") is not None
        and len(case["options"]) == 2
        and case["options"].get("resource") == service
        and case["seams"]["fetchStatusList"] == "lists"
        and case["name"] not in skip
    ]
    assert len(cases) > 20
    for case in cases:
        meta = proof_meta(signer, service, "lookup_order", {"orderId": "ORD-1001"}, case["input"].get("chain"))
        err = refusal(lambda meta=meta: mw({"name": "lookup_order", "input": {"orderId": "ORD-1001"}, "_meta": meta}))
        assert (err.code, list(err.reasons)) == ("PROOF_INVALID", case["expected"]["reasons"]), case["name"]
    assert lookups == []


def test_the_helix_audit_sink_records_a_kyaos_caller_at_its_level_and_refuses_an_error_answer() -> None:
    from helix_mcp_middleware import create_helix_audit_sink

    posted: List[Dict[str, Any]] = []

    class Http:
        def __init__(self, status: int) -> None:
            self.status = status

        def post(self, url: str, **kwargs: Any) -> Any:
            posted.append(json.loads(kwargs["data"]))
            return type("Res", (), {"status_code": self.status})()

    # A-1's typed trail over F-2's caller: proof.verified at the derived level (_CACHED: not every status read live).
    sink = create_helix_audit_sink("http://api.test", "hak", service_did="did:web:svc", http=Http(201))
    sink({"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "authMethod": "kyaos", "agentDid": "did:key:z6Mkagent", "level": "L3", "fresh": False, "effectiveScopes": ["orders:read"]})
    assert [event["eventType"] for event in posted] == ["proof.verified", "authorization.approved"]
    assert posted[0]["details"]["verificationCode"] == "KYAOS_PROOF_L3_CACHED"
    assert posted[0]["actor"] == {"kind": "pairwise_did", "did": "did:key:z6Mkagent"}
    assert posted[1]["authorization"] == {"source": "delegation", "decision": "allowed"}
    with pytest.raises(RuntimeError, match="500"):
        create_helix_audit_sink("http://api.test", "hak", service_did="did:web:svc", http=Http(500))(
            {"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "authMethod": "kyaos", "agentDid": "did:key:z6Mk", "effectiveScopes": []}
        )


def test_a_proof_error_carries_one_of_the_three_proof_codes() -> None:
    from helix_mcp_middleware import PROOF_INVALID

    err = ProofError(PROOF_INVALID, "refused", ["nonce_replayed"])
    assert (err.code, err.reasons) == ("PROOF_INVALID", ("nonce_replayed",))
    with pytest.raises(ValueError, match="PROOF_MISSING, PROOF_INVALID or PROOF_LEVEL_INSUFFICIENT"):
        ProofError("VP_MISSING", "x")


# ── the replay store: the middleware's NonceStore (story L2-A), sync or async ──


class _AsyncStore:
    """An asyncio client's shape (redis.asyncio): insert answers with an awaitable; expiry in Unix seconds."""

    def __init__(self) -> None:
        self.inner = MemoryNonceStore(now=lambda: NOW_MS / 1000)
        self.expiries: List[float] = []

    async def insert(self, nonce: str, agent_did: Any, expires_at: float) -> bool:
        self.expiries.append(expires_at)
        return self.inner.insert(nonce, agent_did, expires_at)


def test_an_async_replay_store_is_awaited_on_the_async_gates_loop_and_refuses_a_replay() -> None:
    import asyncio

    store = _AsyncStore()
    options = fixture_verifier_options(SERVICE, documents={AGENT_OWN["did"]: AGENT_OWN["document"]}, nonce_store=store)
    mw = async_helixid_mcp_middleware(MCPMiddlewareOptions(minimum_level="L1", verifier=options, required_scopes=[]))
    call = {"name": "t", "_meta": proof_meta(AGENT_OWN["signer"], SERVICE, "t")}

    async def twice() -> Any:
        await mw(call)
        with pytest.raises(ProofError) as caught:
            await mw(call)
        return caught.value

    replay = asyncio.run(twice())
    assert replay.reasons == ("nonce_replayed",)
    # The verifier's millisecond expiry reaches the store in Unix seconds.
    assert all(NOW_MS / 1000 < expiry < NOW_MS / 1000 + 3600 for expiry in store.expiries)


def test_an_async_replay_store_under_the_sync_gate_runs_on_a_loop_of_its_own() -> None:
    store = _AsyncStore()
    mw = gate(verifier=own_verifier(nonce_store=store), required_scopes=[])
    call = {"name": "t", "_meta": proof_meta(AGENT_OWN["signer"], SERVICE, "t")}
    assert mw(call) is call
    assert refusal(lambda: mw(call)).reasons == ("nonce_replayed",)


def test_a_replay_store_that_answers_anything_but_true_or_fails_is_never_fresh() -> None:
    class Odd:
        def insert(self, nonce: str, agent_did: Any, expires_at: float) -> Any:
            return "yes"

    class Down:
        def insert(self, nonce: str, agent_did: Any, expires_at: float) -> Any:
            raise ConnectionError("redis down")

    odd = gate(verifier=own_verifier(nonce_store=Odd()), required_scopes=[])
    assert refusal(lambda: odd({"name": "t", "_meta": proof_meta(AGENT_OWN["signer"], SERVICE, "t")})).reasons == ("nonce_replayed",)
    down = gate(verifier=own_verifier(nonce_store=Down()), required_scopes=[])
    assert refusal(lambda: down({"name": "t", "_meta": proof_meta(AGENT_OWN["signer"], SERVICE, "t")})).code == "PROOF_INVALID"


def test_the_default_replay_store_is_the_middlewares_memory_store_in_seconds() -> None:
    verifier = quiet(resolve_did=lambda did: PLAIN_DOCUMENT)
    assert isinstance(verifier.nonce_store, MemoryNonceStore)
    meta = proof_meta(SIGNER, SERVICE, "t")
    assert verifier.verify_call({"name": "t", "_meta": meta}).ok
    assert verifier.verify_call({"name": "t", "_meta": meta}).reasons == ["nonce_replayed"]
