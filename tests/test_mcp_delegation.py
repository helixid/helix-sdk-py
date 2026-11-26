"""KYA-OS story L3-D: forward delegation context on downstream calls, the
Python twin of helix-sdk-js mcp-middleware/tests/delegation.test.ts.

Service A (the fixture world's ``service``) is called by the agent with the
fixture's two-hop chain (owner → parent → agent, targeting A); A forwards it
to service B (a did:web of its own) through ``with_delegation``; B verifies
the headers with its own local verifier. No secret is shared."""

from __future__ import annotations

import base64
import copy
import json
from typing import Any, Dict, List, Optional

import pytest

from helix_sdk.audit import MemoryAuditSink
from helix_sdk.credentials import sign_data_integrity
from helix_sdk.crypto.jws import EnvSigner, read_jws_header, sign_jws
from helix_sdk.did import build_did_document
from helix_sdk.keys import derive_public_key
from helix_sdk.verifier import did_key_document
from helix_mcp_middleware import (
    DELEGATION_HEADERS,
    DelegationContext,
    DelegationContextMissingError,
    InboundDelegationSettings,
    MCPAuthError,
    MCPMiddlewareOptions,
    ProofError,
    RedelegationError,
    VerificationCache,
    agent_of_chain,
    build_chain_string,
    build_outbound_delegation,
    chain_string_of,
    create_local_verifier,
    create_mcp_audit_trail,
    current_delegation,
    decode_delegation_credential,
    delegation_context_of,
    delegation_id_of,
    encode_delegation_credential,
    has_delegation_headers,
    header_values,
    helixid_mcp_middleware,
    host_of,
    host_of_did_web,
    mint_delegation_proof_jwt,
    revocation_invalidation,
    run_with_delegation,
    scope_list,
    verify_delegation_proof_jwt,
    verify_inbound_delegation_headers,
    with_delegation,
)
from helix_mcp_middleware.errors import LevelError, ToolScopeError

from mcp_proof_helpers import NOW_MS, fixture_signer, fixture_verifier_options, have_verifier_fixtures, load_environment, proof_meta, valid_chain

EMPTY_LIST = "H4sIAAAAAAAC_2NgwA8ArVUKGSAAAAA"
needs_fixtures = pytest.mark.skipif(not have_verifier_fixtures(), reason="helix-core verifier fixtures not found")


def _env() -> Dict[str, Any]:
    env = copy.deepcopy(load_environment())
    env["status_lists"]["https://service.example/status/1"] = {
        "encoded_list": EMPTY_LIST,
        "issuer": env["keys"]["service"]["did"],
        "status_purpose": "revocation",
        "id": "https://service.example/status/1",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
    }
    return env


def _sign(env: Dict[str, Any], label: str, doc: Dict[str, Any]) -> Dict[str, Any]:
    return sign_data_integrity(doc, fixture_signer(env, label), created="2026-01-01T00:00:00Z")


def _hop(env: Dict[str, Any], label: str, **spec: Any) -> Dict[str, Any]:
    subject: Dict[str, Any] = {
        "id": spec["id"],
        "invoker": spec["invoker"],
        "parentCapability": spec["parent"],
        "invocationTarget": spec["target"],
        "allowedAction": spec["actions"],
    }
    if spec.get("caveats") is not None:
        subject["caveats"] = spec["caveats"]
    return _sign(
        env,
        label,
        {
            "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/zcap/v1", "https://kya-os.org/ns/delegation/v1"],
            "id": spec["id"],
            "type": ["VerifiableCredential", "DelegationCredential"],
            "issuer": env["keys"][label]["did"],
            "validFrom": "2026-01-01T00:00:00Z",
            "validUntil": spec.get("valid_until", "2026-11-01T00:00:00Z"),
            "credentialSubject": subject,
            "credentialStatus": {
                "id": f"{spec['status'][0]}#{spec['status'][1]}",
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": spec["status"][1],
                "statusListCredential": spec["status"][0],
            },
        },
    )


def _card_for(env: Dict[str, Any], did: str, capabilities: List[str], responsible_party: str) -> Dict[str, Any]:
    card = copy.deepcopy(env["cards"]["attested"])
    card.update(id=did, kid=f"{did}#key-1", responsibleParty=responsible_party)
    card["capabilities"] = [
        {
            "name": capability,
            "attestations": [
                {
                    "vc": _sign(
                        env,
                        "helix",
                        {
                            "@context": ["https://www.w3.org/ns/credentials/v2", "https://helixid.io/contexts/v1"],
                            "id": f"urn:uuid:00000000-0000-4000-8000-0000000d30{index:02d}",
                            "type": ["VerifiableCredential", "CapabilityAttestationCredential"],
                            "issuer": env["keys"]["helix"]["did"],
                            "validFrom": "2026-01-01T00:00:00Z",
                            "validUntil": "2026-12-31T00:00:00Z",
                            "credentialSubject": {"id": did, "capability": capability},
                            "credentialStatus": {
                                "id": f"https://helix.example/status/1#{5 + index}",
                                "type": "BitstringStatusListEntry",
                                "statusPurpose": "revocation",
                                "statusListIndex": str(5 + index),
                                "statusListCredential": "https://helix.example/status/1",
                            },
                        },
                    )
                }
            ],
        }
        for index, capability in enumerate(capabilities)
    ]
    return card


def _service_b() -> Dict[str, Any]:
    did = "did:web:b.helix.test:services:0b"
    key = "11" * 32
    return {"did": did, "document": build_did_document(did, derive_public_key(key))}


@needs_fixtures
class TestForwarding:
    def setup_method(self) -> None:
        self.env = _env()
        self.chain = valid_chain()
        self.B = _service_b()
        self.A = self.env["keys"]["service"]["did"]

    def did(self, label: str) -> str:
        return self.env["keys"][label]["did"]

    def verifier_b(self, **settings: Any) -> Any:
        cards = settings.pop("cards", {self.did("agent"): self.env["cards"]["attested"]})
        return create_local_verifier(fixture_verifier_options(self.B["did"], self.env, {self.B["did"]: self.B["document"]}, cards=cards, **settings))

    def context(self, **changes: Any) -> DelegationContext:
        base = {"agent_did": self.did("agent"), "chain": self.chain, "scopes": ["read:orders", "write:orders"], "session_id": "sess-1"}
        base.update(changes)
        return DelegationContext(**base)

    def sent(self, url: str = "https://b.helix.test/mcp", **options: Any) -> Dict[str, str]:
        captured: Dict[str, Any] = {}

        def request(method: str, target: str, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> str:
            captured.update(method=method, url=target, headers=headers, kwargs=kwargs)
            return "sent"

        options.setdefault("context", self.context())
        forward = with_delegation(request, fixture_signer(self.env, "service"), clock=lambda: NOW_MS, **options)
        assert forward("POST", url, headers={"content-type": "application/json", DELEGATION_HEADERS["agent_did"]: "did:key:spoofed"}, content=b"{}") == "sent"
        assert captured["kwargs"] == {"content": b"{}"}
        return dict(captured["headers"])

    def test_b_accepts_with_no_shared_secret(self) -> None:
        headers = self.sent()
        assert headers["content-type"] == "application/json"
        assert headers[DELEGATION_HEADERS["agent_did"]] == self.did("agent")
        assert headers[DELEGATION_HEADERS["session_id"]] == "sess-1"
        assert DELEGATION_HEADERS["chain"] not in headers
        result = verify_inbound_delegation_headers(headers, self.verifier_b(), forwarders=[self.A])
        assert result.ok, result.reasons
        assert (result.agent_did, result.forwarder, result.responsible_party, result.invocation_target) == (self.did("agent"), self.A, self.did("owner"), self.A)
        assert (result.session_id, result.level, result.fresh, result.cached) == ("sess-1", "L2", True, False)
        assert sorted(result.effective_scopes) == ["read:orders", "write:orders"]
        assert result.claims["sub"] == self.did("owner") and result.claims["aud"] == "b.helix.test"
        assert result.claims["exp"] - result.claims["iat"] == 60
        assert result.delegation_id == self.chain[1]["id"]

    def test_without_the_helper_b_refuses(self) -> None:
        gate = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=self.verifier_b(), tool_scopes={"lookup_order": ["read:orders"]}, tools={"lookup_order": {"minimum_level": "L2"}}))
        with pytest.raises(ProofError) as missing:
            gate({"name": "lookup_order", "headers": {}})
        assert missing.value.code == "PROOF_MISSING"
        # The default accepts any forwarder for the authority granted at that forwarder (Harish, 2026-11-23) ...
        assert verify_inbound_delegation_headers(self.sent(), self.verifier_b()).ok
        # ... and still binds it: a stranger cannot carry a chain granted at A.
        assert verify_inbound_delegation_headers(self.forwarded(signer=fixture_signer(self.env, "stranger")), self.verifier_b()).reasons == ["delegation_target_not_accepted"]
        refused = verify_inbound_delegation_headers(self.sent(), self.verifier_b(), forwarders=[])
        assert (refused.ok, refused.reasons, refused.level, refused.effective_scopes) == (False, ["delegation_target_not_accepted"], "L1", [])

    def test_tampered_advisory_headers_change_nothing(self) -> None:
        clean = verify_inbound_delegation_headers(self.sent(advisory_headers=True), self.verifier_b(), forwarders=[self.A])
        assert (clean.advisory.chain, clean.advisory.granted_scopes, clean.advisory.dropped) == (build_chain_string(self.chain), ["read:orders", "write:orders"], [])
        tampered = self.sent(advisory_headers=True)
        tampered[DELEGATION_HEADERS["granted_scopes"]] = "read:orders,write:orders,admin:everything"
        tampered[DELEGATION_HEADERS["chain"]] = "urn:uuid:forged>del-001"
        result = verify_inbound_delegation_headers(tampered, self.verifier_b(), forwarders=[self.A])
        assert result.ok
        assert sorted(result.effective_scopes) == sorted(clean.effective_scopes)
        assert (result.advisory.chain, result.advisory.granted_scopes, result.advisory.dropped) == (None, None, ["chain", "grantedScopes"])

    def forwarded(self, signer: Any = None, extra: Optional[Dict[str, str]] = None, **claims: Any) -> Dict[str, str]:
        headers = self.sent()
        settings = {"sub": self.did("owner"), "aud": "b.helix.test", "delegation_id": delegation_id_of(self.chain), "delegation_chain": build_chain_string(self.chain), "scope": "read:orders", "now_ms": NOW_MS}
        settings.update(claims)
        headers[DELEGATION_HEADERS["proof"]] = mint_delegation_proof_jwt(signer or fixture_signer(self.env, "service"), **settings)
        headers.update(extra or {})
        return headers

    def reasons(self, headers: Dict[str, str], **options: Any) -> List[str]:
        options.setdefault("forwarders", [self.A])
        return verify_inbound_delegation_headers(headers, self.verifier_b(), **options).reasons

    def test_proof_aud_window_and_sub(self) -> None:
        assert self.reasons(self.forwarded(aud="c.helix.test")) == ["delegation_proof_audience"]
        assert self.reasons(self.forwarded(now_ms=NOW_MS - 120_000)) == ["delegation_proof_expired"]
        assert self.reasons(self.forwarded(now_ms=NOW_MS + 120_000)) == ["delegation_proof_not_yet_valid"]
        assert self.reasons(self.forwarded(sub=self.did("parent"))) == ["delegation_subject_mismatch"]
        assert self.reasons(self.forwarded(sub=self.did("agent"))) == ["delegation_subject_mismatch"]

    def test_agent_did_ids_chain_and_replay(self) -> None:
        assert self.reasons(self.forwarded(extra={DELEGATION_HEADERS["agent_did"]: self.did("stranger")})) == ["agent_did_mismatch"]
        assert self.reasons(self.forwarded(delegation_id="urn:zcap:other")) == ["delegation_id_mismatch"]
        assert self.reasons(self.forwarded(delegation_chain="urn:uuid:a>b")) == ["delegation_chain_mismatch"]
        verifier = self.verifier_b()
        once = self.forwarded(jti="urn:uuid:once")
        assert verify_inbound_delegation_headers(once, verifier, forwarders=[self.A]).ok
        assert verify_inbound_delegation_headers(once, verifier, forwarders=[self.A]).reasons == ["delegation_proof_replayed"]

    def test_stranger_impostor_lifetime_and_malformed(self) -> None:
        stranger = self.forwarded(signer=fixture_signer(self.env, "stranger"))
        assert self.reasons(stranger) == ["delegation_target_not_accepted"]
        assert self.reasons(stranger, resource=self.A) == ["delegation_forwarder_unbound"]
        key = self.env["keys"]["stranger"]["private_key_hex"]
        impostor = EnvSigner(self.A, kid="key-1", env_var="K", env={"K": key})
        assert self.reasons(self.forwarded(signer=impostor)) == ["delegation_proof_invalid"]
        long = self.sent()
        claims = {"iss": self.A, "sub": self.did("owner"), "aud": "b.helix.test", "iat": NOW_MS // 1000, "exp": NOW_MS // 1000 + 3600, "jti": "j", "delegation_id": delegation_id_of(self.chain), "delegation_chain": build_chain_string(self.chain), "scope": ""}
        service = fixture_signer(self.env, "service")
        for payload, header, expected in (
            (claims, None, "delegation_proof_lifetime"),
            ({**claims, "exp": "later"}, None, "delegation_proof_malformed"),
            ({**claims, "sub": ""}, None, "delegation_proof_malformed"),
            (claims, {"typ": "secevent+jwt"}, "delegation_proof_malformed"),
        ):
            long[DELEGATION_HEADERS["proof"]] = sign_jws(payload, service, header)
            assert self.reasons(long) == [expected]
        long[DELEGATION_HEADERS["proof"]] = "not.a.jwt"
        assert self.reasons(long) == ["delegation_proof_malformed"]

    def test_scope_claim_narrows_never_widens(self) -> None:
        assert verify_inbound_delegation_headers(self.forwarded(scope="read:orders"), self.verifier_b(), forwarders=[self.A]).effective_scopes == ["read:orders"]
        widened = verify_inbound_delegation_headers(self.forwarded(scope="read:orders,write:orders,read:catalog,admin"), self.verifier_b(), forwarders=[self.A])
        assert sorted(widened.effective_scopes) == ["read:orders", "write:orders"]

    def test_missing_duplicated_malformed_and_overlong(self) -> None:
        good = self.sent()
        lower = {name.lower(): value for name, value in good.items()}

        def reasons(headers: Any, verifier: Any = None) -> List[str]:
            return verify_inbound_delegation_headers(headers, verifier or self.verifier_b(), forwarders="*").reasons

        assert reasons({**lower, "kya-os-agent-did": []}) == ["delegation_headers_missing"]
        assert reasons({**lower, "kya-os-delegation-proof": ["a", "b"]}) == ["delegation_header_duplicated"]
        assert reasons({**lower, "kya-os-delegation-credential": "not base64url!"}) == ["delegation_credential_malformed"]
        assert reasons({**lower, "kya-os-delegation-credential": encode_delegation_credential([self.chain[0]] * 11)}) == ["chain_too_long"]
        not_web = create_local_verifier(fixture_verifier_options("did:key:z6Mk-not-web", self.env))
        assert reasons(list(good.items()), not_web) == ["configuration_error"]

    def test_a_chain_the_verifier_refuses(self) -> None:
        tampered = [self.chain[0], {**self.chain[1], "validUntil": "2026-11-30T00:00:00Z"}]
        result = verify_inbound_delegation_headers(self.sent(context=self.context(chain=tampered)), self.verifier_b(), forwarders=[self.A])
        assert (result.ok, result.reasons, result.agent_did) == (False, ["hop_proof_invalid"], self.did("agent"))

    # re-delegation: A appends a hop of its own, under a hop the agent's parent issued to A.
    def to_a(self) -> Dict[str, Any]:
        return _hop(
            self.env,
            "parent",
            id="urn:zcap:00000000-0000-4000-8000-0000000d3d01",
            invoker=self.A,
            parent=self.chain[0]["id"],
            target=self.A,
            actions=["read:orders", "write:orders"],
            caveats=[{"type": "MaxAmount", "limit": "500.00", "currency": "USD"}, {"type": "ValidUntil", "date": "2026-11-01T00:00:00Z"}],
            status=("https://parent.example/status/1", "3"),
        )

    def own(self, actions: List[str], valid_until: str = "2026-10-01T00:00:00Z") -> Dict[str, Any]:
        return _hop(
            self.env,
            "service",
            id="urn:zcap:00000000-0000-4000-8000-0000000d3d02",
            invoker=self.A,
            parent="urn:zcap:00000000-0000-4000-8000-0000000d3d01",
            target=self.A,
            actions=actions,
            valid_until=valid_until,
            caveats=[{"type": "MaxAmount", "limit": "100.00", "currency": "USD"}, {"type": "ValidUntil", "date": "2026-10-01T00:00:00Z"}],
            status=("https://service.example/status/1", "1"),
        )

    def delegated(self) -> DelegationContext:
        return DelegationContext(agent_did=self.did("parent"), chain=[self.chain[0], self.to_a()], scopes=["read:orders", "write:orders"])

    def test_redelegation_attenuating_hop_holds(self) -> None:
        cards = {self.A: _card_for(self.env, self.A, ["read:orders", "write:orders"], self.did("owner"))}
        headers = self.sent(context=self.delegated(), redelegate=lambda context, target: self.own(["read:orders"]))
        result = verify_inbound_delegation_headers(headers, self.verifier_b(cards=cards), forwarders=[self.A])
        assert result.ok, result.reasons
        assert (result.agent_did, result.forwarder, result.effective_scopes, len(result.chain)) == (self.did("parent"), self.A, ["read:orders"], 3)

    def test_redelegation_broadening_hop_refused(self) -> None:
        with pytest.raises(RedelegationError):
            self.sent(context=self.delegated(), redelegate=lambda context, target: self.own(["read:orders", "admin:all"]))
        with pytest.raises(RedelegationError, match="validUntil broadened"):
            self.sent(context=self.delegated(), redelegate=lambda context, target: [self.own(["read:orders"], "2027-06-01T00:00:00Z")])
        with pytest.raises(RedelegationError):
            self.sent(context=self.delegated(), redelegate=lambda context, target: {**self.own(["read:orders"]), "issuer": self.did("stranger")})
        with pytest.raises(RedelegationError, match="broken continuity"):
            self.sent(redelegate=lambda context, target: self.own(["read:orders"]))
        broad = [self.chain[0], self.to_a(), self.own(["read:orders", "admin:all"])]
        headers, _ = build_outbound_delegation("https://b.helix.test/mcp", DelegationContext(self.did("parent"), broad, ["read:orders"]), fixture_signer(self.env, "service"), clock=lambda: NOW_MS)
        cards = {self.A: _card_for(self.env, self.A, ["read:orders"], self.did("owner"))}
        result = verify_inbound_delegation_headers(headers, self.verifier_b(cards=cards), forwarders=[self.A])
        assert (result.ok, result.reasons) == (False, ["attenuation_violation"])

    def test_cache_served_then_dropped_by_a_signal(self) -> None:
        verifier = self.verifier_b()
        cache = VerificationCache.for_status_cache(verifier.status_cache, clock=lambda: NOW_MS)
        first = verify_inbound_delegation_headers(self.sent(), verifier, forwarders=[self.A], cache=cache)
        assert (first.ok, first.cached, first.fresh) == (True, False, True)
        second = verify_inbound_delegation_headers(self.sent(), verifier, forwarders=[self.A], cache=cache)
        assert (second.ok, second.cached, second.fresh) == (True, True, False)
        # Helix revokes the root hop; the signal names the root only, and the leaf's verdict falls with it.
        revocation_invalidation(verifier.status_cache).invalidate(self.chain[0]["id"])
        assert cache.size == 0
        assert verify_inbound_delegation_headers(self.sent(), verifier, forwarders=[self.A], cache=cache).cached is False

    def test_cache_bypassed_for_l3_and_never_holds_a_refusal(self) -> None:
        verifier = self.verifier_b()
        cache = VerificationCache(clock=lambda: NOW_MS)
        verify_inbound_delegation_headers(self.sent(), verifier, forwarders=[self.A], cache=cache)
        live = verify_inbound_delegation_headers(self.sent(), verifier, forwarders=[self.A], cache=cache, live_status=True)
        assert (live.cached, live.fresh) == (False, True)
        bad = self.sent(context=self.context(chain=[self.chain[0], {**self.chain[1], "validUntil": "x"}]))
        assert verify_inbound_delegation_headers(bad, verifier, forwarders=[self.A], cache=VerificationCache()).ok is False

    def test_cache_ttl_and_very_chain(self) -> None:
        now = [NOW_MS]
        cache = VerificationCache(ttl_seconds=300, high_privilege_scopes=["write:orders"], clock=lambda: now[0])
        assert (cache.ttl_for(["read:orders"]), cache.ttl_for(["write:orders"])) == (300, 60)

        class Result:
            ok = True
            effective_scopes: List[str] = []

            class chain_summary:  # noqa: N801 - the VerifierResult attribute
                allowed_action = ["read:orders", "write:orders"]

        result = Result()
        cache.set(self.chain, result)
        assert cache.get(self.chain) is result
        assert cache.get([self.chain[0], {**self.chain[1], "validUntil": "2026-11-30T00:00:00Z"}]) is None
        now[0] += 61_000
        assert cache.get(self.chain) is None
        assert cache.get([]) is None
        cache.set([{"no": "id"}], result)
        refused = Result()
        refused.ok = False  # type: ignore[misc]
        cache.set(self.chain, refused)
        assert cache.size == 0
        cache.set(self.chain, result)
        assert revocation_invalidation(type("S", (), {"invalidate": lambda self, i: "credential"})(), cache).invalidate(self.chain[1]["id"]) == "credential"
        assert cache.size == 0
        cache.set(self.chain, result)
        cache.clear()
        assert cache.size == 0
        cache.set([self.chain[1]], result)  # an id already in the graph under another parent: not cached
        assert cache.size == 0
        with pytest.raises(ValueError):
            VerificationCache(high_privilege_ttl=61)
        with pytest.raises(ValueError):
            VerificationCache(ttl_seconds=0)

    def test_outbound_attachment_audited(self) -> None:
        sink = MemoryAuditSink()
        trail = create_mcp_audit_trail(sink, service_did=self.A, clock=lambda: NOW_MS)
        attachments: List[Any] = []

        def audit(attachment: Any) -> None:
            attachments.append(attachment)
            trail.outbound_audit()(attachment)

        self.sent(audit=audit)
        attached = attachments[0]
        assert (attached.audience, attached.chain_string, attached.agent_did, attached.forwarder, attached.redelegated) == (
            "b.helix.test", build_chain_string(self.chain), self.did("agent"), self.A, False,
        )
        assert attached.to_dict()["chainString"] == attached.chain_string and "chain" not in attached.to_dict()
        event = sink.events[0]
        assert event["eventType"] == "delegation.outbound_attached"
        assert event["action"] == {"category": "delegation.outbound", "name": build_chain_string(self.chain)}
        assert event["resource"] == {"kind": "public_did", "did": "did:web:b.helix.test"}
        assert event["actor"] == {"kind": "pairwise_did", "did": self.did("agent")}
        assert event["responsibleParty"] == {"kind": "pairwise_did", "did": self.did("owner")}
        assert event["causationId"] == attached.jti
        assert event["details"] == {"family": "delegation", "phase": "outbound_attached", "delegationRef": self.chain[1]["id"], "parentRef": self.chain[0]["id"]}
        assert event["authorization"]["delegationRef"] == self.chain[1]["id"]
        trail.outbound_attached(attached, target_did="did:web:b.helix.test:services:0b")
        assert sink.events[1]["resource"]["did"] == "did:web:b.helix.test:services:0b"
        attached.audience = "not a host"
        attached.chain = [self.chain[1]]
        trail.outbound_attached(attached)
        assert "resource" not in sink.events[2]
        trail.outbound_audit(target_did=lambda a: "did:web:c.helix.test")(attached)
        assert sink.events[3]["resource"]["did"] == "did:web:c.helix.test"

    def test_outbound_audit_with_signed_forms_and_a_correlation_id(self) -> None:
        sink = MemoryAuditSink()
        trail = create_mcp_audit_trail(sink, service_did=self.A, clock=lambda: NOW_MS)
        attachments: List[Any] = []
        self.sent(context=self.context(correlation_id="audit_1"), audit=attachments.append)
        attached = attachments[0]
        assert attached.to_dict()["correlationId"] == "audit_1"
        # Hops whose proofValue has a §7.8 signed form (base64url) also carry their digests.
        attached.chain = [{"id": "vc-1", "credentialSubject": {"id": "c-1"}, "proof": {"proofValue": "AAAA"}}, {"id": "vc-2", "credentialSubject": {"id": "c-2"}, "proof": {"proofValue": "AAAA"}}]
        trail.outbound_attached(attached)
        event = sink.events[0]
        assert event["correlationId"] == "audit_1"
        assert event["authorization"]["delegationCredentialDigest"].startswith("sha256:")
        assert len(event["authorization"]["delegationChainDigests"]) == 2

    def test_a_redelegated_hop_must_be_this_services_own(self) -> None:
        # The agent's own hop under its leaf holds continuity, but A did not issue it.
        agent_hop = _hop(
            self.env,
            "agent",
            id="urn:zcap:00000000-0000-4000-8000-0000000d3d09",
            invoker=self.A,
            parent=self.chain[1]["id"],
            target=self.A,
            actions=["read:orders"],
            caveats=[{"type": "MaxAmount", "limit": "100.00", "currency": "USD"}, {"type": "ValidUntil", "date": "2026-10-01T00:00:00Z"}],
            valid_until="2026-10-01T00:00:00Z",
            status=("https://agent.example/status/1", "3"),
        )
        with pytest.raises(RedelegationError, match="issued by this service"):
            self.sent(redelegate=lambda context, target: agent_hop)

    def test_audit_failure_never_blocks(self) -> None:
        errors: List[BaseException] = []

        def broken(_attachment: Any) -> None:
            raise RuntimeError("down")

        headers = self.sent(audit=broken, on_audit_error=errors.append)
        assert DELEGATION_HEADERS["proof"] in headers and len(errors) == 1

    def gate(self, **settings: Any) -> Any:
        options = {
            "verifier": self.verifier_b(),
            "tool_scopes": {"lookup_order": ["read:orders"], "refund": ["admin:refund"]},
            "tools": {"lookup_order": {"minimum_level": "L2"}, "refund": {"minimum_level": "L2"}},
            "inbound_delegation": InboundDelegationSettings(forwarders=[self.A]),
        }
        options.update(settings)
        return helixid_mcp_middleware(MCPMiddlewareOptions(**options))

    def test_gate_authorizes_a_forwarded_call(self) -> None:
        caller = self.gate().authorize({"name": "lookup_order", "headers": self.sent()})
        assert (caller.auth_method, caller.agent_did, caller.level, caller.proof_floor, caller.forwarded_by) == ("kyaos", self.did("agent"), "L2", False, self.A)
        assert len(caller.chain) == 2
        context = delegation_context_of(caller, session_id="s")
        assert (context.agent_did, context.session_id) == (self.did("agent"), "s")

    def test_gate_refusals(self) -> None:
        events: List[Dict[str, Any]] = []
        gate = self.gate(audit_sink=events.append)
        with pytest.raises(ToolScopeError):
            gate({"name": "refund", "headers": self.sent()})
        with pytest.raises(LevelError):
            self.gate(tools={})({"name": "lookup_order", "headers": self.sent()})
        stranger = self.sent()
        stranger[DELEGATION_HEADERS["agent_did"]] = self.did("stranger")
        with pytest.raises(ProofError):
            gate({"name": "lookup_order", "headers": stranger})
        replayed = self.sent()
        gate({"name": "lookup_order", "headers": replayed})
        with pytest.raises(ProofError) as refused:
            gate({"name": "lookup_order", "headers": replayed})
        assert list(refused.value.reasons) == ["delegation_proof_replayed"]
        assert any(event.get("reason") == "delegation_proof_replayed" for event in events)

    def test_gate_conflict_off_and_settings(self) -> None:
        headers = self.sent()
        meta = proof_meta(fixture_signer(self.env, "agent"), self.B["did"], "lookup_order", chain=self.chain)
        with pytest.raises(MCPAuthError) as conflict:
            self.gate()({"name": "lookup_order", "headers": headers, "_meta": meta})
        assert conflict.value.code == "CREDENTIAL_CONFLICT"
        with pytest.raises(ProofError) as missing:
            self.gate(inbound_delegation=False)({"name": "lookup_order", "headers": headers})
        assert missing.value.code == "PROOF_MISSING"
        with pytest.raises(ValueError, match="verifier"):
            helixid_mcp_middleware(MCPMiddlewareOptions(tool_scopes={"lookup_order": []}))({"name": "lookup_order", "headers": headers})
        own = VerificationCache()
        self.gate(inbound_delegation=InboundDelegationSettings(forwarders=[self.A], cache=own, audience="b.helix.test"))({"name": "lookup_order", "headers": self.sent()})
        assert own.size == 1
        self.gate(inbound_delegation=InboundDelegationSettings(forwarders=[self.A], cache=False))({"name": "lookup_order", "headers": self.sent()})
        self.gate(inbound_delegation=True, tool_scopes={"lookup_order": []})
        stub = type("Stub", (), {"verify_call": lambda self, call: None, "service_did": self.B["did"]})()
        helixid_mcp_middleware(MCPMiddlewareOptions(verifier=stub, tool_scopes={}))

    def test_agent_call_carries_its_chain_for_the_handler(self) -> None:
        verifier_a = create_local_verifier(fixture_verifier_options(self.A, self.env, cards={self.did("agent"): self.env["cards"]["attested"]}))
        gate_a = helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier_a, tool_scopes={"lookup_order": ["read:orders"]}, tools={"lookup_order": {"minimum_level": "L2"}}))
        meta = proof_meta(fixture_signer(self.env, "agent"), self.A, "lookup_order", chain=self.chain)
        caller = gate_a.authorize({"name": "lookup_order", "_meta": meta})
        context = delegation_context_of(caller)
        assert list(context.chain) == self.chain
        seen: Dict[str, Any] = {}

        def request(method: str, url: str, headers: Optional[Dict[str, str]] = None, **_: Any) -> None:
            seen.update(headers or {})

        forward = with_delegation(request, fixture_signer(self.env, "service"), clock=lambda: NOW_MS)
        with run_with_delegation(context):
            assert current_delegation() is context
            forward("POST", "https://b.helix.test/mcp")
        assert verify_inbound_delegation_headers(seen, self.verifier_b(), forwarders=[self.A]).ok
        with pytest.raises(DelegationContextMissingError):
            forward("POST", "https://b.helix.test/mcp")
        with pytest.raises(DelegationContextMissingError):
            with_delegation(request, fixture_signer(self.env, "service"), context=lambda: None)("GET", "https://b.helix.test")
        with pytest.raises(DelegationContextMissingError):
            with_delegation(request, fixture_signer(self.env, "service"), context=DelegationContext("x", [{}], []))("GET", "https://b.helix.test")
        assert delegation_context_of(type("C", (), {"auth_method": "oauth"})()) is None

    def test_scopes_option_narrows(self) -> None:
        headers = self.sent(scopes=lambda context, target: [s for s in context.scopes if s == "write:orders"])
        assert verify_inbound_delegation_headers(headers, self.verifier_b(), forwarders="*").effective_scopes == ["write:orders"]
        fixed = self.sent(scopes=["read:orders"])
        assert verify_inbound_delegation_headers(fixed, self.verifier_b(), forwarders="*").effective_scopes == ["read:orders"]

    def test_agent_of_chain(self) -> None:
        assert agent_of_chain(self.chain, self.A) == self.did("agent")
        to_service = [{**self.chain[0], "credentialSubject": {**self.chain[0]["credentialSubject"], "invoker": self.A}}]
        assert agent_of_chain(to_service, self.A) == self.A
        assert agent_of_chain([self.chain[0], {"issuer": 7, "credentialSubject": {"invoker": self.A}}], self.A) is None


class TestProofJwtAndChainString:
    """L3.23 / L3.24."""

    SIGNER = EnvSigner("did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw", env_var="K", env={"K": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"})
    BASE = {"sub": "did:key:root", "aud": "downstream.example", "delegation_id": "del-123", "delegation_chain": "vc-abc>del-123", "scope": ["read", "write"]}

    def test_compact_eddsa_jwt_with_every_claim(self) -> None:
        jwt = mint_delegation_proof_jwt(self.SIGNER, **self.BASE)
        assert len(jwt.split(".")) == 3
        assert read_jws_header(jwt) == {"alg": "EdDSA", "kid": f"{self.SIGNER.did}#{self.SIGNER.kid}", "typ": "JWT"}
        import time

        result = verify_delegation_proof_jwt(jwt, resolve_did=did_key_document, audience=["other", "downstream.example"], now_ms=int(time.time() * 1000))
        assert result.ok
        claims = result.claims
        assert {k: claims[k] for k in ("iss", "sub", "aud", "delegation_id", "delegation_chain", "scope")} == {
            "iss": self.SIGNER.did, "sub": "did:key:root", "aud": "downstream.example", "delegation_id": "del-123", "delegation_chain": "vc-abc>del-123", "scope": "read,write",
        }
        assert claims["exp"] - claims["iat"] == 60
        other = mint_delegation_proof_jwt(self.SIGNER, **{**self.BASE, "scope": "read"})
        assert json.loads(base64.urlsafe_b64decode(other.split(".")[1] + "==")) ["jti"] != claims["jti"]

    def test_mint_refusals(self) -> None:
        with pytest.raises(ValueError, match="iss"):
            mint_delegation_proof_jwt(self.SIGNER, iss="did:key:other", **self.BASE)
        with pytest.raises(ValueError, match="aud"):
            mint_delegation_proof_jwt(self.SIGNER, **{**self.BASE, "aud": ""})

    def test_chain_strings(self) -> None:
        assert chain_string_of("vc-abc", "del-123") == "vc-abc>del-123"
        assert chain_string_of(None, "del-123") == "del-123"
        assert chain_string_of("vc-abc") == "vc-abc"
        assert chain_string_of() == ""
        hop = lambda vc, d: {"id": vc, "credentialSubject": {"id": d}}  # noqa: E731
        assert build_chain_string([hop("vc-1", "del-1"), hop("vc-2", "del-2"), hop("vc-3", "del-3")]) == "vc-1>del-1>vc-2>del-2>vc-3>del-3"
        assert build_chain_string([]) == ""
        assert build_chain_string([7, {"credentialSubject": "x"}]) == ""
        assert delegation_id_of([hop("vc-1", "del-1")]) == "del-1"
        assert delegation_id_of([{"id": "vc"}]) is None
        assert scope_list(" a, b,,a ") == ["a", "b"]

    def test_header_codec_and_helpers(self) -> None:
        assert decode_delegation_credential(encode_delegation_credential([{"a": 1}])) == [{"a": 1}]
        b64 = lambda text: base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")  # noqa: E731
        assert decode_delegation_credential(b64('{"a":1}')) == [{"a": 1}]
        for value in (b64("[]"), b64("7"), b64("{"), ""):
            assert decode_delegation_credential(value) is None
        assert has_delegation_headers(None) is False
        assert has_delegation_headers({DELEGATION_HEADERS["proof"]: "x"}) is True
        assert has_delegation_headers([(b"kya-os-delegation-credential", b"x")]) is True
        assert header_values({"KYA-OS-Agent-DID": None, "kya-os-agent-did": ("a", b"b")}, "KYA-OS-Agent-DID") == ["a", "b"]
        assert host_of_did_web("did:web:127.0.0.1%3A3000:services:ab") == "127.0.0.1:3000"
        assert host_of_did_web("did:key:z6Mk") is None
        assert host_of_did_web("did:web:") is None
        assert host_of_did_web("did:web:%E0%A4%A") is None
        assert host_of("https://B.example:443/mcp") == "b.example"
        assert host_of("http://user@127.0.0.1:3000/mcp") == "127.0.0.1:3000"
        assert host_of("http://[::1]:80/x") == "[::1]"
