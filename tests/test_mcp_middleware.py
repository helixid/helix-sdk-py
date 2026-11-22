# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_mcp_middleware: credentials (a KYA-OS request proof or an OAuth bearer
token, story F-2), per-tool scopes, OAuth (JWT, introspection, several
issuers, discovery, presets), HTTP challenges and audit. The local verifier
itself is in test_mcp_verify_locally.py; here a stub stands in for it. The same cases as helix-sdk-js's mcp-middleware tests (auth.test.ts,
oauth.test.ts, middleware.test.ts), with a fake HTTP client instead of a
mocked fetch and real keys generated per test.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Sequence

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from helix_sdk.audit import (
    AUDIT_BINDING_MCP,
    AuditEventInvalidError,
    AuditTrail,
    AuditTrailEntry,
    MemoryAuditSink,
    audit_event_digest,
    credential_digest,
    delegation_chain_digests,
    keyed_commitment_value,
    pairwise_did,
    public_did,
    validate_audit_event,
)
from helix_sdk.errors import HelixError
from helix_mcp_middleware import (
    OAUTH_SUBJECT_KEY_ID,
    AuthorizationServerUnavailableError,
    AuthResult,
    McpAuditTrail,
    MCPMiddlewareOptions,
    NeedsAuthorizationOptions,
    OAuthIntrospectionOptions,
    OAuthIssuerOptions,
    async_helixid_mcp_middleware,
    auth0,
    build_protected_resource_metadata,
    create_helix_audit_reporter,
    create_helix_audit_sink,
    create_mcp_audit_trail,
    create_needs_authorization,
    current_tool_call,
    delegation_evidence_of,
    create_introspection_validator,
    create_jwt_validator,
    create_oauth_validator,
    entra,
    helixid_mcp_middleware,
    keycloak,
    okta,
    protected_resource_metadata_url,
    to_http_error_response,
)
import helix_mcp_middleware.oauth as oauth_module

ISS_A = "https://a.example.com"
ISS_B = "https://b.example.com/oauth2/default"
AUD = "https://mcp.example.com/mcp"
META_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"


def b64(value: Any) -> str:
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Key:
    def __init__(self, kid: str) -> None:
        self.kid = kid
        self.private = ec.generate_private_key(ec.SECP256R1())
        numbers = self.private.public_key().public_numbers()
        self.jwk = {
            "kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig",
            "x": b64(numbers.x.to_bytes(32, "big")), "y": b64(numbers.y.to_bytes(32, "big")),
        }

    def token(self, claims: Dict[str, Any], **header: Any) -> str:
        head = b64({"alg": "ES256", "kid": self.kid, "typ": "at+jwt", **header})
        body = b64(claims)
        r, s = decode_dss_signature(self.private.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
        return f"{head}.{body}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def claims(**extra: Any) -> Dict[str, Any]:
    base = {"iss": ISS_A, "aud": AUD, "sub": "user-1", "exp": int(time.time()) + 300, "scope": "read write", "client_id": "c1"}
    base.update(extra)
    return {k: v for k, v in base.items() if v is not None}


def active(**extra: Any) -> Dict[str, Any]:
    base = {"sub": "opaque-user", "scope": "read", "aud": AUD, "iss": ISS_B, "exp": int(time.time()) + 300, "client_id": "c2"}
    base.update(extra)
    return {k: v for k, v in base.items() if v is not None}


class Response:
    def __init__(self, body: Any, status: int = 200) -> None:
        self._body, self.status_code = body, status

    def json(self) -> Any:
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


class FakeHttp:
    """A requests-shaped client: `routes` maps a URL to a response, or to a
    callable taking the request kwargs. Unknown URLs are 404. Every call is recorded."""

    def __init__(self, routes: Optional[Dict[str, Any]] = None) -> None:
        self.routes = routes or {}
        self.calls: List[Dict[str, Any]] = []

    def _answer(self, method: str, url: str, **kwargs: Any) -> Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        route = self.routes.get(url)
        if route is None:
            return Response({}, 404)
        answer = route(kwargs) if callable(route) else route
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, Response) else Response(answer)

    def get(self, url: str, **kwargs: Any) -> Response:
        return self._answer("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self._answer("POST", url, **kwargs)

    def urls(self) -> List[str]:
        return [c["url"] for c in self.calls]


def introspection_route(known: Dict[str, Dict[str, Any]]) -> Callable[[Dict[str, Any]], Any]:
    def route(kwargs: Dict[str, Any]) -> Any:
        found = known.get(kwargs["data"]["token"])
        return {"active": True, **found} if found else {"active": False}

    return route


def code_of(excinfo: Any) -> Any:
    return getattr(excinfo.value, "code", None)


def raises_invalid(fn: Callable[[], Any], message: Optional[str] = None) -> None:
    with pytest.raises(HelixError) as excinfo:
        fn()
    assert code_of(excinfo) == "OAUTH_TOKEN_INVALID"
    if message:
        assert str(excinfo.value) == message


PROOF = {"prf": "org.kya-os/proof.v1", "stub": True}
PROOF_META = {"org.kya-os/request-proof": PROOF}


class StubVerifier:
    """Stands in for the local verifier: every proof verifies with ``scopes``,
    or is refused with ``reasons``. Records every call it is given."""

    def __init__(self, scopes: Sequence[str], agent: Optional[str] = "did:agent", reasons: Sequence[str] = ()) -> None:
        self.scopes, self.agent, self.reasons = list(scopes), agent, list(reasons)
        self.calls: List[Dict[str, Any]] = []
        self.on_call: Optional[Callable[[], None]] = None

    def verify_call(self, call: Dict[str, Any]) -> Any:
        self.calls.append(call)
        if self.on_call is not None:
            self.on_call()
        ok = not self.reasons
        return SimpleNamespace(
            ok=ok, effective_scopes=self.scopes if ok else [], proof_did=self.agent, level="L2" if ok else "L0",
            fresh=ok, reasons=self.reasons, proof_assurance="proof",
        )


def verifying(scopes: Sequence[str], agent: Optional[str] = "did:agent", reasons: Sequence[str] = ()) -> StubVerifier:
    return StubVerifier(scopes, agent, reasons)


def gate(**options: Any) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    return helixid_mcp_middleware(MCPMiddlewareOptions(**options))


def denied(fn: Callable[[], Any]) -> Any:
    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        fn()
    return excinfo.value


# ── credentials ──────────────────────────────────────────────────────────────


class TestCredentials:
    def test_the_proof_under_the_canonical_or_legacy_key_with_its_chain(self) -> None:
        verifier = verifying(["read"])
        mw = gate(verifier=verifier)
        chain = [{"hop": 1}]
        assert mw({"name": "t", "input": {"a": 1}, "_meta": {**PROOF_META, "org.kya-os/delegation-chain": chain}})["name"] == "t"
        assert mw({"name": "t", "_meta": {"org.kya-os/proof@1": PROOF}})
        assert [c["_meta"] for c in verifier.calls][0]["org.kya-os/delegation-chain"] == chain
        assert verifier.calls[0]["input"] == {"a": 1} and "request" not in verifier.calls[0]
        request = {"method": "tools/call", "params": {"name": "t", "_meta": PROOF_META}}
        mw({"name": "t", "_meta": PROOF_META, "request": request})
        assert verifier.calls[-1]["request"] is request

    def test_multi_value_headers_object(self) -> None:
        class Headers:
            def __init__(self, items: List[Any]) -> None:
                self.items = items

            def getlist(self, name: str) -> List[str]:
                return [v for k, v in self.items if k.lower() == name]

        mw = gate(validate_oauth_token=lambda t: {"sub": "u", "scopes": []})
        assert mw({"name": "t", "headers": Headers([("Authorization", "Bearer x")])})
        err = denied(lambda: mw({"name": "t", "headers": Headers([("authorization", "Bearer a"), ("Authorization", "Bearer x")])}))
        assert err.code == "CREDENTIAL_CONFLICT"

    def test_conflicts_are_rejected_never_resolved(self) -> None:
        mw = gate(verifier=verifying([]), validate_oauth_token=lambda t: {"sub": "u", "scopes": []})
        for call in (
            {"headers": {"authorization": "Bearer tok"}, "_meta": PROOF_META},
            {"headers": {"authorization": ["Bearer a", "Bearer b"]}},
            {"headers": {"authorization": "Bearer"}},
        ):
            assert denied(lambda call=call: mw({"name": "t", **call})).code == "CREDENTIAL_CONFLICT"

    def test_no_credentials_retired_vp_and_bearer_without_oauth(self) -> None:
        mw = gate(verifier=verifying([]))
        assert denied(lambda: mw({"name": "t"})).code == "PROOF_MISSING"
        # Story F-2 retired the Helix VP with no backward compatibility: none of its carriers is read.
        for call in (
            {"_meta": {"x-helix-vp": "eyJ2cCI6MX0"}},
            {"headers": {"x-helix-vp": "eyJ2cCI6MX0"}},
            {"headers": {"authorization": "HelixVP eyJ2cCI6MX0"}},
            {"input": {"org.kya-os/request-proof": PROOF}},
        ):
            assert denied(lambda call=call: mw({"name": "t", **call})).code == "PROOF_MISSING"
        assert denied(lambda: mw({"name": "t", "headers": {"authorization": "Bearer x"}})).code == "OAUTH_TOKEN_INVALID"
        assert "or Authorization: Bearer" not in str(denied(lambda: mw({"name": "t"})))
        assert "or Authorization: Bearer" in str(denied(lambda: gate(validate_oauth_token=lambda t: None)({"name": "t"})))


# ── scopes ───────────────────────────────────────────────────────────────────


class TestToolScopes:
    def test_listed_tool_with_scope_and_deny_by_default(self) -> None:
        mw = gate(verifier=verifying(["read"]), tool_scopes={"query": ["read"], "update": ["write"]}, required_scopes=["never"])
        call = {"_meta": PROOF_META}
        assert mw({"name": "query", **call})
        for name in ("drop", "__class__", "toString", None, 7):
            assert denied(lambda name=name: mw({"name": name, **call})).code == "TOOL_NOT_PERMITTED"
        err = denied(lambda: mw({"name": "update", **call}))
        assert (err.code, err.required_scope, err.required_scopes) == ("INSUFFICIENT_SCOPE", "write", ["write"])

    def test_required_scopes_is_the_fallback_and_empty_list_allows_any_caller(self) -> None:
        call = {"name": "anything", "_meta": PROOF_META}
        assert gate(verifier=verifying(["read"]), required_scopes=["read"])(call)
        assert denied(lambda: gate(verifier=verifying([]), required_scopes=["read"])(call)).code == "INSUFFICIENT_SCOPE"
        assert gate(verifier=verifying([]), tool_scopes={"anything": []})(call)


# ── KYA-OS door ──────────────────────────────────────────────────────────────


class TestKyaOsProof:
    def test_a_refused_proof_is_proof_invalid_with_the_reasons_and_is_audited(self) -> None:
        events: List[Dict[str, Any]] = []
        mw = gate(verifier=verifying([], agent="did:key:agent", reasons=["nonce_replayed", "status_revoked"]), audit_sink=events.append)
        err = denied(lambda: mw({"name": "t", "_meta": PROOF_META}))
        assert (err.code, err.reasons, str(err)) == ("PROOF_INVALID", ("nonce_replayed", "status_revoked"), "The request proof was refused: nonce_replayed, status_revoked")
        assert [(e["event"], e["authMethod"], e["agentDid"], e["reason"], e["level"], e["fresh"]) for e in events] == [
            ("AUTHZ_DENIED", "kyaos", "did:key:agent", "nonce_replayed,status_revoked", "L0", False)
        ]
        res = to_http_error_response(err, META_URL)
        assert (res.status, res.body["error"]) == (401, "invalid_token")

    def test_a_refusal_with_no_principal_is_not_audited(self) -> None:
        events: List[Dict[str, Any]] = []
        mw = gate(verifier=verifying([], agent=None, reasons=["malformed_proof"]), audit_sink=events.append)
        assert denied(lambda: mw({"name": "t", "_meta": PROOF_META})).code == "PROOF_INVALID"
        assert events == []

    def test_a_proof_without_a_verifier_is_a_configuration_error(self) -> None:
        mw = gate(validate_oauth_token=lambda t: {"sub": "u"})
        assert isinstance(denied(lambda: mw({"name": "t", "_meta": PROOF_META})), ValueError)

    def test_the_gate_builds_its_verifier_from_settings(self) -> None:
        from helix_mcp_middleware import LocalVerifier, LocalVerifierOptions

        mw = gate(verifier=LocalVerifierOptions(), service_did="did:web:svc", tool_scopes={"a": ["read"], "b": ["read", "write"]})
        built = mw.verifier  # type: ignore[attr-defined]
        assert isinstance(built, LocalVerifier) and built.service_did == "did:web:svc"
        assert built._base["catalog"] == ["read", "write"] and built._base["expected_audience"] == "did:web:svc"
        own = gate(verifier=LocalVerifierOptions(service_did="did:web:own", catalog=["x"]), expected_target_service="did:web:svc")
        assert own.verifier.service_did == "did:web:own" and own.verifier._base["catalog"] == ["x"]  # type: ignore[attr-defined]
        shared = verifying([])
        assert gate(verifier=shared).verifier is shared  # type: ignore[attr-defined]
        with pytest.raises(ValueError, match="service_did"):
            gate(verifier=LocalVerifierOptions())
        with pytest.raises(TypeError):
            gate(verifier={"service_did": "did:web:svc"})


# ── OAuth callback ───────────────────────────────────────────────────────────


class TestOAuthCallback:
    def test_callback_result_as_dict_or_auth_result(self) -> None:
        events: List[Dict[str, Any]] = []
        for result in ({"sub": "u-9", "scopes": ["read"]}, AuthResult(sub="u-9", scopes=["read"])):
            mw = gate(validate_oauth_token=lambda t, result=result: result, tool_scopes={"t": ["read"]}, audit_sink=events.append, service_did="did:web:svc")
            assert mw({"name": "t", "headers": {"authorization": "Bearer tok"}})
        assert [(e["event"], e["oauthSubject"], e["authMethod"], e["serviceDid"]) for e in events] == [("AUTHZ_GRANTED", "u-9", "oauth", "did:web:svc")] * 2

    def test_callback_that_raises_or_returns_no_subject_is_invalid_token(self) -> None:
        def boom(token: str) -> Any:
            raise RuntimeError("nope")

        call = {"name": "t", "headers": {"authorization": "Bearer x"}}
        assert denied(lambda: gate(validate_oauth_token=boom)(call)).code == "OAUTH_TOKEN_INVALID"
        assert denied(lambda: gate(validate_oauth_token=lambda t: {"scopes": []})(call)).code == "OAUTH_TOKEN_INVALID"
        assert denied(lambda: gate(validate_oauth_token=lambda t: None)(call)).code == "OAUTH_TOKEN_INVALID"

    def test_oauth_and_callback_together_are_refused(self) -> None:
        with pytest.raises(ValueError):
            gate(oauth=OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks"), validate_oauth_token=lambda t: None)


# ── JWT validator ────────────────────────────────────────────────────────────


class TestJwtValidator:
    def setup_method(self) -> None:
        self.k = Key("k1")
        self.http = FakeHttp({f"{ISS_A}/jwks": {"keys": [self.k.jwk]}})
        self.v = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=self.http))

    def test_accepts_a_valid_token(self) -> None:
        result = self.v(self.k.token(claims()))
        assert (result.sub, list(result.scopes), result.client_id) == ("user-1", ["read", "write"], "c1")
        assert self.v(self.k.token(claims(scope=None, scp=["a", "b"]))).scopes == ["a", "b"]
        assert self.v(self.k.token(claims(aud=["x", AUD]))).sub == "user-1"

    def test_rejects_bad_claims_and_signature(self) -> None:
        now = int(time.time())
        other = Key("k1")
        cases = [
            (self.k.token(claims(iss="https://evil.example.com")), "Unexpected token issuer"),
            (self.k.token(claims(iss=None)), "Unexpected token issuer"),
            (self.k.token(claims(aud="https://other.example.com")), "Token audience does not match this server"),
            (self.k.token(claims(aud=None)), "Token has no audience"),
            (self.k.token(claims(exp=now - 3600)), "Token expired"),
            (self.k.token(claims(exp=None)), "Token expired"),
            (self.k.token(claims(nbf=now + 3600)), "Token not yet valid"),
            (self.k.token(claims(sub=None)), "Token has no subject"),
            (other.token(claims()), "Invalid token signature"),
            ("not-a-jwt", "Not a JWT"),
            (f"{b64({'alg': 'none'})}.{b64(claims())}.", "Unsupported token algorithm"),
            (f"{b64({'alg': 'HS256', 'kid': 'k1'})}.{b64(claims())}.c2ln", "Unsupported token algorithm"),
            (self.k.token(claims(), crit=["x"]), "Unsupported critical header"),
            (self.k.token(claims(), kid="unknown"), "No matching signing key"),
        ]
        for token, message in cases:
            raises_invalid(lambda token=token: self.v(token), message)

    def test_caches_keys_and_refetches_once_on_an_unknown_kid(self) -> None:
        k2 = Key("k2")
        published = [self.k.jwk]
        http = FakeHttp({f"{ISS_A}/jwks": lambda kw: {"keys": list(published)}})
        v = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", jwks_refetch_cooldown_seconds=0, http=http))
        v(self.k.token(claims()))
        v(self.k.token(claims()))
        assert len(http.calls) == 1
        published.append(k2.jwk)
        assert v(k2.token(claims())).sub == "user-1"
        assert len(http.calls) == 2

    def test_access_token_type(self) -> None:
        strict = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", require_access_token_type=True, http=self.http))
        raises_invalid(lambda: strict(self.k.token(claims(), typ="JWT")), "Not an access token (typ)")
        assert strict(self.k.token(claims(), typ="application/at+jwt")).sub == "user-1"
        assert self.v(self.k.token(claims(), typ="JWT")).sub == "user-1"

    def test_unreachable_jwks_is_an_outage_not_a_401(self) -> None:
        for route in (Response({}, 503), ConnectionError("down"), {"nope": 1}):
            v = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp({f"{ISS_A}/jwks": route})))
            err = denied(lambda v=v: v(self.k.token(claims())))
            assert isinstance(err, AuthorizationServerUnavailableError)
            assert to_http_error_response(err, META_URL) is None

    def test_https_required_except_loopback(self) -> None:
        with pytest.raises(ValueError):
            create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri="http://as.example.com/jwks"))
        create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri="http://localhost:9000/jwks"))
        with pytest.raises(ValueError):
            create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", algorithms=["HS256"]))


# ── introspection ────────────────────────────────────────────────────────────

INTROSPECT_B = f"{ISS_B}/v1/introspect"


def introspecting(http: FakeHttp, **overrides: Any) -> OAuthIssuerOptions:
    intro = {"client_id": "rs", "client_secret": "s3cret", "endpoint": INTROSPECT_B}
    intro.update({k: overrides.pop(k) for k in list(overrides) if k in ("client_id", "client_secret", "endpoint", "cache_ttl_seconds", "allow_missing_audience")})
    return OAuthIssuerOptions(ISS_B, AUD, introspection=OAuthIntrospectionOptions(**intro), http=http, **overrides)


class TestIntrospection:
    def test_posts_form_with_basic_auth_and_reads_the_answer(self) -> None:
        http = FakeHttp({INTROSPECT_B: introspection_route({"opaque-1": active()})})
        result = create_introspection_validator(introspecting(http))("opaque-1")
        assert (result.sub, list(result.scopes), result.client_id) == ("opaque-user", ["read"], "c2")
        call = http.calls[0]
        assert (call["method"], call["url"]) == ("POST", INTROSPECT_B)
        assert call["data"] == {"token": "opaque-1", "token_type_hint": "access_token"}
        assert call["headers"]["authorization"] == "Basic " + base64.b64encode(b"rs:s3cret").decode()

    def test_client_credentials_are_form_encoded_before_basic(self) -> None:
        http = FakeHttp({INTROSPECT_B: introspection_route({"t": active()})})
        create_introspection_validator(introspecting(http, client_id="my client", client_secret="p@ss+w!rd"))("t")
        assert http.calls[0]["headers"]["authorization"] == "Basic " + base64.b64encode(b"my+client:p%40ss%2Bw%21rd").decode()

    def test_rejections(self) -> None:
        now = int(time.time())
        cases = [
            ({"active": False}, "Token is not active"),
            ({"active": True, **active(aud="https://other.example.com")}, "Token audience does not match this server"),
            ({"active": True, **active(aud=None)}, "Token has no audience"),
            ({"active": True, **active(iss="https://evil.example.com")}, "Unexpected token issuer"),
            ({"active": True, **active(exp=now - 3600)}, "Token expired"),
            ({"active": True, **active(nbf=now + 3600)}, "Token not yet valid"),
            ({"active": True, **active(sub=None, client_id=None)}, "Token has no subject"),
            ({"active": True, **active(), "token_type": "Refresh"}, "Not an access token (token_type)"),
        ]
        for body, message in cases:
            v = create_introspection_validator(introspecting(FakeHttp({INTROSPECT_B: body})))
            raises_invalid(lambda v=v: v("t"), message)

    def test_optional_claims(self) -> None:
        def v(body: Dict[str, Any], **kw: Any) -> AuthResult:
            return create_introspection_validator(introspecting(FakeHttp({INTROSPECT_B: {"active": True, **body}}), **kw))("t")

        assert v(active(sub=None, client_id="svc-7")).sub == "svc-7"
        assert v(active(aud=None), allow_missing_audience=True).sub == "opaque-user"
        assert v(active(exp=None, iss=None)).sub == "opaque-user"
        assert v({**active(), "token_type": "Bearer"}).sub == "opaque-user"

    def test_caches_positive_answers_only_and_never_past_exp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        http = FakeHttp({INTROSPECT_B: introspection_route({"ok": active(), "short": active(exp=int(time.time()) + 1)})})
        v = create_introspection_validator(introspecting(http, clock_tolerance_seconds=0))
        v("ok"), v("ok")
        assert len(http.calls) == 1
        for _ in range(2):
            raises_invalid(lambda: v("nope"))
        assert len(http.calls) == 3
        v("short")
        real = time.time
        monkeypatch.setattr(oauth_module, "_now", lambda: real() + 2.5)
        raises_invalid(lambda: v("short"), "Token expired")  # cache entry died with exp; asked again
        assert len(http.calls) == 5

        uncached = FakeHttp({INTROSPECT_B: introspection_route({"ok": active()})})
        v0 = create_introspection_validator(introspecting(uncached, cache_ttl_seconds=0))
        v0("ok"), v0("ok")
        assert len(uncached.calls) == 2

    def test_broken_authorization_server_is_an_outage(self) -> None:
        for route in (ConnectionError("refused"), Response({"error": "server_error"}, 500), Response("<html>"), {"sub": "x"}):
            v = create_introspection_validator(introspecting(FakeHttp({INTROSPECT_B: route})))
            err = denied(lambda v=v: v("t"))
            assert isinstance(err, AuthorizationServerUnavailableError), route
            assert to_http_error_response(err, META_URL) is None

    def test_endpoint_rules(self) -> None:
        with pytest.raises(ValueError):
            create_introspection_validator(introspecting(FakeHttp(), endpoint="http://b.example.com/i"))
        create_introspection_validator(introspecting(FakeHttp(), endpoint="http://localhost:9/i"))
        with pytest.raises(ValueError):
            create_introspection_validator(introspecting(FakeHttp(), endpoint=None))


# ── several issuers ──────────────────────────────────────────────────────────


class TestMultiIssuer:
    def setup_method(self) -> None:
        self.ka = Key("a1")
        self.http_a = FakeHttp({f"{ISS_A}/jwks": {"keys": [self.ka.jwk]}})
        self.http_b = FakeHttp({INTROSPECT_B: introspection_route({"opaque-ok": active()})})
        self.v = create_oauth_validator([
            OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=self.http_a),
            introspecting(self.http_b),
        ])

    def test_jwt_is_routed_by_iss_and_unknown_issuer_needs_no_network(self) -> None:
        assert self.v(self.ka.token(claims())).sub == "user-1"
        assert (len(self.http_a.calls), len(self.http_b.calls)) == (1, 0)
        raises_invalid(lambda: self.v(self.ka.token(claims(iss="https://evil.example.com"))), "Unknown token issuer")
        raises_invalid(lambda: self.v(self.ka.token(claims(iss=None))), "Token has no issuer")
        raises_invalid(lambda: self.v(self.ka.token(claims(iss=["x"]))), "Token has no issuer")
        assert (len(self.http_a.calls), len(self.http_b.calls)) == (1, 0)
        raises_invalid(lambda: self.v(Key("a1").token(claims())), "Invalid token signature")

    def test_opaque_token_goes_to_the_introspection_issuer_only(self) -> None:
        assert self.v("opaque-ok").sub == "opaque-user"
        raises_invalid(lambda: self.v("opaque-unknown"), "Token is not active")
        assert (len(self.http_a.calls), len(self.http_b.calls)) == (0, 2)
        only_jwt = create_oauth_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=self.http_a))
        raises_invalid(lambda: only_jwt("opaque"), "Not a JWT")

    def test_jwt_from_an_introspection_only_issuer_is_introspected(self) -> None:
        jwt = Key("b1").token(claims(iss=ISS_B))
        http = FakeHttp({INTROSPECT_B: introspection_route({jwt: active()})})
        assert create_oauth_validator([introspecting(http)])(jwt).sub == "opaque-user"

    def test_construction_rules(self) -> None:
        a = OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks")
        with pytest.raises(ValueError, match="listed twice"):
            create_oauth_validator([a, a])
        with pytest.raises(ValueError, match="at least one issuer"):
            create_oauth_validator([])
        second = OAuthIssuerOptions("https://two.example.com", AUD, introspection=OAuthIntrospectionOptions("a", "b", endpoint="https://two.example.com/i"))
        with pytest.raises(ValueError, match="only one issuer may use introspection"):
            create_oauth_validator([introspecting(FakeHttp()), second])
        create_oauth_validator([introspecting(FakeHttp()), a, OAuthIssuerOptions("https://c.example.com", AUD, jwks_uri="https://c.example.com/jwks")])
        with pytest.raises(ValueError, match="needs both"):
            create_oauth_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", introspect_jwts=True))

    def test_introspect_jwts_sees_revocation_before_expiry(self) -> None:
        jwt = self.ka.token(claims())
        known = {jwt: active(iss=ISS_A, sub="user-1")}
        http = FakeHttp({f"{ISS_A}/jwks": {"keys": [self.ka.jwk]}, f"{ISS_A}/introspect": introspection_route(known)})
        entry = OAuthIssuerOptions(
            ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=http,
            introspection=OAuthIntrospectionOptions("rs", "s", endpoint=f"{ISS_A}/introspect", cache_ttl_seconds=0),
        )
        checked = create_oauth_validator(OAuthIssuerOptions(**{**entry.__dict__, "introspect_jwts": True}))
        assert list(checked(jwt).scopes) == ["read", "write"]
        del known[jwt]  # revoked at the issuer; the signature is still good
        raises_invalid(lambda: checked(jwt), "Token is not active")
        before = len(http.calls)
        raises_invalid(lambda: checked(Key("a1").token(claims())))  # forged: never reaches the issuer
        assert len(http.calls) == before
        assert create_oauth_validator(entry)(jwt).sub == "user-1"  # without the flag, still accepted

    def test_through_the_middleware(self) -> None:
        mw = gate(oauth=[OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=self.http_a), introspecting(self.http_b)], tool_scopes={"t": ["read"]})
        assert mw({"name": "t", "headers": {"authorization": f"Bearer {self.ka.token(claims())}"}})
        assert mw({"name": "t", "headers": {"authorization": "Bearer opaque-ok"}})
        down = gate(oauth=OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp({f"{ISS_A}/jwks": Response({}, 503)})), tool_scopes={"t": []})
        err = denied(lambda: down({"name": "t", "headers": {"authorization": f"Bearer {self.ka.token(claims())}"}}))
        assert isinstance(err, AuthorizationServerUnavailableError)


# ── discovery ────────────────────────────────────────────────────────────────


def metadata_for(issuer: str) -> Dict[str, str]:
    return {"issuer": issuer, "jwks_uri": f"{issuer}/keys", "introspection_endpoint": f"{issuer}/introspect"}


class TestDiscovery:
    def setup_method(self) -> None:
        self.k = Key("d1")
        self.oidc = f"{ISS_B}/.well-known/openid-configuration"

    def routes(self, metadata: Any, opaque: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {self.oidc: metadata, f"{ISS_B}/keys": {"keys": [self.k.jwk]}, f"{ISS_B}/introspect": introspection_route(opaque or {})}

    def test_issuer_alone_finds_its_keys_once(self) -> None:
        http = FakeHttp(self.routes(metadata_for(ISS_B)))
        v = create_oauth_validator(OAuthIssuerOptions(ISS_B, AUD, http=http))
        assert http.calls == []  # nothing until a token arrives
        v(self.k.token(claims(iss=ISS_B))), v(self.k.token(claims(iss=ISS_B)))
        assert http.urls() == [self.oidc, f"{ISS_B}/keys"]

    def test_introspection_endpoint_from_metadata(self) -> None:
        http = FakeHttp(self.routes(metadata_for(ISS_B), {"opq": active()}))
        v = create_oauth_validator(OAuthIssuerOptions(ISS_B, AUD, introspection=OAuthIntrospectionOptions("rs", "s"), http=http))
        assert v("opq").sub == "opaque-user"
        assert http.urls() == [self.oidc, f"{ISS_B}/introspect"]

    def test_falls_back_to_rfc8414(self) -> None:
        rfc = "https://b.example.com/.well-known/oauth-authorization-server/oauth2/default"
        http = FakeHttp({rfc: metadata_for(ISS_B), f"{ISS_B}/keys": {"keys": [self.k.jwk]}})
        assert create_oauth_validator(OAuthIssuerOptions(ISS_B, AUD, http=http))(self.k.token(claims(iss=ISS_B))).sub == "user-1"
        assert http.urls()[:2] == [self.oidc, rfc]

    def test_bad_metadata_is_an_outage(self) -> None:
        token = self.k.token(claims(iss=ISS_B))
        for metadata in (metadata_for("https://evil.example.com"), {"issuer": ISS_B}, {"issuer": ISS_B, "jwks_uri": "http://b.example.com/keys"}, Response({}, 500)):
            v = create_oauth_validator(OAuthIssuerOptions(ISS_B, AUD, http=FakeHttp(self.routes(metadata))))
            assert isinstance(denied(lambda v=v: v(token)), AuthorizationServerUnavailableError), metadata

    def test_outage_is_retried_after_the_backoff(self, monkeypatch: pytest.MonkeyPatch) -> None:
        up = {"now": False}
        good = self.routes(metadata_for(ISS_B))
        http = FakeHttp({self.oidc: lambda kw: good[self.oidc] if up["now"] else ConnectionError("refused"), f"{ISS_B}/keys": good[f"{ISS_B}/keys"]})
        v = create_oauth_validator(OAuthIssuerOptions(ISS_B, AUD, http=http))
        token = self.k.token(claims(iss=ISS_B))
        assert isinstance(denied(lambda: v(token)), AuthorizationServerUnavailableError)
        up["now"] = True
        lookups = len(http.calls)
        # Within the backoff the failure is shared, with no new request ...
        assert isinstance(denied(lambda: v(token)), AuthorizationServerUnavailableError)
        assert len(http.calls) == lookups
        # ... after it, the lookup is retried.
        real = time.time
        monkeypatch.setattr(oauth_module, "_now", lambda: real() + 3)
        assert v(token).sub == "user-1"

    def test_discovery_needs_https_issuer(self) -> None:
        with pytest.raises(ValueError, match="https"):
            create_oauth_validator(OAuthIssuerOptions("http://as.example.com", AUD))
        create_oauth_validator(OAuthIssuerOptions("http://127.0.0.1:9000", AUD))


# ── presets ──────────────────────────────────────────────────────────────────

TENANT = "11111111-2222-3333-4444-555555555555"


class TestPresets:
    def test_entra(self) -> None:
        e = entra(TENANT.upper(), "api-client-id")
        assert (e.issuer, e.jwks_uri, e.audience, tuple(e.scope_claims)) == (
            f"https://login.microsoftonline.com/{TENANT}/v2.0",
            f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys",
            "api-client-id",
            ("scp", "roles"),
        )
        for alias in ("common", "organizations", "consumers", ""):
            with pytest.raises(ValueError):
                entra(alias, "x")
        k = Key("e1")
        e.http = FakeHttp({e.jwks_uri: {"keys": [k.jwk]}})
        v = create_oauth_validator(e)
        assert v(k.token(claims(iss=e.issuer, aud="api-client-id", scope=None, scp="orders:read"))).scopes == ["orders:read"]
        assert v(k.token(claims(iss=e.issuer, aud="api-client-id", scope=None, roles=["orders:admin"]))).scopes == ["orders:admin"]

    def test_auth0(self) -> None:
        for domain in ("acme.us.auth0.com", "https://acme.us.auth0.com/"):
            a = auth0(domain, AUD)
            assert (a.issuer, a.jwks_uri, a.introspection) == ("https://acme.us.auth0.com/", "https://acme.us.auth0.com/.well-known/jwks.json", None)
        with pytest.raises(ValueError):
            auth0(" ", AUD)

    def test_okta(self) -> None:
        o = okta("dev-1.okta.com", AUD)
        assert (o.issuer, o.jwks_uri, o.introspection) == ("https://dev-1.okta.com/oauth2/default", "https://dev-1.okta.com/oauth2/default/v1/keys", None)
        o = okta("dev-1.okta.com", AUD, authorization_server_id="aus123", introspection=OAuthIntrospectionOptions("c", "s"), introspect_jwts=True)
        assert (o.issuer, o.introspection.endpoint, o.introspect_jwts) == ("https://dev-1.okta.com/oauth2/aus123", "https://dev-1.okta.com/oauth2/aus123/v1/introspect", True)

    def test_keycloak(self) -> None:
        kc = keycloak("https://id.example.com/", "shop", AUD, introspection=OAuthIntrospectionOptions("c", "s"))
        assert (kc.issuer, kc.jwks_uri, kc.introspection.endpoint) == (
            "https://id.example.com/realms/shop",
            "https://id.example.com/realms/shop/protocol/openid-connect/certs",
            "https://id.example.com/realms/shop/protocol/openid-connect/token/introspect",
        )

    def test_presets_share_one_validator(self) -> None:
        k = Key("p1")
        a, o = auth0("acme.us.auth0.com", AUD), okta("dev-1.okta.com", AUD)
        a.http = FakeHttp({a.jwks_uri: {"keys": [k.jwk]}})
        o.http = FakeHttp({o.jwks_uri: {"keys": [k.jwk]}})
        v = create_oauth_validator([a, o])
        assert v(k.token(claims(iss=a.issuer))).sub == v(k.token(claims(iss=o.issuer))).sub == "user-1"
        raises_invalid(lambda: v(k.token(claims(iss="https://acme.us.auth0.com"))), "Unknown token issuer")


# ── HTTP responses and metadata ──────────────────────────────────────────────


class TestHttp:
    def test_metadata(self) -> None:
        assert protected_resource_metadata_url(AUD) == META_URL
        assert protected_resource_metadata_url("https://mcp.example.com") == "https://mcp.example.com/.well-known/oauth-protected-resource"
        assert build_protected_resource_metadata(AUD, authorization_servers=[ISS_A], scopes_supported=["read"], resource_name="X") == {
            "resource": AUD, "authorization_servers": [ISS_A], "scopes_supported": ["read"],
            "bearer_methods_supported": ["header"], "resource_name": "X",
        }
        assert build_protected_resource_metadata(AUD) == {"resource": AUD, "bearer_methods_supported": ["header"]}

    def test_missing_credentials_is_401_with_both_challenges_and_no_error(self) -> None:
        res = to_http_error_response(denied(lambda: gate(verifier=verifying([]))({"name": "t"})), META_URL)
        assert res.status == 401
        assert res.headers["WWW-Authenticate"] == f'Bearer resource_metadata="{META_URL}", KyaOS resource_metadata="{META_URL}"'
        assert res.body["error"] == "unauthorized"

    def test_status_mapping(self) -> None:
        for code, status, name in (
            ("OAUTH_TOKEN_INVALID", 401, "invalid_token"), ("PROOF_INVALID", 401, "invalid_token"),
            ("CREDENTIAL_CONFLICT", 400, "invalid_request"),
            ("INSUFFICIENT_SCOPE", 403, "insufficient_scope"), ("TOOL_NOT_PERMITTED", 403, "insufficient_scope"),
        ):
            res = to_http_error_response(HelixError(code, "x", 400), META_URL)
            assert (res.status, res.body["error"]) == (status, name)
            assert "scope=" not in res.headers["WWW-Authenticate"]
        # The retired VP codes are no longer answered as the caller's fault.
        for error in (HelixError("ADMIN_AUTH_REQUIRED", "x", 403), HelixError("VP_VERIFICATION_FAILED", "x", 401), RuntimeError("boom"), None):
            assert to_http_error_response(error, META_URL) is None

    def test_403_lists_every_required_scope_and_header_charset_is_confined(self) -> None:
        mw = gate(validate_oauth_token=lambda t: {"sub": "u", "scopes": ["read"]}, tool_scopes={"t": ["read", "admin", "export"]})
        res = to_http_error_response(denied(lambda: mw({"name": "t", "headers": {"authorization": "Bearer x"}})), META_URL)
        assert res.status == 403
        assert 'error="insufficient_scope", error_description="Required scope: admin", scope="read admin export"' in res.headers["WWW-Authenticate"]
        odd = to_http_error_response(HelixError("PROOF_INVALID", 'bad é\u0007 "quote" \\slash', 401), META_URL)
        assert 'error_description="bad     quote   slash"' in odd.headers["WWW-Authenticate"]


# ── audit ────────────────────────────────────────────────────────────────────


def posted(call: Dict[str, Any]) -> Any:
    """The JSON body of a recorded POST (the reporter sends the canonical event text)."""
    return json.loads(call["data"].decode("utf-8"))


def _agent_vc(vc_id: str) -> Dict[str, Any]:
    """An agent credential signed the way SPEC section 7.8 reads it (proofValue is base64)."""
    return {
        "id": vc_id,
        "type": ["VerifiableCredential", "HelixAgentCredential"],
        "issuer": "did:web:issuer.example",
        "credentialSubject": {"id": "did:key:a"},
        "proof": {"type": "Ed25519Signature2020", "proofValue": "AQIDBA=="},
    }


class TestAudit:
    def test_events_for_kyaos_callers(self) -> None:
        events: List[Dict[str, Any]] = []
        mw = gate(verifier=verifying(["read"], agent="did:key:agent"), tool_scopes={"q": ["read"], "u": ["write"]}, audit_sink=events.append, expected_target_service="did:web:svc")
        mw({"name": "q", "_meta": PROOF_META})
        denied(lambda: mw({"name": "u", "_meta": PROOF_META}))
        denied(lambda: mw({"name": "zzz", "_meta": PROOF_META}))
        assert [(e["event"], e["result"], e["toolName"], e.get("requiredScope"), e.get("reason")) for e in events] == [
            ("AUTHZ_GRANTED", "allowed", "q", None, None),
            ("AUTHZ_DENIED", "denied", "u", "write", "insufficient scope"),
            ("AUTHZ_DENIED", "denied", "zzz", None, "tool is not in toolScopes"),
        ]
        assert all(
            e["agentDid"] == "did:key:agent" and e["level"] == "L2" and e["fresh"] is True and e["serviceDid"] == "did:web:svc" and e["authMethod"] == "kyaos"
            for e in events
        )
        assert all("vpId" not in e for e in events)
        assert events[0]["timestamp"].endswith("Z")

    def test_unidentified_callers_are_not_logged_and_a_failing_sink_never_blocks(self) -> None:
        events: List[Any] = []
        errors: List[BaseException] = []

        def failing(event: Dict[str, Any]) -> None:
            events.append(event)
            raise RuntimeError("sink down")

        mw = gate(verifier=verifying([]), audit_sink=failing, on_audit_error=errors.append)
        denied(lambda: mw({"name": "t"}))
        assert events == []
        assert mw({"name": "t", "_meta": PROOF_META})
        assert len(events) == 1 and str(errors[0]) == "sink down"

    # -- create_helix_audit_reporter (JS: createHelixAuditReporter) -------------

    def test_a_refused_request_proof_is_proof_rejected_by_its_first_reason(self) -> None:
        memory = MemoryAuditSink()
        sink = create_mcp_audit_trail(memory, "did:web:svc").tool_audit_sink()
        sink({"event": "AUTHZ_DENIED", "result": "denied", "timestamp": "t", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": [], "reason": "proof_expired,status_unavailable"})
        sink({"event": "AUTHZ_DENIED", "result": "denied", "timestamp": "t", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": [], "reason": " "})
        assert memory.event_types == ["proof.rejected", "proof.rejected"]
        assert memory.events[0]["reason"] == {"code": "proof_expired"} and memory.events[0]["outcome"] == "denied"
        assert memory.events[0]["actor"] == {"kind": "pairwise_did", "did": "did:key:a"}
        assert memory.events[1]["reason"] == {"code": "proof_invalid"}

    def test_the_verification_code_names_the_level_and_a_cached_status(self) -> None:
        memory = MemoryAuditSink()
        sink = create_mcp_audit_trail(memory, "did:web:svc").tool_audit_sink()
        sink({"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": [], "level": "L2", "fresh": True})
        sink({"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": [], "level": "L3", "fresh": False})
        assert [e["details"].get("verificationCode") for e in memory.events if e["eventType"] == "proof.verified"] == ["KYAOS_PROOF_L2", "KYAOS_PROOF_L3_CACHED"]

    def test_an_l3e_needs_authorization_challenge_keeps_its_reason(self) -> None:
        sink = MemoryAuditSink()
        trail = create_mcp_audit_trail(sink, "did:web:orders.example")
        layer = create_needs_authorization(
            NeedsAuthorizationOptions(authorization_url="https://consent.example/authorize", audit_sink=trail.tool_audit_sink(), service_did="did:web:orders.example")
        )
        layer.challenge(agent_did="did:key:zAgent", tool="delete_order", scopes=["orders:admin"], effective_scopes=["orders:read"])
        assert sink.event_types == ["proof.verified", "authorization.denied"]
        denied = sink.events[1]
        assert denied["outcome"] == "denied" and denied["reason"] == {"code": "needs_authorization"}
        assert denied["authorization"]["decision"] == "denied" and denied["authorization"]["scopeId"] == "orders:admin"

    def test_reporter_posts_the_canonical_event_text_with_the_bearer_key(self) -> None:
        http = FakeHttp({"http://api.test/v1/audit-log/events": {}})
        reporter = create_helix_audit_reporter("http://api.test/", "hak", timeout_seconds=2.5, http=http)
        trail = AuditTrail(sink=reporter, source_id="s", producer=pairwise_did("did:web:svc"), tenant_ref=pairwise_did("did:web:svc"))
        entry = trail.record({"eventType": "session.established", "action": {"category": "session"}, "outcome": "succeeded", "details": {"family": "session", "phase": "established"}})
        assert http.calls == [{
            "method": "POST",
            "url": "http://api.test/v1/audit-log/events",
            "data": entry.canonical.encode("utf-8"),
            "headers": {"content-type": "application/json", "authorization": "Bearer hak"},
            "timeout": 2.5,
        }]
        assert posted(http.calls[0]) == entry.event

    def test_reporter_raises_on_a_non_2xx_answer(self) -> None:
        entry = AuditTrailEntry(event={"eventType": "x"}, canonical="{}", event_digest="sha256:" + "0" * 64)
        with pytest.raises(RuntimeError, match="responded 500"):
            create_helix_audit_reporter("http://api.test", "hak", http=FakeHttp({"http://api.test/v1/audit-log/events": Response({}, 500)})).append(entry)

    def test_reporter_uses_requests_and_a_5_s_timeout_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import requests

        calls: List[Dict[str, Any]] = []
        monkeypatch.setattr(requests, "post", lambda url, **kw: calls.append({"url": url, **kw}) or Response({}, 201))
        create_helix_audit_reporter("http://api.test", "hak").append(AuditTrailEntry(event={"eventType": "x"}, canonical='{"eventType":"x"}', event_digest="sha256:" + "0" * 64))
        assert calls[0]["url"] == "http://api.test/v1/audit-log/events" and calls[0]["data"] == b'{"eventType":"x"}' and calls[0]["timeout"] == 5.0

    # -- create_helix_audit_sink (JS: createHelixAuditSink) ---------------------

    def test_helix_audit_sink_posts_typed_events(self) -> None:
        http = FakeHttp({"http://api.test/v1/audit-log/events": {}})
        sink = create_helix_audit_sink("http://api.test/", "hak_1", service_did="did:web:svc", http=http)
        sink({"event": "AUTHZ_DENIED", "result": "denied", "timestamp": "t", "authMethod": "oauth", "effectiveScopes": ["read"], "oauthSubject": "u-9", "toolName": "refund", "requiredScope": "admin", "reason": "insufficient scope"})
        assert len(http.calls) == 1
        call = http.calls[0]
        assert call["headers"]["authorization"] == "Bearer hak_1" and call["timeout"] == 5.0
        event = posted(call)
        assert validate_audit_event(event) == (True, event)
        assert event["eventType"] == "authorization.denied" and event["outcome"] == "denied"
        assert event["binding"] == AUDIT_BINDING_MCP
        assert event["source"] == {"producer": {"kind": "pairwise_did", "did": "did:web:svc"}, "sourceId": "mcp-middleware:did:web:svc", "sourceSequence": "1"}
        assert event["resource"] == {"kind": "public_did", "did": "did:web:svc"}
        assert event["actor"]["kind"] == "keyed_commitment" and event["actor"]["keyId"] == "oauth-subject-v1"
        assert event["reason"] == {"code": "insufficient_scope"}
        assert event["authorization"] == {"source": "policy", "decision": "denied", "scopeId": "admin"}
        assert event["details"] == {"family": "authorization", "phase": "denied"}
        assert "name" not in event["action"]  # tool names are withheld by default
        assert "u-9" not in json.dumps(event)

        # A HelixID VP caller: proof.verified then authorization.approved, chained by the trail.
        sink({"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "authMethod": "kyaos", "effectiveScopes": ["read"], "agentDid": "did:key:agent", "toolName": "q"})
        events = [posted(c) for c in http.calls]
        assert [e["eventType"] for e in events] == ["authorization.denied", "proof.verified", "authorization.approved"]
        assert [e["source"]["sourceSequence"] for e in events] == ["1", "2", "3"]
        assert events[2]["source"]["previousSourceEventDigest"] == audit_event_digest(events[1])
        assert events[1]["actor"] == {"kind": "pairwise_did", "did": "did:key:agent"}
        assert events[1]["details"] == {"family": "proof", "phase": "verified", "verificationCode": "KYAOS_PROOF"}

    def test_helix_audit_sink_passes_source_id_and_include_tool_names_through(self) -> None:
        http = FakeHttp({"http://api.test/v1/audit-log/events": {}})
        sink = create_helix_audit_sink("http://api.test", "k", service_did="did:web:svc", http=http, source_id="srv-1", include_tool_names=True)
        sink({"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "authMethod": "oauth", "oauthSubject": "s", "effectiveScopes": [], "toolName": "refund"})
        event = posted(http.calls[0])
        assert event["action"] == {"category": "authorization", "name": "refund"} and event["source"]["sourceId"] == "srv-1"

    def test_helix_audit_sink_lets_a_failed_post_propagate_and_needs_the_server_did(self) -> None:
        with pytest.raises(ValueError, match="service_did"):
            create_helix_audit_sink("http://api.test", "k", http=FakeHttp())
        with pytest.raises(RuntimeError, match="responded 404"):
            create_helix_audit_sink("http://api.test", "k", service_did="did:web:d", http=FakeHttp())({"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "authMethod": "oauth", "oauthSubject": "s", "effectiveScopes": []})

    # -- create_mcp_audit_trail (JS: createMcpAuditTrail) ------------------------

    def test_trail_needs_a_server_did_or_a_producer(self) -> None:
        with pytest.raises(ValueError, match="service_did"):
            create_mcp_audit_trail(MemoryAuditSink())
        assert create_mcp_audit_trail(MemoryAuditSink(), producer=public_did("did:web:p")).service_did is None

    def test_trail_defaults(self) -> None:
        memory = MemoryAuditSink()
        audit = create_mcp_audit_trail(memory, "did:web:svc")
        assert isinstance(audit, McpAuditTrail) and audit.service_did == "did:web:svc" and audit.include_tool_names is False
        event = audit.session("established", True).event
        assert event["source"]["producer"] == pairwise_did("did:web:svc") and event["source"]["sourceId"] == "mcp-middleware:did:web:svc"
        assert event["tenantRef"] == pairwise_did("did:web:svc") and event["binding"] == AUDIT_BINDING_MCP
        assert event["resource"] == public_did("did:web:svc")
        assert event["eventId"].startswith("audit_")

    def test_trail_takes_producer_tenant_source_clock_and_ids_and_has_no_resource_without_a_server_did(self) -> None:
        memory = MemoryAuditSink()
        ids = iter(["e-1", "e-2"])
        audit = create_mcp_audit_trail(
            memory,
            producer=public_did("did:web:p"),
            tenant_ref=public_did("did:web:t"),
            source_id="src",
            clock=lambda: 1750000000000,
            new_event_id=lambda: next(ids),
        )
        event = audit.session("established", True).event
        assert event["source"] == {"producer": public_did("did:web:p"), "sourceId": "src", "sourceSequence": "1"}
        assert event["tenantRef"] == public_did("did:web:t") and event["occurredAt"] == 1750000000000 and event["eventId"] == "e-1"
        assert "resource" not in event
        assert create_mcp_audit_trail(MemoryAuditSink(), producer=public_did("did:web:p")).session("established", True).event["source"]["sourceId"] == "mcp-middleware:server"

    # -- McpAuditTrail events -----------------------------------------------------

    def test_session_an_expired_session_failed_a_rejected_one_was_denied(self) -> None:
        audit = create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc")
        assert audit.session("expired", False).event["outcome"] == "failed"
        rejected = audit.session("rejected", False, reason_code="replay").event
        assert rejected["outcome"] == "denied" and rejected["reason"] == {"code": "replay"}
        assert rejected["details"] == {"family": "session", "phase": "rejected", "reasonCode": "replay"}
        assert audit.session("replay_rejected", False).event["outcome"] == "denied"

    def test_proof_digest_verification_code_and_reason(self) -> None:
        audit = create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc")
        event = audit.proof("rejected", "failed", proof_digest="sha256:" + "a" * 64, verification_code="VP_EXPIRED", reason_code="vp_expired").event
        assert event["eventType"] == "proof.rejected" and event["action"] == {"category": "proof"} and event["outcome"] == "failed"
        assert event["details"] == {"family": "proof", "phase": "rejected", "proofDigest": "sha256:" + "a" * 64, "verificationCode": "VP_EXPIRED"}
        assert event["reason"] == {"code": "vp_expired"}
        assert audit.proof("generated", "succeeded").event["details"] == {"family": "proof", "phase": "generated"}

    def test_delegation_reference_parent_and_reason(self) -> None:
        audit = create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc")
        event = audit.delegation("rejected", "urn:uuid:d", "denied", reason_code="chain_broken", parent_ref="urn:uuid:p").event
        assert event["details"] == {"family": "delegation", "phase": "rejected", "delegationRef": "urn:uuid:d", "parentRef": "urn:uuid:p"}
        assert event["reason"] == {"code": "chain_broken"} and event["action"] == {"category": "delegation"}
        assert audit.delegation("issued", "urn:uuid:e", "succeeded").event["details"] == {"family": "delegation", "phase": "issued", "delegationRef": "urn:uuid:e"}

    def test_authorization_every_phase_grant_used_the_grant_reference_and_the_tool_name_policy(self) -> None:
        withheld = create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc")
        named = create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc", include_tool_names=True)
        for phase in ("evaluated", "approved", "denied", "step_up_required"):
            assert withheld.authorization(phase, "succeeded").event["eventType"] == f"authorization.{phase}"
        used = withheld.authorization("grant_used", "succeeded", grant_ref="vc:grant-1", tool_name="refund").event
        assert used["eventType"] == "grant.used" and used["details"] == {"family": "authorization", "phase": "grant_used", "grantRef": "vc:grant-1"}
        assert used["action"] == {"category": "authorization"}
        assert named.authorization("approved", "succeeded", tool_name="refund").event["action"] == {"category": "authorization", "name": "refund"}
        challenged = withheld.authorization("step_up_required", "challenged", reason_code="mfa").event
        assert challenged["reason"] == {"code": "mfa"} and challenged["outcome"] == "challenged"

    def test_tool_attempt_defaults_to_1_reason_and_the_tool_name_policy(self) -> None:
        withheld = create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc")
        named = create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc", include_tool_names=True)
        assert withheld.tool("started", "unknown", tool_name="refund").event["details"] == {"family": "tool", "phase": "started", "attempt": "1"}
        failed = withheld.tool("failed", "failed", tool_name="refund", attempt="2", reason_code="handler_error").event
        assert failed["details"] == {"family": "tool", "phase": "failed", "attempt": "2"} and failed["reason"] == {"code": "handler_error"}
        assert failed["action"] == {"category": "tool.call"}
        assert named.tool("completed", "succeeded", tool_name="refund").event["action"] == {"category": "tool.call", "name": "refund"}

    def test_copies_the_context_onto_the_event(self) -> None:
        audit = create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc")
        context = {
            "actor": pairwise_did("did:key:a"),
            "responsibleParty": public_did("did:key:user"),
            "correlationId": "c",
            "causationId": "k",
            "authorization": {"source": "policy", "decision": "allowed"},
            "ignored": 1,
        }
        event = audit.session("established", True, context=context).event
        assert event["actor"] == pairwise_did("did:key:a") and event["responsibleParty"] == public_did("did:key:user")
        assert event["correlationId"] == "c" and event["causationId"] == "k"
        assert event["authorization"] == {"source": "policy", "decision": "allowed"}
        assert "ignored" not in event
        with pytest.raises(AuditEventInvalidError):  # errors propagate: a call that cannot be recorded does not run
            audit.tool("started", "unknown", attempt="x")
        # Python only: on_error takes the failure instead, and the method returns None.
        errors: List[BaseException] = []
        reporting = create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc", on_error=errors.append)
        assert reporting.on_error is not None and reporting.tool("started", "unknown", attempt="x") is None
        assert isinstance(errors[0], AuditEventInvalidError)

    def test_commits_an_oauth_subject_under_the_trail_key(self) -> None:
        def trail(key: Any = None) -> McpAuditTrail:
            return create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc", oauth_subject_key=key)

        fixed = trail(b"k" * 32)
        assert fixed.oauth_actor("alice") == fixed.oauth_actor("alice") == trail(bytearray(b"k" * 32)).oauth_actor("alice")
        assert fixed.oauth_actor("alice") != fixed.oauth_actor("bob")
        assert fixed.oauth_actor("alice") != trail().oauth_actor("alice")  # a random key per trail
        assert fixed.oauth_actor("alice") == {"kind": "keyed_commitment", "value": keyed_commitment_value(b"k" * 32, "alice"), "keyId": OAUTH_SUBJECT_KEY_ID}

    # -- McpAuditTrail.tool_audit_sink (JS: toolAuditSink) ------------------------

    def test_sink_a_helixid_caller_allowed(self) -> None:
        memory = MemoryAuditSink()
        sink = create_mcp_audit_trail(memory, "did:web:svc").tool_audit_sink()
        sink({"event": "AUTHZ_GRANTED", "result": "allowed", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": ["read"], "toolName": "q"})
        proof, approved = memory.events
        assert memory.event_types == ["proof.verified", "authorization.approved"]
        assert proof["actor"] == approved["actor"] == pairwise_did("did:key:a")
        assert "authorization" not in proof and proof["details"] == {"family": "proof", "phase": "verified", "verificationCode": "KYAOS_PROOF"}
        assert approved["authorization"] == {"source": "delegation", "decision": "allowed"} and approved["outcome"] == "succeeded"

    def test_sink_records_delegation_verified_when_the_decision_carries_the_presented_credential(self) -> None:
        memory = MemoryAuditSink()
        sink = create_mcp_audit_trail(memory, "did:web:svc").tool_audit_sink()
        delegation = {"delegationRef": "urn:uuid:d", "delegationCredentialDigest": "sha256:" + "a" * 64, "delegationChainDigests": ["sha256:" + "a" * 64], "ignored": None}
        sink({"event": "AUTHZ_GRANTED", "result": "allowed", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": [], "delegation": delegation})
        proof, verified, approved = memory.events
        expected = {"source": "delegation", "decision": "allowed", "delegationRef": "urn:uuid:d", "delegationCredentialDigest": "sha256:" + "a" * 64, "delegationChainDigests": ["sha256:" + "a" * 64]}
        assert memory.event_types == ["proof.verified", "delegation.verified", "authorization.approved"]
        assert proof["authorization"] == verified["authorization"] == approved["authorization"] == expected
        assert verified["details"] == {"family": "delegation", "phase": "verified", "delegationRef": "urn:uuid:d"}

    def test_sink_names_an_id_less_presented_credential_unknown(self) -> None:
        memory = MemoryAuditSink()
        create_mcp_audit_trail(memory, "did:web:svc").tool_audit_sink()({"event": "AUTHZ_GRANTED", "result": "allowed", "authMethod": "kyaos", "effectiveScopes": [], "delegation": {}})
        assert memory.events[1]["details"]["delegationRef"] == "unknown"
        assert memory.events[1]["authorization"] == {"source": "delegation", "decision": "allowed"}

    def test_sink_a_helixid_caller_denied(self) -> None:
        memory = MemoryAuditSink()
        sink = create_mcp_audit_trail(memory, "did:web:svc").tool_audit_sink()
        sink({"event": "AUTHZ_DENIED", "result": "denied", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": [], "requiredScope": "write"})
        sink({"event": "AUTHZ_DENIED", "result": "denied", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": [], "delegation": {"delegationRef": "urn:uuid:d"}})
        events = memory.events
        assert memory.event_types == ["proof.verified", "authorization.denied", "proof.verified", "delegation.verified", "authorization.denied"]
        assert events[1]["reason"] == {"code": "insufficient_scope"} and events[1]["authorization"] == {"source": "delegation", "decision": "denied", "scopeId": "write"}
        assert events[4]["reason"] == {"code": "tool_not_permitted"} and events[4]["authorization"] == {"source": "delegation", "decision": "denied", "delegationRef": "urn:uuid:d"}
        sink({"event": "AUTHZ_DENIED", "result": "denied", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": [], "requiredScope": "write", "delegation": {"delegationRef": "urn:uuid:d"}})
        assert memory.events[-1]["authorization"] == {"source": "delegation", "decision": "denied", "scopeId": "write", "delegationRef": "urn:uuid:d"}

    def test_sink_an_oauth_caller(self) -> None:
        memory = MemoryAuditSink()
        audit = create_mcp_audit_trail(memory, "did:web:svc", oauth_subject_key=b"k" * 32)
        audit.tool_audit_sink()({"event": "AUTHZ_GRANTED", "result": "allowed", "authMethod": "oauth", "oauthSubject": "u-1", "effectiveScopes": ["read"]})
        assert memory.event_types == ["authorization.approved"]
        event = memory.events[0]
        assert event["actor"] == audit.oauth_actor("u-1") and event["authorization"] == {"source": "policy", "decision": "allowed"}
        assert "u-1" not in json.dumps(event)

    def test_sink_handles_odd_shapes_and_no_named_caller(self) -> None:
        memory = MemoryAuditSink()
        sink = create_mcp_audit_trail(memory, "did:web:svc").tool_audit_sink()
        sink({"event": "AUTHZ_DENIED", "result": "denied", "authMethod": "oauth", "effectiveScopes": [], "toolName": 5, "requiredScope": 7, "delegation": "not-a-dict"})
        sink({"event": "AUTHZ_GRANTED", "result": "allowed", "authMethod": "kyaos", "effectiveScopes": [], "correlationId": "given"})
        events = memory.events
        assert "actor" not in events[0] and events[0]["reason"] == {"code": "tool_not_permitted"} and events[0]["authorization"] == {"source": "policy", "decision": "denied"}
        assert "actor" not in events[1] and events[1]["correlationId"] == "given" and events[2]["correlationId"] == "given"

    def test_sink_records_the_tool_name_on_the_authorization_event_only_when_include_tool_names(self) -> None:
        decision = {"event": "AUTHZ_GRANTED", "result": "allowed", "authMethod": "oauth", "oauthSubject": "s", "effectiveScopes": [], "toolName": "refund"}
        withheld, named = MemoryAuditSink(), MemoryAuditSink()
        create_mcp_audit_trail(withheld, "did:web:svc").tool_audit_sink()(decision)
        create_mcp_audit_trail(named, "did:web:svc", include_tool_names=True).tool_audit_sink()(decision)
        assert withheld.events[0]["action"] == {"category": "authorization"}
        assert named.events[0]["action"] == {"category": "authorization", "name": "refund"}

    def test_sink_lets_a_reporter_failure_propagate(self) -> None:
        class Failing:
            def append(self, entry: AuditTrailEntry) -> None:
                raise RuntimeError("reporter down")

        with pytest.raises(RuntimeError, match="reporter down"):
            create_mcp_audit_trail(Failing(), "did:web:svc").tool_audit_sink()({"event": "AUTHZ_GRANTED", "result": "allowed", "authMethod": "oauth", "oauthSubject": "s", "effectiveScopes": []})

    # -- McpAuditTrail.begin_tool_call (JS: beginToolCall) -------------------------

    def test_begin_tool_call_gives_an_audit_uuid_correlation_id_or_keeps_the_one_given(self) -> None:
        audit = create_mcp_audit_trail(MemoryAuditSink(), "did:web:svc")
        with audit.begin_tool_call("q") as call:
            assert call.correlation_id.startswith("audit_") and len(call.correlation_id) == len("audit_") + 36
        with audit.begin_tool_call("q", correlation_id="call-1") as call:
            assert call.correlation_id == "call-1" and call.tool_name == "q" and call.delegation is None
        assert current_tool_call() is None

    def test_begin_tool_call_joins_the_gate_decision_and_the_lifecycle(self) -> None:
        memory = MemoryAuditSink()
        audit = create_mcp_audit_trail(memory, "did:web:svc", include_tool_names=True)
        mw = gate(validate_oauth_token=lambda t: {"sub": "u-1", "scopes": ["read"]}, tool_scopes={"q": ["read"], "u": ["write"]}, audit_sink=audit.tool_audit_sink(), expected_target_service="did:web:svc")
        with audit.begin_tool_call("q", correlation_id="call-1") as call:
            assert current_tool_call() is call
            mw({"name": "q", "headers": {"authorization": "Bearer tok"}})
            started = call.started()
            completed = call.completed()
        assert started.event["eventType"] == "tool.call.started" and completed.event["outcome"] == "succeeded"
        denied(lambda: mw({"name": "u", "headers": {"authorization": "Bearer tok"}}))
        events = memory.events
        assert memory.event_types == ["session.established", "authorization.approved", "tool.call.started", "tool.call.completed", "authorization.denied"]
        assert all(e["correlationId"] == "call-1" for e in events[:4]) and "correlationId" not in events[4]
        assert "actor" not in events[0]  # the caller is not known before the gate
        assert all(e["actor"]["kind"] == "keyed_commitment" for e in events[1:])
        assert events[1]["actor"] == events[2]["actor"] == events[4]["actor"] == call.actor  # learned from the gate's decision
        assert events[2]["action"] == {"category": "tool.call", "name": "q"}
        assert "u-1" not in json.dumps(events)

    def test_begin_tool_call_keeps_a_given_actor_and_records_failed_and_denied(self) -> None:
        memory = MemoryAuditSink()
        audit = create_mcp_audit_trail(memory, "did:web:svc", source_id="s", tenant_ref=public_did("did:web:tenant"))
        with audit.begin_tool_call(None, actor=pairwise_did("did:key:a")) as call:
            assert call.tool_name is None
            call.denied("vp_missing")
        with audit.begin_tool_call("t") as call:
            call.failed("handler_error")
        with audit.begin_tool_call("t", actor=pairwise_did("did:key:given")):
            # A decision that names no caller keeps the call's actor.
            audit.tool_audit_sink()({"event": "AUTHZ_GRANTED", "result": "allowed", "authMethod": "kyaos", "effectiveScopes": []})
        assert memory.events[-1]["actor"] == memory.events[-2]["actor"] == pairwise_did("did:key:given")
        del memory.entries[4:]
        events = memory.events
        assert memory.event_types == ["session.established", "tool.call.denied", "session.established", "tool.call.failed"]
        assert events[0]["correlationId"] == events[1]["correlationId"] != events[2]["correlationId"]
        assert events[0]["actor"] == events[1]["actor"] == pairwise_did("did:key:a")
        assert events[1]["reason"] == {"code": "vp_missing"} and events[1]["outcome"] == "denied"
        assert events[3]["reason"] == {"code": "handler_error"} and events[3]["outcome"] == "failed"
        assert all(e["tenantRef"] == public_did("did:web:tenant") and e["source"]["sourceId"] == "s" for e in events)

    def test_begin_tool_call_scopes_the_context_an_explicit_member_wins(self) -> None:
        memory = MemoryAuditSink()
        audit = create_mcp_audit_trail(memory, "did:web:svc")
        audit.tool("started", "unknown")
        with audit.begin_tool_call("q", correlation_id="inside", actor=pairwise_did("did:key:a")):
            audit.tool("started", "unknown")
            audit.tool("started", "unknown", context={"correlationId": "explicit", "actor": pairwise_did("did:key:b")})
        events = memory.events
        assert "correlationId" not in events[0] and "actor" not in events[0]
        assert events[2]["correlationId"] == "inside" and events[2]["actor"] == pairwise_did("did:key:a")
        assert events[3]["correlationId"] == "explicit" and events[3]["actor"] == pairwise_did("did:key:b")

    def test_begin_tool_call_derives_delegation_evidence_from_a_decoded_vp(self) -> None:
        memory = MemoryAuditSink()
        audit = create_mcp_audit_trail(memory, "did:web:svc")
        parent = _agent_vc("urn:uuid:parent")
        leaf = {**_agent_vc("urn:uuid:leaf"), "delegationChain": [parent]}
        vp = {"verifiableCredential": [_agent_vc("urn:uuid:other"), {"type": ["VerifiableCredential", "DelegationGrantCredential"]}, leaf]}
        expected = {
            "delegationRef": "urn:uuid:leaf",
            "delegationCredentialDigest": credential_digest(leaf),
            "delegationChainDigests": delegation_chain_digests([parent, leaf]),
        }
        with audit.begin_tool_call("q", credential=vp) as call:
            assert call.delegation == expected
            audit.tool_audit_sink()({"event": "AUTHZ_GRANTED", "result": "allowed", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": []})
        assert memory.event_types == ["session.established", "proof.verified", "delegation.verified", "authorization.approved"]
        authorization = {"source": "delegation", "decision": "allowed", **expected}
        assert memory.events[1]["authorization"] == memory.events[2]["authorization"] == memory.events[3]["authorization"] == authorization
        assert memory.events[2]["details"]["delegationRef"] == "urn:uuid:leaf"
        # A decision that carries its own delegation wins over the call's.
        with audit.begin_tool_call("q", credential=vp):
            audit.tool_audit_sink()({"event": "AUTHZ_GRANTED", "result": "allowed", "authMethod": "kyaos", "agentDid": "did:key:a", "effectiveScopes": [], "delegation": {"delegationRef": "urn:uuid:own"}})
        assert memory.events[-2]["details"]["delegationRef"] == "urn:uuid:own"

    def test_delegation_evidence_of(self) -> None:
        assert delegation_evidence_of(None) is None
        assert delegation_evidence_of({"verifiableCredential": "x"}) is None
        assert delegation_evidence_of({"verifiableCredential": [{"type": ["VerifiableCredential"]}, "x"]}) is None
        by_subject = {"credentialSubject": {"type": "HelixAgent", "id": "did:key:a"}, "proof": {"proofValue": "AQIDBA=="}}
        assert delegation_evidence_of({"verifiableCredential": [by_subject]}) == {
            "delegationCredentialDigest": credential_digest(by_subject),
            "delegationChainDigests": [credential_digest(by_subject)],
        }
        unsigned = {"id": "urn:uuid:u", "type": ["HelixAgentCredential"]}
        assert delegation_evidence_of({"verifiableCredential": [unsigned]}) == {"delegationRef": "urn:uuid:u"}
        assert delegation_evidence_of({"verifiableCredential": [{**unsigned, "delegationChain": "x"}]}) == {"delegationRef": "urn:uuid:u"}


def test_async_wrapper_runs_the_same_gate() -> None:
    mw = async_helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifying(["read"]), tool_scopes={"q": ["read"]}))
    assert asyncio.run(mw({"name": "q", "_meta": PROOF_META}))["name"] == "q"
    with pytest.raises(HelixError) as excinfo:
        asyncio.run(mw({"name": "nope", "_meta": PROOF_META}))
    assert excinfo.value.code == "TOOL_NOT_PERMITTED"


# ── every supported signature algorithm, with real keys ──────────────────────


def _int_b64(value: int) -> str:
    return b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _signer(alg: str) -> Any:
    """(jwk, sign(data) -> JWS signature bytes) for a fresh key of the algorithm's type."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

    digests = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
    if alg == "EdDSA":
        key = ed25519.Ed25519PrivateKey.generate()
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64(raw)}, key.sign
    digest = digests[alg[2:]]()
    if alg[:2] in ("RS", "PS"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = key.public_key().public_numbers()
        pad = padding.PKCS1v15() if alg.startswith("RS") else padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size)
        return {"kty": "RSA", "n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}, lambda data: key.sign(data, pad, digest)
    curve, crv, size = {"ES256": (ec.SECP256R1, "P-256", 32), "ES384": (ec.SECP384R1, "P-384", 48), "ES512": (ec.SECP521R1, "P-521", 66)}[alg]
    key = ec.generate_private_key(curve())
    numbers = key.public_key().public_numbers()

    def sign(data: bytes) -> bytes:
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(digest)))
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    return {"kty": "EC", "crv": crv, "x": b64(numbers.x.to_bytes(size, "big")), "y": b64(numbers.y.to_bytes(size, "big"))}, sign


def _jwt(alg: str, sign: Any, body: Dict[str, Any], kid: str = "k") -> str:
    signing_input = f"{b64({'alg': alg, 'kid': kid})}.{b64(body)}"
    return f"{signing_input}.{b64(sign(signing_input.encode()))}"


ALL_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]


@pytest.mark.parametrize("alg", ALL_ALGS)
def test_verifies_each_algorithm_and_rejects_a_tampered_or_foreign_signature(alg: str) -> None:
    jwk, sign = _signer(alg)
    v = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp({f"{ISS_A}/jwks": {"keys": [{**jwk, "kid": "k"}]}})))
    token = _jwt(alg, sign, claims())
    assert v(token).sub == "user-1"

    head, body, sig = token.split(".")
    forged_body = b64({**claims(), "sub": "attacker"})
    raises_invalid(lambda: v(f"{head}.{forged_body}.{sig}"), "Invalid token signature")
    _, other_sign = _signer(alg)
    raises_invalid(lambda: v(_jwt(alg, other_sign, claims())), "Invalid token signature")
    raises_invalid(lambda: v(f"{head}.{body}.{sig[:-4]}"))  # truncated signature
    raises_invalid(lambda: v(f"{head}.{body}."))  # no signature at all


def test_algorithm_and_key_type_cannot_be_mixed() -> None:
    rsa_jwk, rsa_sign = _signer("RS256")
    ec_jwk, ec_sign = _signer("ES256")
    keys = [{**rsa_jwk, "kid": "r"}, {**ec_jwk, "kid": "e"}]
    v = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp({f"{ISS_A}/jwks": {"keys": keys}})))
    assert v(_jwt("RS256", rsa_sign, claims(), kid="r")).sub == "user-1"
    # The header names a key of the other type: no key is selected, whatever the signature.
    raises_invalid(lambda: v(_jwt("ES256", ec_sign, claims(), kid="r")), "No matching signing key")
    raises_invalid(lambda: v(_jwt("RS256", rsa_sign, claims(), kid="e")), "No matching signing key")
    # A key that declares its own alg or use is only used for that.
    pinned = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp({f"{ISS_A}/jwks": {"keys": [{**rsa_jwk, "kid": "r", "alg": "PS256"}, {**ec_jwk, "kid": "e", "use": "enc"}]}})))
    raises_invalid(lambda: pinned(_jwt("RS256", rsa_sign, claims(), kid="r")), "No matching signing key")
    raises_invalid(lambda: pinned(_jwt("ES256", ec_sign, claims(), kid="e")), "No matching signing key")


def test_token_without_kid_needs_an_unambiguous_key() -> None:
    jwk1, sign1 = _signer("ES256")
    jwk2, _ = _signer("ES256")

    def no_kid(sign: Any) -> str:
        signing_input = f"{b64({'alg': 'ES256'})}.{b64(claims())}"
        return f"{signing_input}.{b64(sign(signing_input.encode()))}"

    one = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp({f"{ISS_A}/jwks": {"keys": [jwk1]}})))
    assert one(no_kid(sign1)).sub == "user-1"
    two = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp({f"{ISS_A}/jwks": {"keys": [jwk1, jwk2]}})))
    raises_invalid(lambda: two(no_kid(sign1)), "No matching signing key")


def test_malformed_tokens_and_keys_are_invalid_tokens_never_crashes() -> None:
    jwk, sign = _signer("ES256")
    good = _jwt("ES256", sign, claims())
    head, body, sig = good.split(".")
    broken_key = {"kty": "EC", "crv": "P-256", "kid": "k", "x": "!!", "y": "!!"}
    v = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp({f"{ISS_A}/jwks": {"keys": [{**jwk, "kid": "k"}]}})))
    for token in ("..", "a.b.c", f"{head}.{body}.éé", f"é.{body}.{sig}", f"{b64([1])}.{body}.{sig}",                   # JWS segments are unpadded base64url: padding or stray characters are not ignored.
                  f"{head}.{body}.{sig}==", f"{head}.{body}.{sig}!!", f"{head}.{body}.{sig[:10]} {sig[10:]}"):
        raises_invalid(lambda token=token: v(token))
    bad = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp({f"{ISS_A}/jwks": {"keys": [broken_key]}})))
    raises_invalid(lambda: bad(good), "Token signature could not be verified")


# ── review fixes ─────────────────────────────────────────────────────────────


class TestOutageDoesNotPileUp:
    def test_callers_queued_behind_a_failed_jwks_fetch_share_the_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import threading

        k = Key("k1")

        def slow_failure(kwargs: Dict[str, Any]) -> Any:
            time.sleep(0.2)
            return ConnectionError("down")

        http = FakeHttp({f"{ISS_A}/jwks": slow_failure})
        v = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=http))
        token = k.token(claims())
        errors: List[Any] = []
        threads = [threading.Thread(target=lambda: errors.append(denied(lambda: v(token)))) for _ in range(8)]
        started = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(isinstance(e, AuthorizationServerUnavailableError) for e in errors) and len(errors) == 8
        assert len(http.calls) == 1  # one fetch, not eight in a row
        assert time.time() - started < 1.0
        # After the backoff the next caller tries again.
        real = time.time
        monkeypatch.setattr(oauth_module, "_now", lambda: real() + 3)
        denied(lambda: v(token))
        assert len(http.calls) == 2

    def test_recovery_clears_the_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        k = Key("k1")
        up = {"now": False}
        http = FakeHttp({f"{ISS_A}/jwks": lambda kw: {"keys": [k.jwk]} if up["now"] else Response({}, 503)})
        v = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=http))
        denied(lambda: v(k.token(claims())))
        up["now"] = True
        real = time.time
        monkeypatch.setattr(oauth_module, "_now", lambda: real() + 3)
        assert v(k.token(claims())).sub == "user-1"
        assert v(k.token(claims())).sub == "user-1"
        assert len(http.calls) == 2


class TestAsyncCallbacks:
    def test_the_sync_gate_refuses_async_callbacks_instead_of_dropping_them(self) -> None:
        async def sink(event: Dict[str, Any]) -> None: ...
        async def validate(token: str) -> Dict[str, Any]:
            return {"sub": "u"}

        with pytest.raises(ValueError, match="async_helixid_mcp_middleware"):
            gate(verifier=verifying([]), audit_sink=sink)
        with pytest.raises(ValueError, match="async_helixid_mcp_middleware"):
            gate(validate_oauth_token=validate)

        # A sync callable that returns an awaitable is caught at call time: a sink
        # failure is reported, a validator is a configuration error (never a 401).
        errors: List[BaseException] = []
        mw = gate(verifier=verifying([]), audit_sink=lambda e: sink(e), on_audit_error=errors.append)
        assert mw({"name": "t", "_meta": PROOF_META})
        assert len(errors) == 1 and "awaitable" in str(errors[0])
        err = denied(lambda: gate(validate_oauth_token=lambda t: validate(t))({"name": "t", "headers": {"authorization": "Bearer x"}}))
        assert isinstance(err, TypeError) and to_http_error_response(err, META_URL) is None

    def test_the_async_gate_awaits_async_callbacks_off_the_event_loop_thread(self) -> None:
        import threading

        events: List[Dict[str, Any]] = []
        seen: Dict[str, Any] = {}

        async def validate(token: str) -> Dict[str, Any]:
            await asyncio.sleep(0)
            seen["validate_thread"] = threading.get_ident()
            return {"sub": "u-1", "scopes": ["read"]}

        async def sink(event: Dict[str, Any]) -> None:
            await asyncio.sleep(0)
            events.append(event)

        verifier = verifying(["read"])
        verifier.on_call = lambda: seen.update(verify_thread=threading.get_ident())

        async def run() -> None:
            seen["loop_thread"] = threading.get_ident()
            mw = async_helixid_mcp_middleware(MCPMiddlewareOptions(verifier=verifier, validate_oauth_token=validate, audit_sink=sink, tool_scopes={"q": ["read"]}))
            await mw({"name": "q", "headers": {"authorization": "Bearer tok"}})
            await mw({"name": "q", "_meta": PROOF_META})

        asyncio.run(run())
        assert [(e["event"], e.get("oauthSubject"), e.get("agentDid")) for e in events] == [("AUTHZ_GRANTED", "u-1", None), ("AUTHZ_GRANTED", None, "did:agent")]
        assert seen["validate_thread"] == seen["loop_thread"]  # the async callback ran on the loop
        assert seen["verify_thread"] != seen["loop_thread"]  # the blocking verification did not


class TestHostileInput:
    def test_absurdly_nested_json_is_a_bad_credential_not_a_crash(self) -> None:
        deep = base64.urlsafe_b64encode(b"[" * 100_000).rstrip(b"=").decode()
        mw = gate(verifier=verifying([]), oauth=OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp()))
        assert denied(lambda: mw({"name": "t", "headers": {"authorization": f"Bearer {deep}.{deep}.x"}})).code == "OAUTH_TOKEN_INVALID"

    def test_meta_that_is_not_a_mapping_is_treated_as_absent(self) -> None:
        mw = gate(verifier=verifying([]))
        for meta in ("x", [1], 5, object()):
            assert denied(lambda meta=meta: mw({"name": "t", "_meta": meta})).code == "PROOF_MISSING"

        class Meta:  # the shape of the MCP Python SDK's RequestParams.Meta
            def model_dump(self, by_alias: bool = False) -> Dict[str, Any]:
                return {"progressToken": None, "org.kya-os/request-proof": PROOF}

        assert mw({"name": "t", "_meta": Meta()})["name"] == "t"

    def test_signatures_must_be_canonical_base64url_but_published_keys_may_be_padded(self) -> None:
        k = Key("k1")
        padded = {**k.jwk, "x": k.jwk["x"] + "=", "y": k.jwk["y"] + "="}
        v = create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=FakeHttp({f"{ISS_A}/jwks": {"keys": [padded]}})))
        token = k.token(claims())
        assert v(token).sub == "user-1"
        head, body, sig = token.split(".")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        # 64 signature bytes leave unused bits in the last character: exactly one spelling is accepted.
        accepted = [c for c in alphabet if _accepts(v, f"{head}.{body}.{sig[:-1]}{c}")]
        assert accepted == [sig[-1]]
        raises_invalid(lambda: v(f"{head}.{body}.{sig}\n"))


def _accepts(validator: Any, token: str) -> bool:
    try:
        validator(token)
        return True
    except HelixError:
        return False


class TestOptionAndClaimEdges:
    def setup_method(self) -> None:
        self.k = Key("k1")
        self.http = FakeHttp({f"{ISS_A}/jwks": {"keys": [self.k.jwk]}})

    def jwt(self, **options: Any) -> Any:
        return create_jwt_validator(OAuthIssuerOptions(ISS_A, AUD, jwks_uri=f"{ISS_A}/jwks", http=self.http, **options))

    def test_empty_lists_mean_none_not_the_default(self) -> None:
        raises_invalid(lambda: self.jwt(algorithms=[])(self.k.token(claims())), "Unsupported token algorithm")
        assert list(self.jwt(scope_claims=[])(self.k.token(claims())).scopes) == []
        for bad in ({"scope_claims": "roles"}, {"algorithms": "ES256"}):
            with pytest.raises(ValueError, match="list of strings"):
                self.jwt(**bad)

    def test_timestamps_must_be_real_finite_numbers(self) -> None:
        v = self.jwt()
        for exp in (float("nan"), float("inf"), 10**400, True, "9999999999"):
            head, body = b64({"alg": "ES256", "kid": "k1"}), base64.urlsafe_b64encode(json.dumps({**claims(), "exp": exp}).encode()).rstrip(b"=").decode()
            r, s = decode_dss_signature(self.k.private.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
            token = f"{head}.{body}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
            raises_invalid(lambda token=token: v(token), "Token expired")

    def test_present_but_null_claims_are_malformed_on_introspection(self) -> None:
        def answer(**body: Any) -> Any:
            return create_introspection_validator(introspecting(FakeHttp({INTROSPECT_B: {"active": True, **active(), **body}}), allow_missing_audience=True))

        for body, message in (({"exp": None}, "Token expired"), ({"nbf": None}, "Token not yet valid"), ({"iss": None}, "Unexpected token issuer"), ({"aud": None}, "Token audience does not match this server")):
            raises_invalid(lambda body=body: answer(**body)("t"), message)
        assert answer(client_id="", azp="fallback").__call__("t").client_id is None  # an empty client_id is not replaced by azp

    def test_introspection_cache_is_swept_when_large(self, monkeypatch: pytest.MonkeyPatch) -> None:
        soon = int(time.time()) + 1
        known = {f"t{i}": active(exp=soon) for i in range(1000)}
        known["fresh"] = active()
        http = FakeHttp({INTROSPECT_B: introspection_route(known)})
        v = create_introspection_validator(introspecting(http, clock_tolerance_seconds=0))
        for i in range(1000):
            v(f"t{i}")
        real = time.time
        monkeypatch.setattr(oauth_module, "_now", lambda: real() + 2.5)
        assert v("fresh").sub == "opaque-user"  # the 1001st insert sweeps the 1000 expired entries
        raises_invalid(lambda: v("t0"), "Token expired")  # asked again: its entry is gone
        v("fresh")  # served from cache
        assert len(http.calls) == 1002
