# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Phase 1 of helix_mcp_middleware: credentials, per-tool scopes, OAuth (JWT,
introspection, several issuers, discovery, presets), HTTP challenges and
audit. The same cases as helix-sdk-js's mcp-middleware tests (auth.test.ts,
oauth.test.ts, middleware.test.ts), with a fake HTTP client instead of a
mocked fetch and real keys generated per test.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from helix_sdk.errors import HelixError
from helix_sdk.vp_transport import encode_helix_vp
from helix_mcp_middleware import (
    AuthorizationServerUnavailableError,
    AuthResult,
    MCPMiddlewareOptions,
    OAuthIntrospectionOptions,
    OAuthIssuerOptions,
    async_helixid_mcp_middleware,
    auth0,
    build_protected_resource_metadata,
    create_helix_audit_sink,
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


VP = encode_helix_vp({"id": "vp:helix:test"})


def verifying_client(scopes: List[str], agent: str = "did:agent") -> MagicMock:
    client = MagicMock()
    client.verify_vp.return_value = {
        "valid": True, "agentDid": agent, "privilegeScopes": scopes, "effectiveScopes": scopes,
        "vpId": "vp:helix:test", "delegationChain": [],
    }
    return client


def gate(**options: Any) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    return helixid_mcp_middleware(MCPMiddlewareOptions(**options))


def denied(fn: Callable[[], Any]) -> Any:
    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        fn()
    return excinfo.value


# ── credentials ──────────────────────────────────────────────────────────────


class TestCredentials:
    def test_authorization_helixvp_any_case_and_same_vp_in_several_places(self) -> None:
        mw = gate(client=verifying_client(["read"]))
        assert mw({"name": "t", "headers": {"Authorization": f"helixVP {VP}"}})["name"] == "t"
        assert mw({"name": "t", "headers": {"authorization": f"HelixVP {VP}", "X-Helix-VP": VP}, "_meta": {"x-helix-vp": VP}})

    def test_multi_value_headers_object(self) -> None:
        class Headers:
            def __init__(self, items: List[Any]) -> None:
                self.items = items

            def getlist(self, name: str) -> List[str]:
                return [v for k, v in self.items if k.lower() == name]

        mw = gate(client=verifying_client([]))
        assert mw({"name": "t", "headers": Headers([("Authorization", f"HelixVP {VP}")])})
        err = denied(lambda: mw({"name": "t", "headers": Headers([("authorization", f"HelixVP {VP}"), ("Authorization", "Bearer x")])}))
        assert err.code == "CREDENTIAL_CONFLICT"

    def test_conflicts_are_rejected_never_resolved(self) -> None:
        mw = gate(client=verifying_client([]), validate_oauth_token=lambda t: {"sub": "u", "scopes": []})
        other = encode_helix_vp({"id": "vp:other"})
        for call in (
            {"headers": {"x-helix-vp": VP}, "_meta": {"x-helix-vp": other}},
            {"headers": {"authorization": "Bearer tok", "x-helix-vp": VP}},
            {"headers": {"authorization": ["Bearer a", "Bearer b"]}},
            {"headers": {"authorization": "Bearer"}},
        ):
            assert denied(lambda call=call: mw({"name": "t", **call})).code == "CREDENTIAL_CONFLICT"

    def test_no_credentials_and_bearer_without_oauth(self) -> None:
        mw = gate(client=verifying_client([]))
        assert denied(lambda: mw({"name": "t"})).code == "VP_MISSING"
        assert denied(lambda: mw({"name": "t", "input": {"x-helix-vp": VP}})).code == "VP_MISSING"
        assert denied(lambda: mw({"name": "t", "headers": {"authorization": "Bearer x"}})).code == "OAUTH_TOKEN_INVALID"
        assert denied(lambda: mw({"name": "t", "_meta": {"x-helix-vp": 5}})).code == "VP_INVALID_STRUCTURE"


# ── scopes ───────────────────────────────────────────────────────────────────


class TestToolScopes:
    def test_listed_tool_with_scope_and_deny_by_default(self) -> None:
        mw = gate(client=verifying_client(["read"]), tool_scopes={"query": ["read"], "update": ["write"]}, required_scopes=["never"])
        call = {"_meta": {"x-helix-vp": VP}}
        assert mw({"name": "query", **call})
        for name in ("drop", "__class__", "toString", None, 7):
            assert denied(lambda name=name: mw({"name": name, **call})).code == "TOOL_NOT_PERMITTED"
        err = denied(lambda: mw({"name": "update", **call}))
        assert (err.code, err.required_scope, err.required_scopes) == ("INSUFFICIENT_SCOPE", "write", ["write"])

    def test_required_scopes_is_the_fallback_and_empty_list_allows_any_caller(self) -> None:
        call = {"name": "anything", "_meta": {"x-helix-vp": VP}}
        assert gate(client=verifying_client(["read"]), required_scopes=["read"])(call)
        assert denied(lambda: gate(client=verifying_client([]), required_scopes=["read"])(call)).code == "INSUFFICIENT_SCOPE"
        assert gate(client=verifying_client([]), tool_scopes={"anything": []})(call)


# ── HelixID door ─────────────────────────────────────────────────────────────


class TestHelixVp:
    def test_passes_target_service_and_rejects_invalid(self) -> None:
        client = verifying_client(["read"])
        gate(client=client, expected_target_service="did:web:svc")({"name": "t", "_meta": {"x-helix-vp": VP}})
        assert client.verify_vp.call_args.kwargs["expected_target_service"] == "did:web:svc"
        client.verify_vp.return_value = {"valid": False, "error": "bad signature"}
        err = denied(lambda: gate(client=client)({"name": "t", "_meta": {"x-helix-vp": VP}}))
        assert (err.code, str(err)) == ("VP_VERIFICATION_FAILED", "bad signature")

    def test_credential_errors_from_the_api_become_verification_failures(self) -> None:
        for code in ("VC_REVOKED", "VP_EXPIRED", "VP_SIGNATURE_INVALID", "DELEGATION_CHAIN_INVALID", "DID_NOT_FOUND"):
            client = MagicMock()
            client.verify_vp.side_effect = HelixError(code, f"api said {code}", 400)
            err = denied(lambda client=client: gate(client=client)({"name": "t", "_meta": {"x-helix-vp": VP}}))
            assert (err.code, str(err)) == ("VP_VERIFICATION_FAILED", f"api said {code}"), code

    def test_api_failures_that_are_not_about_the_credential_pass_through(self) -> None:
        for code in ("ACCESS_TOKEN_INVALID", "ADMIN_AUTH_REQUIRED", "INTERNAL_ERROR"):
            client = MagicMock()
            client.verify_vp.side_effect = HelixError(code, "x", 500)
            err = denied(lambda client=client: gate(client=client)({"name": "t", "_meta": {"x-helix-vp": VP}}))
            assert err.code == code
            assert to_http_error_response(err, META_URL) is None
        client = MagicMock()
        client.verify_vp.side_effect = ConnectionError("down")
        assert isinstance(denied(lambda: gate(client=client)({"name": "t", "_meta": {"x-helix-vp": VP}})), ConnectionError)

    def test_vp_without_client_is_a_configuration_error(self) -> None:
        mw = gate(validate_oauth_token=lambda t: {"sub": "u"})
        assert isinstance(denied(lambda: mw({"name": "t", "_meta": {"x-helix-vp": VP}})), ValueError)


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

    def test_outage_is_retried_on_the_next_token(self) -> None:
        up = {"now": False}
        good = self.routes(metadata_for(ISS_B))
        http = FakeHttp({self.oidc: lambda kw: good[self.oidc] if up["now"] else ConnectionError("refused"), f"{ISS_B}/keys": good[f"{ISS_B}/keys"]})
        v = create_oauth_validator(OAuthIssuerOptions(ISS_B, AUD, http=http))
        token = self.k.token(claims(iss=ISS_B))
        assert isinstance(denied(lambda: v(token)), AuthorizationServerUnavailableError)
        up["now"] = True
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
        res = to_http_error_response(denied(lambda: gate(client=MagicMock())({"name": "t"})), META_URL)
        assert res.status == 401
        assert res.headers["WWW-Authenticate"] == f'Bearer resource_metadata="{META_URL}", HelixVP resource_metadata="{META_URL}"'
        assert res.body["error"] == "unauthorized"

    def test_status_mapping(self) -> None:
        for code, status, name in (
            ("OAUTH_TOKEN_INVALID", 401, "invalid_token"), ("VP_VERIFICATION_FAILED", 401, "invalid_token"),
            ("VP_INVALID_STRUCTURE", 401, "invalid_token"), ("CREDENTIAL_CONFLICT", 400, "invalid_request"),
            ("INSUFFICIENT_SCOPE", 403, "insufficient_scope"), ("TOOL_NOT_PERMITTED", 403, "insufficient_scope"),
        ):
            res = to_http_error_response(HelixError(code, "x", 400), META_URL)
            assert (res.status, res.body["error"]) == (status, name)
            assert "scope=" not in res.headers["WWW-Authenticate"]
        for error in (HelixError("ADMIN_AUTH_REQUIRED", "x", 403), RuntimeError("boom"), None):
            assert to_http_error_response(error, META_URL) is None

    def test_403_lists_every_required_scope_and_header_charset_is_confined(self) -> None:
        mw = gate(validate_oauth_token=lambda t: {"sub": "u", "scopes": ["read"]}, tool_scopes={"t": ["read", "admin", "export"]})
        res = to_http_error_response(denied(lambda: mw({"name": "t", "headers": {"authorization": "Bearer x"}})), META_URL)
        assert res.status == 403
        assert 'error="insufficient_scope", error_description="Required scope: admin", scope="read admin export"' in res.headers["WWW-Authenticate"]
        odd = to_http_error_response(HelixError("VP_VERIFICATION_FAILED", 'bad é\u0007 "quote" \\slash', 400), META_URL)
        assert 'error_description="bad     quote   slash"' in odd.headers["WWW-Authenticate"]


# ── audit ────────────────────────────────────────────────────────────────────


class TestAudit:
    def test_events_for_vp_callers(self) -> None:
        events: List[Dict[str, Any]] = []
        mw = gate(client=verifying_client(["read"], agent="did:key:agent"), tool_scopes={"q": ["read"], "u": ["write"]}, audit_sink=events.append, expected_target_service="did:web:svc")
        mw({"name": "q", "_meta": {"x-helix-vp": VP}})
        denied(lambda: mw({"name": "u", "_meta": {"x-helix-vp": VP}}))
        denied(lambda: mw({"name": "zzz", "_meta": {"x-helix-vp": VP}}))
        assert [(e["event"], e["result"], e["toolName"], e.get("requiredScope"), e.get("reason")) for e in events] == [
            ("AUTHZ_GRANTED", "allowed", "q", None, None),
            ("AUTHZ_DENIED", "denied", "u", "write", "insufficient scope"),
            ("AUTHZ_DENIED", "denied", "zzz", None, "tool is not in toolScopes"),
        ]
        assert all(e["agentDid"] == "did:key:agent" and e["vpId"] == "vp:helix:test" and e["serviceDid"] == "did:web:svc" and e["authMethod"] == "helixvp" for e in events)
        assert events[0]["timestamp"].endswith("Z")

    def test_unidentified_callers_are_not_logged_and_a_failing_sink_never_blocks(self) -> None:
        events: List[Any] = []
        errors: List[BaseException] = []

        def failing(event: Dict[str, Any]) -> None:
            events.append(event)
            raise RuntimeError("sink down")

        mw = gate(client=verifying_client([]), audit_sink=failing, on_audit_error=errors.append)
        denied(lambda: mw({"name": "t"}))
        assert events == []
        assert mw({"name": "t", "_meta": {"x-helix-vp": VP}})
        assert len(events) == 1 and str(errors[0]) == "sink down"

    def test_helix_audit_sink(self) -> None:
        http = FakeHttp({"http://api.test/v1/audit-log/events": {}})
        sink = create_helix_audit_sink("http://api.test/", "hak_1", service_did="did:web:svc", http=http)
        sink({"event": "AUTHZ_DENIED", "result": "denied", "timestamp": "t", "authMethod": "oauth", "effectiveScopes": ["read"], "oauthSubject": "u-9", "toolName": "refund", "requiredScope": "admin", "reason": "insufficient scope"})
        call = http.calls[0]
        assert call["headers"]["authorization"] == "Bearer hak_1"
        assert call["json"] == {
            "event": "AUTHZ_DENIED", "timestamp": "t", "effectiveScopes": ["read"], "result": "denied", "source": "mcp-middleware",
            "serviceDid": "did:web:svc", "toolName": "refund", "requiredScope": "admin", "reason": "insufficient scope", "oauthSubject": "u-9",
        }
        with pytest.raises(ValueError):
            create_helix_audit_sink("http://api.test", "k", http=http)({"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "effectiveScopes": []})
        with pytest.raises(RuntimeError):
            create_helix_audit_sink("http://api.test", "k", service_did="d", http=FakeHttp())({"event": "AUTHZ_GRANTED", "result": "allowed", "timestamp": "t", "effectiveScopes": []})


def test_async_wrapper_runs_the_same_gate() -> None:
    mw = async_helixid_mcp_middleware(MCPMiddlewareOptions(client=verifying_client(["read"]), tool_scopes={"q": ["read"]}))
    assert asyncio.run(mw({"name": "q", "_meta": {"x-helix-vp": VP}}))["name"] == "q"
    with pytest.raises(HelixError) as excinfo:
        asyncio.run(mw({"name": "nope", "_meta": {"x-helix-vp": VP}}))
    assert excinfo.value.code == "TOOL_NOT_PERMITTED"
