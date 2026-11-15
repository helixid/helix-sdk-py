# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""OAuth 2.1 access-token validation, ported from helix-sdk-js's
mcp-middleware/src/oauth.ts: JWTs against the issuer's JWKS, opaque tokens
by RFC 7662 introspection, one trusted issuer or several, and endpoints read
from the issuer's metadata when left out. Built on `cryptography` and
`requests`, both already dependencies of helix_sdk."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import quote_plus, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .errors import OAUTH_TOKEN_INVALID, AuthorizationServerUnavailableError, MCPAuthError


@dataclass
class AuthResult:
    """The outcome of validating an OAuth access token."""

    sub: str
    """The token's subject. Logged as the caller identity in audit events."""
    scopes: Sequence[str] = ()
    client_id: Optional[str] = None
    claims: Optional[Dict[str, Any]] = None


@dataclass
class OAuthIntrospectionOptions:
    """RFC 7662 token introspection: how to ask the issuer whether an opaque
    (or JWT) token is active."""

    client_id: str
    """This resource server's client credentials at the authorization server (HTTP Basic)."""
    client_secret: str
    endpoint: Optional[str] = None
    """The `introspection_endpoint`. https only (http allowed for loopback).
    Left out, create_oauth_validator() reads it from the issuer's metadata."""
    cache_ttl_seconds: float = 60.0
    """How long a positive answer is reused. Never past the token's `exp`. 0 disables."""
    allow_missing_audience: bool = False
    """Accept an active token whose answer has no `aud`. Off by default:
    without an audience there is no proof the token was minted for this server."""


@dataclass
class OAuthIssuerOptions:
    """One trusted authorization server. `jwks_uri` (or neither URL) means
    JWTs are verified against its keys; `introspection` means tokens are
    introspected. `{issuer, audience}` alone is enough: the keys URL comes
    from the issuer's metadata."""

    issuer: str
    """Expected `iss`, matched exactly (Auth0 issuers end in `/`, Okta's do not)."""
    audience: Union[str, Sequence[str]]
    """Expected `aud`: this MCP server's resource identifier."""
    jwks_uri: Optional[str] = None
    introspection: Optional[OAuthIntrospectionOptions] = None
    introspect_jwts: bool = False
    """With both `jwks_uri` and `introspection`: also introspect a JWT that
    passed its keys, so one revoked at the issuer is refused before it expires."""
    scope_claims: Optional[Sequence[str]] = None
    """Claims that carry the scopes; all are merged. Default ('scope', 'scp')."""
    algorithms: Optional[Sequence[str]] = None
    """Allowed JWS algorithms. Default RS/PS/ES 256-512 and EdDSA. `none` and HS* are never accepted."""
    clock_tolerance_seconds: float = 30.0
    jwks_cache_ttl_seconds: float = 600.0
    jwks_refetch_cooldown_seconds: float = 30.0
    """Minimum gap between refetches triggered by an unknown `kid`."""
    require_access_token_type: bool = False
    """Require the JWT header `typ` to be `at+jwt` (RFC 9068)."""
    http: Any = None
    """Injectable for tests: an object with requests-style get() and post()."""


OAuthOptions = Union[OAuthIssuerOptions, Sequence[OAuthIssuerOptions]]
Validator = Callable[[str], AuthResult]

_HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
_CURVES = {"P-256": (ec.SECP256R1, 32), "P-384": (ec.SECP384R1, 48), "P-521": (ec.SECP521R1, 66)}
# alg -> (kty, crv)
_ALGS: Dict[str, Tuple[str, Optional[str]]] = {
    "RS256": ("RSA", None), "RS384": ("RSA", None), "RS512": ("RSA", None),
    "PS256": ("RSA", None), "PS384": ("RSA", None), "PS512": ("RSA", None),
    "ES256": ("EC", "P-256"), "ES384": ("EC", "P-384"), "ES512": ("EC", "P-521"),
    "EdDSA": ("OKP", "Ed25519"),
}
_DEFAULT_SCOPE_CLAIMS = ("scope", "scp")
_CACHE_SWEEP_AT = 1000
# (connect, read) seconds for every call to an authorization server.
_TIMEOUT = (3.05, 5)
# After a failed JWKS or metadata fetch, callers within this window get the same
# failure without another request.
_FAILURE_BACKOFF = 2.0


def _now() -> float:
    return time.time()


def _invalid(reason: str) -> MCPAuthError:
    return MCPAuthError(OAUTH_TOKEN_INVALID, reason)


class _ActiveTokenRejectedError(MCPAuthError):
    """The issuer confirmed the token is genuine and active, but its claims do
    not fit this server."""


_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


def _b64url(segment: str) -> bytes:
    """A JWS segment: unpadded, canonical base64url and nothing else.
    base64.urlsafe_b64decode silently drops characters outside the alphabet,
    tolerates padding and ignores unused trailing bits, so many strings would
    decode to the same bytes; here exactly one does."""
    if not isinstance(segment, str) or not _B64URL.fullmatch(segment) or len(segment) % 4 == 1:
        raise ValueError("not base64url")
    decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        raise ValueError("not canonical base64url")
    return decoded


def _b64url_jwk(member: Any) -> bytes:
    """A JWK member. Published key sets are not always canonical (some pad), and
    nothing here is attacker-chosen per request, so padding is tolerated."""
    if not isinstance(member, str) or not _B64URL.fullmatch(member.rstrip("=")):
        raise ValueError("not base64url")
    stripped = member.rstrip("=")
    return base64.urlsafe_b64decode(stripped + "=" * (-len(stripped) % 4))


def _decode_segment(segment: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(_b64url(segment).decode("utf-8"))
    except (ValueError, TypeError, RecursionError):  # RecursionError: absurdly nested JSON
        parsed = None
    if not isinstance(parsed, dict):
        raise _invalid("Malformed token")
    return parsed


def _assert_https_or_loopback(uri: str, what: str) -> None:
    url = urlsplit(uri)
    loopback = url.hostname in ("localhost", "127.0.0.1", "::1")
    if url.scheme != "https" and not (url.scheme == "http" and loopback):
        raise ValueError(f"{what} must use https (http is allowed only for localhost)")


def _http(options: OAuthIssuerOptions) -> Any:
    if options.http is not None:
        return options.http
    import requests  # a helix_sdk dependency; imported late so tests can run without sockets

    return requests


def _audiences(options: OAuthIssuerOptions) -> List[str]:
    return [options.audience] if isinstance(options.audience, str) else list(options.audience)


def _check_list_options(options: "OAuthIssuerOptions") -> None:
    # A bare string would be iterated character by character and silently match nothing.
    for name in ("scope_claims", "algorithms"):
        if isinstance(getattr(options, name), str):
            raise ValueError(f"{name} must be a list of strings, not a string")


def _parse_scopes(claims: Dict[str, Any], scope_claims: Optional[Sequence[str]]) -> List[str]:
    scopes: List[str] = []
    for name in _DEFAULT_SCOPE_CLAIMS if scope_claims is None else scope_claims:
        value = claims.get(name)
        items = value.split(" ") if isinstance(value, str) else value if isinstance(value, list) else []
        for item in items:
            if isinstance(item, str) and item and item not in scopes:
                scopes.append(item)
    return scopes


def _is_number(value: Any) -> bool:
    """A usable timestamp: a real, finite number. Python's json accepts NaN and
    Infinity (which would never expire) and arbitrarily large ints (which
    overflow in arithmetic); none of those is a time."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not math.isfinite(value):
        return False
    return abs(value) < 1e13


def _check_standard_claims(
    claims: Dict[str, Any],
    options: OAuthIssuerOptions,
    require_exp: bool,
    require_aud: bool,
    sub_from_client_id: bool = False,
) -> AuthResult:
    """The common claim checks, once the token is known to be genuine
    (signature verified, or introspected as active)."""
    now = _now()
    tolerance = options.clock_tolerance_seconds
    # Presence, not truthiness: a claim that is present but null is malformed, not absent.
    exp = claims.get("exp")
    if "exp" in claims or require_exp:
        if not _is_number(exp) or exp + tolerance < now:
            raise _invalid("Token expired")
    nbf = claims.get("nbf")
    if "nbf" in claims and (not _is_number(nbf) or nbf - tolerance > now):
        raise _invalid("Token not yet valid")
    if "iss" in claims and claims["iss"] != options.issuer:
        raise _invalid("Unexpected token issuer")
    aud = claims.get("aud")
    if "aud" not in claims:
        if require_aud:
            raise _invalid("Token has no audience")
    else:
        token_aud = aud if isinstance(aud, list) else [aud]
        allowed = _audiences(options)
        if not any(isinstance(a, str) and a in allowed for a in token_aud):
            raise _invalid("Token audience does not match this server")
    client_id = claims["client_id"] if claims.get("client_id") is not None else claims.get("azp")
    client_id = client_id if isinstance(client_id, str) and client_id else None
    sub = claims.get("sub")
    if not (isinstance(sub, str) and sub):
        # RFC 7662 makes `sub` optional: a client-credentials token may carry only client_id.
        sub = client_id if sub_from_client_id else None
    if not sub:
        raise _invalid("Token has no subject")
    return AuthResult(sub=sub, scopes=_parse_scopes(claims, options.scope_claims), client_id=client_id, claims=claims)


def _public_key(jwk: Dict[str, Any]) -> Any:
    kty = jwk.get("kty")
    as_int = lambda name: int.from_bytes(_b64url_jwk(jwk[name]), "big")  # noqa: E731
    if kty == "RSA":
        return rsa.RSAPublicNumbers(e=as_int("e"), n=as_int("n")).public_key()
    if kty == "EC":
        curve = _CURVES[jwk["crv"]][0]()
        return ec.EllipticCurvePublicNumbers(as_int("x"), as_int("y"), curve).public_key()
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(_b64url_jwk(jwk["x"]))
    raise ValueError("unsupported key")


def _verify(alg: str, jwk: Dict[str, Any], data: bytes, signature: bytes) -> None:
    """Raises InvalidSignature when the signature does not match; anything else is a malformed key or signature."""
    key = _public_key(jwk)
    if alg == "EdDSA":
        key.verify(signature, data)
        return
    digest = _HASHES[alg[2:]]()
    if alg.startswith("RS"):
        key.verify(signature, data, padding.PKCS1v15(), digest)
    elif alg.startswith("PS"):
        key.verify(signature, data, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest)
    else:  # ES*: JWS carries r || s; cryptography wants DER
        size = _CURVES[_ALGS[alg][1]][1]  # type: ignore[index]
        if len(signature) != 2 * size:
            raise InvalidSignature()
        r, s = int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
        key.verify(encode_dss_signature(r, s), data, ec.ECDSA(digest))


def create_jwt_validator(options: OAuthIssuerOptions) -> Validator:
    """Validates JWT access tokens: signature against the authorization
    server's JWKS (cached, refetched on key rotation), then issuer, audience,
    expiry and not-before."""
    jwks_uri = options.jwks_uri
    if not jwks_uri:
        raise ValueError("jwks_uri is required here; create_oauth_validator can discover it from the issuer")
    _assert_https_or_loopback(jwks_uri, "jwks_uri")
    _check_list_options(options)
    allowed = set(_ALGS if options.algorithms is None else options.algorithms)
    for alg in allowed:
        if alg not in _ALGS:
            raise ValueError(f"Unsupported algorithm: {alg}")

    state: Dict[str, Any] = {"keys": [], "fetched_at": 0.0, "failed_at": None, "failure": None}
    lock = threading.Lock()

    def refresh() -> None:
        res = _http(options).get(jwks_uri, headers={"accept": "application/json"}, timeout=_TIMEOUT)
        if not 200 <= res.status_code < 300:
            raise RuntimeError(f"JWKS fetch failed: {res.status_code}")
        body = res.json()
        if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
            raise RuntimeError("JWKS response has no keys array")
        state["keys"] = [k for k in body["keys"] if isinstance(k, dict)]
        state["fetched_at"] = _now()

    def select(kid: Optional[str], alg: str) -> List[Dict[str, Any]]:
        kty, crv = _ALGS[alg]
        return [
            k
            for k in state["keys"]
            if k.get("kty") == kty
            and (crv is None or k.get("crv") == crv)
            and k.get("use") in (None, "sig")
            and k.get("alg") in (None, alg)
            and (kid is None or k.get("kid") == kid)
        ]

    def find_key(kid: Optional[str], alg: str) -> Dict[str, Any]:
        with lock:
            # Callers queue on this lock while one of them fetches. If that fetch
            # just failed, the ones behind it share the failure instead of each
            # repeating a slow, doomed request while still holding the lock.
            if state["failed_at"] is not None and _now() - state["failed_at"] < _FAILURE_BACKOFF:
                raise state["failure"]
            try:
                if _now() - state["fetched_at"] > options.jwks_cache_ttl_seconds:
                    refresh()
                candidates = select(kid, alg)
                if not candidates and _now() - state["fetched_at"] >= options.jwks_refetch_cooldown_seconds:
                    refresh()  # unknown kid: the issuer may have rotated keys
                    candidates = select(kid, alg)
                state["failed_at"] = None
            except Exception as exc:  # noqa: BLE001 - the authorization server, not the caller, is the problem
                failure = AuthorizationServerUnavailableError(f"Signing keys could not be retrieved from {jwks_uri}: {exc}")
                failure.__cause__ = exc
                state["failed_at"], state["failure"] = _now(), failure
                raise failure from exc
        # Without a kid, only accept an unambiguous key.
        if len(candidates) != 1:
            raise _invalid("No matching signing key")
        return candidates[0]

    def validate(token: str) -> AuthResult:
        parts = token.split(".")
        if len(parts) != 3:
            raise _invalid("Not a JWT")
        h, p, s = parts
        header = _decode_segment(h)
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in allowed:
            raise _invalid("Unsupported token algorithm")
        if "crit" in header:
            raise _invalid("Unsupported critical header")
        if options.require_access_token_type:
            typ = header.get("typ")
            if not isinstance(typ, str) or typ.lower() not in ("at+jwt", "application/at+jwt"):
                raise _invalid("Not an access token (typ)")
        kid = header.get("kid") if isinstance(header.get("kid"), str) else None

        jwk = find_key(kid, alg)
        try:
            _verify(alg, jwk, f"{h}.{p}".encode("ascii"), _b64url(s))
        except InvalidSignature:
            raise _invalid("Invalid token signature") from None
        except Exception:  # noqa: BLE001 - malformed key or signature encoding
            raise _invalid("Token signature could not be verified") from None

        claims = _decode_segment(p)
        if claims.get("iss") is None:
            raise _invalid("Unexpected token issuer")
        return _check_standard_claims(claims, options, require_exp=True, require_aud=True)

    return validate


def create_introspection_validator(options: OAuthIssuerOptions) -> Validator:
    """RFC 7662 token introspection: asks the authorization server whether the
    token is active and reads subject, scopes, audience and expiry from its
    answer. Positive answers are cached briefly; "not active" and failures
    are not. An unreachable or misbehaving authorization server raises
    AuthorizationServerUnavailableError: the caller's token was not shown to
    be bad."""
    introspection = options.introspection
    if introspection is None or not introspection.endpoint:
        raise ValueError("introspection.endpoint is required here; create_oauth_validator can discover it from the issuer")
    endpoint = introspection.endpoint
    _assert_https_or_loopback(endpoint, "introspection endpoint")
    _check_list_options(options)
    # RFC 6749 section 2.3.1: form-encode the id and secret before Basic-encoding them.
    pair = f"{quote_plus(introspection.client_id, safe='')}:{quote_plus(introspection.client_secret, safe='')}"
    basic = base64.b64encode(pair.encode("utf-8")).decode("ascii")
    ttl = introspection.cache_ttl_seconds
    cache: Dict[str, Tuple[AuthResult, float]] = {}
    lock = threading.Lock()

    def unavailable(detail: str) -> AuthorizationServerUnavailableError:
        return AuthorizationServerUnavailableError(f"Token introspection at {endpoint} failed: {detail}")

    def validate(token: str) -> AuthResult:
        key = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with lock:
            hit = cache.get(key)
            if hit is not None:
                if hit[1] > _now():
                    return hit[0]
                del cache[key]

        try:
            res = _http(options).post(
                endpoint,
                data={"token": token, "token_type_hint": "access_token"},
                headers={"accept": "application/json", "authorization": f"Basic {basic}"},
                timeout=_TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001
            raise unavailable(str(exc)) from exc
        if not 200 <= res.status_code < 300:
            raise unavailable(f"HTTP {res.status_code}")
        try:
            claims = res.json()
        except (ValueError, RecursionError):
            raise unavailable("response is not JSON") from None
        if not isinstance(claims, dict) or not isinstance(claims.get("active"), bool):
            raise unavailable('response has no boolean "active"')
        if claims["active"] is not True:
            raise _invalid("Token is not active")

        # From here on the issuer has vouched for the token: a failure means it
        # is a real token that does not fit this server, never "unknown token".
        try:
            token_type = claims.get("token_type")
            if isinstance(token_type, str) and token_type.lower() not in ("bearer", "access_token"):
                raise _invalid("Not an access token (token_type)")
            result = _check_standard_claims(
                claims,
                options,
                require_exp=False,
                require_aud=not introspection.allow_missing_audience,
                sub_from_client_id=True,
            )
        except MCPAuthError as exc:
            raise _ActiveTokenRejectedError(exc.code, exc.message) from None
        if ttl > 0:
            exp = claims.get("exp")
            expires_at = min(_now() + ttl, exp) if _is_number(exp) else _now() + ttl
            with lock:
                if len(cache) >= _CACHE_SWEEP_AT:
                    now = _now()
                    for stale in [k for k, v in cache.items() if v[1] <= now]:
                        del cache[stale]
                cache[key] = (result, expires_at)
        return result

    return validate


def _discover_metadata(options: OAuthIssuerOptions) -> Dict[str, Any]:
    """OpenID Connect discovery first (what Auth0, Okta, Entra and Keycloak
    serve), then the two RFC 8414 forms. The document must name the same
    issuer, or a server could answer for an issuer it is not."""
    issuer = options.issuer
    url = urlsplit(issuer)
    origin = f"{url.scheme}://{url.netloc}"
    path = url.path.rstrip("/")
    candidates = [f"{origin}{path}/.well-known/openid-configuration", f"{origin}/.well-known/oauth-authorization-server{path}"]
    if path:
        candidates.append(f"{origin}{path}/.well-known/oauth-authorization-server")
    last = "no metadata document found"
    for candidate in candidates:
        try:
            res = _http(options).get(candidate, headers={"accept": "application/json"}, timeout=_TIMEOUT)
            if not 200 <= res.status_code < 300:
                last = f"{candidate}: HTTP {res.status_code}"
                continue
            metadata = res.json()
        except Exception as exc:  # noqa: BLE001
            last = f"{candidate}: {exc}"
            continue
        if not isinstance(metadata, dict):
            last = f"{candidate}: not a JSON object"
            continue
        if metadata.get("issuer") != issuer:
            raise AuthorizationServerUnavailableError(
                f"Metadata at {candidate} is for issuer {metadata.get('issuer')}, not {issuer}"
            )
        return metadata
    raise AuthorizationServerUnavailableError(f"Authorization server metadata for {issuer} could not be retrieved ({last})")


def _issuer_validators(entry: OAuthIssuerOptions) -> Tuple[Optional[Validator], Optional[Validator]]:
    """(jwt, introspect) for one issuer. A URL the entry leaves out is read
    from the issuer's metadata on first use and kept; a failed lookup is
    retried on the next token."""
    introspection = entry.introspection
    wants_jwt = entry.jwks_uri is not None or introspection is None
    if entry.introspect_jwts and not (entry.jwks_uri and introspection):
        raise ValueError(f"oauth: issuer {entry.issuer} sets introspect_jwts, which needs both jwks_uri and introspection")
    needs_discovery = (wants_jwt and not entry.jwks_uri) or (introspection is not None and not introspection.endpoint)
    if needs_discovery:
        _assert_https_or_loopback(entry.issuer, "issuer (for metadata discovery)")

    def build(metadata: Dict[str, Any]) -> Tuple[Optional[Validator], Optional[Validator]]:
        def from_metadata(name: str) -> str:
            value = metadata.get(name)
            if not isinstance(value, str) or not value:
                raise AuthorizationServerUnavailableError(f"Metadata for {entry.issuer} has no {name}")
            return value

        try:
            by_keys = (
                create_jwt_validator(replace(entry, jwks_uri=entry.jwks_uri or from_metadata("jwks_uri"))) if wants_jwt else None
            )
            introspect = (
                create_introspection_validator(
                    replace(
                        entry,
                        introspection=replace(
                            introspection, endpoint=introspection.endpoint or from_metadata("introspection_endpoint")
                        ),
                    )
                )
                if introspection is not None
                else None
            )
        except AuthorizationServerUnavailableError:
            raise
        except ValueError as exc:
            # Without discovery a bad URL is the operator's typo: fail at construction.
            if not needs_discovery:
                raise
            raise AuthorizationServerUnavailableError(f"Metadata for {entry.issuer} is unusable: {exc}") from exc

        jwt = by_keys
        if by_keys is not None and introspect is not None and entry.introspect_jwts:

            def jwt(token: str, _by_keys: Validator = by_keys, _introspect: Validator = introspect) -> AuthResult:
                result = _by_keys(token)  # cheap and offline first
                _introspect(token)  # then: is it still active at the issuer?
                return result

        return jwt, introspect

    built: List[Tuple[Optional[Validator], Optional[Validator]]] = [] if needs_discovery else [build({})]
    lock = threading.Lock()
    failed: Dict[str, Any] = {"at": None, "error": None}

    def ready() -> Tuple[Optional[Validator], Optional[Validator]]:
        with lock:
            if not built:
                # As in find_key: callers queued behind a failed lookup share its failure.
                if failed["at"] is not None and _now() - failed["at"] < _FAILURE_BACKOFF:
                    raise failed["error"]
                try:
                    built.append(build(_discover_metadata(entry)))
                except AuthorizationServerUnavailableError as exc:
                    failed["at"], failed["error"] = _now(), exc
                    raise
            return built[0]

    jwt_validator: Optional[Validator] = (lambda token: ready()[0](token)) if wants_jwt else None  # type: ignore[misc]
    introspect_validator: Optional[Validator] = (lambda token: ready()[1](token)) if introspection is not None else None  # type: ignore[misc]
    return jwt_validator, introspect_validator


def _peek_jwt(token: str) -> Optional[Dict[str, Any]]:
    """The payload of something shaped enough like a JWT to route it."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = _decode_segment(parts[0])
        if not isinstance(header.get("alg"), str):
            return None
        return _decode_segment(parts[1])
    except MCPAuthError:
        return None


def create_oauth_validator(options: OAuthOptions) -> Validator:
    """Validates bearer tokens from one or more trusted authorization servers.
    A JWT is routed by its (as yet unverified) `iss` claim to that issuer's
    validator, which re-checks `iss` on the verified claims; an issuer not in
    the list is refused without any network call. A token that is not a JWT
    is opaque and names no issuer, so it goes to the one issuer configured
    for introspection. Only one issuer may be: introspection needs this
    server's own client credentials, which fits the authorization server the
    operator runs, and with two a token would have to be shown to both."""
    issuers = [options] if isinstance(options, OAuthIssuerOptions) else list(options)
    if not issuers:
        raise ValueError("oauth: at least one issuer is required")

    by_issuer: Dict[str, Tuple[Optional[Validator], Optional[Validator]]] = {}
    for entry in issuers:
        if entry.issuer in by_issuer:
            raise ValueError(f"oauth: issuer {entry.issuer} is listed twice")
        by_issuer[entry.issuer] = _issuer_validators(entry)
    introspecting = [entry.issuer for entry in issuers if entry.introspection is not None]
    if len(introspecting) > 1:
        raise ValueError(
            f"oauth: only one issuer may use introspection (found {', '.join(introspecting)}); "
            "an opaque token names no issuer, so it would have to be sent to each of them"
        )
    introspect_opaque = by_issuer[introspecting[0]][1] if introspecting else None

    def validate(token: str) -> AuthResult:
        payload = _peek_jwt(token)
        if payload is not None:
            iss = payload.get("iss")
            if not isinstance(iss, str):
                raise _invalid("Token has no issuer")
            validators = by_issuer.get(iss)
            if validators is None:
                raise _invalid("Unknown token issuer")
            jwt, introspect = validators
            return jwt(token) if jwt is not None else introspect(token)  # type: ignore[misc]
        if introspect_opaque is None:
            raise _invalid("Not a JWT")
        return introspect_opaque(token)

    return validate
