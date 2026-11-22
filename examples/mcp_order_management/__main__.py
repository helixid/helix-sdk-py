# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Command-line entry point: `python -m mcp_order_management` from examples/.

Configuration (environment), the same as the JS sample:
  PORT, HOST            listen address (default 3700 on 127.0.0.1)
  MCP_RESOURCE          public URL of the MCP endpoint (default http://localhost:$PORT/mcp); the OAuth audience
  HELIX_API_URL         HelixID API to verify VPs and write audit events. Required whenever
  HELIX_API_KEY         HELIX_API_KEY is set: there is deliberately no default URL.
  SERVICE_DID           this server's DID: VPs for other services are rejected
  OAUTH_ISSUER          OAuth door, one authorization server. The issuer alone is enough: its keys are
                        read from its metadata (aud must be MCP_RESOURCE). Optional:
  OAUTH_JWKS_URI          its jwks_uri, to skip discovery
  OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET
                          this server's client credentials: tokens are introspected (RFC 7662, opaque tokens)
  OAUTH_INTROSPECTION_URL its introspection endpoint, to skip discovery
  OAUTH_ISSUERS         several authorization servers: a JSON array of provider presets
                        {"provider": "entra", "tenantId", "audience"} | {"provider": "auth0", "domain"}
                        | {"provider": "okta", "domain", "authorizationServerId"?, "introspection"?}
                        | {"provider": "keycloak", "baseUrl", "realm", "introspection"?}
                        or custom {"issuer", "jwksUri"?, "introspection"?: {"clientId", "clientSecret", "endpoint"?}}
  DEMO_MODE=1           local demo only: accept the fixed bearer tokens below instead of an
                        authorization server. Refused unless HOST is loopback.
  PUBLIC_ORIGIN         KYA-OS story C-A: serve this server's did.json and card.json (its did:web is
                        derived from the origin and MCP path). Optional with it:
  SERVICE_NAME            the card's display name (default "Order Management (HelixID sample)")
  SERVICE_PUBLIC_KEY_JWK  the service key's public JWK, {"kty":"OKP","crv":"Ed25519","x":...}
  SERVICE_KID             its verification-method fragment (default key-1)
  SERVICE_RESPONSIBLE_PARTY  the accountable org DID, when there is one
  SERVICE_SIGNING_KEY   KYA-OS (story L2-A): this server's Ed25519 private key (hex), the key
                        SERVICE_DID's document lists as key-1. Turns on the _kyaos_handshake tool,
                        sessions and a server-signed proof on every tool call outcome. Optional:
  KYAOS_PUBLIC_ORIGIN     the origin agents connect to, accepted as handshake audience next to the
                          DID (default: the origin of MCP_RESOURCE)
  KYAOS_CLOCK_SKEW_SECONDS  30 to 600 (default 120)
  KYAOS_SESSIONS=0        no sessions: the handshake is refused, calls are proven without one
  KYAOS_SESSION_TTL_MINUTES idle TTL (default 30; fractions allowed)
  KYAOS_NONCE_STORE       the replay store: memory (default, this instance only), redis or dynamo,
                          read by helix_mcp_middleware itself (nonce_store_from_env); with it:
                          redis: KYAOS_REDIS_URL, KYAOS_NONCE_KEY_PREFIX (pip install 'helixid-sdk-py[redis]')
                          dynamo: KYAOS_DYNAMO_TABLE, KYAOS_DYNAMO_KEY_ATTRIBUTE, KYAOS_DYNAMO_TTL_ATTRIBUTE,
                                  KYAOS_DYNAMO_REGION, KYAOS_DYNAMO_ENDPOINT (pip install 'helixid-sdk-py[dynamo]';
                                  AWS credentials: boto3's chain). JS and Python instances share one store.
                          See .env.example.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, NoReturn, Optional
from urllib.parse import urlsplit

import uvicorn

from helix_sdk import HelixClient
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.errors import HelixError
from helix_mcp_middleware import (
    AuthResult,
    KyaOsOptions,
    KyaOsRuntime,
    KyaOsSessionOptions,
    MCPMiddlewareOptions,
    OAuthIntrospectionOptions,
    ServeIdentityOptions,
    OAuthIssuerOptions,
    auth0,
    create_helix_audit_sink,
    create_kyaos,
    describe_nonce_store,
    read_nonce_store_config,
    entra,
    keycloak,
    okta,
)

from .app import create_order_app
from .orders import TOOL_SCOPES

DEMO_TOKENS = {
    "demo-reader": AuthResult(sub="demo-reader", scopes=["orders:read"]),
    "demo-admin": AuthResult(sub="demo-admin", scopes=["orders:read", "orders:admin"]),
}


def fail(message: str) -> NoReturn:
    print(f"order-management: {message}", file=sys.stderr)
    sys.exit(1)


def _only_keys(raw: Dict[str, Any], allowed: List[str], where: str) -> None:
    unknown = [k for k in raw if k not in allowed]
    if unknown:
        fail(f"{where}: unknown key(s) {', '.join(unknown)}; allowed: {', '.join(allowed)}")


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _introspection(raw: Any, where: str, endpoint_allowed: bool) -> Optional[OAuthIntrospectionOptions]:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        fail(f"{where}.introspection: expected an object")
    _only_keys(raw, ["clientId", "clientSecret", "cacheTtlMs", "allowMissingAudience"] + (["endpoint"] if endpoint_allowed else []), f"{where}.introspection")
    client_id, client_secret = _text(raw.get("clientId")), _text(raw.get("clientSecret"))
    if not client_id or not client_secret:
        fail(f"{where}: introspection needs clientId and clientSecret")
    options = OAuthIntrospectionOptions(client_id, client_secret, endpoint=_text(raw.get("endpoint")))
    if "cacheTtlMs" in raw:  # milliseconds, so one OAUTH_ISSUERS value works for the JS and Python samples
        if isinstance(raw["cacheTtlMs"], bool) or not isinstance(raw["cacheTtlMs"], (int, float)) or raw["cacheTtlMs"] < 0:
            fail(f"{where}: cacheTtlMs must be a non-negative number")
        options.cache_ttl_seconds = raw["cacheTtlMs"] / 1000
    if "allowMissingAudience" in raw:
        if not isinstance(raw["allowMissingAudience"], bool):
            fail(f"{where}: allowMissingAudience must be a boolean")
        options.allow_missing_audience = raw["allowMissingAudience"]
    return options


def issuer_from_entry(entry: Any, where: str, resource: str) -> OAuthIssuerOptions:
    """One OAUTH_ISSUERS entry: a provider preset or a custom issuer."""
    if not isinstance(entry, dict):
        fail(f"{where}: expected an object")

    def need(key: str) -> str:
        return _text(entry.get(key)) or fail(f"{where}: {key} is required")

    def flag(key: str) -> bool:
        if key in entry and not isinstance(entry[key], bool):
            fail(f"{where}: {key} must be a boolean")
        return entry.get(key) is True

    # Tokens must name this server. Entra is the exception: its v2.0 tokens carry the API's client ID in aud.
    audience = _text(entry.get("audience")) or resource
    provider = entry.get("provider")
    try:
        if provider == "entra":
            _only_keys(entry, ["provider", "tenantId", "audience"], where)
            if not _text(entry.get("audience")):
                fail(f"{where}: entra needs audience (the API's application ID; Entra puts that in aud, not the URL)")
            return entra(need("tenantId"), audience)
        if provider == "auth0":
            _only_keys(entry, ["provider", "domain", "audience"], where)
            return auth0(need("domain"), audience)
        if provider == "okta":
            _only_keys(entry, ["provider", "domain", "authorizationServerId", "audience", "introspection", "introspectJwts"], where)
            return okta(
                need("domain"), audience,
                authorization_server_id=_text(entry.get("authorizationServerId")) or "default",
                introspection=_introspection(entry.get("introspection"), where, endpoint_allowed=False),
                introspect_jwts=flag("introspectJwts"),
            )
        if provider == "keycloak":
            _only_keys(entry, ["provider", "baseUrl", "realm", "audience", "introspection", "introspectJwts"], where)
            return keycloak(
                need("baseUrl"), need("realm"), audience,
                introspection=_introspection(entry.get("introspection"), where, endpoint_allowed=False),
                introspect_jwts=flag("introspectJwts"),
            )
        if provider is None:
            _only_keys(entry, ["issuer", "jwksUri", "introspection", "introspectJwts", "requireAccessTokenType", "audience"], where)
            return OAuthIssuerOptions(
                need("issuer"), audience,
                jwks_uri=_text(entry.get("jwksUri")),
                introspection=_introspection(entry.get("introspection"), where, endpoint_allowed=True),
                introspect_jwts=flag("introspectJwts"),
                require_access_token_type=flag("requireAccessTokenType"),
            )
    except ValueError as error:
        fail(f"{where}: {error}")
    fail(f"{where}: unknown provider {provider!r}; use entra, auth0, okta, keycloak, or leave it out and give issuer")


def oauth_issuers_from_env(env: Dict[str, str], resource: str) -> List[OAuthIssuerOptions]:
    issuers: List[OAuthIssuerOptions] = []
    if env.get("OAUTH_ISSUERS"):
        try:
            parsed = json.loads(env["OAUTH_ISSUERS"])
        except ValueError:
            fail("OAUTH_ISSUERS is not valid JSON")
        if not isinstance(parsed, list):
            fail("OAUTH_ISSUERS must be a JSON array")
        issuers += [issuer_from_entry(item, f"OAUTH_ISSUERS[{i}]", resource) for i, item in enumerate(parsed)]

    client_id, client_secret = env.get("OAUTH_CLIENT_ID"), env.get("OAUTH_CLIENT_SECRET")
    jwks_uri, introspection_url = env.get("OAUTH_JWKS_URI"), env.get("OAUTH_INTROSPECTION_URL")
    if env.get("OAUTH_ISSUER"):
        if bool(client_id) != bool(client_secret):
            fail("OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET go together")
        if introspection_url and not client_id:
            fail("OAUTH_INTROSPECTION_URL needs OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET")
        # Only the issuer: its keys come from its metadata. With client credentials:
        # tokens are introspected, at OAUTH_INTROSPECTION_URL or the metadata's endpoint.
        issuers.append(
            OAuthIssuerOptions(
                env["OAUTH_ISSUER"], resource,
                jwks_uri=jwks_uri or None,
                introspection=OAuthIntrospectionOptions(client_id, client_secret, endpoint=introspection_url or None)
                if client_id and client_secret
                else None,
            )
        )
    elif jwks_uri or introspection_url or client_id or client_secret:
        fail("OAUTH_JWKS_URI / OAUTH_INTROSPECTION_URL / OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET need OAUTH_ISSUER")
    return issuers


def identity_from_env(env: Dict[str, str], resource: str, service_did: Optional[str]) -> Optional[ServeIdentityOptions]:
    """PUBLIC_ORIGIN and SERVICE_*: what the JS sample reads for the same card."""
    public_origin = env.get("PUBLIC_ORIGIN")
    if not public_origin:
        return None
    card: Dict[str, Any] = {
        "name": env.get("SERVICE_NAME") or "Order Management (HelixID sample)",
        "capabilities": ["tools/list", "tools/call", *TOOL_SCOPES.keys()],
    }
    if env.get("SERVICE_PUBLIC_KEY_JWK"):
        try:
            card["publicKeyJwk"] = json.loads(env["SERVICE_PUBLIC_KEY_JWK"])
        except ValueError:
            fail("SERVICE_PUBLIC_KEY_JWK is not valid JSON")
        card["kid"] = env.get("SERVICE_KID") or "key-1"
    if env.get("SERVICE_RESPONSIBLE_PARTY"):
        card["responsibleParty"] = env["SERVICE_RESPONSIBLE_PARTY"]
    return ServeIdentityOptions(public_origin=public_origin, path=urlsplit(resource).path, did=service_did or None, card=card)


_KYAOS_SETTINGS = ("KYAOS_NONCE_STORE", "KYAOS_PUBLIC_ORIGIN", "KYAOS_CLOCK_SKEW_SECONDS", "KYAOS_SESSIONS", "KYAOS_SESSION_TTL_MINUTES")


def _positive_number(env: Dict[str, str], name: str, integer: bool) -> Optional[float]:
    """A positive number from an optional variable; `integer` demands a whole one."""
    raw = env.get(name)
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        value = float("nan")
    if not value > 0 or value == float("inf") or (integer and not value.is_integer()):
        fail(f"{name} must be a positive {'integer' if integer else 'number'}")
    return value


def kyaos_from_env(env: Dict[str, str], resource: str, service_did: Optional[str]) -> Optional[KyaOsRuntime]:
    """The KYA-OS layer from SERVICE_SIGNING_KEY and the KYAOS_* variables, or None when it is off."""
    if not env.get("SERVICE_SIGNING_KEY"):
        if any(env.get(name) for name in _KYAOS_SETTINGS):
            fail("KYAOS_* settings need SERVICE_SIGNING_KEY")
        return None
    if not service_did:
        fail("SERVICE_SIGNING_KEY needs SERVICE_DID (the DID whose document lists the key)")
    skew = _positive_number(env, "KYAOS_CLOCK_SKEW_SECONDS", True)
    ttl_minutes = _positive_number(env, "KYAOS_SESSION_TTL_MINUTES", False)
    url = urlsplit(resource)
    try:
        return create_kyaos(
            KyaOsOptions(
                # The key is read from the environment at every signature; the server never holds it.
                signer=EnvSigner(service_did, env_var="SERVICE_SIGNING_KEY"),
                public_origin=env.get("KYAOS_PUBLIC_ORIGIN") or f"{url.scheme}://{url.netloc}",
                clock_skew_seconds=int(skew) if skew is not None else None,
                session=KyaOsSessionOptions(enabled=env.get("KYAOS_SESSIONS") != "0", ttl_minutes=ttl_minutes),
                # The replay store: the one KYAOS_NONCE_STORE names (nonce_store_from_env), read from the same environment.
                env=env,
                tools_endpoint=resource,
            )
        )
    except ValueError as error:
        fail(f"KYA-OS: {error}")


def main() -> None:
    env = dict(os.environ)
    try:
        port = int(env.get("PORT", "3700"))
    except ValueError:
        fail(f"PORT must be a number, got {env.get('PORT')!r}")
    host = env.get("HOST", "127.0.0.1")
    resource = env.get("MCP_RESOURCE") or f"http://localhost:{port}/mcp"
    api_url, api_key, service_did = env.get("HELIX_API_URL"), env.get("HELIX_API_KEY"), env.get("SERVICE_DID")
    demo = env.get("DEMO_MODE") == "1"

    if api_key and not api_url:
        # HelixClient given only an API key talks to the hosted production API.
        fail("HELIX_API_KEY is set but HELIX_API_URL is not; set HELIX_API_URL explicitly (e.g. a local server)")
    if demo and host not in ("127.0.0.1", "localhost", "::1"):
        fail("DEMO_MODE accepts fixed tokens and is only allowed on a loopback HOST")
    issuers = oauth_issuers_from_env(env, resource)
    if demo and issuers:
        fail("use either DEMO_MODE or OAUTH_ISSUER / OAUTH_ISSUERS, not both")

    auth = MCPMiddlewareOptions(
        expected_target_service=service_did or None,
        service_did=service_did or None,
        on_audit_error=lambda error: print("audit write failed:", error, file=sys.stderr),
    )
    if api_url:
        auth.client = HelixClient(api_url, api_key=api_key) if api_key else HelixClient(api_url)
        if api_key:
            auth.audit_sink = create_helix_audit_sink(api_url, api_key, service_did=service_did or None)
    if demo:
        def demo_token(token: str) -> AuthResult:
            if token not in DEMO_TOKENS:
                raise ValueError("unknown demo token")
            return DEMO_TOKENS[token]

        auth.validate_oauth_token = demo_token
    elif issuers:
        auth.oauth = issuers
    if auth.client is None and auth.validate_oauth_token is None and auth.oauth is None:
        fail("no way to authenticate callers: set HELIX_API_URL (HelixID VPs), OAUTH_ISSUER / OAUTH_ISSUERS, or DEMO_MODE=1")

    identity = identity_from_env(env, resource, service_did)
    kyaos = kyaos_from_env(env, resource, service_did)
    try:
        app = create_order_app(
            resource,
            auth,
            authorization_servers=[i.issuer for i in issuers] or None,
            on_server_error=lambda error: print("server error:", repr(error), file=sys.stderr),
            identity=identity,
            kyaos=kyaos,
        )
    except ValueError as error:
        fail(str(error))
    except HelixError as error:  # an invalid card (EntityCardError)
        fail(str(error))

    print(f"order-management MCP server on {resource}")
    print(f"  HelixID VPs: {'verified via ' + api_url if auth.client else 'off (set HELIX_API_URL)'}")
    print(f"  OAuth:       {'DEMO tokens demo-reader, demo-admin' if demo else ', '.join(i.issuer for i in issuers) or 'off'}")
    print(f"  Audit:       {api_url + '/v1/audit-log/events' if auth.audit_sink else 'off (set HELIX_API_URL + HELIX_API_KEY)'}")
    path = urlsplit(resource).path.rstrip("/")
    print(f"  Identity:    {identity.public_origin + path + '/{did,card}.json' if identity else 'off (set PUBLIC_ORIGIN)'}")
    if kyaos is not None:
        print(
            f"  KYA-OS:      proofs by {kyaos.server_did}, sessions {'on' if kyaos.sessions_enabled else 'off'}, "
            f"skew {kyaos.clock_skew_seconds} s, {describe_nonce_store(read_nonce_store_config(env))}"
        )
    else:
        print("  KYA-OS:      off (set SERVICE_SIGNING_KEY)")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
