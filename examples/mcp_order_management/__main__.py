# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Command-line entry point: `python -m mcp_order_management` from examples/.

Configuration (environment), the same as the JS sample:
  PORT, HOST            listen address (default 3700 on 127.0.0.1)
  MCP_RESOURCE          public URL of the MCP endpoint (default http://localhost:$PORT/mcp); the OAuth audience
  HELIX_API_URL         HelixID API the audit sink writes to. Required whenever HELIX_API_KEY
  HELIX_API_KEY         is set: there is deliberately no default URL. Never on the request path.
  SERVICE_DID           this server's DID: the KYA-OS door (story F-2). Every tool call that carries
                        a request proof in _meta["org.kya-os/request-proof"] (and its delegation chain
                        in _meta["org.kya-os/delegation-chain"]) is verified in-process against this
                        DID as audience and resource, from public DID documents, status lists and the
                        agent's Entity Card alone. Optional:
  KYAOS_TRUSTED_ISSUERS   comma-separated attestation issuers, or * (default: allow all)
  KYAOS_TRUSTED_ROOTS     comma-separated DIDs the root hop may be issued by (default: any)
  KYAOS_MAX_CHAIN_LENGTH  longest carried chain read (default 10)
  KYAOS_CARDS_FILE        JSON file mapping agent DIDs to their Entity Cards (local config, read before
                          the card is fetched from the agent's DID document)
  KYAOS_ALLOW_LOOPBACK_HTTP=1  development only: read DID documents, cards and status lists over
                          http on loopback hosts
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
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, NoReturn, Optional

import uvicorn

from helix_mcp_middleware import (
    AuthResult,
    LocalVerifierOptions,
    MCPMiddlewareOptions,
    OAuthIntrospectionOptions,
    OAuthIssuerOptions,
    auth0,
    create_helix_audit_sink,
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


def did_list(env: Dict[str, str], name: str) -> Optional[List[str]]:
    """A comma-separated list of DIDs, or None when the variable is unset or `*`."""
    raw = (env.get(name) or "").strip()
    if not raw or raw == "*":
        return None
    dids = [did.strip() for did in raw.split(",") if did.strip()]
    if any(not did.startswith("did:") for did in dids):
        fail(f"{name} must list DIDs")
    return dids


def verifier_from_env(env: Dict[str, str], service_did: str) -> LocalVerifierOptions:
    """The local verifier's settings (story F-2), the same variables as the JS sample."""
    max_chain_length: Optional[int] = None
    if env.get("KYAOS_MAX_CHAIN_LENGTH"):
        try:
            max_chain_length = int(env["KYAOS_MAX_CHAIN_LENGTH"])
        except ValueError:
            max_chain_length = 0
        if max_chain_length < 1:
            fail("KYAOS_MAX_CHAIN_LENGTH must be a positive integer")
    cards: Optional[Dict[str, Any]] = None
    if env.get("KYAOS_CARDS_FILE"):
        try:
            with open(env["KYAOS_CARDS_FILE"], encoding="utf-8") as handle:
                cards = json.load(handle)
        except (OSError, ValueError) as error:
            fail(f"KYAOS_CARDS_FILE: {error}")
        if not isinstance(cards, dict):
            fail("KYAOS_CARDS_FILE must hold a JSON object of agent DID to card")
    trusted = did_list(env, "KYAOS_TRUSTED_ISSUERS")
    return LocalVerifierOptions(
        service_did=service_did,
        trusted_issuers=trusted if trusted is not None else "*",
        trusted_root_issuers=did_list(env, "KYAOS_TRUSTED_ROOTS"),
        max_chain_length=max_chain_length,
        cards=cards,
        allow_loopback_http=env.get("KYAOS_ALLOW_LOOPBACK_HTTP") == "1",
        catalog=list(dict.fromkeys(scope for scopes in TOOL_SCOPES.values() for scope in scopes)),
        # Story A-1 connects the audit trail here; until then each verification is logged once as unrecorded.
        log=lambda message: print(message, file=sys.stderr),
    )


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
        # An audit sink given only an API key would talk to the hosted production API.
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
    if api_url and api_key:
        # The audit sink is the only thing that talks to the Helix API, and never on the request path.
        auth.audit_sink = create_helix_audit_sink(api_url, api_key, service_did=service_did or None)
    if service_did:
        # The KYA-OS door (story F-2): every request proof is verified here, in-process.
        auth.verifier = verifier_from_env(env, service_did)
    elif any(env.get(name) for name in ("KYAOS_TRUSTED_ISSUERS", "KYAOS_TRUSTED_ROOTS", "KYAOS_MAX_CHAIN_LENGTH", "KYAOS_CARDS_FILE")):
        fail("KYAOS_TRUSTED_ISSUERS / KYAOS_TRUSTED_ROOTS / KYAOS_MAX_CHAIN_LENGTH / KYAOS_CARDS_FILE need SERVICE_DID")
    if demo:
        def demo_token(token: str) -> AuthResult:
            if token not in DEMO_TOKENS:
                raise ValueError("unknown demo token")
            return DEMO_TOKENS[token]

        auth.validate_oauth_token = demo_token
    elif issuers:
        auth.oauth = issuers
    if auth.verifier is None and auth.validate_oauth_token is None and auth.oauth is None:
        fail("no way to authenticate callers: set SERVICE_DID (KYA-OS request proofs), OAUTH_ISSUER / OAUTH_ISSUERS, or DEMO_MODE=1")

    try:
        app = create_order_app(
            resource,
            auth,
            authorization_servers=[i.issuer for i in issuers] or None,
            on_server_error=lambda error: print("server error:", repr(error), file=sys.stderr),
        )
    except ValueError as error:
        fail(str(error))

    print(f"order-management MCP server on {resource}")
    verifier = auth.verifier
    print(
        "  KYA-OS proofs: "
        + (
            f"verified in-process for {service_did}, trusted issuers {env.get('KYAOS_TRUSTED_ISSUERS') or '*'}, "
            f"chain length <= {env.get('KYAOS_MAX_CHAIN_LENGTH') or 10}"
            if verifier is not None
            else "off (set SERVICE_DID)"
        )
    )
    print(f"  OAuth:       {'DEMO tokens demo-reader, demo-admin' if demo else ', '.join(i.issuer for i in issuers) or 'off'}")
    print(f"  Audit:       {api_url + '/v1/audit-log/events' if auth.audit_sink else 'off (set HELIX_API_URL + HELIX_API_KEY)'}")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
