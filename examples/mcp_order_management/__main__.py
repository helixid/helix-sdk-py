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
  KYAOS_AUTHORIZATION_URL KYA-OS (story L3-E): the consent page a caller without the authority for a
                        tool is sent to. Turns on the signed needs_authorization challenge and the
                        resume flow; the resume-token store follows KYAOS_NONCE_STORE, read by
                        helix_mcp_middleware itself (resume_token_store_from_env): Redis on
                        KYAOS_REDIS_URL, key prefix KYAOS_RESUME_KEY_PREFIX, when the replay store is
                        Redis (records shared with JS instances), memory otherwise. In
                        DEMO_MODE the retry's DelegationCredential is checked structurally only (see
                        demo_authorizer.py); outside it every retry is refused until a verifier
                        (stories F-2, L3-H) is wired in. Optional:
  KYAOS_RESUME_TTL_SECONDS  resume-token lifetime (default 600)
  AUDIT_LOG_FILE        append every audit event as one JSON line to this file, next to (or instead
                        of) the HelixID audit sink; for local runs and the e2e suite
  WELL_KNOWN_MCP        KYA-OS discovery (story L1-D): GET /.well-known/mcp is served whenever SERVICE_DID
                        is a did:web or did:key (the document's serverDid), with endpoints at
                        KYAOS_PUBLIC_ORIGIN (default: the origin of MCP_RESOURCE) and the KYA-OS values
                        above. 0 turns the route off (404); 1 makes a SERVICE_DID the document cannot
                        carry a startup error instead of a notice. Optional:
  STATUS_LIST_CREDENTIAL  URL of this server's status list credential, advertised in the document
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Callable, Dict, List, NoReturn, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import uvicorn

from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.errors import HelixError
from helix_mcp_middleware import (
    AuthResult,
    KyaOsOptions,
    KyaOsRuntime,
    KyaOsSessionOptions,
    LocalVerifierOptions,
    MCPMiddlewareOptions,
    NeedsAuthorization,
    NeedsAuthorizationOptions,
    OAuthIntrospectionOptions,
    ServeIdentityOptions,
    OAuthIssuerOptions,
    WellKnownMcp,
    WellKnownMcpConfig,
    WellKnownMcpError,
    auth0,
    create_helix_audit_sink,
    create_kyaos,
    create_needs_authorization,
    create_well_known_mcp,
    describe_nonce_store,
    read_nonce_store_config,
    entra,
    keycloak,
    okta,
)

from .app import create_order_app
from .demo_authorizer import demo_retry_authorizer
from .orders import TOOL_SCOPES

DEMO_TOKENS = {
    "demo-reader": AuthResult(sub="demo-reader", scopes=["orders:read"]),
    "demo-admin": AuthResult(sub="demo-admin", scopes=["orders:read", "orders:admin"]),
    # Agents with a DID as subject, for the needs_authorization flow (story L3-E): read only until a delegation grants more.
    "demo-agent": AuthResult(sub="did:key:z6MkdemoAgentOrdersRead", scopes=["orders:read"]),
    "demo-agent-2": AuthResult(sub="did:key:z6MkdemoAgentTwoOrdersRead", scopes=["orders:read"]),
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


def did_list(env: Dict[str, str], name: str) -> Optional[List[str]]:
    """A comma-separated list of DIDs, or None when the variable is unset or `*`."""
    raw = (env.get(name) or "").strip()
    if not raw or raw == "*":
        return None
    dids = [did.strip() for did in raw.split(",") if did.strip()]
    if any(not did.startswith("did:") for did in dids):
        fail(f"{name} must list DIDs")
    return dids


def verifier_from_env(env: Dict[str, str], service_did: str, kyaos: Optional[KyaOsRuntime]) -> LocalVerifierOptions:
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
        # One replay store for the handshake, the response proofs and the request proofs.
        nonce_store=kyaos.nonce_store if kyaos is not None else None,
        # Story A-1 connects the audit trail here; until then each verification is logged once as unrecorded.
        log=lambda message: print(message, file=sys.stderr),
    )


def needs_authorization_from_env(
    env: Dict[str, str], service_did: Optional[str], demo: bool, audit_sink: Optional[Callable[[Dict[str, Any]], Any]]
) -> Optional[NeedsAuthorization]:
    """The L3-E layer from KYAOS_AUTHORIZATION_URL and KYAOS_RESUME_TTL_SECONDS, or None when it is off."""
    authorization_url = env.get("KYAOS_AUTHORIZATION_URL")
    if not authorization_url:
        if env.get("KYAOS_RESUME_TTL_SECONDS"):
            fail("KYAOS_RESUME_TTL_SECONDS needs KYAOS_AUTHORIZATION_URL")
        return None
    if not service_did:
        fail("KYAOS_AUTHORIZATION_URL needs SERVICE_DID (the challenge binds the token to this service)")
    ttl_seconds = _positive_number(env, "KYAOS_RESUME_TTL_SECONDS", False)

    def url_for(context: Any) -> str:
        # The consent page, with the binding in its query so the page knows what to show (the token stays out of the URL).
        parts = urlsplit(authorization_url)
        query = urlencode([*parse_qsl(parts.query), ("agent", context.agent_did), ("tool", context.tool), ("scope", " ".join(context.scopes))])
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, parts.fragment))

    base = urlsplit(authorization_url)
    if base.scheme not in ("http", "https") or not base.netloc:
        fail(f"KYAOS_AUTHORIZATION_URL must be an absolute http(s) URL, got {authorization_url!r}")
    try:
        return create_needs_authorization(
            NeedsAuthorizationOptions(
                authorization_url=url_for,
                ttl_seconds=ttl_seconds,
                # The resume-token store follows KYAOS_NONCE_STORE, chosen by helix_mcp_middleware itself from the same environment.
                env=env,
                authorizer=demo_retry_authorizer(service_did) if demo else None,
                audit_sink=audit_sink,
                on_audit_error=lambda error: print("audit write failed:", error, file=sys.stderr),
                service_did=service_did,
            )
        )
    except ValueError as error:
        fail(f"KYA-OS needs_authorization: {error}")


def _file_audit_sink(path: str, then_sink: Optional[Callable[[Dict[str, Any]], Any]]) -> Callable[[Dict[str, Any]], Any]:
    """Appends every event as one JSON line to ``path``, then hands it to ``then_sink`` when there is one."""

    def sink(event: Dict[str, Any]) -> Any:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")
        return then_sink(event) if then_sink is not None else None

    return sink


def well_known_from_env(
    env: Dict[str, str], resource: str, service_did: Optional[str], kyaos: Optional[KyaOsRuntime]
) -> Tuple[Optional[WellKnownMcp], Optional[str]]:
    """The discovery document (story L1-D): built once and validated against the schema, or the reason it is off."""
    setting = env.get("WELL_KNOWN_MCP")
    if setting == "0":
        return create_well_known_mcp(WellKnownMcpConfig(enabled=False)), "off (WELL_KNOWN_MCP=0): 404"
    if not service_did:
        return None, "off (set SERVICE_DID)"
    if not re.match(r"did:(web|key):", service_did) and setting != "1":
        return None, (
            f"off (SERVICE_DID {service_did} is not a did:web or did:key, which the document's serverDid must be; "
            "WELL_KNOWN_MCP=1 makes this an error)"
        )
    url = urlsplit(resource)
    try:
        return create_well_known_mcp(
            WellKnownMcpConfig(
                public_origin=env.get("KYAOS_PUBLIC_ORIGIN") or f"{url.scheme}://{url.netloc}",
                server_did=service_did,
                tools_endpoint=url.path or "/",
                kyaos=kyaos.describe() if kyaos is not None else None,
                status_list_credential=env.get("STATUS_LIST_CREDENTIAL") or None,
            )
        ), None
    except WellKnownMcpError as error:
        fail(f"/.well-known/mcp: {error}")


def describe_well_known(well_known: Optional[WellKnownMcp], off: Optional[str]) -> str:
    """The startup line's text, the same as the JS sample's."""
    document = well_known.document if well_known is not None else None
    if document is None:
        return off or "off"
    tools = urlsplit(document["endpoints"]["tools"])
    return (
        f"{tools.scheme}://{tools.netloc}/.well-known/mcp, serverDid {document['serverDid']}, skew {document['clockSkewSeconds']} s, "
        f"handshake {'advertised' if 'handshake' in document['endpoints'] else 'absent'} "
        "(route the path at that origin to this server: see helix-sdk-js mcp-middleware/docs/well-known.md)"
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
    if env.get("AUDIT_LOG_FILE"):
        auth.audit_sink = _file_audit_sink(env["AUDIT_LOG_FILE"], auth.audit_sink)
    kyaos = kyaos_from_env(env, resource, service_did)
    if service_did:
        # The KYA-OS door (story F-2): every request proof is verified here, in-process.
        auth.verifier = verifier_from_env(env, service_did, kyaos)
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

    identity = identity_from_env(env, resource, service_did)
    auth.needs_authorization = needs_authorization_from_env(env, service_did, demo, auth.audit_sink)
    well_known, well_known_off = well_known_from_env(env, resource, service_did, kyaos)
    try:
        app = create_order_app(
            resource,
            auth,
            authorization_servers=[i.issuer for i in issuers] or None,
            on_server_error=lambda error: print("server error:", repr(error), file=sys.stderr),
            identity=identity,
            kyaos=kyaos,
            well_known=well_known,
        )
    except ValueError as error:
        fail(str(error))
    except HelixError as error:  # an invalid card (EntityCardError)
        fail(str(error))

    print(f"order-management MCP server on {resource}")
    print(
        "  KYA-OS proofs: "
        + (
            f"verified in-process for {service_did}, trusted issuers {env.get('KYAOS_TRUSTED_ISSUERS') or '*'}, "
            f"chain length <= {env.get('KYAOS_MAX_CHAIN_LENGTH') or 10}"
            if auth.verifier is not None
            else "off (set SERVICE_DID)"
        )
    )
    print(f"  OAuth:       {'DEMO tokens demo-reader, demo-admin, demo-agent, demo-agent-2' if demo else ', '.join(i.issuer for i in issuers) or 'off'}")
    audits = [f"{api_url}/v1/audit-log/events" if api_url and api_key else "", f"file {env['AUDIT_LOG_FILE']}" if env.get("AUDIT_LOG_FILE") else ""]
    print(f"  Audit:       {' + '.join(a for a in audits if a) or 'off (set HELIX_API_URL + HELIX_API_KEY, or AUDIT_LOG_FILE)'}")
    path = urlsplit(resource).path.rstrip("/")
    print(f"  Identity:    {identity.public_origin + path + '/{did,card}.json' if identity else 'off (set PUBLIC_ORIGIN)'}")
    if auth.needs_authorization is not None:
        store = "in redis (KYAOS_REDIS_URL)" if read_nonce_store_config(env).kind == "redis" else "in memory"
        retries = "checked structurally (DEMO_MODE, no signature verification)" if demo else "refused until a verifier is wired in"
        print(f"  Consent:     needs_authorization challenges to {env['KYAOS_AUTHORIZATION_URL']}, resume tokens {store}, retries {retries}")
    else:
        print("  Consent:     off (set KYAOS_AUTHORIZATION_URL)")
    if kyaos is not None:
        print(
            f"  KYA-OS:      proofs by {kyaos.server_did}, sessions {'on' if kyaos.sessions_enabled else 'off'}, "
            f"skew {kyaos.clock_skew_seconds} s, {describe_nonce_store(read_nonce_store_config(env))}"
        )
    else:
        print("  KYA-OS:      off (set SERVICE_SIGNING_KEY)")
    print(f"  Discovery:   {describe_well_known(well_known, well_known_off)}")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
