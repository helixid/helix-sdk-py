# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Command-line entry point: `python -m mcp_order_management` from examples/.

Configuration (environment), the same as the JS sample:
  PORT, HOST            listen address (default 3700 on 127.0.0.1)
  MCP_RESOURCE          public URL of the MCP endpoint (default http://localhost:$PORT/mcp); the OAuth audience
  HELIX_API_URL         HelixID API the audit trail writes to. Required whenever HELIX_API_KEY
  HELIX_API_KEY         is set: there is deliberately no default URL. Never on the request path. The
                        key turns on the audit trail (KYA-OS typed events), whose producer is this
                        server, so it also needs SERVICE_DID.
  AUDIT_INCLUDE_TOOL_NAMES=1
                        record tool names (`action.name`) in audit events; off by default, a tool
                        name being a caller-presented reference
  AUDIT_DELIVERY        required (default): each event's recorder receipt before the call goes on;
                        buffered: a durable outbox (AUDIT_OUTBOX_DIR) delivered in the background;
                        best-effort: only with AUDIT_ACCEPT_AAP1=1
  AUDIT_OUTBOX_DIR      buffered delivery's durable outbox directory (AUDIT_OUTBOX=memory asks for the
                        ephemeral one, which buffered delivery refuses at startup)
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
  Revocation (story L3-C): every status list's proof is verified before a bit is read; lists and
  verdicts are cached (in KYAOS_REDIS_URL when set, shared by every instance, JS or Python):
  KYAOS_STATUS_CACHE_TTL      seconds a list or verdict is cached (default 300)
  KYAOS_HIGH_PRIVILEGE_SCOPES comma-separated scopes whose reads are cached at most
  KYAOS_HIGH_PRIVILEGE_TTL      seconds (default 60, at most 60)
  KYAOS_MAX_STALE_SECONDS     seconds a list may be served past its validUntil from the cache (default 60)
  KYAOS_STATUS_LIST_ISSUERS   JSON object: issuer DID -> status-list URLs or https origins it keeps
  KYAOS_SIGNAL_ISSUERS        comma-separated DIDs whose revocation signals (RFC 8417 SETs) are honoured;
                              needed by either of:
  KYAOS_REVOCATION_EVENTS_URL   Helix's SSE endpoint (<api>/v1/events/revocations): one outbound
                                connection, reconnecting on drop
  KYAOS_REVOCATION_WEBHOOK_PATH a path on this server that receives pushed SETs (RFC 8935)
  KYAOS_VERIFICATION_LOG      1: print each verification (level, fresh, reasons) and each revocation signal
                              as one JSON line; a file path: append them there as JSON lines instead
  KYAOS_REDIS_URL             also the status cache's Redis, whatever KYAOS_NONCE_STORE says: lists and
                              verdicts shared by every instance, JS or Python (pip install 'helixid-sdk-py[redis]');
                              without it the cache is in memory and covers this instance only
  KYAOS_MINIMUM_LEVEL     story C-C: the Card level every tool demands, L1, L2 or L3 (default L3)
  KYAOS_TOOL_LEVELS       per-tool minimums, tool=level,... (e.g. lookup_order=L2); the handshake takes L1
  KYAOS_L3_MINUS_SATISFIES_L3=0  refuse L3-minus (a proof with no token cnf to fuse) for L3 tools (default 1)
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
from dataclasses import replace
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
    RedisStatusCacheStore,
    RevocationSignalClient,
    SignalReport,
    WellKnownMcp,
    WellKnownMcpConfig,
    WellKnownMcpError,
    auth0,
    create_helix_audit_delivery,
    create_kyaos,
    create_local_verifier,
    create_mcp_audit_trail,
    create_needs_authorization,
    create_revocation_signal_client,
    create_well_known_mcp,
    describe_nonce_store,
    read_nonce_store_config,
    entra,
    keycloak,
    okta,
)
from helix_sdk.verifier import StatusCache

from .app import create_order_app
from .levels import LEVEL_VARIABLES, describe_level_settings, read_level_settings
from .demo_authorizer import demo_retry_authorizer
from .orders import TOOL_SCOPES

L3C_SETTINGS = (
    "KYAOS_STATUS_CACHE_TTL",
    "KYAOS_HIGH_PRIVILEGE_SCOPES",
    "KYAOS_HIGH_PRIVILEGE_TTL",
    "KYAOS_MAX_STALE_SECONDS",
    "KYAOS_STATUS_LIST_ISSUERS",
    "KYAOS_SIGNAL_ISSUERS",
    "KYAOS_REVOCATION_EVENTS_URL",
    "KYAOS_REVOCATION_WEBHOOK_PATH",
    "KYAOS_VERIFICATION_LOG",
    "KYAOS_REDIS_URL",
)

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


def seconds_from_env(env: Dict[str, str], name: str, positive: bool = False) -> Optional[float]:
    """A number of seconds from an optional variable: non-negative, or positive when ``positive``."""
    raw = env.get(name)
    if raw is None or raw == "":
        return None
    try:
        value = float(raw)
    except ValueError:
        value = -1.0
    if value != value or value in (float("inf"),) or value < 0 or (positive and value == 0):
        fail(f"{name} must be a {'positive' if positive else 'non-negative'} number of seconds")
    return value


def json_object_from_env(env: Dict[str, str], name: str) -> Optional[Dict[str, Any]]:
    raw = env.get(name)
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        fail(f"{name} is not valid JSON")
    if not isinstance(parsed, dict):
        fail(f"{name} must be a JSON object")
    return parsed


def event_logger(env: Dict[str, str]) -> Optional[Callable[[str, Dict[str, Any]], None]]:
    """One JSON line per verification or signal: on stdout (KYAOS_VERIFICATION_LOG=1), or appended to the file it names."""
    target = env.get("KYAOS_VERIFICATION_LOG") or None
    if target is None:
        return None

    def log_event(kind: str, report: Dict[str, Any]) -> None:
        if target == "1":
            print(f"[kya-os] {kind} {json.dumps(report)}", flush=True)
        else:
            with open(target, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({"kind": kind, **report}) + "\n")

    return log_event


def status_cache_redis_from_env(env: Dict[str, str]) -> Any:
    """The status cache's Redis (story L3-C): a redis-py client for KYAOS_REDIS_URL, loaded only when it is set.
    The replay store's comes from nonce_store_from_env (story L2-A), whatever KYAOS_NONCE_STORE says."""
    url = env.get("KYAOS_REDIS_URL") or None
    if url is None:
        return None
    if not url.startswith(("redis://", "rediss://")):
        fail("KYAOS_REDIS_URL must be a redis:// or rediss:// URL")
    try:
        import redis  # noqa: PLC0415 - optional: pip install 'helixid-sdk-py[redis]'
    except ImportError:
        fail("KYAOS_REDIS_URL needs the redis package: pip install 'helixid-sdk-py[redis]'")
    return redis.Redis.from_url(url)


def status_cache_from_env(env: Dict[str, str], redis: Any) -> StatusCache:
    """The status cache (story L3-C point 6), shared through KYAOS_REDIS_URL when set."""
    scopes = [scope.strip() for scope in (env.get("KYAOS_HIGH_PRIVILEGE_SCOPES") or "").split(",") if scope.strip()]
    settings: Dict[str, Any] = {"high_privilege_scopes": scopes}
    for name, key, positive in (
        ("KYAOS_STATUS_CACHE_TTL", "status_cache_ttl", True),
        ("KYAOS_HIGH_PRIVILEGE_TTL", "high_privilege_ttl", True),
        ("KYAOS_MAX_STALE_SECONDS", "max_stale_seconds", False),
    ):
        value = seconds_from_env(env, name, positive)
        if value is not None:
            settings[key] = value
    if redis is not None:
        # Shared by every instance: one signal's delete is seen by all.
        settings["store"] = RedisStatusCacheStore(redis)
    try:
        return StatusCache(**settings)
    except ValueError as error:
        fail(f"status cache: {error}")


def revocation_signals_from_env(
    env: Dict[str, str], verifier: Any, log_event: Optional[Callable[[str, Dict[str, Any]], None]]
) -> Tuple[Optional[RevocationSignalClient], Optional[str]]:
    """The revocation signal client (story L3-C point 7) and the webhook path, from the environment."""
    events_url = env.get("KYAOS_REVOCATION_EVENTS_URL") or None
    webhook_path = env.get("KYAOS_REVOCATION_WEBHOOK_PATH") or None
    signal_issuers = did_list(env, "KYAOS_SIGNAL_ISSUERS")
    if not events_url and not webhook_path:
        if signal_issuers is not None:
            fail("KYAOS_SIGNAL_ISSUERS needs KYAOS_REVOCATION_EVENTS_URL or KYAOS_REVOCATION_WEBHOOK_PATH")
        return None, None
    if signal_issuers is None:
        fail("KYAOS_REVOCATION_EVENTS_URL / KYAOS_REVOCATION_WEBHOOK_PATH need KYAOS_SIGNAL_ISSUERS (the Helix issuer DID)")
    if webhook_path is not None and not webhook_path.startswith("/"):
        fail("KYAOS_REVOCATION_WEBHOOK_PATH must be a path")

    def on_signal(report: SignalReport) -> None:
        # Every signal, honoured or ignored, is one line: the sample's audit of the signal channel.
        print(f"[kya-os] revocation-signal {json.dumps(report.to_dict())}", flush=True)
        if log_event is not None:
            log_event("revocation-signal", report.to_dict())

    def on_connection_change(connected: bool, error: Optional[BaseException]) -> None:
        print(f"[kya-os] revocation-events {'connected' if connected else 'disconnected'}{f': {error}' if error else ''}", flush=True)
        if log_event is not None:
            log_event("revocation-events", {"connected": connected, **({"error": str(error)} if error else {})})

    client = create_revocation_signal_client(verifier, signal_issuers, events_url=events_url, on_signal=on_signal, on_connection_change=on_connection_change)
    return client, webhook_path


def verifier_from_env(env: Dict[str, str], service_did: str, kyaos: Optional[KyaOsRuntime] = None) -> LocalVerifierOptions:
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
    redis = status_cache_redis_from_env(env)
    log_event = event_logger(env)
    return LocalVerifierOptions(
        service_did=service_did,
        trusted_issuers=trusted if trusted is not None else "*",
        trusted_root_issuers=did_list(env, "KYAOS_TRUSTED_ROOTS"),
        max_chain_length=max_chain_length,
        cards=cards,
        allow_loopback_http=env.get("KYAOS_ALLOW_LOOPBACK_HTTP") == "1",
        catalog=list(dict.fromkeys(scope for scopes in TOOL_SCOPES.values() for scope in scopes)),
        status_cache=status_cache_from_env(env, redis),
        status_list_issuers=json_object_from_env(env, "KYAOS_STATUS_LIST_ISSUERS"),
        report_verification=(lambda report: log_event("verification", report)) if log_event is not None else None,
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
    audit = None
    if api_url and api_key:
        # The audit trail is the only thing that talks to the Helix API, and never on the request path.
        if not service_did:
            fail("HELIX_API_KEY writes audit events, whose producer is this server: set SERVICE_DID")
        # A-2: delivery to the HelixID recorder (POST /v1/audit/submissions).
        delivery = env.get("AUDIT_DELIVERY") or "required"
        try:
            reporter = create_helix_audit_delivery(
                api_url,
                api_key,
                delivery=delivery,
                outbox_dir=env.get("AUDIT_OUTBOX_DIR") or None,
                outbox="memory" if env.get("AUDIT_OUTBOX") == "memory" else None,
                accept_aap1=env.get("AUDIT_ACCEPT_AAP1") == "1",
                on_delivery_failure=lambda error, _event: print("audit delivery failed:", error, file=sys.stderr),
            )
        except ValueError as error:
            fail(f"audit delivery refused: {error}")
        audit = create_mcp_audit_trail(
            reporter,
            service_did,
            include_tool_names=env.get("AUDIT_INCLUDE_TOOL_NAMES") == "1",
        )
        # The gate's decisions and the call lifecycle share one trail (one source, one sequence).
        auth.audit_sink = audit.tool_audit_sink()
    if env.get("AUDIT_LOG_FILE"):
        auth.audit_sink = _file_audit_sink(env["AUDIT_LOG_FILE"], auth.audit_sink)
    kyaos = kyaos_from_env(env, resource, service_did)
    signals: Optional[RevocationSignalClient] = None
    webhook_path: Optional[str] = None
    levels: Dict[str, Any] = {}
    if service_did:
        # The KYA-OS door (story F-2): every request proof is verified here, in-process.
        local = create_local_verifier(verifier_from_env(env, service_did, kyaos))
        auth.verifier = local
        signals, webhook_path = revocation_signals_from_env(env, local, event_logger(env))
        # Story C-C: the minimum Card level, per tool.
        try:
            levels = read_level_settings(env, list(TOOL_SCOPES))
        except ValueError as error:
            fail(str(error))
        auth = replace(auth, **levels)
    elif any(env.get(name) for name in ("KYAOS_TRUSTED_ISSUERS", "KYAOS_TRUSTED_ROOTS", "KYAOS_MAX_CHAIN_LENGTH", "KYAOS_CARDS_FILE", *L3C_SETTINGS, *LEVEL_VARIABLES)):
        fail("KYAOS_TRUSTED_ISSUERS / KYAOS_TRUSTED_ROOTS / KYAOS_MAX_CHAIN_LENGTH / KYAOS_CARDS_FILE / KYAOS_*_LEVEL(S) and the revocation settings need SERVICE_DID")
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
            audit=audit,
            identity=identity,
            kyaos=kyaos,
            revocation_webhook=(webhook_path, signals.asgi_webhook()) if signals is not None and webhook_path else None,
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
            f"chain length <= {env.get('KYAOS_MAX_CHAIN_LENGTH') or 10}, {describe_level_settings(levels)}"
            if auth.verifier is not None
            else "off (set SERVICE_DID)"
        )
    )
    if auth.verifier is not None:
        channels = [f"SSE {signals.events_url}" if signals is not None and signals.events_url else "", f"webhook {webhook_path}" if webhook_path else ""]
        cache = f"redis {env['KYAOS_REDIS_URL']}" if env.get("KYAOS_REDIS_URL") else "in memory"
        print(f"  Revocation:  list proofs verified, cache {cache}, signals {' + '.join(c for c in channels if c) or 'off'}")
    print(f"  OAuth:       {'DEMO tokens demo-reader, demo-admin, demo-agent, demo-agent-2' if demo else ', '.join(i.issuer for i in issuers) or 'off'}")
    audits = [
        f"{api_url}/v1/audit-log/events (KYA-OS typed events; tool names {'recorded' if audit.include_tool_names else 'withheld'})" if audit else "",
        f"file {env['AUDIT_LOG_FILE']}" if env.get("AUDIT_LOG_FILE") else "",
    ]
    print(f"  Audit:       {' + '.join(a for a in audits if a) or 'off (set HELIX_API_URL + HELIX_API_KEY + SERVICE_DID, or AUDIT_LOG_FILE)'}")
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
    sys.stdout.flush()
    if signals is not None and signals.events_url:
        signals.start()
    try:
        # uvicorn stops on SIGTERM / SIGINT; the signal stream closes with it.
        uvicorn.run(app, host=host, port=port, log_level="warning")
    finally:
        if signals is not None:
            signals.stop()


if __name__ == "__main__":
    main()
