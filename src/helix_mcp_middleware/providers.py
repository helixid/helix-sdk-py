# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Presets for common identity providers, ported from helix-sdk-js's
mcp-middleware/src/providers.ts. Each turns the one or two values an operator
knows (a tenant ID, a domain) into an OAuthIssuerOptions with the provider's
exact issuer string and endpoints. They add no trust of their own: the tenant
named is still the operator's, because a provider-wide default would accept
tokens minted in anyone's tenant.

Any other OpenID Connect / OAuth 2.0 server needs no preset:
OAuthIssuerOptions(issuer=..., audience=...) is enough."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Optional, Sequence, Union
from urllib.parse import quote

from .oauth import OAuthIntrospectionOptions, OAuthIssuerOptions

Audience = Union[str, Sequence[str]]
_GUID = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.IGNORECASE)


def _required(value: Optional[str], what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{what} is required")
    return value.strip()


def _host(value: str) -> str:
    return re.sub(r"^https?://", "", value.strip(), flags=re.IGNORECASE).rstrip("/")


def _with_endpoint(introspection: Optional[OAuthIntrospectionOptions], endpoint: str) -> Optional[OAuthIntrospectionOptions]:
    return replace(introspection, endpoint=endpoint) if introspection is not None else None


def entra(tenant_id: str, audience: Audience) -> OAuthIssuerOptions:
    """Microsoft Entra ID (v2.0 access tokens). `audience` is the API's
    application (client) ID, which is what Entra puts in `aud` for v2.0
    tokens; set `requestedAccessTokenVersion: 2` in the API's app manifest.
    Delegated scopes arrive in `scp`, app permissions in `roles`; both are
    read. Entra issues JWTs only, so there is no introspection."""
    tenant = _required(tenant_id, "entra: tenant_id")
    if not _GUID.match(tenant):
        # "common" / "organizations" would mean every tenant; trust must name one.
        raise ValueError("entra: tenant_id must be the directory (tenant) ID, a GUID")
    base = f"https://login.microsoftonline.com/{tenant.lower()}"
    return OAuthIssuerOptions(
        issuer=f"{base}/v2.0", audience=audience, jwks_uri=f"{base}/discovery/v2.0/keys", scope_claims=("scp", "roles")
    )


def auth0(domain: str, audience: Audience) -> OAuthIssuerOptions:
    """Auth0. `domain` is the tenant domain (or a custom domain). `audience`
    is the API identifier registered in Auth0; clients must request it,
    otherwise Auth0 issues an opaque token meant only for its own /userinfo.
    Auth0 documents no introspection endpoint, so JWTs only."""
    host = _host(_required(domain, "auth0: domain"))
    return OAuthIssuerOptions(
        issuer=f"https://{host}/",  # Auth0 issuers end with a slash
        audience=audience,
        jwks_uri=f"https://{host}/.well-known/jwks.json",
    )


def okta(
    domain: str,
    audience: Audience,
    authorization_server_id: str = "default",
    introspection: Optional[OAuthIntrospectionOptions] = None,
    introspect_jwts: bool = False,
) -> OAuthIssuerOptions:
    """Okta, custom authorization server (`default` unless named). The org
    authorization server is not supported: Okta says its tokens are not meant
    to be validated by your own resource servers."""
    host = _host(_required(domain, "okta: domain"))
    issuer = f"https://{host}/oauth2/{quote((authorization_server_id or 'default').strip() or 'default', safe='')}"
    return OAuthIssuerOptions(
        issuer=issuer,
        audience=audience,
        jwks_uri=f"{issuer}/v1/keys",
        introspection=_with_endpoint(introspection, f"{issuer}/v1/introspect"),
        introspect_jwts=introspect_jwts,
    )


def keycloak(
    base_url: str,
    realm: str,
    audience: Audience,
    introspection: Optional[OAuthIntrospectionOptions] = None,
    introspect_jwts: bool = False,
) -> OAuthIssuerOptions:
    """Keycloak. `base_url` is the server root (plus `/auth` on legacy
    installs). The realm's client needs an audience mapper so access tokens
    name this server in `aud`."""
    base = _required(base_url, "keycloak: base_url").rstrip("/")
    issuer = f"{base}/realms/{quote(_required(realm, 'keycloak: realm'), safe='')}"
    return OAuthIssuerOptions(
        issuer=issuer,
        audience=audience,
        jwks_uri=f"{issuer}/protocol/openid-connect/certs",
        introspection=_with_endpoint(introspection, f"{issuer}/protocol/openid-connect/token/introspect"),
        introspect_jwts=introspect_jwts,
    )
