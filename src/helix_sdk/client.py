# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
HelixClient, ported from helix-sdk-js's src/client/HelixClient.ts.

Per the SDK-API-only design, every operation here is a plain HTTP
call to helix-api -- verification, delegation/grant/renewal payload
construction, DID resolution, and status checks all live server-side.
The only local computation this client does is generating the local
keypair for onboarding/enrollment (the private key is never sent to the
server) and signing the small challenge/hash payloads the prepare/finalize
and onboarding endpoints hand back.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote, urlencode

from . import jwt as helix_jwt
from . import keys
from .errors import SDKOnlyModeNoAPIError
from .http_adapter import HttpAdapter

# Used only when api_key is given with no explicit base_url -- see
# HelixClient.__init__. The hosted HelixID enterprise API.
_DEFAULT_ENTERPRISE_URL = "https://api.helixid.dev"


def _query_string(params: Dict[str, Any]) -> str:
    filtered = {k: v for k, v in params.items() if v is not None}
    if not filtered:
        return ""
    return "?" + urlencode(filtered)


class HelixClient:
    """
    Usage:
        HelixClient()                         # SDK-only mode: local signing
                                               # helpers work, API calls raise
                                               # SDKOnlyModeNoAPIError.
        HelixClient(base_url)                 # OSS/core mode.
        HelixClient(base_url, admin_api_key=...)   # OSS/core, admin-gated calls.
        HelixClient(api_key=...)              # Enterprise mode -- account-scoped
                                               # API key (see
                                               # helix-server-enterprise's
                                               # POST /v1/account/api-keys), sent
                                               # as the bearer token directly, no
                                               # login call. base_url defaults to
                                               # the hosted enterprise API when
                                               # omitted here.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        admin_api_key: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> None:
        resolved_base_url = base_url
        if resolved_base_url is None and api_key:
            resolved_base_url = _DEFAULT_ENTERPRISE_URL

        self._sdk_only_mode = resolved_base_url is None
        self._api_audit_enabled = resolved_base_url is not None and bool(admin_api_key or api_key)
        self._base_url = (
            resolved_base_url[:-1] if resolved_base_url and resolved_base_url.endswith("/") else resolved_base_url
        )
        self._api_key = api_key
        # The adapter sends whichever credential was given on every call, so
        # enterprise (api_key) and core (admin_api_key) differ only in which
        # routes a method targets, never in how it authenticates.
        self._http: Optional[HttpAdapter] = (
            None if self._sdk_only_mode else HttpAdapter(resolved_base_url, admin_api_key, api_key=api_key)
        )

    # -- DID lifecycle ------------------------------------------------------

    def create_did(self, subject_type: str, domains: Optional[List[str]] = None) -> Dict[str, Any]:
        key_pair = keys.generate_key_pair()
        response = self._http_required().post(
            "/v1/dids",
            {
                "publicKeyHex": key_pair.public_key,
                "subjectType": subject_type,
                "domains": domains or [],
            },
        )
        did = response.get("did") or response.get("id") or response["didDocument"]["id"]
        return {
            "did": did,
            "didDocument": response["didDocument"],
            "hederaTransactionId": response.get("hederaTransactionId"),
            "keyPair": key_pair,
        }

    def resolve_did(self, did: str, live: bool = False) -> Dict[str, Any]:
        query = "?live=true" if live else ""
        response = self._http_required().get(f"/v1/dids/{quote(did, safe='')}{query}")
        did_document = response.get("didDocument") or response.get("document") or response
        return {"did": did, "didDocument": did_document, "source": "hedera" if live else "cache"}

    def add_service_endpoint(self, did: str, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        did_document = self._http_required().post(f"/v1/dids/{quote(did, safe='')}/services", endpoint)
        return {"did": did, "didDocument": did_document}

    def remove_service_endpoint(self, did: str, endpoint_id: str) -> Dict[str, Any]:
        did_document = self._http_required().delete(
            f"/v1/dids/{quote(did, safe='')}/services/{quote(endpoint_id, safe='')}"
        )
        return {"did": did, "didDocument": did_document}

    def deactivate_did(self, did: str, reason: str) -> Dict[str, Any]:
        self._http_required().post(f"/v1/dids/{quote(did, safe='')}/deactivate", {"reason": reason})
        return {"did": did, "deactivated": True}

    # -- VC lifecycle (issuer/admin) -----------------------------------------

    def issue_vc(self, **options: Any) -> Dict[str, Any]:
        body = {"expiresInSeconds": 7_776_000, **options}
        return self._http_required().post("/v1/vcs", body)

    def get_vc(self, vc_id: str) -> Dict[str, Any]:
        return self._http_required().get(f"/v1/vcs/{quote(vc_id, safe='')}")

    def list_vcs(
        self,
        subject_did: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        qs = _query_string({"subjectDid": subject_did, "status": status, "limit": limit})
        return self._http_required().get(f"/v1/vcs{qs}")

    def revoke_vc(self, vc_id: str) -> Dict[str, Any]:
        return self._http_required().post(f"/v1/vcs/{quote(vc_id, safe='')}/revoke")

    def renew_vc(
        self,
        vc_id: str,
        privilege_scopes: Optional[List[str]] = None,
        expires_in_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        overrides: Dict[str, Any] = {}
        if privilege_scopes is not None:
            overrides["privilegeScopes"] = privilege_scopes
        if expires_in_seconds is not None:
            overrides["expiresInSeconds"] = expires_in_seconds
        return self._http_required().post(f"/v1/vcs/{quote(vc_id, safe='')}/renew", overrides)

    def register_vc(self, vc: Dict[str, Any]) -> Dict[str, Any]:
        """Registers a VC that was signed outside the platform (an SP-signed
        DelegationGrantCredential, typically) so the server holds it and
        can list/revoke/renew it. The server verifies the proof. Distinct
        from issue_vc(), which has the platform sign a new VC. Returns
        {vcId, alreadyRegistered}; idempotent by vc id."""
        return self._http_required().post("/v1/vcs/register", {"vc": vc})

    def check_vc_status(self, vc: Dict[str, Any]) -> str:
        response = self._http_required().get(f"/v1/vcs/{quote(vc['id'], safe='')}/status")
        return response["status"]

    # -- Service Providers ---------------------------------------------------
    # Services hold no keys: the server mints the service DID, keeps its key,
    # and signs consent grants on the service's behalf -- the same custody
    # model as agents (onboard_agent).

    def create_service(
        self,
        service_name: str,
        display_name: str,
        verified_domain: str,
        api_endpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Enrolls a service on a self-hosted server (admin key). Hosted
        accounts enroll through the console / account API instead.
        Returns {serviceDid, serviceName}."""
        body: Dict[str, Any] = {
            "serviceName": service_name,
            "displayName": display_name,
            "verifiedDomain": verified_domain,
        }
        if api_endpoint is not None:
            body["apiEndpoint"] = api_endpoint
        return self._http_required().post("/v1/services", body)

    # Consent is not a grant a service signs for its user any more: since KYA-OS
    # story L3-H the user's own did:key signs the root hop on Helix's consent
    # page (helix_sdk.consent).

    # -- Status lists ---------------------------------------------------------

    def get_status_list(self, list_id: str) -> Dict[str, Any]:
        return self._http_required().get(f"/v1/status-list/{quote(list_id, safe='')}")

    def create_status_list(self, **options: Any) -> Dict[str, Any]:
        self._assert_api_configured()
        return self._http_required().post("/v1/status-list", options)

    # -- Audit ------------------------------------------------------------------

    def get_audit_log(
        self,
        event_type: Optional[str] = None,
        since: Optional[str] = None,
        limit: Optional[int] = None,
        family: Optional[str] = None,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """``GET /v1/audit-log``: one page, ``{"items": [...], "nextCursor": str | None}``,
        newest first. Pass ``nextCursor`` back as ``cursor`` for the next page
        (``None`` on the last). On helix-core each item is a row ``{id,
        recordedAt, eventDigest, event, ledgerId, ledgerEpochId, sequence,
        entryDigest, receipt}``, ``event`` the typed KYA-OS producer event
        (helix_sdk.audit); a hosted deployment's account view answers the same
        page shape with the event at the account's tier."""
        qs = _query_string({"eventType": event_type, "family": family, "since": since, "cursor": cursor, "limit": limit})
        return self._http_required().get(f"/v1/audit-log{qs}")

    def record_audit_event(self, event: Dict[str, Any]) -> None:
        """Records one typed producer event (``POST /v1/audit-log/events``):
        the body is the event exactly as an ``AuditTrail`` built it, validated
        strictly by the API. A no-op without an API key (audit writes need
        one). Errors propagate: a producer that must not fail on an audit
        write (the wallet) catches them."""
        if not self._api_audit_enabled:
            return
        self._http_required().post("/v1/audit-log/events", event)

    def audit_sink(self) -> Any:
        """An ``AuditSink`` (helix_sdk.audit) for an ``AuditTrail`` whose
        events this client should report to the API."""
        from .audit import CallbackAuditSink

        return CallbackAuditSink(lambda entry: self.record_audit_event(entry.event))

    # -- Sessions ------------------------------------------------------------

    def fetch_session_public_key(self) -> str:
        response = self._http_required().get("/v1/sessions/public-key")
        return response["publicKeyHex"]

    def verify_session_token(self, token: str, public_key_hex: str) -> Dict[str, Any]:
        return helix_jwt.verify_jwt(token, public_key_hex)

    # -- Onboarding ------------------------------------------------------------

    def onboard_agent(self, enrollment_token: str, domains: Optional[List[str]] = None) -> Dict[str, Any]:
        """Onboards an agent in one call -- agent self-custody has been
        retired. The server generates and holds the private key itself; no
        local keypair, no wallet file. Returns {agentDid, vcId} only.
        `enrollment_token` must already exist (POST /v1/enrollment-tokens,
        not exposed as an SDK method -- an agent-owner action, not something
        the onboarding agent itself does)."""
        self._assert_api_configured()
        return self._http_required().post(
            "/v1/onboard",
            {"enrollmentToken": enrollment_token, "domains": domains or []},
        )


    def request_user_challenge(self, user_did: str) -> Dict[str, Any]:
        return self._http_required().post("/v1/challenges", {"did": user_did, "purpose": "user_verification"})

    def verify_user_challenge(self, challenge_id: str, signature: str) -> Dict[str, Any]:
        return self._http_required().post(f"/v1/challenges/{quote(challenge_id, safe='')}/verify", {"signature": signature})

    # -- internals ------------------------------------------------------------

    def _assert_api_configured(self) -> None:
        if self._sdk_only_mode:
            raise SDKOnlyModeNoAPIError()

    def _http_required(self) -> HttpAdapter:
        self._assert_api_configured()
        assert self._http is not None
        return self._http
