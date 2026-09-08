# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
HelixClient, ported from helix-sdk-js's src/client/HelixClient.ts.

Per docs/proposal-sdk-api-only.md, every operation here is a plain HTTP
call to helix-api -- verification, delegation/grant/renewal payload
construction, DID resolution, and status checks all live server-side.
The only local computation this client does is generating the local
keypair for onboarding/enrollment (the private key is never sent to the
server) and signing the small challenge/hash payloads the prepare/finalize
and onboarding endpoints hand back.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode

import requests

from . import jwt as helix_jwt
from . import keys
from .errors import SDKOnlyModeNoAPIError, map_api_error
from .http_adapter import HttpAdapter

# Used only when api_key is given with no explicit base_url -- see
# HelixClient.__init__. Not a claim that any fixed URL is "the" enterprise
# instance; just the default port any local helix-api listens on.
_DEFAULT_ENTERPRISE_URL = "http://localhost:3000"


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
                                               # $HELIX_API_URL or localhost:3000
                                               # when omitted here.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        admin_api_key: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> None:
        resolved_base_url = base_url
        if resolved_base_url is None and api_key:
            resolved_base_url = os.environ.get("HELIX_API_URL") or _DEFAULT_ENTERPRISE_URL

        self._sdk_only_mode = resolved_base_url is None
        self._api_audit_enabled = resolved_base_url is not None and bool(admin_api_key)
        self._base_url = (
            resolved_base_url[:-1] if resolved_base_url and resolved_base_url.endswith("/") else resolved_base_url
        )
        self._api_key = api_key
        self._http: Optional[HttpAdapter] = (
            None if self._sdk_only_mode else HttpAdapter(resolved_base_url, admin_api_key)
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

    def check_vc_status(self, vc: Dict[str, Any]) -> str:
        response = self._http_required().get(f"/v1/vcs/{quote(vc['id'], safe='')}/status")
        return response["status"]

    # -- prepare/finalize: see docs/proposal-sdk-api-only.md. prepare()
    # returns an unsigned payload + hash; the caller signs the hash locally
    # (private key never leaves the client) and finalize() attaches the
    # signature. See delegation.py / grant.py / renewal.py for the full
    # sign-and-submit flows built on top of these.

    def prepare_delegation(
        self, delegator_did: str, from_vc: Dict[str, Any], to: str, scopes: List[str], expires_in: int
    ) -> Dict[str, Any]:
        return self._http_required().post(
            "/v1/vcs/delegation/prepare",
            {
                "delegatorDid": delegator_did,
                "fromVC": from_vc,
                "to": to,
                "scopes": scopes,
                "expiresIn": expires_in,
            },
        )

    def finalize_delegation(
        self, token: str, verification_method: str, signature_hex: str
    ) -> Dict[str, Any]:
        return self._http_required().post(
            "/v1/vcs/delegation/finalize",
            {"token": token, "verificationMethod": verification_method, "signatureHex": signature_hex},
        )

    def prepare_grant(self, **input: Any) -> Dict[str, Any]:
        return self._http_required().post("/v1/vcs/grant/prepare", input)

    def finalize_grant(self, token: str, verification_method: str, signature_hex: str) -> Dict[str, Any]:
        return self._http_required().post(
            "/v1/vcs/grant/finalize",
            {"token": token, "verificationMethod": verification_method, "signatureHex": signature_hex},
        )

    def prepare_agent_renewal(self, **input: Any) -> Dict[str, Any]:
        return self._http_required().post("/v1/vcs/agent-renewal/prepare", input)

    def finalize_agent_renewal(
        self, token: str, verification_method: str, signature_hex: str
    ) -> Dict[str, Any]:
        return self._http_required().post(
            "/v1/vcs/agent-renewal/finalize",
            {"token": token, "verificationMethod": verification_method, "signatureHex": signature_hex},
        )

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
    ) -> List[Dict[str, Any]]:
        qs = _query_string({"eventType": event_type, "since": since, "limit": limit})
        return self._http_required().get(f"/v1/audit-log{qs}")

    def record_consent_granted_audit(self, **entry: Any) -> None:
        """Best-effort consent-grant audit. A failure here must never
        surface to the caller -- see AgentWallet.add_credential()."""
        if not self._api_audit_enabled:
            return
        try:
            self._http_required().post(
                "/v1/audit-log/consent-granted",
                {**entry, "subjectDid": entry.get("agentDid"), "eventType": "CONSENT_GRANTED"},
            )
        except Exception:  # noqa: BLE001
            pass

    # -- Verification -------------------------------------------------------

    def verify_vp(
        self,
        vp: Dict[str, Any],
        expected_target_service: Optional[str] = None,
        allow_self_signed: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Verifies a VP via POST /v1/vp/verify. Signature check,
        delegation-chain walk, expiry, target service, and revocation all
        happen server-side, with VP_VERIFIED/VP_REJECTED audit logging
        handled there too -- there is no local fallback, by design (see
        docs/proposal-sdk-api-only.md)."""
        body: Dict[str, Any] = {"signedVP": vp}
        if expected_target_service is not None:
            body["expectedTargetService"] = expected_target_service
        if allow_self_signed is not None:
            body["allowSelfSigned"] = allow_self_signed
        return self._http_required().post("/v1/vp/verify", body)

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

    def sign_vp(
        self,
        did: str,
        target_service: str,
        user_did: Optional[str] = None,
        grant_vc: Optional[Dict[str, Any]] = None,
        vc_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Signs a VP on behalf of a server-custody agent -- the caller
        never has, and never can have, the private key, so this is an API
        call instead of local VPBuilder signing. The server looks up the
        agent's active HelixAgentCredential itself; pass vc_id to pin a
        specific one instead (e.g. right after a renewal, when more than
        one is active). grant_vc is an SP-issued DelegationGrantCredential
        the caller already holds -- not secret material, just data to
        include -- for the consent-grant flow.

        Enterprise mode (self._api_key set): custodial signing is
        account-scoped, a different route + auth than core's admin-key-gated
        /v1/agents/:did/vp -- see HelixClient.__init__'s api_key doc."""
        self._assert_api_configured()
        body: Dict[str, Any] = {"targetService": target_service}
        if user_did is not None:
            body["userDid"] = user_did
        if grant_vc is not None:
            body["grantVC"] = grant_vc
        if vc_id is not None:
            body["vcId"] = vc_id

        if self._api_key:
            response = requests.post(
                f"{self._base_url}/v1/custodial-agents/{quote(did, safe='')}/vp",
                json=body,
                headers={"content-type": "application/json", "authorization": f"Bearer {self._api_key}"},
                timeout=30.0,
            )
            try:
                data = response.json()
            except ValueError:
                data = {}
            if not response.ok:
                raise map_api_error({**(data if isinstance(data, dict) else {}), "status": response.status_code})
            return data["signedVP"]

        result = self._http_required().post(f"/v1/agents/{quote(did, safe='')}/vp", body)
        return result["signedVP"]

    def delegate_authority(
        self,
        did: str,
        to: str,
        scopes: List[str],
        expires_in: int,
        vc_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Delegates a slice of a server-custody agent's authority to another
        DID -- the custodial counterpart to a wallet-based delegate(), which
        needed the delegator's own private key and so has nothing legitimate
        to call since agent self-custody was retired. Same trust boundary as
        sign_vp(): this is an API call that authorizes HelixID to sign on the
        delegator's behalf, not a local signature.

        Mirrors sign_vp()'s two modes: enterprise (self._api_key set) hits
        the account-scoped custodial route; core/OSS hits the admin-key-gated
        route. Pass vc_id to pin which of the delegator's active credentials
        to delegate from."""
        self._assert_api_configured()
        body: Dict[str, Any] = {"to": to, "scopes": scopes, "expiresIn": expires_in}
        if vc_id is not None:
            body["vcId"] = vc_id

        if self._api_key:
            response = requests.post(
                f"{self._base_url}/v1/custodial-agents/{quote(did, safe='')}/delegate",
                json=body,
                headers={"content-type": "application/json", "authorization": f"Bearer {self._api_key}"},
                timeout=30.0,
            )
            try:
                data = response.json()
            except ValueError:
                data = {}
            if not response.ok:
                raise map_api_error({**(data if isinstance(data, dict) else {}), "status": response.status_code})
            return data["delegatedVC"]

        result = self._http_required().post(f"/v1/agents/{quote(did, safe='')}/delegate", body)
        return result["delegatedVC"]

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
