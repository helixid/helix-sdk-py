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

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode

from . import jwt as helix_jwt
from . import keys
from . import vp_crypto
from .errors import SDKOnlyModeNoAPIError
from .http_adapter import HttpAdapter


def _query_string(params: Dict[str, Any]) -> str:
    filtered = {k: v for k, v in params.items() if v is not None}
    if not filtered:
        return ""
    return "?" + urlencode(filtered)


@dataclass
class PendingKeyPair:
    public_key: str
    private_key: str
    did_create_signing_payload_hex: Optional[str] = None


class HelixClient:
    """
    Usage:
        HelixClient()                         # SDK-only mode: local signing
                                               # helpers work, API calls raise
                                               # SDKOnlyModeNoAPIError.
        HelixClient(base_url)                 # normal mode.
        HelixClient(base_url, admin_api_key=...)
    """

    def __init__(self, base_url: Optional[str] = None, admin_api_key: Optional[str] = None) -> None:
        self._sdk_only_mode = base_url is None
        self._api_audit_enabled = base_url is not None and bool(admin_api_key)
        self._http: Optional[HttpAdapter] = (
            None if self._sdk_only_mode else HttpAdapter(base_url, admin_api_key)
        )
        self._pending_key_pair: Optional[PendingKeyPair] = None

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

    # -- Onboarding / enrollment ----------------------------------------------

    def request_onboarding_challenge(
        self, bootstrap_token: str, domains: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        self._assert_api_configured()
        key_pair = keys.generate_key_pair()
        self._pending_key_pair = PendingKeyPair(public_key=key_pair.public_key, private_key=key_pair.private_key)
        challenge = self._http_required().post(
            "/v1/onboard",
            {"enrollmentToken": bootstrap_token, "publicKeyHex": key_pair.public_key, "domains": domains or []},
        )
        self._pending_key_pair.did_create_signing_payload_hex = challenge.get("didCreateSigningPayloadHex")
        return challenge

    def complete_onboarding(self, challenge_id: str, nonce: str) -> Dict[str, Any]:
        """Returns the onboarding result (agentDid, vc, vcId) plus the
        freshly generated keypair -- unlike the JS SDK's
        completeOnboarding(), which writes an encrypted wallet file
        directly, this returns everything so the caller decides how (or
        whether) to persist it; see wallet.py's AgentWallet for an
        equivalent encrypted-file helper."""
        self._assert_api_configured()
        if self._pending_key_pair is None:
            raise RuntimeError("No pending onboarding keypair")
        signature = vp_crypto.sign_bytes(bytes.fromhex(nonce), self._pending_key_pair.private_key)
        did_create_signature = self._sign_pending_did_create_payload()
        result = self._http_required().post(
            "/v1/onboard/verify",
            {"challengeId": challenge_id, "signature": signature, "didCreateSignature": did_create_signature},
        )
        key_pair = self._pending_key_pair
        self._pending_key_pair = None
        return {
            "agentDid": result["agentDid"],
            "vc": result["vc"],
            "vcId": result["vcId"],
            "publicKeyHex": key_pair.public_key,
            "privateKeyHex": key_pair.private_key,
        }

    def enroll(self, bootstrap_token: str, agent_did: str, agent_private_key_hex: str) -> Dict[str, Any]:
        self._assert_api_configured()
        timestamp = int(time.time() * 1000)
        import json

        proof_payload = json.dumps(
            {"bootstrapToken": bootstrap_token, "agentDid": agent_did, "timestamp": timestamp},
            separators=(",", ":"),
        )
        proof_signature = keys.sign_data(proof_payload, agent_private_key_hex)
        response = self._http_required().post(
            "/v1/enroll",
            {
                "bootstrapToken": bootstrap_token,
                "agentDid": agent_did,
                "timestamp": timestamp,
                "proofSignature": proof_signature,
            },
        )
        return response["vc"]

    def request_user_challenge(self, user_did: str) -> Dict[str, Any]:
        return self._http_required().post("/v1/challenges", {"did": user_did, "purpose": "user_verification"})

    def verify_user_challenge(self, challenge_id: str, signature: str) -> Dict[str, Any]:
        return self._http_required().post(f"/v1/challenges/{quote(challenge_id, safe='')}/verify", {"signature": signature})

    # -- internals ------------------------------------------------------------

    def _sign_pending_did_create_payload(self) -> Optional[str]:
        if self._pending_key_pair is None or not self._pending_key_pair.did_create_signing_payload_hex:
            return None
        return vp_crypto.sign_bytes(
            bytes.fromhex(self._pending_key_pair.did_create_signing_payload_hex),
            self._pending_key_pair.private_key,
        )

    def _assert_api_configured(self) -> None:
        if self._sdk_only_mode:
            raise SDKOnlyModeNoAPIError()

    def _http_required(self) -> HttpAdapter:
        self._assert_api_configured()
        assert self._http is not None
        return self._http
