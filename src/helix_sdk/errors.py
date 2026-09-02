# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
Typed exception taxonomy, ported from helix-sdk-js's
src/core/HelixError.ts + src/errors/index.ts.

Every error carries the same `code` (see codes.py), `http_status`, and
optional `details` as its JS counterpart, so a Python catch block can match
on either the exception type or the wire-level string code -- whichever a
caller already knows from the JS SDK or from helix-api's error responses.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from . import codes


class HelixError(Exception):
    """Base class for all Helix ID errors -- both raised locally by this SDK
    and reconstructed from helix-api's JSON error responses via
    map_api_error()."""

    def __init__(
        self,
        code: str,
        message: str,
        http_status: int,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.details = dict(details) if details is not None else None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"{type(self).__name__}(code={self.code!r}, http_status={self.http_status})"


# ── Convenience constructors ────────────────────────────────────────────────


class InvalidPublicKeyError(HelixError):
    def __init__(self) -> None:
        super().__init__(
            codes.INVALID_PUBLIC_KEY,
            "The submitted public key is not a valid 32-byte Ed25519 public key.",
            400,
        )


class InvalidDIDFormatError(HelixError):
    def __init__(self, did: str) -> None:
        super().__init__(codes.INVALID_DID_FORMAT, f"The value '{did}' is not a valid Helix DID.", 400)


class DIDNotFoundError(HelixError):
    def __init__(self, did: str = "") -> None:
        super().__init__(codes.DID_NOT_FOUND, f"DID '{did}' was not found.", 404)


class DIDMethodNotAvailableError(HelixError):
    def __init__(self, message: str) -> None:
        super().__init__(codes.DID_METHOD_NOT_AVAILABLE, message, 501)


class UnsupportedDIDMethodError(HelixError):
    def __init__(self, did: str) -> None:
        super().__init__(codes.UNSUPPORTED_DID_METHOD, f"Unsupported DID method: {did}", 400, {"did": did})


class DIDAlreadyExistsError(HelixError):
    def __init__(self) -> None:
        super().__init__(codes.DID_ALREADY_EXISTS, "A DID already exists for this public key.", 409)


class DIDDeactivatedError(HelixError):
    def __init__(self, did: str = "") -> None:
        super().__init__(
            codes.DID_DEACTIVATED, f"DID '{did}' has been deactivated and cannot be used.", 410
        )


class InvalidServiceEndpointUrlError(HelixError):
    def __init__(self, url: str) -> None:
        super().__init__(
            codes.INVALID_SERVICE_ENDPOINT_URL,
            f"Service endpoint URL '{url}' must be a valid HTTPS URL.",
            400,
        )


class ServiceEndpointNotFoundError(HelixError):
    def __init__(self, endpoint_id: str) -> None:
        super().__init__(
            codes.SERVICE_ENDPOINT_NOT_FOUND,
            f"Service endpoint '{endpoint_id}' was not found in the DID document.",
            404,
        )


class ServiceEndpointAlreadyExistsError(HelixError):
    def __init__(self, endpoint_id: str) -> None:
        super().__init__(
            codes.SERVICE_ENDPOINT_ALREADY_EXISTS,
            f"A service endpoint with ID '{endpoint_id}' already exists.",
            409,
        )


class HederaAnchorFailedError(HelixError):
    def __init__(
        self,
        message: str = "Failed to anchor the DID document on Hedera. Please retry.",
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(codes.HEDERA_ANCHOR_FAILED, message, 502, details)


class HederaResolutionFailedError(HelixError):
    def __init__(
        self,
        message: str = "Failed to resolve the DID document from Hedera.",
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(codes.HEDERA_RESOLUTION_FAILED, message, 502, details)


class InternalError(HelixError):
    def __init__(self) -> None:
        super().__init__(codes.INTERNAL_ERROR, "An unexpected error occurred.", 500)


class ValidationError(HelixError):
    def __init__(self, message: str) -> None:
        super().__init__(codes.VALIDATION_ERROR, message, 400)


class AdminAuthRequiredError(HelixError):
    def __init__(self, message: str = "Admin authorization is required") -> None:
        super().__init__(codes.ADMIN_AUTH_REQUIRED, message, 403)


class VCNotFoundError(HelixError):
    def __init__(self, vc_id: str) -> None:
        super().__init__(codes.VC_NOT_FOUND, f"Verifiable Credential not found: {vc_id}", 404)


class VCAlreadyRevokedError(HelixError):
    def __init__(self, message: str = "The Verifiable Credential has already been revoked") -> None:
        super().__init__(codes.VC_ALREADY_REVOKED, message, 409)


class VCExpiredError(HelixError):
    def __init__(self, message: str = "The Verifiable Credential has expired") -> None:
        super().__init__(codes.VC_EXPIRED, message, 400)


class VCNotYetValidError(HelixError):
    def __init__(self, message: str = "The Verifiable Credential is not valid yet") -> None:
        super().__init__(codes.VC_NOT_YET_VALID, message, 400)


class VCSubjectDIDNotFoundError(HelixError):
    def __init__(self, did: str) -> None:
        super().__init__(codes.VC_SUBJECT_DID_NOT_FOUND, f"Subject DID not found: {did}", 404)


class VCInvalidPrivilegeScopeError(HelixError):
    def __init__(self, scope: str) -> None:
        super().__init__(codes.VC_INVALID_PRIVILEGE_SCOPE, f"Invalid privilege scope: {scope}", 400)


class StatusListIndexExhaustedError(HelixError):
    def __init__(self, message: str = "The status list index space is exhausted") -> None:
        super().__init__(codes.STATUS_LIST_INDEX_EXHAUSTED, message, 503)


class VCSignatureInvalidError(HelixError):
    def __init__(self, message: str = "The Verifiable Credential signature is invalid") -> None:
        super().__init__(codes.VC_SIGNATURE_INVALID, message, 400)


class SelfSignedVCNotAllowedError(HelixError):
    def __init__(
        self, message: str = "Self-signed VCs are not allowed unless allowSelfSigned is true"
    ) -> None:
        super().__init__(codes.SELF_SIGNED_VC_NOT_ALLOWED, message, 403)


class ScopeEscalationDeniedError(HelixError):
    """Canonical scope-escalation error for issuance-time and
    chain-validation failures (delegation and grant issuance both raise
    this)."""

    def __init__(self, scope: str) -> None:
        super().__init__(
            codes.SCOPE_ESCALATION_DENIED,
            f"Delegated scope is not permitted by the parent credential: {scope}",
            400,
        )


class MaxDelegationDepthExceededError(HelixError):
    """Canonical delegation-depth error."""

    def __init__(self, message: str = "Maximum delegation depth has been exceeded") -> None:
        super().__init__(codes.MAX_DELEGATION_DEPTH_EXCEEDED, message, 400)


# Consolidated aliases, mirroring the JS side: DelegationDepthExceededError
# and DelegationScopeEscalationError duplicated the two canonical classes
# above with different codes and no distinct behavior in the original
# helix-core. The names remain exported so code written against either
# naming still works; the wire codes DELEGATION_DEPTH_EXCEEDED /
# DELEGATION_SCOPE_ESCALATION stay in codes.py because the SDK still maps
# them from API responses (see map_api_error below).
DelegationDepthExceededError = MaxDelegationDepthExceededError
DelegationScopeEscalationError = ScopeEscalationDeniedError


class DelegationChainInvalidError(HelixError):
    def __init__(self, reason: str) -> None:
        super().__init__(
            codes.DELEGATION_CHAIN_INVALID, f"Delegation chain is invalid: {reason}", 400, {"reason": reason}
        )


class DelegationParentVCNotFoundError(HelixError):
    def __init__(self, message: str = "Parent VC in delegation chain was not found") -> None:
        super().__init__(codes.DELEGATION_PARENT_VC_NOT_FOUND, message, 404)


class DelegationParentVCRevokedError(HelixError):
    def __init__(self, message: str = "Parent VC in delegation chain has been revoked") -> None:
        super().__init__(codes.DELEGATION_PARENT_VC_REVOKED, message, 400)


class DelegationNotPermittedError(HelixError):
    def __init__(self, message: str = "Delegation is not permitted for this credential") -> None:
        super().__init__(codes.DELEGATION_NOT_PERMITTED, message, 403)


class VCRevokedError(HelixError):
    def __init__(self, message: str = "The Verifiable Credential has been revoked") -> None:
        super().__init__(codes.VC_REVOKED, message, 400)


class VCIssuerNotFoundError(HelixError):
    def __init__(self, message: str = "The Verifiable Credential issuer DID could not be resolved") -> None:
        super().__init__(codes.VC_ISSUER_NOT_FOUND, message, 400)


class WalletAlreadyExistsError(HelixError):
    def __init__(
        self,
        message: str = "Wallet file already exists. Use AgentWallet.load() to load an existing wallet.",
    ) -> None:
        super().__init__(codes.WALLET_ALREADY_EXISTS, message, 409)


class NoCredentialInWalletError(HelixError):
    def __init__(self, message: str = "Wallet has no credentials") -> None:
        super().__init__(codes.NO_CREDENTIAL_IN_WALLET, message, 400)


class CredentialNotForThisAgentError(HelixError):
    def __init__(self, message: str = "Credential subject does not match this wallet DID") -> None:
        super().__init__(codes.CREDENTIAL_NOT_FOR_THIS_AGENT, message, 400)


class CredentialAlreadyInWalletError(HelixError):
    def __init__(self, message: str = "Credential is already in this wallet") -> None:
        super().__init__(codes.CREDENTIAL_ALREADY_IN_WALLET, message, 409)


class SDKOnlyModeNoAPIError(HelixError):
    def __init__(
        self,
        message: str = (
            "This operation requires a HelixID API URL. Pass the API URL to "
            'HelixClient constructor: HelixClient("http://your-api")'
        ),
    ) -> None:
        super().__init__(codes.SDK_ONLY_MODE_NO_API, message, 400)


class InsufficientScopeError(HelixError):
    def __init__(self, required_scope: str) -> None:
        super().__init__(codes.INSUFFICIENT_SCOPE, f"Required scope: {required_scope}", 403)


class VPMissingError(HelixError):
    def __init__(self, message: str = "No _helixVP in tool call input") -> None:
        super().__init__(codes.VP_MISSING, message, 401)


class VPNotFoundError(HelixError):
    def __init__(self, message: str = "VP not found") -> None:
        super().__init__(codes.VP_NOT_FOUND, message, 404)


class VPExpiredError(HelixError):
    def __init__(self, message: str = "VP has expired") -> None:
        super().__init__(codes.VP_EXPIRED, message, 400)


class VPAlreadyConsumedError(HelixError):
    def __init__(self, message: str = "VP was already consumed") -> None:
        super().__init__(codes.VP_ALREADY_CONSUMED, message, 400)


class VPVerificationFailedError(HelixError):
    def __init__(self, message: str = "The Verifiable Presentation could not be verified") -> None:
        super().__init__(codes.VP_VERIFICATION_FAILED, message, 400)


class VPSignatureInvalidError(HelixError):
    def __init__(self, message: str = "The Verifiable Presentation signature is invalid") -> None:
        super().__init__(codes.VP_SIGNATURE_INVALID, message, 400)


class VPInvalidStructureError(HelixError):
    def __init__(self, message: str = "VP payload is invalid") -> None:
        super().__init__(codes.VP_INVALID_STRUCTURE, message, 400)


class ConsentGrantSubjectMismatchError(HelixError):
    def __init__(
        self,
        message: str = "Consent grant does not match the presenting agent or the VP user identifier",
    ) -> None:
        super().__init__(codes.CONSENT_GRANT_SUBJECT_MISMATCH, message, 400)


class ConsentGrantInvalidError(HelixError):
    def __init__(self, message: str = "Consent grant credential is structurally invalid") -> None:
        super().__init__(codes.CONSENT_GRANT_INVALID, message, 400)


class VPAgentDIDNotFoundError(HelixError):
    def __init__(self, message: str = "Agent DID not found") -> None:
        super().__init__(codes.VP_AGENT_DID_NOT_FOUND, message, 404)


class VPNoActiveVCError(HelixError):
    def __init__(self, message: str = "No active VC found for agent") -> None:
        super().__init__(codes.VP_NO_ACTIVE_VC, message, 400)


class VPMultipleActiveVCError(HelixError):
    def __init__(self, message: str = "Multiple active VCs found for agent") -> None:
        super().__init__(codes.VP_MULTIPLE_ACTIVE_VC, message, 400)


class InvalidJWTError(HelixError):
    def __init__(self, message: str = "JWT is invalid") -> None:
        super().__init__(codes.JWT_INVALID, message, 400)


class JWTExpiredError(HelixError):
    def __init__(self, message: str = "JWT has expired") -> None:
        super().__init__(codes.JWT_EXPIRED, message, 401)


class JWTPublicKeyNotFoundError(HelixError):
    def __init__(self, message: str = "JWT public key is not configured") -> None:
        super().__init__(codes.JWT_PUBLIC_KEY_NOT_FOUND, message, 500)


class EnrollmentTokenNotFoundError(HelixError):
    def __init__(self, message: str = "Enrollment token was not found") -> None:
        super().__init__(codes.ENROLLMENT_TOKEN_NOT_FOUND, message, 404)


class EnrollmentTokenExpiredError(HelixError):
    def __init__(self, message: str = "Enrollment token has expired") -> None:
        super().__init__(codes.ENROLLMENT_TOKEN_EXPIRED, message, 400)


class EnrollmentTokenAlreadyUsedError(HelixError):
    def __init__(self, message: str = "Enrollment token was already used") -> None:
        super().__init__(codes.ENROLLMENT_TOKEN_ALREADY_USED, message, 409)


class ChallengeNotFoundError(HelixError):
    def __init__(self, message: str = "Challenge was not found") -> None:
        super().__init__(codes.CHALLENGE_NOT_FOUND, message, 404)


class ChallengeExpiredError(HelixError):
    def __init__(self, message: str = "Challenge has expired") -> None:
        super().__init__(codes.CHALLENGE_EXPIRED, message, 410)


class ChallengeAlreadyVerifiedError(HelixError):
    def __init__(self, message: str = "Challenge was already verified") -> None:
        super().__init__(codes.CHALLENGE_ALREADY_VERIFIED, message, 409)


class ChallengeSignatureInvalidError(HelixError):
    def __init__(self, message: str = "Challenge signature is invalid") -> None:
        super().__init__(codes.CHALLENGE_SIGNATURE_INVALID, message, 400)


class AgentAlreadyOnboardedError(HelixError):
    def __init__(self, message: str = "Agent is already onboarded") -> None:
        super().__init__(codes.AGENT_ALREADY_ONBOARDED, message, 409)


class PreparedPayloadNotFoundError(HelixError):
    def __init__(self, message: str = "Prepared payload was not found") -> None:
        super().__init__(codes.PREPARED_PAYLOAD_NOT_FOUND, message, 404)


class PreparedPayloadExpiredError(HelixError):
    def __init__(self, message: str = "Prepared payload has expired") -> None:
        super().__init__(codes.PREPARED_PAYLOAD_EXPIRED, message, 410)


class PreparedPayloadAlreadyConsumedError(HelixError):
    def __init__(self, message: str = "Prepared payload was already consumed") -> None:
        super().__init__(codes.PREPARED_PAYLOAD_ALREADY_CONSUMED, message, 409)


class PreparedPayloadSignatureInvalidError(HelixError):
    def __init__(self, message: str = "Prepared payload signature is invalid") -> None:
        super().__init__(codes.PREPARED_PAYLOAD_SIGNATURE_INVALID, message, 400)


class PreparedPayloadPurposeMismatchError(HelixError):
    def __init__(
        self, message: str = "Prepared payload purpose does not match finalize endpoint"
    ) -> None:
        super().__init__(codes.PREPARED_PAYLOAD_PURPOSE_MISMATCH, message, 400)


class RenewalWindowNotOpenError(HelixError):
    def __init__(self, message: str = "VC is not yet within its renewal window") -> None:
        super().__init__(codes.RENEWAL_WINDOW_NOT_OPEN, message, 400)


class RenewalWindowExpiredError(HelixError):
    def __init__(
        self,
        message: str = "VC renewal grace period has passed; a fresh issuance is required",
    ) -> None:
        super().__init__(codes.RENEWAL_WINDOW_EXPIRED, message, 400)


class MaxRenewalCountExceededError(HelixError):
    def __init__(
        self,
        message: str = "VC has reached its maximum renewal count; a fresh issuance is required",
    ) -> None:
        super().__init__(codes.MAX_RENEWAL_COUNT_EXCEEDED, message, 400)


class VCMissingCredentialStatusError(HelixError):
    def __init__(
        self, message: str = "VC has no credentialStatus entry; revocation cannot be checked"
    ) -> None:
        super().__init__(codes.VC_MISSING_CREDENTIAL_STATUS, message, 400)


class ServiceNotFoundError(HelixError):
    def __init__(self, message: str = "Service was not found") -> None:
        super().__init__(codes.SERVICE_NOT_FOUND, message, 404)


class ServiceAlreadyExistsError(HelixError):
    def __init__(self, message: str = "Service already exists") -> None:
        super().__init__(codes.SERVICE_ALREADY_EXISTS, message, 409)


class AccountAlreadyExistsError(HelixError):
    def __init__(self, message: str = "An account with this email already exists") -> None:
        super().__init__(codes.ACCOUNT_ALREADY_EXISTS, message, 409)


class AccountNotFoundError(HelixError):
    def __init__(self, message: str = "Account was not found") -> None:
        super().__init__(codes.ACCOUNT_NOT_FOUND, message, 404)


class InvalidCredentialsError(HelixError):
    def __init__(self, message: str = "Email or password is incorrect") -> None:
        super().__init__(codes.INVALID_CREDENTIALS, message, 401)


class AccountHasNoPasswordError(HelixError):
    def __init__(
        self, message: str = "This account signs in with Google only; no password is set"
    ) -> None:
        super().__init__(codes.ACCOUNT_HAS_NO_PASSWORD, message, 401)


class RefreshTokenInvalidError(HelixError):
    def __init__(self, message: str = "Refresh token is invalid") -> None:
        super().__init__(codes.REFRESH_TOKEN_INVALID, message, 401)


class RefreshTokenExpiredError(HelixError):
    def __init__(self, message: str = "Refresh token has expired; please sign in again") -> None:
        super().__init__(codes.REFRESH_TOKEN_EXPIRED, message, 401)


class RefreshTokenReuseDetectedError(HelixError):
    def __init__(
        self,
        message: str = (
            "This refresh token was already used. All sessions for this account have "
            "been signed out as a precaution."
        ),
    ) -> None:
        super().__init__(codes.REFRESH_TOKEN_REUSE_DETECTED, message, 401)


class AccessTokenInvalidError(HelixError):
    def __init__(self, message: str = "Access token is invalid") -> None:
        super().__init__(codes.ACCESS_TOKEN_INVALID, message, 401)


class AccessTokenExpiredError(HelixError):
    def __init__(self, message: str = "Access token has expired") -> None:
        super().__init__(codes.ACCESS_TOKEN_EXPIRED, message, 401)


class GoogleOAuthFailedError(HelixError):
    def __init__(self, message: str = "Google sign-in failed") -> None:
        super().__init__(codes.GOOGLE_OAUTH_FAILED, message, 401)


class EmailNotVerifiedError(HelixError):
    def __init__(
        self,
        message: str = "Please verify your email before issuing credentials or enrollment tokens",
    ) -> None:
        super().__init__(codes.EMAIL_NOT_VERIFIED, message, 403)


class EmailVerificationTokenInvalidError(HelixError):
    def __init__(self, message: str = "Verification link is invalid") -> None:
        super().__init__(codes.EMAIL_VERIFICATION_TOKEN_INVALID, message, 400)


class EmailVerificationTokenExpiredError(HelixError):
    def __init__(self, message: str = "Verification link has expired; request a new one") -> None:
        super().__init__(codes.EMAIL_VERIFICATION_TOKEN_EXPIRED, message, 400)


class AccountQuotaExceededError(HelixError):
    def __init__(self, message: str = "Daily quota exceeded for this account") -> None:
        super().__init__(codes.ACCOUNT_QUOTA_EXCEEDED, message, 429)


class CaptchaFailedError(HelixError):
    def __init__(self, message: str = "CAPTCHA verification failed") -> None:
        super().__init__(codes.CAPTCHA_FAILED, message, 400)


# ── API error mapping ───────────────────────────────────────────────────────

_CODE_TO_ERROR = {
    codes.VALIDATION_ERROR: ValidationError,
    codes.DID_NOT_FOUND: DIDNotFoundError,
    codes.DID_DEACTIVATED: DIDDeactivatedError,
    codes.DID_ALREADY_EXISTS: lambda message: DIDAlreadyExistsError(),
    codes.ENROLLMENT_TOKEN_NOT_FOUND: EnrollmentTokenNotFoundError,
    codes.ENROLLMENT_TOKEN_EXPIRED: EnrollmentTokenExpiredError,
    codes.ENROLLMENT_TOKEN_ALREADY_USED: EnrollmentTokenAlreadyUsedError,
    codes.CHALLENGE_NOT_FOUND: ChallengeNotFoundError,
    codes.CHALLENGE_EXPIRED: ChallengeExpiredError,
    codes.CHALLENGE_ALREADY_VERIFIED: ChallengeAlreadyVerifiedError,
    codes.CHALLENGE_SIGNATURE_INVALID: ChallengeSignatureInvalidError,
    codes.AGENT_ALREADY_ONBOARDED: AgentAlreadyOnboardedError,
    codes.SERVICE_NOT_FOUND: ServiceNotFoundError,
    codes.SERVICE_ALREADY_EXISTS: ServiceAlreadyExistsError,
    codes.DELEGATION_NOT_PERMITTED: DelegationNotPermittedError,
    codes.DELEGATION_DEPTH_EXCEEDED: DelegationDepthExceededError,
    codes.DELEGATION_SCOPE_ESCALATION: DelegationScopeEscalationError,
    codes.DELEGATION_CHAIN_INVALID: DelegationChainInvalidError,
    codes.DELEGATION_PARENT_VC_NOT_FOUND: DelegationParentVCNotFoundError,
    codes.DELEGATION_PARENT_VC_REVOKED: DelegationParentVCRevokedError,
    codes.MAX_DELEGATION_DEPTH_EXCEEDED: MaxDelegationDepthExceededError,
    codes.SCOPE_ESCALATION_DENIED: ScopeEscalationDeniedError,
    codes.PREPARED_PAYLOAD_NOT_FOUND: PreparedPayloadNotFoundError,
    codes.PREPARED_PAYLOAD_EXPIRED: PreparedPayloadExpiredError,
    codes.PREPARED_PAYLOAD_ALREADY_CONSUMED: PreparedPayloadAlreadyConsumedError,
    codes.PREPARED_PAYLOAD_SIGNATURE_INVALID: PreparedPayloadSignatureInvalidError,
    codes.PREPARED_PAYLOAD_PURPOSE_MISMATCH: PreparedPayloadPurposeMismatchError,
    codes.VC_REVOKED: VCRevokedError,
    codes.VC_MISSING_CREDENTIAL_STATUS: VCMissingCredentialStatusError,
    codes.RENEWAL_WINDOW_NOT_OPEN: RenewalWindowNotOpenError,
    codes.RENEWAL_WINDOW_EXPIRED: RenewalWindowExpiredError,
    codes.MAX_RENEWAL_COUNT_EXCEEDED: MaxRenewalCountExceededError,
    codes.VC_EXPIRED: VCExpiredError,
    codes.VC_NOT_YET_VALID: VCNotYetValidError,
    codes.VC_SIGNATURE_INVALID: VCSignatureInvalidError,
    codes.SELF_SIGNED_VC_NOT_ALLOWED: SelfSignedVCNotAllowedError,
    codes.VP_MISSING: VPMissingError,
    codes.VP_EXPIRED: VPExpiredError,
    codes.VP_VERIFICATION_FAILED: VPVerificationFailedError,
    codes.VP_SIGNATURE_INVALID: VPSignatureInvalidError,
    codes.VP_INVALID_STRUCTURE: VPInvalidStructureError,
    codes.CONSENT_GRANT_SUBJECT_MISMATCH: ConsentGrantSubjectMismatchError,
    codes.CONSENT_GRANT_INVALID: ConsentGrantInvalidError,
}


def map_api_error(body: Any) -> HelixError:
    """Maps a structured API error response to a typed HelixError instance,
    mirroring helix-sdk-js's mapApiError() in src/errors/index.ts exactly,
    including its fallback behavior for unrecognized codes."""
    response_body: Mapping[str, Any] = body if isinstance(body, dict) else {}
    error_body = response_body.get("error")
    if not isinstance(error_body, dict) or not error_body.get("code"):
        return InternalError()

    code = error_body["code"]
    message = error_body.get("message", "")

    ctor = _CODE_TO_ERROR.get(code)
    if ctor is not None:
        try:
            return ctor(message)
        except TypeError:
            # Constructors with no-arg signatures (e.g. DIDAlreadyExistsError)
            return ctor()  # type: ignore[call-arg]

    status = response_body.get("statusCode", response_body.get("status", 500))
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 500
    return HelixError(code, message, status)
