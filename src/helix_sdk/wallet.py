# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
AgentWallet, ported from helix-sdk-js's src/wallet/AgentWallet.ts.

The encrypted wallet file format (version 1: AES-256-GCM with a
PBKDF2-HMAC-SHA256-derived key, 100,000 iterations) is byte-for-byte
compatible with the JS SDK's wallet files -- a wallet created by
helix-sdk-js can be loaded here and vice versa, since both sides use the
same KDF parameters and the same JSON field layout.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import keys, self_signed
from .client import HelixClient
from .errors import CredentialAlreadyInWalletError, CredentialNotForThisAgentError
from .self_signed import SelfIssueOptions

_PBKDF2_ITERATIONS = 100_000
_KEY_LEN = 32


def _now_iso() -> str:
    from .proof import _to_iso_z

    return _to_iso_z(datetime.now(timezone.utc))


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=_KEY_LEN, salt=salt, iterations=_PBKDF2_ITERATIONS)
    return kdf.derive(passphrase.encode("utf-8"))


def _is_delegation_grant_vc(vc: Dict[str, Any]) -> bool:
    return isinstance(vc.get("type"), list) and "DelegationGrantCredential" in vc["type"]


@dataclass
class WalletCredential:
    vc_id: str
    vc_json: str
    type: List[str]
    added_at: str
    updated_at: str
    issuer: Optional[str] = None
    subject_did: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "vcId": self.vc_id,
            "vcJson": self.vc_json,
            "type": self.type,
            "addedAt": self.added_at,
            "updatedAt": self.updated_at,
        }
        if self.issuer is not None:
            d["issuer"] = self.issuer
        if self.subject_did is not None:
            d["subjectDid"] = self.subject_did
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "WalletCredential":
        return WalletCredential(
            vc_id=d["vcId"],
            vc_json=d["vcJson"],
            type=d.get("type", []),
            added_at=d["addedAt"],
            updated_at=d["updatedAt"],
            issuer=d.get("issuer"),
            subject_did=d.get("subjectDid"),
        )

    @staticmethod
    def from_vc(vc_id: str, vc: Union[str, Dict[str, Any]]) -> "WalletCredential":
        vc_json = vc if isinstance(vc, str) else json.dumps(vc)
        parsed = json.loads(vc) if isinstance(vc, str) else vc
        subject = parsed.get("credentialSubject") if isinstance(parsed.get("credentialSubject"), dict) else {}
        now = _now_iso()
        cred = WalletCredential(
            vc_id=vc_id,
            vc_json=vc_json,
            type=[t for t in parsed.get("type", []) if isinstance(t, str)],
            added_at=now,
            updated_at=now,
        )
        if isinstance(parsed.get("issuer"), str):
            cred.issuer = parsed["issuer"]
        if isinstance(subject.get("id"), str):
            cred.subject_did = subject["id"]
        return cred


@dataclass
class AgentWallet:
    client: Optional[HelixClient] = None
    private_key_hex: Optional[str] = field(default=None, repr=False)
    public_key_hex: Optional[str] = None
    did_value: Optional[str] = None
    wallet_path: Optional[str] = None
    passphrase: Optional[str] = field(default=None, repr=False)
    wallet_credentials: List[WalletCredential] = field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def __post_init__(self) -> None:
        if self.private_key_hex:
            self.public_key_hex = keys.derive_public_key(self.private_key_hex)
        elif self.client is not None and self.private_key_hex is None:
            kp = keys.generate_key_pair()
            self.private_key_hex = kp.private_key
            self.public_key_hex = kp.public_key

    # -- accessors ------------------------------------------------------------

    @property
    def credentials(self) -> List[Dict[str, Any]]:
        return [json.loads(c.vc_json) for c in self.wallet_credentials]

    @property
    def did(self) -> str:
        return self.get_did()

    def get_public_key(self) -> str:
        if not self.public_key_hex:
            raise RuntimeError("Wallet has no in-memory public key")
        return self.public_key_hex

    def get_private_key_hex(self) -> str:
        if not self.private_key_hex:
            raise RuntimeError("Wallet has no in-memory private key")
        return self.private_key_hex

    def get_did(self) -> str:
        if not self.did_value:
            raise RuntimeError(
                "Wallet has no DID. Pass a live DID into AgentWallet or load an onboarded wallet file."
            )
        return self.did_value

    def sign(self, data: Union[str, bytes]) -> str:
        if not self.private_key_hex:
            raise RuntimeError("Wallet has no in-memory private key")
        return keys.sign_data(data, self.private_key_hex)

    # -- API-backed operations (require a client) ------------------------------

    def create_did(self, subject_type: str) -> Dict[str, Any]:
        if self.client is None:
            raise RuntimeError("Wallet has no HelixClient")
        return self.client.create_did(subject_type)

    def add_service(self, endpoint: Dict[str, Any]) -> Any:
        if self.client is None:
            raise RuntimeError("Wallet has no HelixClient")
        return self.client.add_service_endpoint(self.get_did(), endpoint)

    def remove_service(self, endpoint_id: str) -> Any:
        if self.client is None:
            raise RuntimeError("Wallet has no HelixClient")
        return self.client.remove_service_endpoint(self.get_did(), endpoint_id)

    def deactivate(self, reason: str = "user_request") -> None:
        if self.client is None:
            raise RuntimeError("Wallet has no HelixClient")
        self.client.deactivate_did(self.get_did(), reason)

    # -- encrypted file persistence --------------------------------------------

    def save(self, file_path: str) -> None:
        if not (self.did_value and self.public_key_hex and self.private_key_hex and self.passphrase):
            raise RuntimeError("Wallet is missing did/keys/passphrase required to save")
        salt = os.urandom(16)
        iv = os.urandom(12)
        key = _derive_key(self.passphrase, salt)
        aesgcm = AESGCM(key)
        combined = aesgcm.encrypt(iv, self.private_key_hex.encode("utf-8"), None)
        ciphertext, auth_tag = combined[:-16], combined[-16:]

        payload = {
            "version": 1,
            "did": self.did_value,
            "publicKeyHex": self.public_key_hex,
            "encryptedPrivateKey": ciphertext.hex(),
            "authTag": auth_tag.hex(),
            "iv": iv.hex(),
            "salt": salt.hex(),
            "credentials": [c.to_dict() for c in self.wallet_credentials],
            "createdAt": self.created_at or _now_iso(),
            "updatedAt": _now_iso(),
        }
        Path(file_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.updated_at = payload["updatedAt"]
        self.created_at = payload["createdAt"]
        self.wallet_path = file_path

    @staticmethod
    def _decrypt(passphrase: str, stored: Dict[str, Any]) -> str:
        try:
            key = _derive_key(passphrase, bytes.fromhex(stored["salt"]))
            iv = bytes.fromhex(stored["iv"])
            combined = bytes.fromhex(stored["encryptedPrivateKey"]) + bytes.fromhex(stored["authTag"])
            plaintext = AESGCM(key).decrypt(iv, combined, None)
            return plaintext.decode("utf-8")
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("Invalid passphrase or corrupted wallet") from exc

    @classmethod
    def load(cls, wallet_path: str, passphrase: str, client: Optional[HelixClient] = None) -> "AgentWallet":
        stored = json.loads(Path(wallet_path).read_text(encoding="utf-8"))
        private_key_hex = cls._decrypt(passphrase, stored)
        return cls(
            client=client,
            private_key_hex=private_key_hex,
            did_value=stored["did"],
            wallet_path=wallet_path,
            passphrase=passphrase,
            wallet_credentials=[WalletCredential.from_dict(c) for c in stored.get("credentials", [])],
            created_at=stored.get("createdAt"),
            updated_at=stored.get("updatedAt"),
        )

    @classmethod
    def create(cls, wallet_path: str, passphrase: str, client: Optional[HelixClient] = None) -> "AgentWallet":
        if Path(wallet_path).exists():
            return cls.load(wallet_path, passphrase, client)
        key_pair = keys.generate_key_pair()
        wallet = cls(
            client=client,
            private_key_hex=key_pair.private_key,
            did_value=f"did:key:{keys.public_key_to_multibase(key_pair.public_key)}",
            wallet_path=wallet_path,
            passphrase=passphrase,
        )
        wallet.save(wallet_path)
        return wallet

    # -- credential management --------------------------------------------------

    def add_credential(self, vc: Dict[str, Any]) -> None:
        if not self.did_value:
            raise RuntimeError(
                "Wallet has no DID. Pass a live DID into AgentWallet or load an onboarded wallet file."
            )
        if vc["credentialSubject"]["id"] != self.did_value:
            raise CredentialNotForThisAgentError()
        if any(c.vc_id == vc["id"] for c in self.wallet_credentials):
            raise CredentialAlreadyInWalletError()
        self.wallet_credentials.append(WalletCredential.from_vc(vc["id"], vc))
        if self.wallet_path and self.passphrase:
            self.save(self.wallet_path)
        self._record_consent_grant(vc)

    def _record_consent_grant(self, vc: Dict[str, Any]) -> None:
        """Emits CONSENT_GRANTED when the credential just stored is an
        SP-issued delegation grant. Swallows everything: a wallet with no
        client, a down API, or an unexpected shape must all leave the
        stored credential untouched."""
        if self.client is None or not _is_delegation_grant_vc(vc):
            return
        try:
            subject = vc["credentialSubject"]
            self.client.record_consent_granted_audit(
                vcId=vc["id"],
                agentDid=subject["id"],
                issuer=vc.get("issuer"),
                userDid=subject.get("userDid"),
                scopes=subject.get("scopes"),
                durability=subject.get("durability"),
                grantedAt=_now_iso(),
                source="sdk",
            )
        except Exception:  # noqa: BLE001
            pass

    def self_issue_vc(self, options: SelfIssueOptions) -> Dict[str, Any]:
        if not self.did_value or not self.private_key_hex:
            raise RuntimeError("Wallet has no DID or private key")
        vc = self_signed.self_issue_vc(options, self.did_value, self.private_key_hex)
        self.add_credential(vc)
        return vc

    def select_grant(self, issuer_did: str, user_did: str) -> Optional[WalletCredential]:
        """Selects the most recent DelegationGrantCredential issued by the
        given SP for the given user."""
        candidates = []
        for c in self.wallet_credentials:
            if "DelegationGrantCredential" not in c.type:
                continue
            if c.issuer != issuer_did:
                continue
            parsed = json.loads(c.vc_json)
            if parsed.get("credentialSubject", {}).get("userDid") != user_did:
                continue
            candidates.append(c)
        if not candidates:
            return None
        return max(candidates, key=lambda c: c.added_at)

    def get_latest_credential(self, vc_type: Optional[str] = None) -> Optional[WalletCredential]:
        candidates = [c for c in self.wallet_credentials if vc_type is None or vc_type in c.type]
        if not candidates:
            return None
        return max(candidates, key=lambda c: c.added_at)

    @staticmethod
    def generate_keypair() -> keys.KeyPair:
        return keys.generate_key_pair()

    @classmethod
    def from_keypair_and_credential(
        cls, keypair: keys.KeyPair, vc: Union[str, Dict[str, Any]]
    ) -> "AgentWallet":
        parsed = json.loads(vc) if isinstance(vc, str) else vc
        vc_id = parsed.get("id")
        if not vc_id:
            raise ValueError("VC has no id")
        subject = parsed.get("credentialSubject", {})
        did = f"did:key:{keys.public_key_to_multibase(keypair.public_key)}"
        if subject.get("id") != did:
            raise CredentialNotForThisAgentError()
        return cls(
            did_value=did,
            private_key_hex=keypair.private_key,
            wallet_credentials=[WalletCredential.from_vc(vc_id, vc)],
        )
