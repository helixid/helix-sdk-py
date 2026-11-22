# Copyright 2026 DgVerse LLP
"""KYA-OS story F-3: helix_init, HelixCustodialSigner, the custody client and
the agent runtime's Signer, with the self-custody invariant on every request.

The cross-language layer reads helix-core's fixtures/kya-os-helix/custody.json
from the sibling checkout (../helix-core/fixtures) or HELIX_CORE_FIXTURES_DIR."""

import base64
import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import nacl.signing
import pytest

from helix_sdk.agent_key import AgentKey, to_public_key_jwk
from helix_sdk.crypto.jws import EnvSigner
from helix_sdk.custody import (
    CUSTODY_LABEL_SELF,
    CustodyApiError,
    HelixCustodialSigner,
    HelixCustodyClient,
    activate_agent,
    base64url_decode,
    base64url_encode,
    change_to_self_custody,
    check_own_hosting,
    enrollment_proof_message,
    helix_init,
    kid_fragment,
    INIT_FILES,
    main,
    rotation_proof,
    rotation_proof_message,
)
from helix_sdk.proof import verify_ed25519_proof
from helix_sdk.vp_builder import VPBuilder, VPBuilderSignOverrides
from helix_sdk.errors import VPInvalidStructureError

FIXTURES_DIR = Path(os.environ.get("HELIX_CORE_FIXTURES_DIR") or Path(__file__).resolve().parents[2] / "helix-core" / "fixtures")
CUSTODY_FIXTURE = FIXTURES_DIR / "kya-os-helix" / "custody.json"

SEED_HEX = "42" * 32
SEED = bytes.fromhex(SEED_HEX)
PUBLIC_HEX = bytes(nacl.signing.SigningKey(SEED).verify_key).hex()
PRIVATE_FORMS = [SEED_HEX, base64url_encode(SEED), base64.b64encode(SEED).decode()]
DID = "did:web:helix.example:acme:bot-1"


def fixed_key() -> AgentKey:
    return AgentKey(private_key_hex=SEED_HEX, public_key_hex=PUBLIC_HEX)


class FakeApi:
    """A Helix API stand-in: answers by route, records every request exactly as sent."""

    def __init__(self, routes: Dict[str, Any]) -> None:
        self.routes = routes
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, Any]:
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        from urllib.parse import unquote, urlsplit

        path = unquote(urlsplit(url).path)
        route = self.routes.get(f"{method} {path}")
        if route is None:
            return 404, {"error": {"code": "NOT_FOUND", "message": path}}
        answer = route(json.loads(body) if body else {})
        return (answer[0], answer[1]) if isinstance(answer, tuple) else (200, answer)

    def assert_no_private_material_sent(self) -> None:
        for call in self.calls:
            for form in PRIVATE_FORMS:
                assert form not in (call["body"] or ""), call["url"]
            if call["body"]:
                text = json.dumps(json.loads(call["body"]))
                for name in ('"d":', '"privateKey":', '"privateKeyHex":', '"seed":', '"secret":'):
                    assert name not in text, call["url"]


def documents_for(did: str, kid: str, x: str, origin: str) -> Dict[str, Any]:
    return {
        "didDocument": {
            "id": did,
            "verificationMethod": [{"id": kid, "type": "Ed25519VerificationKey2020", "controller": did, "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}],
            "service": [{"id": "#kya-os-card", "type": "KyaOsEntityCard", "serviceEndpoint": f"{origin}/card.json"}],
        },
        "card": {"id": did, "entityType": "agent", "name": "Bot", "kid": kid, "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid}, "proofProfile": "org.kya-os/proof.v1", "didDocument": f"{origin}/did.json"},
        "didDocumentUrl": f"{origin}/did.json",
        "cardUrl": f"{origin}/card.json",
    }


# ------------------------------------------------------------ cross-language


@pytest.fixture(scope="module")
def custody_fixture() -> Dict[str, Any]:
    if not CUSTODY_FIXTURE.exists():
        pytest.skip(f"{CUSTODY_FIXTURE} not found: check out helix-core beside this repo or set HELIX_CORE_FIXTURES_DIR")
    return json.loads(CUSTODY_FIXTURE.read_text(encoding="utf-8"))


def test_fixture_proof_messages_and_signatures(custody_fixture: Dict[str, Any]) -> None:
    seed = bytes.fromhex(custody_fixture["key"]["seedHex"])
    enrollment = custody_fixture["enrollment"]
    message = enrollment_proof_message(enrollment["did"], enrollment["kid"], enrollment["nonce"])
    assert message.decode() == enrollment["message"]
    assert base64url_encode(nacl.signing.SigningKey(seed).sign(message).signature) == enrollment["signature"]
    rotation = custody_fixture["rotation"]
    assert rotation_proof_message(rotation["did"], rotation["kid"], rotation["issuedAt"]).decode() == rotation["message"]
    signer = EnvSigner(rotation["did"], kid=rotation["kid"], env={"HELIX_SIGNING_KEY": custody_fixture["key"]["seedHex"]})
    assert rotation_proof(signer, rotation["did"], rotation["kid"], rotation["issuedAt"]) == {"issuedAt": rotation["issuedAt"], "signature": rotation["signature"]}
    assert to_public_key_jwk(custody_fixture["key"]["publicKeyHex"]) == custody_fixture["key"]["publicKeyJwk"]
    assert custody_fixture["labels"]["self"] == CUSTODY_LABEL_SELF


def test_fixture_custodial_signer_request_and_response(custody_fixture: Dict[str, Any]) -> None:
    sign = custody_fixture["sign"]
    api = FakeApi({f"POST /v1/agents/{sign['did']}/sign": lambda body: sign["response"]})
    signer = HelixCustodialSigner(sign["did"], api_url="https://helix.example", admin_api_key="k", http=api)
    signature = signer.sign(sign["payloadUtf8"].encode())
    assert json.loads(api.calls[0]["body"]) == {**sign["request"], "kid": "key-1"}
    assert base64url_encode(signature) == sign["response"]["signature"]


# ----------------------------------------------------------------- helpers


def test_encoding_and_kid_helpers() -> None:
    assert base64url_decode(base64url_encode(b"\x00\xff")) == b"\x00\xff"
    assert base64url_decode("a+b") is None
    assert base64url_decode("a") is None
    assert base64url_decode(3) is None  # type: ignore[arg-type]
    assert kid_fragment(DID, f"{DID}#key-1") == "key-1"
    assert kid_fragment(DID, "#k") == "k"
    with pytest.raises(ValueError):
        kid_fragment(DID, "")
    with pytest.raises(ValueError):
        enrollment_proof_message(DID, "a b", "n")
    proof = rotation_proof(EnvSigner(DID, env={"HELIX_SIGNING_KEY": SEED_HEX}), DID, f"{DID}#key-2")
    assert proof["issuedAt"].endswith("Z")
    assert nacl.signing.VerifyKey(bytes.fromhex(PUBLIC_HEX)).verify(rotation_proof_message(DID, f"{DID}#key-2", proof["issuedAt"]), base64url_decode(proof["signature"]))


# ------------------------------------------------------------------ client


def test_client_sends_the_right_credential_and_maps_refusals() -> None:
    api = FakeApi(
        {
            "GET /v1/custody/defaults": lambda body: {"custody": {"defaultKeyCustody": "self", "defaultDidHosting": "helix"}, "source": "built-in"},
            "POST /v1/agents": lambda body: (409, {"error": {"code": "CUSTODY_STATE_INVALID", "message": "no", "details": {"status": "active"}}}),
            "GET /v1/conformance/report": lambda body: (500, None),
        }
    )
    admin = HelixCustodyClient("https://helix.example/", admin_api_key="admin", http=api)
    assert admin.defaults()["source"] == "built-in"
    assert api.calls[0]["url"] == "https://helix.example/v1/custody/defaults"
    assert api.calls[0]["headers"] == {"x-admin-api-key": "admin"}
    account = HelixCustodyClient("https://helix.example", api_key="acc", http=api)
    with pytest.raises(CustodyApiError) as refused:
        account.create_agent(name="x")
    assert (refused.value.status, refused.value.code, refused.value.details) == (409, "CUSTODY_STATE_INVALID", {"status": "active"})
    assert api.calls[1]["headers"] == {"authorization": "Bearer acc", "content-type": "application/json"}
    with pytest.raises(CustodyApiError) as failed:
        account.conformance_report()
    assert failed.value.code == "HTTP_ERROR"
    with pytest.raises(ValueError):
        HelixCustodyClient("")


def test_client_refuses_to_send_private_material() -> None:
    api = FakeApi({})
    client = HelixCustodyClient("https://helix.example", http=api)
    with pytest.raises(ValueError, match="never leave"):
        client.enroll("t", {"kty": "OKP", "crv": "Ed25519", "x": "x", "d": "secret"}, "sig")
    with pytest.raises(ValueError, match="never leave"):
        client.create_service(name="s", domain="d", requiredScopes=["a"], privateKey="x")
    assert api.calls == []


def test_create_agent_sends_requested_domains_and_max_delegation_depth() -> None:
    api = FakeApi({"POST /v1/agents": lambda body: (201, {"did": DID, **body})})
    client = HelixCustodyClient("https://helix.example", admin_api_key="admin", http=api)
    client.create_agent(name="Router", keyCustody="helix", requestedDomains=["orders.example"], maxDelegationDepth=2)
    assert json.loads(api.calls[0]["body"]) == {"name": "Router", "keyCustody": "helix", "requestedDomains": ["orders.example"], "maxDelegationDepth": 2}


def test_client_reaches_every_endpoint() -> None:
    seen: List[str] = []

    def http(method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, Any]:
        from urllib.parse import urlsplit

        seen.append(f"{method} {urlsplit(url).path}")
        return 200, {}

    client = HelixCustodyClient("https://h", http=http)
    client.create_owner(name="o")
    client.create_service(name="s", domain="d", requiredScopes=["a"])
    client.activate(DID, kind="service")
    client.activate(DID, "enroll:t")
    client.get_custody(DID, "owner")
    client.finalize_rotation(DID, force=True)
    client.change_custody(DID, keyCustody="helix")
    client.conformance_report()
    did = DID.replace(":", "%3A")
    assert seen == [
        "POST /v1/owners",
        "POST /v1/services",
        f"POST /v1/services/{did}/activate",
        f"POST /v1/agents/{did}/activate",
        f"GET /v1/owners/{did}/custody",
        f"POST /v1/agents/{did}/custody/finalize",
        f"POST /v1/agents/{did}/custody",
        "GET /v1/conformance/report",
    ]
    with pytest.raises(ValueError):
        client.get_custody(DID, "user")


# ----------------------------------------------------------------- signers

HELIX_SEED = bytes.fromhex("7e" * 32)
HELIX_PUBLIC = bytes(nacl.signing.SigningKey(HELIX_SEED).verify_key)


def signing_api(kid: str = f"{DID}#key-1", subject: str = "agents", seed: bytes = HELIX_SEED) -> FakeApi:
    return FakeApi(
        {
            f"POST /v1/{subject}/{DID}/sign": lambda body: {
                "did": DID,
                "kid": kid,
                "alg": "EdDSA",
                "signature": base64url_encode(nacl.signing.SigningKey(seed).sign(base64url_decode(body["payload"])).signature),
            }
        }
    )


def test_custodial_signer_signs_through_the_api_and_holds_nothing() -> None:
    api = signing_api()
    signer = HelixCustodialSigner(DID, api_url="https://helix.example", api_key="acc", http=api)
    signature = signer.sign(b"payload")
    nacl.signing.VerifyKey(HELIX_PUBLIC).verify(b"payload", signature)
    assert json.loads(api.calls[0]["body"]) == {"payload": base64url_encode(b"payload"), "kid": "key-1"}
    assert api.calls[0]["headers"]["authorization"] == "Bearer acc"
    assert repr(signer) == f"HelixCustodialSigner(did={DID!r}, kid='key-1')"
    assert signer.verification_method_id == f"{DID}#key-1"
    owner = HelixCustodialSigner(DID, api_url="https://h", subject="owner", http=signing_api(subject="owners"))
    assert len(owner.sign(b"x")) == 64
    via_client = HelixCustodialSigner(DID, client=HelixCustodyClient("https://h", http=signing_api()))
    assert len(via_client.sign(bytearray(b"x"))) == 64


def test_custodial_signer_refuses_what_is_not_its_signature() -> None:
    with pytest.raises(ValueError, match="signed with"):
        HelixCustodialSigner(DID, api_url="https://h", http=signing_api(kid=f"{DID}#key-9")).sign(b"x")
    short = FakeApi({f"POST /v1/agents/{DID}/sign": lambda body: {"did": DID, "kid": f"{DID}#key-1", "signature": "AAAA"}})
    with pytest.raises(ValueError, match="64-byte"):
        HelixCustodialSigner(DID, api_url="https://h", http=short).sign(b"x")
    refused = FakeApi({f"POST /v1/agents/{DID}/sign": lambda body: (409, {"error": {"code": "CUSTODIAL_SIGNING_REFUSED", "message": "self"}})})
    with pytest.raises(CustodyApiError) as error:
        HelixCustodialSigner(DID, api_url="https://h", http=refused).sign(b"x")
    assert error.value.code == "CUSTODIAL_SIGNING_REFUSED"
    with pytest.raises(TypeError):
        HelixCustodialSigner(DID, api_url="https://h").sign("text")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        HelixCustodialSigner("x", api_url="https://h")
    with pytest.raises(ValueError, match="api_url or client"):
        HelixCustodialSigner(DID)


# ----------------------------------------------- the runtime takes any Signer

CREDENTIAL = {"id": "vc:1", "type": ["VerifiableCredential", "HelixAgentCredential"], "credentialSubject": {"id": DID}}


def present(signer: Any) -> Dict[str, Any]:
    """The application code: the same whichever custody mode the signer stands for."""
    from datetime import datetime, timezone

    overrides = VPBuilderSignOverrides(
        id="vp:helix:fixed",
        nonce="ab" * 32,
        expires_at=datetime(2026, 11, 21, 0, 5, tzinfo=timezone.utc),
        proof_created_at=datetime(2026, 11, 21, tzinfo=timezone.utc),
    )
    return VPBuilder(credentials=[CREDENTIAL], holder_did=signer.did, target_service="orders").sign_with(signer, overrides)


def test_vp_signed_through_any_signer_matches_sign() -> None:
    from datetime import datetime, timezone

    overrides = VPBuilderSignOverrides(
        id="vp:helix:fixed",
        nonce="ab" * 32,
        expires_at=datetime(2026, 11, 21, 0, 5, tzinfo=timezone.utc),
        proof_created_at=datetime(2026, 11, 21, tzinfo=timezone.utc),
    )
    legacy = VPBuilder(credentials=[CREDENTIAL], holder_did=DID, target_service="orders").sign(SEED_HEX, f"{DID}#key-1", overrides)
    via_env = present(EnvSigner(DID, env={"HELIX_SIGNING_KEY": SEED_HEX}))
    via_helix = present(HelixCustodialSigner(DID, api_url="https://h", http=signing_api(seed=SEED)))
    assert via_env == legacy
    assert via_helix == legacy
    payload = {key: value for key, value in via_helix.items() if key != "proof"}
    assert verify_ed25519_proof(payload, via_helix["proof"], PUBLIC_HEX)


def test_vp_sign_with_refuses_a_foreign_or_broken_signer() -> None:
    builder = VPBuilder(credentials=[CREDENTIAL], holder_did=DID, target_service="orders")
    with pytest.raises(VPInvalidStructureError, match="not the VP holder"):
        builder.sign_with(EnvSigner("did:web:other", env={"HELIX_SIGNING_KEY": SEED_HEX}))

    class Broken:
        did = DID
        kid = "key-1"

        def sign(self, data: bytes) -> bytes:
            return b"\x00"

    with pytest.raises(VPInvalidStructureError, match="64-byte"):
        builder.sign_with(Broken())
    assert builder.sign_with(EnvSigner(DID, env={"HELIX_SIGNING_KEY": SEED_HEX}))["proof"]["verificationMethod"] == f"{DID}#key-1"


# --------------------------------------------------------------- helix_init


def init_api(did: str, did_hosting: str, origin: str, status: str) -> FakeApi:
    kid = f"{did}#key-1"
    nonce = "cd" * 32

    def enroll(body: Dict[str, Any]) -> Any:
        x = body["publicKeyJwk"]["x"]
        message = enrollment_proof_message(did, f"{did}#{body['kid']}", nonce)
        try:
            nacl.signing.VerifyKey(base64url_decode(x)).verify(message, base64url_decode(body["signature"]))
        except Exception:  # noqa: BLE001
            return 400, {"error": {"code": "ENROLLMENT_PROOF_INVALID", "message": "bad proof"}}
        result = {"did": did, "keyCustody": "self", "didHosting": did_hosting, "label": "custody: self", "status": status, "kid": kid, "documents": documents_for(did, kid, x, origin)}
        if status == "active":
            result["vcId"] = "vc:1"
        return 201, result

    return FakeApi(
        {
            "POST /v1/agents/enroll/challenge": lambda body: {"did": did, "kid": kid, "nonce": nonce, "keyCustody": "self", "didHosting": did_hosting, "name": "Bot", "didDocumentUrl": f"{origin}/did.json", "cardUrl": f"{origin}/card.json"},
            "POST /v1/agents/enroll": enroll,
            f"POST /v1/agents/{did}/activate": lambda body: {"did": did, "status": "active", "vcId": "vc:2"} if body.get("enrollmentToken") == "enroll:t" else (403, {"error": {"code": "ADMIN_AUTH_REQUIRED", "message": "no"}}),
        }
    )


def test_helix_init_on_helix_hosting(tmp_path: Path) -> None:
    api = init_api(DID, "helix", "https://helix.example/acme/bot-1", "active")
    result = helix_init("https://helix.example", "enroll:t", str(tmp_path), http=api, generate_key=fixed_key)
    assert (result.did, result.kid, result.status, result.label, result.vc_id, result.key_custody) == (DID, f"{DID}#key-1", "active", "custody: self", "vc:1", "self")
    assert result.public_key_jwk == to_public_key_jwk(PUBLIC_HEX)
    api.assert_no_private_material_sent()
    assert [call["url"] for call in api.calls] == ["https://helix.example/v1/agents/enroll/challenge", "https://helix.example/v1/agents/enroll"]
    assert json.loads((tmp_path / "did.json").read_text())["id"] == DID
    assert json.loads((tmp_path / "card.json").read_text())["entityType"] == "agent"
    env = (tmp_path / "signing-key.env").read_text()
    assert f"HELIX_SIGNING_KEY={SEED_HEX}" in env
    assert stat.S_IMODE(os.stat(tmp_path / "signing-key.env").st_mode) == 0o600
    summary = (tmp_path / "helix-agent.json").read_text()
    for form in PRIVATE_FORMS:
        assert form not in summary
    assert EnvSigner(DID, env={"HELIX_SIGNING_KEY": SEED_HEX}).public_key_hex() == PUBLIC_HEX


def test_helix_init_on_own_hosting_then_activate(tmp_path: Path) -> None:
    did = "did:web:owner.example:agents:bot"
    origin = "https://owner.example/agents/bot"
    api = init_api(did, "own", origin, "pending_resolution")
    served: Dict[str, Any] = {}

    def fetch_json(url: str) -> Any:
        if url not in served:
            raise RuntimeError(f"404 {url}")
        return served[url]

    pending = helix_init("https://helix.example", "enroll:t", str(tmp_path), did=did, http=api, fetch_json=fetch_json, generate_key=fixed_key)
    assert pending.status == "pending_resolution"
    assert pending.resolution and pending.resolution["ok"] is False
    assert not any(call["url"].endswith("/activate") for call in api.calls)
    served[f"{origin}/did.json"] = json.loads((tmp_path / "did.json").read_text())
    served[f"{origin}/card.json"] = json.loads((tmp_path / "card.json").read_text())
    active = activate_agent("https://helix.example", "enroll:t", str(tmp_path), http=api, fetch_json=fetch_json)
    assert (active.status, active.resolution, active.vc_id) == ("active", {"ok": True}, "vc:2")
    api.assert_no_private_material_sent()
    later = helix_init("https://helix.example", "enroll:t", str(tmp_path / "again"), did=did, http=init_api(did, "own", origin, "pending_resolution"), activate=False)
    assert later.status == "pending_resolution" and later.resolution is None


def test_check_own_hosting_against_the_registered_key() -> None:
    did = "did:web:owner.example:agents:bot"
    origin = "https://owner.example/agents/bot"
    x = to_public_key_jwk(PUBLIC_HEX)["x"]
    docs = documents_for(did, f"{did}#key-1", x, origin)
    jwk = to_public_key_jwk(PUBLIC_HEX)

    def serve(document: Any, card: Any):
        return lambda url: document if url.endswith("did.json") else card

    assert check_own_hosting(did, f"{did}#key-1", jwk, serve(docs["didDocument"], docs["card"])) == {"ok": True}
    assert "does not list" in check_own_hosting(did, f"{did}#key-1", jwk, serve({**docs["didDocument"], "verificationMethod": []}, docs["card"]))["reason"]
    other_x = to_public_key_jwk(bytes(nacl.signing.SigningKey(b"\x09" * 32).verify_key).hex())["x"]
    card = {**docs["card"], "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": other_x}}
    assert "another key" in check_own_hosting(did, f"{did}#key-1", jwk, serve(docs["didDocument"], card))["reason"]
    assert check_own_hosting(did, f"{did}#key-1", jwk, serve({**docs["didDocument"], "id": "did:web:x"}, docs["card"]))["ok"] is False


def test_helix_init_refusals(tmp_path: Path) -> None:
    api = init_api(DID, "helix", "https://helix.example/acme/bot-1", "active")
    with pytest.raises(ValueError, match="is for"):
        helix_init("https://helix.example", "enroll:t", str(tmp_path), did="did:web:owner.example:x", http=api)
    with pytest.raises(ValueError, match="enrollment token"):
        helix_init("https://h", "", str(tmp_path))
    with pytest.raises(ValueError, match="output directory"):
        helix_init("https://h", "t", "")
    no_docs = FakeApi({"POST /v1/agents/enroll/challenge": lambda body: {"did": DID, "kid": f"{DID}#key-1", "nonce": "n"}, "POST /v1/agents/enroll": lambda body: (201, {"did": DID, "status": "active"})})
    with pytest.raises(ValueError, match="did not return"):
        helix_init("https://h", "t", str(tmp_path), http=no_docs)
    custom = helix_init("https://helix.example", "enroll:t", str(tmp_path / "custom"), kid="agent-key", env_var="AGENT_KEY", http=api)
    assert custom.kid == f"{DID}#agent-key"
    assert "AGENT_KEY=" in Path(custom.files["signing_key"]).read_text()


# ---------------------------------------------------- change to self custody


def test_change_to_self_custody_sends_only_the_public_key_and_a_proof(tmp_path: Path) -> None:
    sent: Dict[str, Any] = {}

    def change(body: Dict[str, Any]) -> Any:
        sent.update(body)
        kid = f"{DID}#{body['kid']}"
        return {"did": DID, "keyCustody": "self", "didHosting": "own", "label": "custody: self", "kid": kid, "previousKeyShredded": True, "publishRequired": True, "documents": documents_for(DID, kid, body["publicKeyJwk"]["x"], "https://owner.example")}

    api = FakeApi({f"POST /v1/agents/{DID}/custody": change})
    out = change_to_self_custody(HelixCustodyClient("https://helix.example", admin_api_key="admin", http=api), DID, str(tmp_path), kid="key-2", overlap_seconds=60, generate_key=fixed_key)
    assert out["result"]["previousKeyShredded"] is True
    assert sorted(sent) == ["keyCustody", "kid", "overlapSeconds", "proof", "publicKeyJwk"]
    nacl.signing.VerifyKey(bytes.fromhex(PUBLIC_HEX)).verify(rotation_proof_message(DID, f"{DID}#key-2", sent["proof"]["issuedAt"]), base64url_decode(sent["proof"]["signature"]))
    api.assert_no_private_material_sent()
    assert f"HELIX_SIGNING_KEY={SEED_HEX}" in (tmp_path / "signing-key.env").read_text()
    assert json.loads((tmp_path / "did.json").read_text())["id"] == DID
    helix_hosted = FakeApi({f"POST /v1/services/{DID}/custody": lambda body: {"did": DID, "kid": f"{DID}#{body['kid']}", "didHosting": "helix", "publishRequired": False, "documents": {}}})
    second = change_to_self_custody(HelixCustodyClient("https://h", http=helix_hosted), DID, str(tmp_path / "svc"), subject="service")
    assert second["result"]["kid"].startswith(f"{DID}#key-")
    assert not (tmp_path / "svc" / "did.json").exists()


# ------------------------------------------------------------- command line


def _run(*args: str) -> Tuple[int, str, str]:
    import io

    out, err = io.StringIO(), io.StringIO()
    code = main(list(args), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def _seed_from(env_file: Path) -> str:
    import re

    found = re.search(r"HELIX_SIGNING_KEY=([0-9a-f]{64})", env_file.read_text(encoding="utf-8"))
    assert found is not None
    return found.group(1)


def test_cli_init_on_helix_hosting_reports_like_the_js_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import helix_sdk.custody as custody_module

    api = init_api(DID, "helix", "https://helix.example/acme/bot-1", "active")
    monkeypatch.setattr(custody_module, "_requests_call", api)
    code, out, _ = _run("init", "--token", "enroll:t", "--out", str(tmp_path / "a"), "--api-url", "https://helix.example")
    assert code == 0
    seed = _seed_from(tmp_path / "a" / "signing-key.env")
    for call in api.calls:
        assert seed not in (call["body"] or "")
    assert out.startswith(f"\u2713 Agent enrolled and active: {DID}\n")
    assert f"Key:        {DID}#key-1 (custody: self, generated here; only the public key was sent)" in out
    assert "Credential: vc:1" in out
    assert "(private key, mode 0600: keep it on this host)" in out
    assert "Publish the two documents" not in out

    code, out, _ = _run("init", "--token", "enroll:t", "--out", str(tmp_path / "j"), "--api-url", "https://helix.example", "--json")
    assert code == 0
    assert json.loads(out) == {
        "did": DID,
        "kid": f"{DID}#key-1",
        "label": "custody: self",
        "didHosting": "helix",
        "status": "active",
        "files": {name: str(tmp_path / "j" / file) for name, file in INIT_FILES.items()},
        "didDocumentUrl": "https://helix.example/acme/bot-1/did.json",
        "cardUrl": "https://helix.example/acme/bot-1/card.json",
        "resolution": None,
        "vcId": "vc:1",
    }


def test_cli_own_hosting_pending_then_activate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import helix_sdk.custody as custody_module

    did = "did:web:owner.example:agents:bot"
    own = init_api(did, "own", "https://owner.example/agents/bot", "pending_resolution")
    monkeypatch.setattr(custody_module, "_requests_call", own)
    monkeypatch.setattr(custody_module, "resolve_entity_card", lambda did, fetch_json=None: (_ for _ in ()).throw(RuntimeError("not published")))
    code, out, _ = _run("init", "--token", "enroll:t", "--out", str(tmp_path / "b"), "--api-url", "https://h", "--did", did)
    assert code == 0
    assert out.startswith(f"\u26a0 Agent enrolled, waiting for its documents on your domain: {did}")
    assert "Publish the two documents, then activate:" in out
    assert f"{tmp_path / 'b' / 'did.json'}  ->  https://owner.example/agents/bot/did.json" in out
    assert "(not resolving yet: not published)" in out
    assert f"helix-custody activate --token <token> --out {tmp_path / 'b'}" in out

    code, out, _ = _run("activate", "--token", "enroll:t", "--out", str(tmp_path / "b"), "--api-url", "https://h")
    assert (code, out) == (0, "\u26a0 Not active yet: not published\n")
    assert not any(call["url"].endswith("/activate") for call in own.calls)

    documents = json.loads((tmp_path / "b" / "did.json").read_text(encoding="utf-8"))
    card = json.loads((tmp_path / "b" / "card.json").read_text(encoding="utf-8"))
    monkeypatch.setattr(custody_module, "resolve_entity_card", lambda did, fetch_json=None: type("R", (), {"did_document": documents, "card": card})())
    code, out, _ = _run("activate", "--token", "enroll:t", "--out", str(tmp_path / "b"), "--api-url", "https://h")
    assert (code, out) == (0, f"\u2713 Agent active: {did}\n")
    code, out, _ = _run("activate", "--token", "enroll:t", "--out", str(tmp_path / "b"), "--api-url", "https://h", "--json")
    assert json.loads(out)["status"] == "active"

    monkeypatch.setattr(custody_module, "resolve_entity_card", lambda did, fetch_json=None: (_ for _ in ()).throw(RuntimeError("x")))
    code, out, _ = _run("init", "--token", "enroll:t", "--out", str(tmp_path / "n"), "--api-url", "https://h", "--no-activate", "--kid", "key-1", "--env-var", "HELIX_SIGNING_KEY")
    assert code == 0 and "not resolving yet" not in out
    code, out, _ = _run("activate", "--token", "enroll:t", "--out", str(tmp_path / "n"), "--api-url", "https://h")
    assert out == "\u26a0 Not active yet: x\n"


def test_cli_activate_with_no_reason_and_failures_exit_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import helix_sdk.custody as custody_module

    pending = custody_module.HelixInitResult(did=DID, kid=f"{DID}#key-1", did_hosting="own", status="pending_resolution", label="custody: self", public_key_jwk={}, env_var="V", files={}, did_document_url="", card_url="")
    monkeypatch.setattr(custody_module, "activate_agent", lambda *a, **k: pending)
    assert _run("activate", "--token", "t", "--out", str(tmp_path), "--api-url", "https://h")[1] == "\u26a0 Not active yet: the documents do not resolve from your domain\n"
    monkeypatch.setattr(custody_module, "_requests_call", FakeApi({}))
    code, out, err = _run("init", "--token", "enroll:t", "--out", str(tmp_path / "e"), "--api-url", "https://h")
    assert (code, out) == (1, "")
    assert err.strip() == "/v1/agents/enroll/challenge"


def test_cli_custody_take_reports_like_the_js_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import helix_sdk.custody as custody_module

    def change(body: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "did": DID,
            "label": "custody: self",
            "kid": f"{DID}#{body['kid']}",
            "previousKid": f"{DID}#key-1",
            "previousKeyShredded": True,
            "retiresAt": "2026-11-23T00:00:00.000Z",
            "hopReissue": {"reissued": 0, "pending": True},
            "publishRequired": True,
            "documents": {"didDocument": {"id": DID}, "card": {"id": DID}, "didDocumentUrl": "u", "cardUrl": "c"},
        }

    take = FakeApi({f"POST /v1/agents/{DID}/custody": change})
    monkeypatch.setattr(custody_module, "_requests_call", take)
    code, out, _ = _run("custody", "take", "--did", DID, "--out", str(tmp_path / "c"), "--api-url", "https://h", "--admin-key", "admin", "--overlap", "60")
    assert code == 0
    seed = _seed_from(tmp_path / "c" / "signing-key.env")
    assert seed not in take.calls[0]["body"]
    assert sorted(json.loads(take.calls[0]["body"])) == ["keyCustody", "kid", "overlapSeconds", "proof", "publicKeyJwk"]
    assert take.calls[0]["headers"]["x-admin-api-key"] == "admin"
    lines = out.splitlines()
    assert lines[0] == f"\u2713 {DID} is now custody: self"
    assert lines[1].startswith(f"New key:      {DID}#key-") and lines[1].endswith(f"(generated here; private key in {tmp_path / 'c' / 'signing-key.env'})")
    assert lines[2] == f"Previous key: {DID}#key-1, in the DID document until 2026-11-23T00:00:00.000Z, shredded in Helix"
    assert lines[3] == "Hops:         not reissued (story C-E)"
    assert lines[4] == f"Publish the updated did.json and card.json from {tmp_path / 'c'} on your domain."

    quiet = FakeApi({f"POST /v1/services/{DID}/custody": lambda body: {"did": DID, "label": "custody: self", "kid": f"{DID}#{body['kid']}", "previousKid": f"{DID}#key-1", "retiresAt": "r", "hopReissue": {"reissued": 1, "pending": False}, "documents": {}}})
    monkeypatch.setattr(custody_module, "_requests_call", quiet)
    code, out, _ = _run("take", "--did", DID, "--out", str(tmp_path / "s"), "--api-url", "https://h", "--api-key", "acc", "--subject", "service")
    assert code == 0
    assert "shredded" not in out and "not reissued" not in out and "Publish the updated" not in out
    assert quiet.calls[0]["headers"]["authorization"] == "Bearer acc"
    code, out, _ = _run("take", "--did", DID, "--out", str(tmp_path / "s2"), "--api-url", "https://h", "--subject", "service", "--json")
    assert json.loads(out)["label"] == "custody: self"


def test_parity_helpers_and_exports() -> None:
    import helix_sdk
    import helix_sdk.custody as custody_module

    signer = EnvSigner(DID, kid="#signing", env={"HELIX_SIGNING_KEY": SEED_HEX})
    assert custody_module.verification_method_of(signer) == f"{DID}#signing"
    assert custody_module.verification_method_of(type("S", (), {"did": DID, "kid": "#k"})()) == f"{DID}#k"
    assert [custody_module._base36(n) for n in (0, 35, 36, 1795347962687)] == ["0", "z", "10", "mwrrtlxb"]
    for name in ("custody", "EnvSigner", "Signer", "HelixCustodialSigner", "HelixCustodyClient", "helix_init", "activate_agent", "check_own_hosting", "change_to_self_custody", "rotation_proof", "verification_method_of", "KeyCustodyMode", "DidHostingMode", "CustodyLabel"):
        assert name in helix_sdk.__all__ and hasattr(helix_sdk, name), name
    assert {"enrollmentToken", "documents", "publishRequired", "vcId"} <= set(custody_module.OnboardingResult.__annotations__)
    assert custody_module.OnboardingResult.__total__ is False and custody_module.CustodyView.__total__ is True
    assert set(custody_module.CustodyView.__annotations__) == {"did", "subjectType", "name", "keyCustody", "didHosting", "label", "conformant", "status", "kid", "credentialVcId", "keys"}
