# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
End-to-end CLI tests using Click's CliRunner -- these invoke the real
`helix` command tree (not the underlying Python functions directly),
against real wallet/status-list files on disk, the same way a person
running the CLI from a shell would.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from helix_cli.cli import cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def passphrase_env(monkeypatch):
    monkeypatch.setenv("HELIX_WALLET_PASSPHRASE", "test-cli-passphrase")
    return "test-cli-passphrase"


class TestDidCreate:
    def test_create_web_did_and_status_list(self, runner: CliRunner, passphrase_env, tmp_path: Path) -> None:
        wallet_path = tmp_path / "issuer.json"
        result = runner.invoke(
            cli, ["did", "create", "--method", "web", "--domain", "example.com", "--wallet", str(wallet_path)]
        )
        assert result.exit_code == 0, result.output
        assert "Issuer DID created: did:web:example.com" in result.output
        assert wallet_path.exists()

        status_list_path = tmp_path / "status-list.json"
        assert status_list_path.exists()
        status_list = json.loads(status_list_path.read_text())
        assert status_list["credentialSubject"]["type"] == "BitstringStatusList"
        assert status_list["proof"]["type"] == "Ed25519Signature2020"

    def test_create_key_did(self, runner: CliRunner, passphrase_env, tmp_path: Path) -> None:
        wallet_path = tmp_path / "agent.json"
        result = runner.invoke(cli, ["did", "create", "--method", "key", "--wallet", str(wallet_path)])
        assert result.exit_code == 0, result.output
        assert "Agent DID created: did:key:" in result.output
        assert wallet_path.exists()

    def test_create_refuses_existing_wallet(self, runner: CliRunner, passphrase_env, tmp_path: Path) -> None:
        wallet_path = tmp_path / "agent.json"
        wallet_path.write_text("{}")
        result = runner.invoke(cli, ["did", "create", "--method", "key", "--wallet", str(wallet_path)])
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_create_hedera_fails_loudly_not_silently(
        self, runner: CliRunner, passphrase_env, monkeypatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HEDERA_OPERATOR_ID", "0.0.1234")
        monkeypatch.setenv("HEDERA_OPERATOR_KEY", "fake-key")
        wallet_path = tmp_path / "hedera-agent.json"
        result = runner.invoke(cli, ["did", "create", "--method", "hedera", "--wallet", str(wallet_path)])
        assert result.exit_code == 1
        assert "not yet supported" in result.output
        assert not wallet_path.exists()

    def test_missing_passphrase_fails(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(cli, ["did", "create", "--method", "key", "--wallet", str(tmp_path / "x.json")])
        assert result.exit_code == 1
        assert "HELIX_WALLET_PASSPHRASE" in result.output


class TestIssuerAndVcLifecycle:
    def test_full_issue_and_revoke_flow(self, runner: CliRunner, passphrase_env, tmp_path: Path) -> None:
        wallet_path = tmp_path / "issuer.json"
        runner.invoke(
            cli, ["did", "create", "--method", "web", "--domain", "example.com", "--wallet", str(wallet_path)]
        )
        status_list_path = tmp_path / "status-list.json"

        init_result = runner.invoke(cli, ["issuer", "init", "--wallet", str(wallet_path)])
        assert init_result.exit_code == 0
        assert "Issuer ready" in init_result.output
        assert "did:web:example.com" in init_result.output

        vc_output_path = tmp_path / "agent-vc.json"
        issue_result = runner.invoke(
            cli,
            [
                "vc",
                "issue",
                "--agent-did",
                "did:key:zTestAgent",
                "--scopes",
                "read:orders,write:orders",
                "--expires",
                "90d",
                "--status-list",
                str(status_list_path),
                "--base-url",
                "https://example.com/.well-known/helix-status-list.json",
                "--wallet",
                str(wallet_path),
                "--output",
                str(vc_output_path),
            ],
        )
        assert issue_result.exit_code == 0, issue_result.output
        assert "VC issued" in issue_result.output
        assert vc_output_path.exists()

        issued_vc = json.loads(vc_output_path.read_text())
        assert issued_vc["credentialSubject"]["id"] == "did:key:zTestAgent"
        assert issued_vc["credentialSubject"]["privilegeScopes"] == ["read:orders", "write:orders"]
        assert issued_vc["proof"]["type"] == "Ed25519Signature2020"

        # Status index must be recorded in the updated status list's registry.
        updated_list = json.loads(status_list_path.read_text())
        assert issued_vc["id"] in updated_list["helixIndexRegistry"]

        # Revoke it and confirm the bit flips.
        revoke_result = runner.invoke(
            cli,
            [
                "revoke",
                "--vc-id",
                issued_vc["id"],
                "--status-list",
                str(status_list_path),
                "--wallet",
                str(wallet_path),
            ],
        )
        assert revoke_result.exit_code == 0, revoke_result.output
        assert "VC revoked" in revoke_result.output
        assert "0 → 1" in revoke_result.output

    def test_issue_rejects_empty_scopes(self, runner: CliRunner, passphrase_env, tmp_path: Path) -> None:
        wallet_path = tmp_path / "issuer.json"
        runner.invoke(
            cli, ["did", "create", "--method", "web", "--domain", "example.com", "--wallet", str(wallet_path)]
        )
        status_list_path = tmp_path / "status-list.json"

        result = runner.invoke(
            cli,
            [
                "vc",
                "issue",
                "--agent-did",
                "did:key:zTestAgent",
                "--scopes",
                "  ,  ",
                "--expires",
                "90d",
                "--status-list",
                str(status_list_path),
                "--base-url",
                "https://example.com/list.json",
                "--wallet",
                str(wallet_path),
            ],
        )
        assert result.exit_code == 1
        assert "At least one scope is required" in result.output


class TestSelfIssueAndInspect:
    def test_self_issue_and_inspect(self, runner: CliRunner, passphrase_env, tmp_path: Path) -> None:
        wallet_path = tmp_path / "agent.json"
        runner.invoke(cli, ["did", "create", "--method", "key", "--wallet", str(wallet_path)])

        self_issue_result = runner.invoke(
            cli,
            [
                "vc",
                "self-issue",
                "--scopes",
                "read:orders",
                "--expires",
                "24h",
                "--wallet",
                str(wallet_path),
            ],
        )
        assert self_issue_result.exit_code == 0, self_issue_result.output
        assert "for local development only" in self_issue_result.output

        inspect_result = runner.invoke(cli, ["wallet", "inspect", "--wallet", str(wallet_path)])
        assert inspect_result.exit_code == 0, inspect_result.output
        assert "Credentials: 1" in inspect_result.output
        assert "Scopes:  read:orders" in inspect_result.output
        # Must never print the private key.
        agent_wallet_json = json.loads(wallet_path.read_text())
        assert agent_wallet_json["encryptedPrivateKey"] not in inspect_result.output

    def test_inspect_missing_wallet_fails(self, runner: CliRunner, passphrase_env, tmp_path: Path) -> None:
        result = runner.invoke(cli, ["wallet", "inspect", "--wallet", str(tmp_path / "does-not-exist.json")])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_inspect_wrong_passphrase_fails(self, runner: CliRunner, passphrase_env, tmp_path: Path, monkeypatch) -> None:
        wallet_path = tmp_path / "agent.json"
        runner.invoke(cli, ["did", "create", "--method", "key", "--wallet", str(wallet_path)])

        monkeypatch.setenv("HELIX_WALLET_PASSPHRASE", "wrong-passphrase")
        result = runner.invoke(cli, ["wallet", "inspect", "--wallet", str(wallet_path)])
        assert result.exit_code != 0
        assert "Invalid passphrase" in result.output
