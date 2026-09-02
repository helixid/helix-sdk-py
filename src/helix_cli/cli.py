#!/usr/bin/env python3
# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix CLI, ported from helix-sdk-js's cli package (Commander.js -> Click).

    helix did create --method web --domain example.com --wallet issuer.json
    helix issuer init --wallet issuer.json
    helix status-list create --length 131072 --output status-list.json \\
        --base-url https://example.com/.well-known/helix-status-list.json \\
        --wallet issuer.json
    helix vc issue --agent-did did:key:... --scopes read:orders --expires 90d \\
        --status-list status-list.json --base-url https://... --wallet issuer.json
    helix vc self-issue --scopes read:orders --expires 24h --wallet agent.json
    helix revoke --vc-id urn:uuid:... --status-list status-list.json --wallet issuer.json
    helix wallet inspect --wallet agent.json
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import click

from helix_sdk import generate_key_pair, public_key_to_multibase
from helix_sdk.did import build_did_document
from helix_sdk.self_signed import self_issue_vc, SelfIssueOptions

from .duration import parse_duration
from .env import require_hedera_operator, require_passphrase
from .issuer_ops import (
    build_cli_status_list_payload,
    issue_agent_credential,
    parse_status_list_file,
    revoke_credential_in_status_list,
    sign_credential,
)
from .output import error, success
from .wallet_ops import load_issuer_key_material, load_wallet, save_new_wallet

DEFAULT_STATUS_LIST_LENGTH = 131072


@click.group()
@click.version_option(version="0.1.0", prog_name="helix")
def cli() -> None:
    """HelixID CLI for Platform Operator setup."""


# -- did ----------------------------------------------------------------------


@cli.group()
def did() -> None:
    """DID commands."""


@did.command("create")
@click.option("--method", required=True, type=click.Choice(["web", "hedera", "key"]), help="DID method")
@click.option("--domain", help="Domain for did:web (required for web method)")
@click.option(
    "--network", default="testnet", type=click.Choice(["testnet", "previewnet", "mainnet"]), help="Hedera network"
)
@click.option("--wallet", required=True, help="Path to encrypted wallet file")
@click.option("--status-list/--no-status-list", default=True, help="Create the initial status list (did:web only)")
@click.option("--status-list-length", type=int, help="Status list capacity in bits (did:web only)")
@click.option(
    "--status-list-output", help="Status list output file path (default: status-list.json next to the wallet file)"
)
@click.option(
    "--status-list-base-url",
    help="Public URL where the status list will be served "
    "(default: https://<domain>/.well-known/helix-status-list.json)",
)
def did_create(
    method: str,
    domain: str,
    network: str,
    wallet: str,
    status_list: bool,
    status_list_length: int,
    status_list_output: str,
    status_list_base_url: str,
) -> None:
    """Create a new DID and wallet (did:web also creates its initial status list)."""
    passphrase = require_passphrase()

    if Path(wallet).exists():
        error(f"Wallet file already exists: {wallet}. Use a different path or remove the file.")

    key_pair = generate_key_pair()

    if method == "web":
        if not domain:
            error("--domain is required for --method web")
        did_value = f"did:web:{domain}"
        did_document = build_did_document(did_value, key_pair.public_key)
        save_new_wallet(wallet, passphrase, did_value, key_pair)

        success(f"Issuer DID created: {did_value}")
        click.echo("")
        click.echo(f"Serve this file at: https://{domain}/.well-known/did.json")
        click.echo("")
        click.echo(json.dumps(did_document, indent=2))

        if status_list:
            resolved_output = status_list_output or str(Path(wallet).parent / "status-list.json")
            resolved_base_url = (
                status_list_base_url or f"https://{domain}/.well-known/helix-status-list.json"
            )
            click.echo("")
            _status_list_create(
                length=status_list_length or DEFAULT_STATUS_LIST_LENGTH,
                output=resolved_output,
                base_url=resolved_base_url,
                wallet=wallet,
            )
            click.echo("")
            click.echo("This command produced two artifacts. Host both on your domain:")
            click.echo(f"  1. DID document -> https://{domain}/.well-known/did.json")
            click.echo(f"  2. Status list  -> {resolved_base_url} (file: {resolved_output})")
        return

    if method == "key":
        did_value = f"did:key:{public_key_to_multibase(key_pair.public_key)}"
        save_new_wallet(wallet, passphrase, did_value, key_pair)
        success(f"Agent DID created: {did_value}")
        click.echo("")
        click.echo("Note: did:key is for agents, not issuers.")
        return

    if method == "hedera":
        # NOTE: unlike the JS CLI (which dynamically imports
        # @helixid/did-hedera), this Python SDK has no did-hedera package
        # ported yet -- see README's Known gaps. Rather than silently
        # produce a wallet with no on-ledger anchor, this fails loudly.
        require_hedera_operator()
        error(
            "did:hedera is not yet supported by helix-cli (Python) -- "
            "the did-hedera package has not been ported from helix-sdk-js yet. "
            "Use HelixClient.create_did('agent') against a running helix-api "
            "instance instead, or use the JS CLI for offline did:hedera anchoring."
        )
        return

    error(f"Unknown method: {method}")


# -- issuer ---------------------------------------------------------------------


@cli.group()
def issuer() -> None:
    """Issuer commands."""


@issuer.command("init")
@click.option("--wallet", required=True, help="Path to issuer wallet file")
def issuer_init(wallet: str) -> None:
    """Verify issuer wallet is ready."""
    passphrase = require_passphrase()
    issuer_material = load_issuer_key_material(wallet, passphrase)

    success("Issuer ready")
    click.echo("")
    click.echo(f"DID:                 {issuer_material.did}")
    click.echo(f"Public key:          ed25519:{issuer_material.public_key_hex}")
    click.echo(f"Verification method: {issuer_material.did}#key-1")


# -- status-list ------------------------------------------------------------------


@cli.group("status-list")
def status_list_group() -> None:
    """Status list commands."""


def _status_list_create(length: int, output: str, base_url: str, wallet: str) -> None:
    passphrase = require_passphrase()
    issuer_material = load_issuer_key_material(wallet, passphrase)

    payload = build_cli_status_list_payload(base_url, issuer_material.did, length)
    signed = sign_credential(payload, issuer_material.did, issuer_material.private_key_hex)

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(signed, indent=2), encoding="utf-8")

    success("StatusList created")
    click.echo("")
    click.echo(f"Output:   {output}")
    click.echo(f"Serve at: {base_url}")
    click.echo(f"Capacity: {length} credentials")


@status_list_group.command("create")
@click.option("--length", required=True, type=int, help="Status list capacity in bits")
@click.option("--output", required=True, help="Output file path")
@click.option("--base-url", required=True, help="Public URL where the status list will be served")
@click.option("--wallet", required=True, help="Path to issuer wallet file")
def status_list_create(length: int, output: str, base_url: str, wallet: str) -> None:
    """Create a signed BitstringStatusList credential file."""
    # Bypasses require_passphrase() being called twice in `did create`'s
    # nested call (_status_list_create already calls it) -- kept as two
    # entry points, same as the JS CLI's exported runStatusListCreate(),
    # to preserve the standalone `helix status-list create` command.
    _status_list_create(length=length, output=output, base_url=base_url, wallet=wallet)


# -- vc ---------------------------------------------------------------------------


@cli.group()
def vc() -> None:
    """VC commands."""


@vc.command("issue")
@click.option("--agent-did", required=True, help="Agent DID")
@click.option("--scopes", required=True, help="Comma-separated privilege scopes")
@click.option("--expires", required=True, help="Validity duration (e.g. 90d, 24h)")
@click.option("--status-list", "status_list_path", required=True, help="Path to status list JSON file")
@click.option("--base-url", required=True, help="Public status list URL")
@click.option("--wallet", required=True, help="Path to issuer wallet file")
@click.option("--output", help="Output VC file path (stdout if omitted)")
@click.option("--max-delegation-depth", default=1, type=int, help="Max delegation depth")
def vc_issue(
    agent_did: str,
    scopes: str,
    expires: str,
    status_list_path: str,
    base_url: str,
    wallet: str,
    output: str,
    max_delegation_depth: int,
) -> None:
    """Issue a HelixAgentCredential to an agent DID."""
    passphrase = require_passphrase()
    issuer_material = load_issuer_key_material(wallet, passphrase)
    scope_list = [s.strip() for s in scopes.split(",") if s.strip()]
    if not scope_list:
        error("At least one scope is required in --scopes")

    try:
        status_list_raw = json.loads(Path(status_list_path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        error(f"Status list file not found or invalid: {status_list_path}")
        return

    status_list_data = parse_status_list_file(status_list_raw)
    expires_ms = parse_duration(expires)

    issued_vc, updated_list, index = issue_agent_credential(
        issuer=issuer_material,
        agent_did=agent_did,
        scopes=scope_list,
        expires_ms=expires_ms,
        status_list=status_list_data,
        base_url=base_url,
        max_delegation_depth=max_delegation_depth,
    )

    Path(status_list_path).write_text(json.dumps(updated_list, indent=2), encoding="utf-8")

    vc_json = json.dumps(issued_vc, indent=2)
    if output:
        Path(output).write_text(vc_json, encoding="utf-8")
    else:
        click.echo(vc_json)

    success("VC issued")
    click.echo("")
    click.echo(f"Agent DID:    {agent_did}")
    click.echo(f"VC ID:        {issued_vc['id']}")
    click.echo(f"Scopes:       {', '.join(scope_list)}")
    click.echo(f"Expires:      {issued_vc['validUntil']}")
    click.echo(f"Status index: {index}")
    click.echo("")
    if output:
        click.echo(f"Send {output} to the agent out of band.")
    else:
        click.echo("Send the VC JSON above to the agent out of band.")
    click.echo("Agent runs: wallet.add_credential(vc) to store it.")


@vc.command("self-issue")
@click.option("--scopes", required=True, help="Comma-separated privilege scopes")
@click.option("--expires", required=True, help="Validity duration (e.g. 24h)")
@click.option("--wallet", required=True, help="Path to agent wallet file")
def vc_self_issue(scopes: str, expires: str, wallet: str) -> None:
    """Issue a self-signed dev credential to an agent wallet."""
    passphrase = require_passphrase()
    agent_wallet = load_wallet(wallet, passphrase)
    scope_list = [s.strip() for s in scopes.split(",") if s.strip()]

    agent_wallet.self_issue_vc(SelfIssueOptions(scopes=scope_list, expires_in=expires))

    click.echo("")
    click.echo(click.style("⚠ Self-signed VC — for local development only", fg="yellow"))
    click.echo("")
    click.echo("This VC is not trusted in production. Any verifier running")
    click.echo("verify_vp() in production mode will reject it.")
    click.echo("")
    click.echo(f"VC added to wallet: {wallet}")
    click.echo(f"Scopes: {', '.join(scope_list)}")
    click.echo(f"Expires: {expires}")


# -- revoke -------------------------------------------------------------------------


@cli.command("revoke")
@click.option("--vc-id", required=True, help="VC ID to revoke")
@click.option("--status-list", "status_list_path", required=True, help="Path to status list JSON file")
@click.option("--wallet", required=True, help="Path to issuer wallet file")
def revoke(vc_id: str, status_list_path: str, wallet: str) -> None:
    """Revoke a credential by flipping its status list bit."""
    passphrase = require_passphrase()
    issuer_material = load_issuer_key_material(wallet, passphrase)

    try:
        status_list_raw = json.loads(Path(status_list_path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        error(f"Status list file not found or invalid: {status_list_path}")
        return

    status_list_data = parse_status_list_file(status_list_raw)

    try:
        updated_list, index, previous_bit = revoke_credential_in_status_list(
            issuer=issuer_material, status_list=status_list_data, vc_id=vc_id
        )
        Path(status_list_path).write_text(json.dumps(updated_list, indent=2), encoding="utf-8")

        success("VC revoked")
        click.echo("")
        click.echo(f"VC ID:        {vc_id}")
        click.echo(f"Status index: {index}")
        click.echo(f"Bit flipped:  {previous_bit} → 1")
        click.echo("")
        click.echo(f"Push {status_list_path} to your HTTPS server.")
        click.echo("Verifiers will see the revocation on next StatusList fetch.")
    except ValueError as exc:
        error(str(exc))


# -- wallet -------------------------------------------------------------------------


@cli.group()
def wallet() -> None:
    """Wallet commands."""


@wallet.command("inspect")
@click.option("--wallet", "wallet_path", required=True, help="Path to wallet file")
def wallet_inspect(wallet_path: str) -> None:
    """Inspect wallet contents (never prints private key)."""
    passphrase = require_passphrase()
    agent_wallet = load_wallet(wallet_path, passphrase)

    click.echo(f"DID: {agent_wallet.get_did()}")
    click.echo(f"Public key: ed25519:{agent_wallet.get_public_key()}")
    click.echo(f"Credentials: {len(agent_wallet.credentials)}")

    for credential in agent_wallet.credentials:
        subject = credential.get("credentialSubject", {})
        scopes = ", ".join(subject.get("privilegeScopes", [])) if "privilegeScopes" in subject else "(none)"
        click.echo("")
        click.echo(f"  VC ID:   {credential['id']}")
        click.echo(f"  Scopes:  {scopes}")
        click.echo(f"  Expires: {credential.get('validUntil', '(none)')}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
