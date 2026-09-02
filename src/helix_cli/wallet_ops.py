# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Wallet loading/saving CLI helpers, ported from helix-sdk-js's cli/src/lib/wallet.ts."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from helix_sdk import AgentWallet, KeyPair
from .issuer_ops import IssuerKeyMaterial


def load_wallet(wallet_path: str, passphrase: str) -> AgentWallet:
    if not Path(wallet_path).exists():
        click.echo(click.style(f"Error: Wallet file not found: {wallet_path}", fg="red"), err=True)
        click.echo(
            click.style(
                "Create one with: helix did create --method web --domain example.com --wallet <path>",
                fg="yellow",
            ),
            err=True,
        )
        sys.exit(1)

    try:
        return AgentWallet.load(wallet_path, passphrase)
    except Exception:  # noqa: BLE001
        click.echo(click.style("Error: Invalid passphrase or corrupted wallet", fg="red"), err=True)
        sys.exit(1)


def load_issuer_key_material(wallet_path: str, passphrase: str) -> IssuerKeyMaterial:
    wallet = load_wallet(wallet_path, passphrase)
    return IssuerKeyMaterial(
        did=wallet.get_did(), private_key_hex=wallet.get_private_key_hex(), public_key_hex=wallet.get_public_key()
    )


def save_new_wallet(wallet_path: str, passphrase: str, did: str, key_pair: KeyPair) -> None:
    wallet = AgentWallet(
        private_key_hex=key_pair.private_key, did_value=did, wallet_path=wallet_path, passphrase=passphrase
    )
    wallet.save(wallet_path)
