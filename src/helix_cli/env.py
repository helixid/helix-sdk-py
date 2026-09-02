# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Environment variable helpers, ported from helix-sdk-js's cli/src/lib/env.ts."""

from __future__ import annotations

import os
import sys
from typing import Tuple

import click


def require_passphrase() -> str:
    passphrase = os.environ.get("HELIX_WALLET_PASSPHRASE")
    if not passphrase:
        click.echo(
            click.style("Error: HELIX_WALLET_PASSPHRASE environment variable is required", fg="red"),
            err=True,
        )
        sys.exit(1)
    return passphrase


def require_hedera_operator() -> Tuple[str, str]:
    operator_id = os.environ.get("HEDERA_OPERATOR_ID")
    operator_key = os.environ.get("HEDERA_OPERATOR_KEY")
    if not operator_id or not operator_key:
        click.echo(
            click.style(
                "Error: HEDERA_OPERATOR_ID and HEDERA_OPERATOR_KEY environment variables are required",
                fg="red",
            ),
            err=True,
        )
        sys.exit(1)
    return operator_id, operator_key
