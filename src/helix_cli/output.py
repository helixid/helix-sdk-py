# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Console output helpers, ported from helix-sdk-js's cli/src/lib/output.ts."""

from __future__ import annotations

import sys
from typing import NoReturn

import click


def success(message: str) -> None:
    click.echo(click.style(f"✓ {message}", fg="green"))


def error(message: str) -> NoReturn:
    click.echo(click.style(f"✗ {message}", fg="red"), err=True)
    sys.exit(1)


def warn(message: str) -> None:
    click.echo(click.style(f"⚠ {message}", fg="yellow"))
