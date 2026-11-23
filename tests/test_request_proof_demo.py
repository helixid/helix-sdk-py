# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""examples/request_proof_demo.py runs offline and comes to its expected verdicts (KYA-OS story C-C)."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parents[1] / "examples" / "request_proof_demo.py"


def test_the_demo_signs_verifies_and_refuses_a_replay(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(DEMO), run_name="__main__")
    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "ok=True" in out and "['nonce_replayed']" in out and "['request_hash_mismatch']" in out and "['audience_mismatch']" in out
