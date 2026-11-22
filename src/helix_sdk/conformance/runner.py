# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""The conformance runner (KYA-OS story F-2), the Python twin of helix-sdk-js
``kyaos/conformance/runner.ts``: loads the vendored vector files, feeds each
to the adapter, compares the adapter's accept or reject with ``expected``.
An exception is a harness failure, never a rejection.

    python -m helix_sdk.conformance [vectors_dir]
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .adapter import F2_CATEGORIES, METHOD_FOR_CATEGORY, HelixConformanceAdapter
from .delegation_binding import _json_int


def load_vectors(vectors_dir: os.PathLike, categories: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
    vectors: List[Dict[str, Any]] = []
    seen = set()
    for path in sorted(Path(vectors_dir).glob("*.json")):
        file = json.loads(path.read_text("utf-8"), parse_int=_json_int)
        if categories is not None and file["category"] not in categories:
            continue
        for vector in file["vectors"]:
            if vector["id"] in seen:
                raise ValueError(f"duplicate vector id {vector['id']} in {path.name}")
            seen.add(vector["id"])
            vectors.append(vector)
    return vectors


def run_conformance(adapter: Any, vectors: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    results = []
    for vector in vectors:
        try:
            method = getattr(adapter, METHOD_FOR_CATEGORY[vector["category"]])
            result = method(vector["input"])
            actual, detail = result["outcome"], result.get("detail")
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            actual, detail = "error", f"adapter raised: {exc}"
        results.append({"id": vector["id"], "category": vector["category"], "expected": vector["expected"], "actual": actual, "ok": actual == vector["expected"], "detail": detail})
    categories: Dict[str, Dict[str, int]] = {}
    for result in results:
        entry = categories.setdefault(result["category"], {"total": 0, "passed": 0})
        entry["total"] += 1
        entry["passed"] += 1 if result["ok"] else 0
    passed = sum(1 for result in results if result["ok"])
    return {"adapter": adapter.name, "total": len(results), "passed": passed, "failed": len(results) - passed, "results": results, "allMatched": passed == len(results), "categories": categories}


def format_report(report: Dict[str, Any]) -> str:
    lines = [f"KYA-OS conformance, adapter: {report['adapter']}", ""]
    for result in report["results"]:
        lines.append(f"  [{'PASS' if result['ok'] else 'FAIL'}] {result['id']} ({result['category']}): expected {result['expected']}, got {result['actual']}")
        if not result["ok"] and result.get("detail"):
            lines.append(f"         {result['detail']}")
    lines.append("")
    for category, totals in report["categories"].items():
        lines.append(f"  {category}: {totals['passed']}/{totals['total']}")
    lines.append(f"Total: {report['total']}  Passed: {report['passed']}  Failed: {report['failed']}")
    lines.append("RESULT: PASS (all vectors matched)" if report["allMatched"] else "RESULT: FAIL")
    return "\n".join(lines)


def main(argv: Sequence[str]) -> int:
    default = Path(__file__).resolve().parents[4] / "helix-core" / "fixtures" / "kya-os" / "conformance" / "vectors"
    vectors_dir = Path(argv[0]) if argv else Path(os.environ.get("HELIX_CORE_FIXTURES_DIR", "")) / "kya-os" / "conformance" / "vectors" if os.environ.get("HELIX_CORE_FIXTURES_DIR") else default
    report = run_conformance(HelixConformanceAdapter(), load_vectors(vectors_dir, F2_CATEGORIES))
    print(format_report(report))
    return 0 if report["allMatched"] else 1


if __name__ == "__main__":  # pragma: no cover - command-line entry
    sys.exit(main(sys.argv[1:]))
