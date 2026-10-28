"""wfshield — command line interface.

Usage:
    wfshield <path>... [--json]

Returns the aggregate exit code: 0 clean, 1 warnings, 2 blocked,
64 runtime error.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import rules as R
from . import scanner
from .scanner import ScanError

EXIT_USAGE = 64

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_BANNER = r"""
 ▄▄ ▄  ▄▄▄ ▄▓▄   ▄     ▄  ▄  ▄▄▄ ▄▄  ▄▓▄  ▄  ▄   ▄
 ▓▓ ▓  ▓  ▓ ▓▓ ▓ ▓▓▄    ▓▌ ▓▌ ▓  ▓ ▓▌ ▓ ▓ ▓▌ ▓▄▓▌ ▐▓
 ▓▓ ▓  ▓▓▓▓ ▓▓ ▓  ▓    ▓▓▌ ▓▌ ▓  ▓ ▓▌ ▓ ▓▓▌ ▓  ▌ ▐▓
 ▓█▄▀  ▓  ▓ ▓▓▌ ▓ ▄▓▀   ▓▓ ▓▓ ▓▓▓▓ ▓▓▓▓ ▓  ▌ ▓   ▐▓▄▄▄
"""


def _render(result: dict) -> str:
    out: List[str] = []
    out.append("wfshield — GitHub Actions workflow security audit")
    out.append("")
    for res in result["files"]:
        out.append(f"──[ {res['file']} ]{'─' * max(0, 60 - len(res['file']))}")
        if not res["findings"]:
            out.append("  ✓ no findings — workflow ships the house style")
        fs = sorted(res["findings"],
                    key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.rule))
        for f in fs:
            loc = f"line {f.line}  " if f.line else ""
            out.append(f"  [{f.severity:<8}] {f.rule}  {loc}{f.title}")
            out.append(f"      · {f.detail}")
            out.append(f"      ✓ fix: {f.fix}")
            out.append("")
    counts = {}
    for res in result["files"]:
        for sev, n in res["counts"].items():
            counts[sev] = counts.get(sev, 0) + n
    if counts:
        summary = ", ".join(
            f"{n} {sev}" for sev, n in
            sorted(counts.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9)))
        out.append(f"  score {result['total_score']}"
                   f"  →  {result['overall_verdict']}   ({summary})")
    else:
        out.append(f"  score 0  →  PASS")
    for err in result.get("errors", []):
        out.append(f"  ✓✗ {err}")
    return "\n".join(out)


def _to_json(result: dict) -> str:
    out = {
        "total_score": result["total_score"],
        "overall_verdict": result["overall_verdict"],
        "exit_code": result["exit_code"],
        "total_findings": result["total_findings"],
        "errors": result["errors"],
        "files": [
            {
                "file": r["file"],
                "score": r["score"],
                "verdict": r["verdict"],
                "exit_code": r["exit_code"],
                "counts": r["counts"],
                "findings": [
                    {
                        "rule": f.rule,
                        "severity": f.severity,
                        "line": f.line,
                        "title": f.title,
                        "detail": f.detail,
                        "fix": f.fix,
                    }
                    for f in r["findings"]
                ],
            }
            for r in result["files"]
        ],
    }
    return json.dumps(out, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="wfshield",
        description="Audit GitHub Actions workflows for CI supply-chain "
                    "risks (unpinned actions, over-broad tokens, untrusted "
                    "interpolation, secret leakage).")
    ap.add_argument("paths", nargs="+",
                    help="workflow files, or directories to search for *.yml")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON instead of text")
    args = ap.parse_args(argv)

    try:
        result = scanner.scan(args.paths)
    except ScanError as exc:
        if args.json:
            print(json.dumps({"error": str(exc), "exit_code": EXIT_USAGE}))
        else:
            print(f"wfshield: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        print(_to_json(result))
    else:
        print(_render(result))
    return result["exit_code"]


def run() -> int:
    sys.exit(main())


if __name__ == "__main__":
    run()
