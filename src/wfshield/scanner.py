"""wfshield scanner — walk files/directories, parse workflows, run rules."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from . import rules
from .rules import Finding, verdict_for
from .wfyaml import parse, YamlError

WORKFLOW_DIRS = (".github/workflows", ".github\\workflows")
WORKFLOW_EXTS = (".yml", ".yaml")


class ScanError(Exception):
    """A file could not be read or parsed."""


def _targets(path: str) -> List[str]:
    """Expand a user-supplied path into workflow file candidates."""
    if os.path.isdir(path):
        found: List[str] = []
        for root, _dirs, files in os.walk(path):
            if os.sep + ".git" + os.sep in root + os.sep:
                continue
            for name in files:
                if name.lower().endswith(WORKFLOW_EXTS):
                    found.append(os.path.join(root, name))
        found.sort()
        return found
    if os.path.isfile(path):
        return [path]
    return []


def scan_file(path: str) -> Dict[str, Any]:
    """Analyse one YAML file. Raises ScanError on read/parse failure."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise ScanError(f"cannot read {path}: {exc}") from exc
    rel = os.path.relpath(path)
    try:
        data = parse(text)
    except YamlError as exc:
        raise ScanError(f"{rel}: structurally invalid workflow ({exc})") from exc
    if not isinstance(data, dict) or "jobs" not in data:
        raise ScanError(f"{rel}: no 'jobs:' block — not a workflow file; skipping")
    findings = rules.analyse_workflow(data, rel)
    score = rules.score_findings(findings)
    verdict, code = verdict_for(score)
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "file": rel,
        "findings": findings,
        "score": score,
        "verdict": verdict,
        "exit_code": code,
        "counts": counts,
    }


def scan(paths: List[str]) -> Dict[str, Any]:
    """Scan every target; returns a result dict ready for JSON output."""
    files: List[str] = []
    for p in paths:
        files.extend(_targets(p))
    if not files:
        raise ScanError("no workflow files found at the given paths")

    results: List[Dict[str, Any]] = []
    errors: List[str] = []
    for f in (files or []):
        try:
            results.append(scan_file(f))
        except ScanError as exc:
            errors.append(str(exc))

    total = sum(r["score"] for r in results)
    worst = max((r["exit_code"] for r in results), default=0)
    verdict, _ = verdict_for(sum(r["score"] for r in results) or 0)
    overall_score = total
    overall_verdict, overall_code = verdict_for(overall_score)
    overall_code = max(overall_code, worst)
    return {
        "files": results,
        "errors": errors,
        "total_score": overall_score,
        "overall_verdict": overall_verdict,
        "exit_code": overall_code,
        "verdict": overall_verdict,
        "total_findings": sum(len(r["findings"]) for r in results),
    }
