import os
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wfshield import rules
from wfshield.wfyaml import parse


EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def dedent(t: str) -> str:
    return textwrap.dedent(t).lstrip("\n")


def analyse(text: str):
    return rules.analyse_workflow(parse(text), "test.yml")


def codes(findings):
    return [f.rule for f in findings]


class PinningRules(unittest.TestCase):
    def test_unpinned_third_party_action_is_high(self):
        f = analyse("on: push\njobs:\n  a:\n    steps:\n"
                    "      - uses: random-org/cool-action@main\n")
        self.assertIn(("WF-001", "HIGH"), [(x.rule, x.severity) for x in f])

    def test_unpinned_third_party_tag_is_high(self):
        f = analyse("on: push\njobs:\n  a:\n    steps:\n"
                    "      - uses: org/action@v1.2\n")
        self.assertIn("WF-001", codes(f))

    def test_sha_pinned_action_is_clean(self):
        f = analyse("on: push\njobs:\n  a:\n    steps:\n"
                    "      - uses: org/action@a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e\n")
        self.assertNotIn("WF-001", codes(f))

    def test_official_action_tag_is_low_only(self):
        f = analyse("on: push\njobs:\n  a:\n    steps:\n"
                    "      - uses: actions/checkout@v4\n")
        self.assertIn("WF-002", codes(f))
        self.assertNotIn("WF-001", codes(f))
        sev = [x.severity for x in f if x.rule == "WF-002"]
        self.assertEqual(sev, ["LOW"])

    def test_official_action_sha_pinned_clean(self):
        f = analyse("on: push\njobs:\n  a:\n    steps:\n"
                    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n")
        self.assertNotIn("WF-002", codes(f))

    def test_local_action_clean(self):
        f = analyse("on: push\njobs:\n  a:\n    steps:\n"
                    "      - uses: ./local-action\n")
        self.assertNotIn("WF-001", codes(f))

    def test_docker_pinned_by_digest_clean(self):
        f = analyse("on: push\njobs:\n  a:\n    steps:\n"
                    "      - uses: docker://alpine@sha256:abc123\n")
        self.assertNotIn("WF-001", codes(f))

    def test_docker_tag_only_is_medium(self):
        f = analyse("on: push\njobs:\n  a:\n    steps:\n"
                    "      - uses: docker://alpine:3.19\n")
        w = [x for x in f if x.rule == "WF-001"]
        self.assertEqual([x.severity for x in w], ["MEDIUM"])

    def test_unpinned_reusable_workflow_call(self):
        f = analyse(dedent("""\
        on: push
        jobs:
          a:
            uses: owner/helper@v1
            secrets: inherit
        """))
        self.assertIn("WF-001", codes(f))
        self.assertIn("WF-010", codes(f))


class PermissionRules(unittest.TestCase):
    def test_write_all_top_level(self):
        f = analyse("on: push\npermissions: write-all\njobs:\n  a: {}\n")
        w = [x for x in f if x.rule == "WF-003"]
        self.assertEqual([x.severity for x in w], ["HIGH"])

    def test_write_all_job_level(self):
        f = analyse("on: push\npermissions: write-all\njobs:\n  a:\n"
                    "    permissions: write-all\n")
        w = [x for x in f if x.rule == "WF-003"]
        self.assertEqual(len(w), 2)

    def test_missing_permissions_block(self):
        f = analyse("on: push\njobs:\n  a:\n    steps:\n      - run: ls\n")
        self.assertIn("WF-004", codes(f))

    def test_explicit_read_permissions_no_finding(self):
        f = analyse("on: push\npermissions:\n  contents: read\njobs:\n  a:\n"
                    "    steps:\n      - run: ls\n")
        self.assertNotIn("WF-004", codes(f))
        self.assertNotIn("WF-003", codes(f))


class PullRequestTargetRules(unittest.TestCase):
    def test_fork_head_checkout_is_critical(self):
        f = analyse(dedent("""\
        on: pull_request_target
        jobs:
          a:
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - run: ./dangerous.sh
        """))
        w = [x for x in f if x.rule == "WF-005"]
        self.assertEqual([x.severity for x in w], ["CRITICAL"])

    def test_base_checkout_no_finding(self):
        f = analyse(dedent("""\
        on: pull_request_target
        jobs:
          a:
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: refs/heads/main
              - run: ./safe.sh
        """))
        self.assertNotIn("WF-005", codes(f))

    def test_git_fetch_fork_in_run_block(self):
        f = analyse(dedent("""\
        on: pull_request_target
        jobs:
          a:
            steps:
              - run: |
                  git fetch origin ${{ github.event.pull_request.head.sha }}
                  make test
        """))
        self.assertIn("WF-005", codes(f))

    def test_no_trigger_no_finding(self):
        f = analyse(dedent("""\
        on: push
        jobs:
          a:
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: refs/heads/main
        """))
        self.assertNotIn("WF-005", codes(f))


class InjectionRules(unittest.TestCase):
    def test_event_context_in_run_is_high(self):
        f = analyse(dedent("""\
        on: push
        jobs:
          a:
            steps:
              - run: echo "${{ github.event.head_commit.message }}"
        """))
        w = [x for x in f if x.rule == "WF-006"]
        self.assertEqual([x.severity for x in w], ["HIGH"])

    def test_head_ref_in_run_is_high(self):
        f = analyse(dedent("""\
        on: pull_request
        jobs:
          a:
            steps:
              - run: git switch ${{ github.head_ref }}
        """))
        self.assertIn("WF-006", codes(f))

    def test_safe_contexts_pass(self):
        f = analyse(dedent("""\
        on: push
        jobs:
          a:
            steps:
              - run: |
                  echo "${{ github.sha }}" "${{ github.event_name }}"
                  echo "${{ matrix.os }}" "${{ runner.arch }}"
        """))
        self.assertNotIn("WF-006", codes(f))

    def test_secret_in_run_is_separate_high(self):
        f = analyse(dedent("""\
        on: push
        jobs:
          a:
            steps:
              - run: echo ${{ secrets.GITHUB_TOKEN }}
        """))
        self.assertIn("WF-007", codes(f))
        self.assertNotIn("WF-006", codes(f))

    def test_secret_via_env_is_clean(self):
        f = analyse(dedent("""\
        on: push
        jobs:
          a:
            steps:
              - env:
                  TOKEN: ${{ secrets.GITHUB_TOKEN }}
                run: ./build.sh
        """))
        self.assertNotIn("WF-007", codes(f))


class RunnerRules(unittest.TestCase):
    def test_self_hosted_with_pull_request(self):
        f = analyse("on: [pull_request]\njobs:\n  a:\n    runs-on: self-hosted\n"
                    "    steps:\n      - run: make\n")
        w = [x for x in f if x.rule == "WF-008"]
        self.assertEqual([x.severity for x in w], ["HIGH"])

    def test_self_hosted_push_only_clean(self):
        f = analyse("on: push\njobs:\n  a:\n    runs-on: self-hosted\n"
                    "    steps:\n      - run: make\n")
        self.assertNotIn("WF-008", codes(f))

    def test_hosted_runner_fork_clean(self):
        f = analyse("on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                    "    steps:\n      - run: make\n")
        self.assertNotIn("WF-008", codes(f))


class SupplyChainRules(unittest.TestCase):
    def test_curl_pipe_bash(self):
        f = analyse(dedent("""\
        on: push
        jobs:
          a:
            steps:
              - run: curl -sSL https://x.example/i.sh | bash
        """))
        self.assertIn("WF-009", codes(f))

    def test_wget_pipe_sudo_python(self):
        f = analyse(dedent("""\
        on: push
        jobs:
          a:
            steps:
              - run: |
                  wget -qO- https://x.example/i.py | sudo python3
        """))
        self.assertIn("WF-009", codes(f))

    def test_verified_download_clean(self):
        f = analyse(dedent("""\
        on: push
        jobs:
          a:
            steps:
              - run: |
                  curl -sSL -o /tmp/i.sh https://x.example/i.sh
                  echo "$HASH  /tmp/i.sh" | sha256sum -c -
                  bash /tmp/i.sh
        """))
        self.assertNotIn("WF-009", codes(f))

    def test_cache_with_pull_request(self):
        f = analyse(dedent("""\
        on: [push, pull_request]
        jobs:
          a:
            steps:
              - uses: actions/cache@v4
        """))
        self.assertIn("WF-011", codes(f))

    def test_cache_push_only_clean(self):
        f = analyse(dedent("""\
        on: push
        jobs:
          a:
            steps:
              - uses: actions/cache@v4
        """))
        self.assertNotIn("WF-011", codes(f))


class Scoring(unittest.TestCase):
    def test_verdict_thresholds(self):
        self.assertEqual(rules.verdict_for(0), ("PASS", 0))
        self.assertEqual(rules.verdict_for(14), ("PASS", 0))
        self.assertEqual(rules.verdict_for(15), ("WARN", 1))
        self.assertEqual(rules.verdict_for(29), ("WARN", 1))
        self.assertEqual(rules.verdict_for(30), ("BLOCK", 2))

    def test_vulnerable_example_blocks(self):
        from wfshield.scanner import scan_file
        r = scan_file(os.path.join(EXAMPLES, "vulnerable.yml"))
        self.assertEqual(r["verdict"], "BLOCK")
        self.assertGreaterEqual(r["score"], 30)
        self.assertEqual(r["exit_code"], 2)

    def test_hardened_example_passes(self):
        from wfshield.scanner import scan_file
        r = scan_file(os.path.join(EXAMPLES, "hardened.yml"))
        self.assertEqual(r["verdict"], "PASS")
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["exit_code"], 0)

    def test_line_numbers_are_real(self):
        f = analyse("on: push\njobs:\n  a:\n    steps:\n"
                    "      - uses: org/action@v1\n")
        w = [x for x in f if x.rule == "WF-001"]
        self.assertEqual(w[0].line, 5)


if __name__ == "__main__":
    unittest.main()
