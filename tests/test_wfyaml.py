import textwrap
import unittest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wfshield import wfyaml
from wfshield.wfyaml import Loc, parse, YamlError


def dedent(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


class ParserBasics(unittest.TestCase):
    def test_flat_map(self):
        d = parse("name: CI\ntrue_key: yes\n")
        self.assertEqual(str(d["name"]), "CI")

    def test_comments_ignored(self):
        d = parse("# a comment\nname: CI  # trailing\nfail-fast: false\n")
        self.assertEqual(str(d["name"]), "CI")
        self.assertIs(d["fail-fast"], False)

    def test_inline_list_triggers(self):
        d = parse("on: [push, pull_request]\n")
        self.assertEqual([str(v) for v in d["on"]], ["push", "pull_request"])

    def test_block_map_triggers_with_nested_keys(self):
        d = parse(dedent("""\
        on:
          push:
            branches: [ main ]
          schedule:
            - cron: "30 5 * * 1"
        """))
        self.assertIn("push", d["on"])
        self.assertIn("schedule", d["on"])
        cron = d["on"]["schedule"][0]["cron"]
        self.assertEqual(str(cron), "30 5 * * 1")

    def test_quoted_keys_and_values(self):
        d = parse('"on": push\nrunner: "ubuntu latest"\n')
        self.assertIn("on", d)
        self.assertEqual(str(d["runner"]), "ubuntu latest")

    def test_scalars(self):
        d = parse("n: 42\nf: 3.14\nb: true\nnil: null\ntilde: ~\n")
        self.assertEqual(d["n"], 42)
        self.assertEqual(d["f"], 3.14)
        self.assertIs(d["b"], True)
        self.assertIsNone(d["nil"])
        self.assertIsNone(d["tilde"])

    def test_empty_containers(self):
        d = parse("a: {}\nb: []\n")
        self.assertEqual(d["a"], {})
        self.assertEqual(d["b"], [])

    def test_lineno_tracking(self):
        d = parse("name: CI\n\n# c\npermissions: write-all\n")
        self.assertEqual(d["permissions"].lineno, 4)


class ParserSeqs(unittest.TestCase):
    def test_seq_at_deeper_indent(self):
        d = parse(dedent("""\
        on:
          push:
            branches:
              - main
              - dev
        """))
        self.assertEqual([str(x) for x in d["on"]["push"]["branches"]],
                         ["main", "dev"])

    def test_seq_at_same_indent_as_key(self):
        d = parse(dedent("""\
        steps:
        - name: A
          uses: actions/checkout@v4
        - name: B
          uses: ./.github/actions/x
        """))
        self.assertEqual(str(d["steps"][0]["name"]), "A")
        self.assertEqual(str(d["steps"][1]["uses"]), "./.github/actions/x")

    def test_mapping_items_with_nested_maps(self):
        d = parse(dedent("""\
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout
                uses: actions/checkout@v4
                with:
                  ref: refs/heads/main
                  depth: 1
        """))
        step = d["jobs"]["test"]["steps"][0]
        self.assertEqual(str(step["with"]["ref"]), "refs/heads/main")
        self.assertEqual(step["with"]["depth"], 1)

    def test_scalar_seq_items_with_colons(self):
        d = parse(dedent("""\
        list:
          - ubuntu-latest
          - ghcr.io/foo:latest
        """))
        self.assertEqual([str(x) for x in d["list"]],
                         ["ubuntu-latest", "ghcr.io/foo:latest"])

    def test_loc_survives_string_ops(self):
        d = parse("on: push\n")
        val = d["on"] + "-suffix"
        self.assertIsInstance(val, str)


class ParserBlockScalars(unittest.TestCase):
    def test_literal_block(self):
        d = parse(dedent("""\
        jobs:
          a:
            steps:
              - name: S
                run: |
                  echo one
                  echo two
        """))
        self.assertEqual(str(d["jobs"]["a"]["steps"][0]["run"]),
                         "echo one\necho two\n")

    def test_literal_block_strip(self):
        d = parse(dedent("""\
        run: |-
          echo x
        """))
        self.assertEqual(str(d["run"]), "echo x")

    def test_block_keeps_comments_and_blanks(self):
        d = parse(dedent("""\
        test:
          run: |
            # this stays
            if [ -f x ]; then
              cp x y
            fi

            echo done
        """))
        text = str(d["test"]["run"])
        self.assertIn("# this stays", text)
        self.assertIn("\n\n", text)
        self.assertIn("cp x y", text)

    def test_block_scalar_stops_at_dedent(self):
        d = parse(dedent("""\
        test:
          run: |
            echo one
        next: value
        """))
        self.assertEqual(str(d["test"]["run"]), "echo one\n")
        self.assertEqual(str(d["next"]), "value")

    def test_expression_chars_survive(self):
        d = parse(dedent("""\
        test:
          run: |
            echo "${{ matrix.os }} ${{ github.event.head_commit.message }}"
        """))
        text = str(d["test"]["run"])
        self.assertIn("${{ matrix.os }}", text)
        self.assertIn("github.event.head_commit.message", text)

    def test_folded_scalar(self):
        d = parse(dedent("""\
        test:
          text: >
            line one
            line two
        """))
        self.assertEqual(str(d["test"]["text"]), "line one line two\n")


class ParserHardCases(unittest.TestCase):
    def test_docker_uses_not_a_mapping(self):
        d = parse("uses: docker://alpine:3.19\n")
        self.assertEqual(str(d["uses"]), "docker://alpine:3.19")

    def test_colon_inside_value(self):
        d = parse("url: https://example.com:443/x\n")
        self.assertEqual(str(d["url"]), "https://example.com:443/x")

    def test_top_level_seq_rejected(self):
        with self.assertRaises(YamlError):
            parse("- a\n- b\n")

    def test_empty_document(self):
        self.assertEqual(parse(""), {})

    def test_overindented_garbage_does_not_crash(self):
        d = parse(dedent("""\
        a: 1
            b: 2
        c: 3
        """))
        self.assertEqual(str(d["c"]), "3")


if __name__ == "__main__":
    unittest.main()
