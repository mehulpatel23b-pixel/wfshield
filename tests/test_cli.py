import json
import tempfile
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wfshield import cli
from wfshield.scanner import ScanError

ROOT = os.path.join(os.path.dirname(__file__), "..")
EXAMPLES = os.path.join(ROOT, "examples")


class CliTextMode(unittest.TestCase):
    def test_vulnerable_example_exit_2(self):
        code = cli.main([os.path.join(EXAMPLES, "vulnerable.yml")])
        self.assertEqual(code, 2)

    def test_hardened_example_exit_0(self):
        code = cli.main(["--json", os.path.join(EXAMPLES, "hardened.yml")])
        self.assertEqual(code, 0)

    def test_directory_walk_finds_workflows(self):
        code = cli.main([EXAMPLES])
        self.assertEqual(code, 2)  # dir contains the vulnerable example


class CliJsonMode(unittest.TestCase):
    def _json(self, *argv):
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["--json", *argv])
        return code, json.loads(buf.getvalue())

    def test_json_shape(self):
        code, out = self._json(os.path.join(EXAMPLES, "vulnerable.yml"))
        self.assertEqual(code, 2)
        self.assertEqual(out["overall_verdict"], "BLOCK")
        self.assertEqual(out["exit_code"], 2)
        f = out["files"][0]
        self.assertIn("findings", f)
        self.assertIn("score", f)
        first = f["findings"][0]
        for key in ("rule", "severity", "line", "title", "detail", "fix"):
            self.assertIn(key, first)
        rules_seen = {x["rule"] for x in f["findings"]}
        self.assertIn("WF-001", rules_seen)
        self.assertIn("WF-005", rules_seen)

    def test_json_clean_file(self):
        code, out = self._json(os.path.join(EXAMPLES, "hardened.yml"))
        self.assertEqual(code, 0)
        self.assertEqual(out["overall_verdict"], "PASS")
        self.assertEqual(out["files"][0]["findings"], [])

    def test_error_json_on_missing_paths(self):
        code, out = self._json(os.path.join(EXAMPLES, "nope.yml"))
        self.assertEqual(code, 64)


class ScannerBehaviour(unittest.TestCase):
    def test_non_yml_ignored_in_dir_walk(self):
        from wfshield.scanner import _targets
        targets = _targets(EXAMPLES)
        self.assertTrue(all(t.endswith((".yml", ".yaml")) for t in targets))
        self.assertEqual(len(targets), 2)

    def test_missing_file_raises_scan_error(self):
        from wfshield.scanner import scan_file
        with self.assertRaises(ScanError):
            scan_file("/path/does/not/exist.yml")

    def test_yaml_without_jobs_raises_scan_error(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write("name: not a workflow\n")
            path = fh.name
        from wfshield.scanner import scan_file
        try:
            with self.assertRaises(ScanError):
                scan_file(path)
        finally:
            os.unlink(path)

    def test_no_input_targets_explodes(self):
        from wfshield.scanner import scan
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ScanError):
                scan([d])


if __name__ == "__main__":
    unittest.main()
