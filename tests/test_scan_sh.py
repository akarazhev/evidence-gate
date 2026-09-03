"""Tests for the scanner entry point.

The refusal path must work without semgrep installed, which is why rule
resolution happens before semgrep is invoked.
"""

import subprocess
import unittest

from tests import REPO_ROOT
from tests.helpers import temp_tree

SCAN = REPO_ROOT / "scripts" / "scan.sh"


class TestScanScript(unittest.TestCase):
    def run_scan(self, repo, env_config):
        env = {"PATH": "/usr/bin:/bin", "SEMGREP_CONFIG": env_config}
        return subprocess.run(
            ["/bin/sh", str(SCAN), str(repo)],
            capture_output=True,
            text=True,
            cwd=str(repo),
            env=env,
        )

    def test_empty_rules_directory_refuses(self):
        with temp_tree({"rules/README.md": "placeholder\n"}) as root:
            proc = self.run_scan(root, str(root / "rules"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED", proc.stderr)
        self.assertIn("SEMGREP_CONFIG", proc.stderr)

    def test_missing_rules_directory_refuses(self):
        with temp_tree({"placeholder": ""}) as root:
            proc = self.run_scan(root, str(root / "absent"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED", proc.stderr)

    def test_refusal_leaves_no_state_behind(self):
        with temp_tree({"rules/README.md": "placeholder\n"}) as root:
            self.run_scan(root, str(root / "rules"))
            self.assertFalse((root / "findings").exists())

    def test_telemetry_is_disabled_unconditionally(self):
        self.assertIn("--metrics=off", SCAN.read_text(encoding="utf-8"))

    def test_registry_config_prints_an_egress_banner(self):
        with temp_tree({"placeholder": ""}) as root:
            proc = self.run_scan(root, "p/security-audit")
        # semgrep is absent from the stripped PATH, so the run fails after the
        # banner. The banner itself is what this asserts.
        self.assertIn("NETWORK", proc.stderr)
        self.assertIn("docs/03-data-handling.md", proc.stderr)


if __name__ == "__main__":
    unittest.main()
