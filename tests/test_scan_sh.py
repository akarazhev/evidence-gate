"""Tests for the scanner entry point.

The refusal path must work without semgrep installed, which is why rule
resolution happens before semgrep is invoked.
"""

import subprocess
import unittest
from pathlib import Path

from tests import REPO_ROOT
from tests.helpers import temp_tree

SCAN = REPO_ROOT / "scripts" / "scan.sh"


class TestScanScript(unittest.TestCase):
    def run_scan(self, repo, env_config, bindir=None):
        # A stripped PATH is not a guarantee that semgrep is absent: package
        # managers do put it in /usr/bin. Tests that exercise the registry
        # branch must supply a stand-in on PATH, or they can reach the network.
        path = f"{bindir}:/usr/bin:/bin" if bindir else "/usr/bin:/bin"
        env = {"PATH": path, "SEMGREP_CONFIG": env_config}
        return subprocess.run(
            ["/bin/sh", str(SCAN), str(repo)],
            capture_output=True,
            text=True,
            cwd=str(repo),
            env=env,
        )

    def make_fake_semgrep(self, bindir: Path) -> Path:
        """Install a stand-in that records its arguments and exits 42.

        Returns the path it writes those arguments to. The distinctive exit
        code proves the stand-in is what ran, rather than a real semgrep found
        elsewhere on PATH or a silent failure that happens to look similar.
        """
        bindir.mkdir(parents=True, exist_ok=True)
        args_file = bindir / "args.txt"
        fake = bindir / "semgrep"
        fake.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$@" > "{args_file}"\n'
            "exit 42\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return args_file

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

    def test_local_rules_pass_metrics_off_and_the_local_config(self):
        with temp_tree({"rules/x.yaml": "rules: []\n"}) as root:
            args_file = self.make_fake_semgrep(root / "bin")
            proc = self.run_scan(root, str(root / "rules"), bindir=root / "bin")
            recorded = args_file.read_text(encoding="utf-8").split("\n")
        self.assertEqual(proc.returncode, 42, "the stand-in must be what ran")
        self.assertIn("--metrics=off", recorded)
        self.assertIn("--disable-version-check", recorded)
        self.assertIn(str(root / "rules"), recorded)
        self.assertNotIn("NETWORK", proc.stderr)

    def test_registry_config_announces_egress_and_still_disables_telemetry(self):
        with temp_tree({"placeholder": ""}) as root:
            args_file = self.make_fake_semgrep(root / "bin")
            proc = self.run_scan(root, "p/security-audit", bindir=root / "bin")
            recorded = args_file.read_text(encoding="utf-8").split("\n")
        self.assertEqual(proc.returncode, 42, "the stand-in must be what ran")
        self.assertIn("NETWORK", proc.stderr)
        self.assertIn("docs/03-data-handling.md", proc.stderr)
        self.assertIn("--metrics=off", recorded)
        self.assertIn("--disable-version-check", recorded)
        self.assertIn("p/security-audit", recorded)

    def test_arbitrary_https_config_is_described_as_remote_rules(self):
        with temp_tree({"placeholder": ""}) as root:
            self.make_fake_semgrep(root / "bin")
            proc = self.run_scan(
                root, "https://rules.example.invalid/custom.yml", bindir=root / "bin"
            )
        self.assertEqual(proc.returncode, 42, "the stand-in must be what ran")
        self.assertIn("remote rules", proc.stderr)
        self.assertNotIn("Semgrep registry", proc.stderr)


if __name__ == "__main__":
    unittest.main()
