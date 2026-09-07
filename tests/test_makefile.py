"""Behavioral tests for Makefile entry points."""

import os
import subprocess
import unittest
from pathlib import Path

from tests import REPO_ROOT
from tests.helpers import temp_tree

MAKEFILE = REPO_ROOT / "Makefile"


class TestInstall(unittest.TestCase):
    def run_install(self, root: Path, version=None):
        bindir = root / "bin"
        bindir.mkdir()
        args_file = root / "pip-args.txt"
        fake_pip = bindir / "pip"
        fake_pip.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$@" > "{args_file}"\n',
            encoding="utf-8",
        )
        fake_pip.chmod(0o755)

        command = ["make", "-f", str(MAKEFILE), "install"]
        if version is not None:
            command.append(f"SEMGREP_VERSION={version}")
        env = os.environ.copy()
        env["PATH"] = f"{bindir}:/usr/bin:/bin"
        env.pop("SEMGREP_VERSION", None)
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=root,
            env=env,
        )
        return proc, args_file

    def test_install_refuses_an_unpinned_scanner_before_pip(self):
        with temp_tree({"placeholder": ""}) as root:
            proc, args_file = self.run_install(root)
            pip_was_called = args_file.exists()

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Set SEMGREP_VERSION=<version>.", proc.stdout)
        self.assertFalse(pip_was_called)

    def test_install_passes_the_exact_pinned_scanner_to_pip(self):
        with temp_tree({"placeholder": ""}) as root:
            proc, args_file = self.run_install(root, "1.2.3")
            pip_args = args_file.read_text(encoding="utf-8").splitlines()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(pip_args, ["install", "semgrep==1.2.3"])


if __name__ == "__main__":
    unittest.main()
