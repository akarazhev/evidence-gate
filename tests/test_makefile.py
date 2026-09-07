"""Behavioral tests for Makefile entry points."""

import json
import os
import subprocess
import unittest
from pathlib import Path

from tests import REPO_ROOT
from tests.helpers import FIXTURES, temp_tree

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


class TestQueueTargets(unittest.TestCase):
    def run_make(self, root, target, *variables):
        return subprocess.run(
            ["make", "-f", str(MAKEFILE), target, *variables],
            cwd=root, capture_output=True, text=True,
        )

    def test_list_and_index_forward_the_same_filters_and_repository(self):
        recorder = "import json, sys\nfrom pathlib import Path\nPath('argv.json').write_text(json.dumps(sys.argv[1:]))\n"
        with temp_tree({
            "scripts/build_packet.py": recorder, "app/one.py": "", "app/two.py": "",
        }) as root:
            for target, selector in (("list", ["--list"]), ("triage", ["--index", "2"])):
                with self.subTest(target=target):
                    proc = self.run_make(root, target, "REPO=source", "SARIF=input.sarif", "N=2",
                                         "LEVEL=warning", "RULE=target", "PATH_GLOB=app/*.py",
                                         "UNREVIEWED=1", "LIMIT=3")
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertEqual(json.loads((root / "argv.json").read_text()), [
                        "--sarif", "input.sarif", "--repo", "source", *selector,
                        "--level", "warning", "--rule", "target", "--path", "app/*.py",
                        "--unreviewed", "--limit", "3",
                    ])

    def test_id_addressing_does_not_forward_queue_filters(self):
        recorder = "import json, sys\nfrom pathlib import Path\nPath('argv.json').write_text(json.dumps(sys.argv[1:]))\n"
        with temp_tree({"scripts/build_packet.py": recorder}) as root:
            proc = self.run_make(root, "triage", "REPO=source", "SARIF=input.sarif", "ID=F-known",
                                 "LEVEL=error", "RULE=missing", "PATH_GLOB=absent/*",
                                 "UNREVIEWED=1", "LIMIT=0")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(json.loads((root / "argv.json").read_text()), [
                "--sarif", "input.sarif", "--repo", "source", "--finding-id", "F-known",
            ])

    def test_filtered_list_index_builds_the_listed_finding_in_another_repo(self):
        results = []
        for level, name in (("error", "first"), ("warning", "target")):
            results.append({
                "ruleId": f"demo.{name}", "level": level, "message": {"text": name},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f"app/{name}.py"},
                    "region": {"startLine": 1},
                }}],
            })
        with temp_tree({
            "scripts/build_packet.py": (REPO_ROOT / "scripts/build_packet.py").read_text(),
            "scripts/check_scope.py": (REPO_ROOT / "scripts/check_scope.py").read_text(),
            "policy/excluded-paths.yml": (FIXTURES / "policy-basic.yml").read_text(),
            "source/app/first.py": "first()\n", "source/app/target.py": "target()\n",
            "input.sarif": json.dumps({"runs": [{"results": results}]}),
        }) as root:
            variables = ("REPO=source", "SARIF=input.sarif", "LEVEL=warning", "RULE=target",
                         "PATH_GLOB=app/*.py", "UNREVIEWED=1", "LIMIT=1")
            listing = self.run_make(root, "list", *variables)
            self.assertEqual(listing.returncode, 0, listing.stdout + listing.stderr)
            self.assertNotIn("(no id)", listing.stdout, "list must derive identity from REPO")
            self.assertIn("app/target.py:1", listing.stdout)
            self.assertNotIn("app/first.py", listing.stdout)
            triage = self.run_make(root, "triage", "N=0", *variables)
            self.assertEqual(triage.returncode, 0, triage.stdout + triage.stderr)
            packets = list((root / "findings/packets").glob("*.json"))
            self.assertEqual(len(packets), 1)
            packet = json.loads(packets[0].read_text())
            self.assertEqual(packet["location"]["file"], "app/target.py")
            self.assertIn(packet["finding_id"], listing.stdout)
            self.assertIn("target()", packet["target_code"])


if __name__ == "__main__":
    unittest.main()
