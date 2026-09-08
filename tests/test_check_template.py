"""Tests for the template control.

docs/03 tells the reader that a passing check-template proves CLAUDE.md
describes this repository. The shell version reported success when the file was
absent, so the claim was false in exactly the case that matters most.
"""

import subprocess
import sys
import unittest

import check_template
from tests import REPO_ROOT
from tests.helpers import temp_tree

SCRIPT = REPO_ROOT / "scripts" / "check_template.py"

FILLED = (
    "# Project context\n\n"
    "- Attacker-controlled input enters at: HTTP handlers in app/routes.py\n"
    "- Security-critical modules: app/auth.py, app/crypto.py\n"
)
TEMPLATED = (
    "# Project context\n\n"
    "- Attacker-controlled input enters at: `<HTTP handlers, queue consumers>`\n"
    "- Security-critical modules requiring extra scrutiny: `<auth, crypto>`\n"
)


class TestFindPlaceholders(unittest.TestCase):
    def test_reports_line_numbers(self):
        found = check_template.find_placeholders(TEMPLATED)
        self.assertEqual([number for number, _ in found], [3, 4])

    def test_filled_file_has_none(self):
        self.assertEqual(check_template.find_placeholders(FILLED), [])

    def test_multiline_placeholders_report_start_line_and_first_line(self):
        self.assertEqual(
            check_template.find_placeholders("# Context\n<HTTP handlers,\n queues> and <Auth>\n"),
            [(2, "<HTTP handlers,"), (3, "<Auth>")],
        )

    def test_prose_angle_brackets_do_not_count(self):
        # "less than" in prose must not be mistaken for a placeholder.
        self.assertEqual(check_template.find_placeholders("if a < b and c > d\n"), [])


class TestProcess(unittest.TestCase):
    def run_check(self, path):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(path)],
            capture_output=True,
            text=True,
        )

    def test_placeholders_are_refused(self):
        with temp_tree({"CLAUDE.md": TEMPLATED}) as root:
            proc = self.run_check(root / "CLAUDE.md")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED", proc.stderr)

    def test_filled_file_passes(self):
        with temp_tree({"CLAUDE.md": FILLED}) as root:
            proc = self.run_check(root / "CLAUDE.md")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("no unfilled placeholders", proc.stdout)

    def test_multiline_placeholder_is_refused(self):
        with temp_tree({"CLAUDE.md": "# Context\n<HTTP handlers,\n queue consumers>\n"}) as root:
            proc = self.run_check(root / "CLAUDE.md")
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("2  <HTTP handlers,", proc.stderr)

    def test_missing_file_is_refused_not_reported_clean(self):
        # The shell version printed "no unfilled placeholders" and exited 0
        # here, which is the fail-open this control exists to avoid.
        with temp_tree({}) as root:
            proc = self.run_check(root / "CLAUDE.md")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED", proc.stderr)
        self.assertNotIn("no unfilled placeholders", proc.stdout)


if __name__ == "__main__":
    unittest.main()
