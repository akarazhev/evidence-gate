"""Tests for packet construction.

The ordering test is the important one: docs/03-data-handling.md claims the
scope check runs before any file content is read, and that claim is what makes
the data-handling story true.
"""

import unittest
from pathlib import Path

import build_packet
import check_scope
from tests.helpers import FIXTURES, fixture_exclusions, temp_tree

SARIF = FIXTURES / "sample.sarif"


class TestLoadSarif(unittest.TestCase):
    def setUp(self):
        self.results = build_packet.load_sarif_results(SARIF)

    def test_reads_every_result(self):
        self.assertEqual(len(self.results), 3)

    def test_prefers_full_description_over_message(self):
        self.assertEqual(self.results[0]["rule_description"], "Detected the use of exec")

    def test_falls_back_to_short_description(self):
        self.assertEqual(self.results[1]["rule_description"], "SQL injection")

    def test_extracts_code_flows(self):
        steps = self.results[1]["code_flows"][0]["steps"]
        self.assertEqual(steps[0]["file"], "app/routes.py")
        self.assertEqual(steps[0]["line"], 3)

    def test_result_without_flows_has_empty_list(self):
        self.assertEqual(self.results[0]["code_flows"], [])


class TestScopeCheckOrdering(unittest.TestCase):
    """The scope check must refuse before the file is opened."""

    def test_excluded_path_refuses_even_when_file_is_absent(self):
        results = build_packet.load_sarif_results(SARIF)
        excluded = results[2]
        self.assertEqual(excluded["file"], "secrets/prod.env")

        # Empty tree: the file does not exist. If the builder read first and
        # checked second, this would raise FileNotFoundError instead.
        with temp_tree({}) as repo:
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.build_triage_packet(
                    excluded, repo, 40, fixture_exclusions()
                )


class TestReadContext(unittest.TestCase):
    def setUp(self):
        self.text = "\n".join(f"line{i}" for i in range(1, 11)) + "\n"

    def test_window_clamps_at_start_of_file(self):
        with temp_tree({"a.py": self.text}) as root:
            out = build_packet.read_context(root / "a.py", 1, 1, 3)
        self.assertTrue(out.splitlines()[0].endswith("| line1"))
        self.assertEqual(len(out.splitlines()), 4)

    def test_window_clamps_at_end_of_file(self):
        with temp_tree({"a.py": self.text}) as root:
            out = build_packet.read_context(root / "a.py", 10, 10, 3)
        self.assertTrue(out.splitlines()[-1].endswith("| line10"))

    def test_window_wider_than_file_returns_whole_file(self):
        with temp_tree({"a.py": self.text}) as root:
            out = build_packet.read_context(root / "a.py", 5, 5, 500)
        self.assertEqual(len(out.splitlines()), 10)

    def test_missing_file_returns_none(self):
        self.assertIsNone(build_packet.read_context(Path("/nope/absent.py"), 1, 1, 3))


if __name__ == "__main__":
    unittest.main()
