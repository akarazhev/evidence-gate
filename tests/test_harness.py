"""Proves the harness itself works before anything depends on it."""

import unittest
from pathlib import Path

from tests.helpers import FIXTURES, fixture_exclusions, temp_tree


class TestHarness(unittest.TestCase):
    def test_scripts_are_importable(self):
        import check_scope

        self.assertTrue(hasattr(check_scope, "check_path"))

    def test_fixture_policy_is_present(self):
        self.assertTrue((FIXTURES / "policy-basic.yml").exists())

    def test_fixture_exclusions_load(self):
        self.assertEqual(len(fixture_exclusions()), 3)

    def test_temp_tree_materialises_files(self):
        with temp_tree({"a/b.py": "print(1)\n"}) as root:
            self.assertEqual((root / "a" / "b.py").read_text(), "print(1)\n")
        self.assertFalse(Path(root).exists())


if __name__ == "__main__":
    unittest.main()
