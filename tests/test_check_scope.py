"""Tests for the scope control.

check_scope is the only component in this repository whose refusal is a
security control rather than a convenience, so it is tested first and hardest.
"""

import unittest

import check_scope
from tests.helpers import FIXTURES


class TestParsePolicy(unittest.TestCase):
    def setUp(self):
        self.exclusions, self.scan_noise = check_scope.load_policy(
            FIXTURES / "policy-basic.yml"
        )

    def test_reads_every_exclusion(self):
        patterns = [rule["pattern"] for rule in self.exclusions]
        self.assertEqual(patterns, ["**/.env", "**/*.pem", "secrets/"])

    def test_keeps_owner_and_reason(self):
        first = self.exclusions[0]
        self.assertEqual(first["owner"], "appsec")
        self.assertEqual(first["reason"], "Runtime secrets")

    def test_strips_trailing_comment(self):
        third = self.exclusions[2]
        self.assertEqual(third["pattern"], "secrets/")

    def test_reads_scan_noise_as_bare_strings(self):
        self.assertEqual(self.scan_noise, ["node_modules/", "dist/"])

    def test_missing_policy_refuses_rather_than_defaulting(self):
        with self.assertRaises(FileNotFoundError):
            check_scope.load_policy(FIXTURES / "does-not-exist.yml")

    def test_rules_without_a_pattern_are_dropped(self):
        exclusions, _ = check_scope._parse_policy(
            "exclusions:\n"
            "  - owner: appsec\n"
            "    reason: no pattern key\n"
            '  - pattern: "**/id_rsa"\n'
            "    owner: appsec\n"
        )
        self.assertEqual([r["pattern"] for r in exclusions], ["**/id_rsa"])


if __name__ == "__main__":
    unittest.main()
