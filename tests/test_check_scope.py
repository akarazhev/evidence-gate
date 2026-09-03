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


class TestMatches(unittest.TestCase):
    def setUp(self):
        self.exclusions = check_scope.load_policy(FIXTURES / "policy-basic.yml")[0]

    def assertRefused(self, path):
        with self.assertRaises(check_scope.ScopeViolation):
            check_scope.check_path(path, self.exclusions)

    def assertAllowed(self, path):
        check_scope.check_path(path, self.exclusions)

    def test_dotfile_at_root(self):
        self.assertRefused(".env")

    def test_dotfile_nested(self):
        self.assertRefused("services/api/.env")

    def test_dot_slash_prefix_is_stripped_not_lstripped(self):
        # lstrip("./") would eat the leading dot and turn ".env" into "env",
        # defeating every dotfile exclusion in the policy.
        self.assertRefused("./.env")

    def test_extension_glob_at_root_and_at_depth(self):
        self.assertRefused("server.pem")
        self.assertRefused("certs/intermediate/server.pem")

    def test_directory_pattern_covers_contents(self):
        self.assertRefused("secrets/token.txt")
        self.assertRefused("app/secrets/token.txt")

    def test_windows_separators_are_normalised(self):
        self.assertRefused("services\\api\\.env")

    def test_similar_names_are_not_refused(self):
        self.assertAllowed("src/environment.py")
        self.assertAllowed("docs/env-setup.md")
        self.assertAllowed("src/secretsmanager.py")

    # --- Red until Task 10 -------------------------------------------------
    # macOS APFS and Windows NTFS are case-insensitive by default, so `.ENV`
    # and `.env` name the same file with the same contents. fnmatch.fnmatch
    # delegates to os.path.normcase, which is the identity on POSIX, so the
    # glob is case-sensitive there and the second spelling walks straight past
    # the exclusion.

    def test_uppercase_dotfile_is_refused(self):
        self.assertRefused(".ENV")

    def test_mixed_case_extension_is_refused(self):
        self.assertRefused("certs/Server.PEM")


if __name__ == "__main__":
    unittest.main()
