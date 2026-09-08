"""Tests for the scope control.

check_scope is the only component in this repository whose refusal is a
security control rather than a convenience, so it is tested first and hardest.
"""

import subprocess
import sys
import unittest

import check_scope
from tests import REPO_ROOT
from tests.helpers import FIXTURES, fixture_exclusions, temp_tree


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

    def test_rule_without_a_pattern_is_refused(self):
        with self.assertRaises(ValueError):
            check_scope._parse_policy(
                "exclusions:\n"
                "  - owner: appsec\n"
                "    reason: no pattern key\n"
                '  - pattern: "**/id_rsa"\n'
                "    owner: appsec\n"
            )

    def test_whitespace_only_pattern_is_refused(self):
        with self.assertRaisesRegex(ValueError, "pattern"):
            check_scope._parse_policy(
                "exclusions:\n"
                '  - pattern: "   "\n'
                "    owner: appsec\n"
                "    reason: empty patterns disable the rule\n"
            )

    def test_exclusion_without_owner_is_refused(self):
        with self.assertRaisesRegex(ValueError, "owner"):
            check_scope._parse_policy(
                "exclusions:\n"
                '  - pattern: "**/.env"\n'
                "    reason: Runtime secrets\n"
            )

    def test_exclusion_without_reason_is_refused(self):
        with self.assertRaisesRegex(ValueError, "reason"):
            check_scope._parse_policy(
                "exclusions:\n"
                '  - pattern: "**/.env"\n'
                "    owner: appsec\n"
            )

    def test_unrecognized_exclusion_line_is_refused_with_line_number(self):
        with self.assertRaisesRegex(ValueError, "line 3"):
            check_scope._parse_policy(
                "exclusions:\n"
                '  - pattern: "**/.env"\n'
                "    this is not a key-value pair\n"
                "    owner: appsec\n"
                "    reason: Runtime secrets\n"
            )

    def test_live_policy_has_complete_exclusions(self):
        exclusions, _ = check_scope.load_policy()
        self.assertTrue(exclusions)
        for rule in exclusions:
            self.assertTrue(rule["pattern"].strip())
            self.assertTrue(rule["owner"].strip())
            self.assertTrue(rule["reason"].strip())


class TestPolicyProcess(unittest.TestCase):
    def run_with_policy(self, policy):
        files = {
            "scripts/check_scope.py": (
                REPO_ROOT / "scripts" / "check_scope.py"
            ).read_text(encoding="utf-8"),
            "policy/excluded-paths.yml": policy,
            ".env": "SECRET=value\n",
        }
        with temp_tree(files) as repo:
            return subprocess.run(
                [
                    sys.executable,
                    str(repo / "scripts" / "check_scope.py"),
                    "--repo",
                    str(repo),
                    ".env",
                ],
                cwd=repo,
                capture_output=True,
                text=True,
            )

    def test_cli_refuses_unknown_policy_section(self):
        proc = self.run_with_policy(
            'exclusions:\n  - pattern: "**/*.pem"\n'
            "    owner: appsec\n    reason: private keys\n"
            'exclusion:\n  - pattern: "**/.env"\n'
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("exclusion", proc.stderr)
        self.assertIn("exclusions", proc.stderr)
        self.assertIn("scan_noise", proc.stderr)

    def test_cli_refuses_exclusion_without_pattern(self):
        proc = self.run_with_policy(
            "exclusions:\n  - owner: appsec\n    reason: missing pattern\n"
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("entry 1", proc.stderr)
        self.assertIn("pattern", proc.stderr)

    def test_cli_honours_tab_after_list_marker(self):
        proc = self.run_with_policy(
            'exclusions:\n  -\tpattern: "**/.env"\n'
            "    owner: appsec\n"
            "    reason: Runtime secrets\n"
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("REFUSED", proc.stderr)
        self.assertIn("**/.env", proc.stderr)

    def test_cli_refuses_bare_list_entry_without_pattern(self):
        proc = self.run_with_policy(
            'exclusions:\n  - pattern: "**/*.pem"\n'
            "    owner: first\n"
            "    reason: private keys\n"
            "  -\n"
            "    owner: second\n"
            "    reason: missing pattern\n"
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("entry 2", proc.stderr)
        self.assertIn("pattern", proc.stderr)

    def test_cli_refuses_policy_with_zero_rules(self):
        proc = self.run_with_policy("")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("disabled control", proc.stderr)


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


class TestScopeProcess(unittest.TestCase):
    def run_check(self, repo, path, explicit_repo=False):
        command = [sys.executable, str(REPO_ROOT / "scripts/check_scope.py")]
        if explicit_repo:
            command += ["--repo", str(repo)]
        return subprocess.run(command + [str(path)], cwd=repo,
                              capture_output=True, text=True)

    def test_cli_refuses_symlink_to_excluded_file(self):
        with temp_tree({"app/safe.py": "safe()\n", "secrets/token.txt": "secret\n"}) as repo:
            (repo / "app/handler.py").symlink_to("../secrets/token.txt")
            proc = self.run_check(repo, "app/handler.py")
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("secrets/", proc.stderr)

    def test_cli_refuses_absolute_path_outside_repository(self):
        with temp_tree({"repo/safe.py": "safe()\n", "outside.txt": "outside\n"}) as root:
            proc = self.run_check(root / "repo", root / "outside.txt")
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("outside repository", proc.stderr)

    def test_cli_accepts_regular_file_with_default_and_explicit_repo(self):
        with temp_tree({"app/safe.py": "safe()\n"}) as repo:
            for explicit_repo in (False, True):
                with self.subTest(explicit_repo=explicit_repo):
                    proc = self.run_check(repo, "app/safe.py", explicit_repo)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertIn("OK", proc.stdout)


class TestResolveWithin(unittest.TestCase):
    def test_regular_file_and_allowed_link_return_the_resolved_path(self):
        with temp_tree({"app/safe.py": "safe()\n"}) as repo:
            (repo / "app/alias.py").symlink_to("safe.py")
            for relative in ("app/safe.py", "app/alias.py"):
                with self.subTest(relative=relative):
                    target = check_scope.resolve_within(repo, relative, fixture_exclusions())
                    self.assertEqual(target, (repo / "app/safe.py").resolve())
                    self.assertEqual(target.read_text(encoding="utf-8"), "safe()\n")

    def test_symlink_to_excluded_file_is_refused(self):
        with temp_tree({"app/safe.py": "safe()\n", "secrets/token.txt": "TOP-SECRET\n"}) as repo:
            (repo / "app/handler.py").symlink_to("../secrets/token.txt")
            with self.assertRaises(check_scope.ScopeViolation) as caught:
                check_scope.resolve_within(repo, "app/handler.py", fixture_exclusions())
            self.assertEqual(caught.exception.path, "secrets/token.txt")
            self.assertEqual(caught.exception.pattern, "secrets/")

    def test_outside_symlink_is_refused_with_resolved_destination(self):
        with temp_tree({"repo/app/safe.py": "safe()\n", "outside.txt": "OUTSIDE-CONTENT\n"}) as root:
            repo = root / "repo"
            (repo / "app/handler.py").symlink_to(root / "outside.txt")
            with self.assertRaises(check_scope.ScopeViolation) as caught:
                check_scope.resolve_within(repo, "app/handler.py", [])
            self.assertEqual(caught.exception.path, "app/handler.py")
            self.assertEqual(caught.exception.pattern, "<outside repository>")
            self.assertIn(str((root / "outside.txt").resolve()), caught.exception.reason)
            self.assertIn(str(repo.resolve()), caught.exception.reason)

    def test_symlink_directory_in_the_middle_of_a_path_is_refused(self):
        with temp_tree({"app/safe.py": "safe()\n", "secrets/token.txt": "TOP-SECRET\n"}) as repo:
            (repo / "app/linked").symlink_to("../secrets", target_is_directory=True)
            with self.assertRaises(check_scope.ScopeViolation):
                check_scope.resolve_within(repo, "app/linked/token.txt", fixture_exclusions())

    def test_excluded_link_name_is_refused_even_if_target_is_allowed(self):
        with temp_tree({"app/safe.py": "safe()\n", "secrets/token.txt": "TOP-SECRET\n"}) as repo:
            (repo / "secrets/alias.py").symlink_to("../app/safe.py")
            with self.assertRaises(check_scope.ScopeViolation) as caught:
                check_scope.resolve_within(repo, "secrets/alias.py", fixture_exclusions())
            self.assertEqual(caught.exception.path, "secrets/alias.py")

    def test_explicit_empty_exclusions_do_not_load_live_policy(self):
        with temp_tree({"app/safe.py": "safe()\n", "secrets/token.txt": "fixture\n"}) as repo:
            (repo / "app/handler.py").symlink_to("../secrets/token.txt")
            self.assertEqual(
                check_scope.resolve_within(repo, "app/handler.py", []),
                (repo / "secrets/token.txt").resolve(),
            )


if __name__ == "__main__":
    unittest.main()
