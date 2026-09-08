"""Tests for packet construction.

The ordering test is the important one: docs/03-data-handling.md claims the
scope check runs before any file content is read, and that claim is what makes
the data-handling story true.
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import build_packet
import check_scope
from tests import REPO_ROOT
from tests.helpers import FIXTURES, fixture_exclusions, temp_tree

SARIF = FIXTURES / "sample.sarif"


class TestChallengeRevisionPacket(unittest.TestCase):
    def test_packet_binds_the_canonical_verdict_and_tells_validator_to_copy_digest(self):
        verdict = {"finding_id": "F-test", "verdict": "true_positive"}
        packet = build_packet.build_challenge_packet(verdict)
        self.assertEqual(packet.get("verdict_digest"), "af3811fd881463e4")
        reordered = build_packet.build_challenge_packet(dict(reversed(list(verdict.items()))))
        self.assertEqual(packet["verdict_digest"], reordered["verdict_digest"])
        revised = build_packet.build_challenge_packet({**verdict, "verdict": "false_positive"})
        self.assertNotEqual(packet["verdict_digest"], revised["verdict_digest"])
        self.assertIn("verdict_digest", packet["instructions"])
        self.assertIn("verbatim", packet["instructions"])


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
        # Excluded by **/*.pem under BOTH the fixture policy and the live one.
        # The manual check in Task 11 Step 8 runs against the live policy, so a
        # fixture path excluded only by the fixture would look in-scope there.
        self.assertEqual(excluded["file"], "config/server.pem")

        # Empty tree: the file does not exist. If the builder read first and
        # checked second, this would raise FileNotFoundError instead.
        with temp_tree({}) as repo:
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.build_triage_packet(
                    excluded, repo, 40, fixture_exclusions()
                )


class TestResolvedScopeControl(unittest.TestCase):
    def setUp(self):
        self.result = build_packet.load_sarif_results(SARIF)[0]
        self.result.update(start_line=1, end_line=1)

    def test_annotation_refuses_excluded_and_outside_links_even_with_fingerprints(self):
        for fingerprint in ({}, {"semgrep.fingerprint": "fixture-target"}):
            for destination in ("../secrets/token.txt", "../../outside.txt"):
                with self.subTest(fingerprint=fingerprint, destination=destination), temp_tree({
                    "repo/app/safe.py": "safe()\n", "repo/secrets/token.txt": "secret\n",
                    "outside.txt": "outside\n",
                }) as root:
                    repo = root / "repo"
                    (repo / "app/handler.py").symlink_to(destination)
                    result = {**self.result, "partialFingerprints": fingerprint}
                    item = build_packet.annotate([result], repo, fixture_exclusions())[0]
                    self.assertFalse(item["in_scope"], "scope label must describe the resolved target")
                    self.assertIsNone(item["finding_id"], "excluded aliases must not acquire usable identities")

    def test_list_json_marks_excluded_symlink_out_of_scope_without_an_id(self):
        with temp_tree({"app/safe.py": "safe()\n", "secrets/token.txt": "secret\n"}) as repo:
            (repo / "app/handler.py").symlink_to("../secrets/token.txt")
            proc = subprocess.run([
                sys.executable, str(REPO_ROOT / "scripts/build_packet.py"),
                "--sarif", str(SARIF), "--repo", str(repo), "--list", "--json",
            ], cwd=repo, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            item = next(item for item in json.loads(proc.stdout) if item["file"] == "app/handler.py")
            self.assertFalse(item["in_scope"])
            self.assertIsNone(item["finding_id"])

    def test_content_identity_refuses_an_excluded_symlink(self):
        with temp_tree({"app/safe.py": "safe()\n", "secrets/token.txt": "TOP-SECRET\n"}) as repo:
            (repo / "app/handler.py").symlink_to("../secrets/token.txt")
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.compute_finding_id(self.result, repo, fixture_exclusions())

    def test_target_symlink_is_refused_even_with_a_fingerprint(self):
        self.result["partialFingerprints"] = {"semgrep.fingerprint": "fixture-target"}
        with temp_tree({"app/safe.py": "safe()\n", "secrets/token.txt": "TOP-SECRET\n"}) as repo:
            (repo / "app/handler.py").symlink_to("../secrets/token.txt")
            with self.assertRaises(check_scope.ScopeViolation):
                packet = build_packet.build_triage_packet(
                    self.result, repo, 0, fixture_exclusions()
                )
                self.fail(f"Excluded source entered target_code: {packet['target_code']}")

    def test_dataflow_symlink_is_refused_before_target_content_is_read(self):
        self.result["code_flows"] = [{"steps": [
            {"file": "app/route.py", "line": 1, "message": "source"},
        ]}]
        # Leave the primary file absent: resolving the dataflow must refuse
        # before content identity attempts to open that primary file.
        with temp_tree({"app/safe.py": "safe()\n", "secrets/token.txt": "TOP-SECRET\n"}) as repo:
            (repo / "app/route.py").symlink_to("../secrets/token.txt")
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.build_triage_packet(
                    self.result, repo, 0, fixture_exclusions()
                )

    def test_dataflow_symlink_cannot_expose_excluded_content(self):
        self.result["code_flows"] = [{"steps": [
            {"file": "app/route.py", "line": 1, "message": "source"},
        ]}]
        with temp_tree({"app/handler.py": "safe()\n", "secrets/token.txt": "TOP-SECRET\n"}) as repo:
            (repo / "app/route.py").symlink_to("../secrets/token.txt")
            with self.assertRaises(check_scope.ScopeViolation):
                packet = build_packet.build_triage_packet(
                    self.result, repo, 0, fixture_exclusions()
                )
                self.fail(f"Excluded source entered dataflow_context: {packet['dataflow_context']}")

    def test_allowed_links_supply_target_and_dataflow_context(self):
        self.result["code_flows"] = [{"steps": [
            {"file": "app/route.py", "line": 1, "message": "source"},
        ]}]
        with temp_tree({"app/safe.py": "safe()\n", "app/source.py": "source()\n"}) as repo:
            (repo / "app/handler.py").symlink_to("safe.py")
            (repo / "app/route.py").symlink_to("source.py")
            packet = build_packet.build_triage_packet(
                self.result, repo, 0, fixture_exclusions()
            )
        self.assertEqual(packet["target_code"], "     1 | safe()")
        self.assertEqual(packet["dataflow_context"], [{
            "file": "app/route.py", "line": 1,
            "scanner_note": "source", "code": "     1 | source()",
        }])

    def test_cli_refuses_symlink_targets_without_writing_packets(self):
        for destination in ("excluded", "outside", "directory"):
            with self.subTest(destination=destination), temp_tree({
                "repo/app/safe.py": "safe()\n",
                "repo/secrets/token.txt": "TOP-SECRET\n",
                "outside.txt": "OUTSIDE-CONTENT\n",
            }) as root:
                repo = root / "repo"
                if destination == "excluded":
                    (repo / "app/handler.py").symlink_to("../secrets/token.txt")
                    target_path = "app/handler.py"
                elif destination == "outside":
                    (repo / "app/handler.py").symlink_to(root / "outside.txt")
                    target_path = "app/handler.py"
                else:
                    (repo / "app/linked").symlink_to("../secrets", target_is_directory=True)
                    target_path = "app/linked/token.txt"
                data = json.loads(SARIF.read_text(encoding="utf-8"))
                result = data["runs"][0]["results"][0]
                result["locations"][0]["physicalLocation"] = {
                    "artifactLocation": {"uri": target_path},
                    "region": {"startLine": 1, "endLine": 1},
                }
                data["runs"][0]["results"] = [result]
                sarif = root / "input.sarif"
                sarif.write_text(json.dumps(data), encoding="utf-8")
                out = root / "packets"
                proc = subprocess.run(
                    [
                        sys.executable, str(REPO_ROOT / "scripts/build_packet.py"),
                        "--sarif", str(sarif), "--repo", str(repo),
                        "--index", "0", "--out", str(out),
                    ],
                    capture_output=True, text=True, cwd=root,
                )
                written = [
                    json.loads(path.read_text(encoding="utf-8"))["target_code"]
                    for path in out.glob("*.json")
                ]
                self.assertEqual(proc.returncode, 2, f"{proc.stdout}{proc.stderr}written={written}")
                self.assertIn("REFUSED", proc.stderr)
                if destination == "outside":
                    self.assertIn(str((root / "outside.txt").resolve()), proc.stderr)
                    self.assertIn("<outside repository>", proc.stderr)
                self.assertFalse(out.exists(), "a refused run must not create packets")
                self.assertNotIn("TOP-SECRET", proc.stdout + proc.stderr)
                self.assertNotIn("OUTSIDE-CONTENT", proc.stdout + proc.stderr)


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


FILE_BEFORE = "import os\n\n\ndef run(cmd):\n    exec(cmd)\n"
FILE_AFTER = "import os\nimport sys\n\n\ndef run(cmd):\n    exec(cmd)\n"


def result_at(path="app/handler.py", start=5, end=5, **extra):
    base = {
        "rule_id": "python.lang.security.audit.exec-detected",
        "file": path,
        "start_line": start,
        "end_line": end,
    }
    base.update(extra)
    return base


class TestFindingIdentity(unittest.TestCase):
    """The old id hashed the line number, so any edit above a finding gave it a
    new identity: its verdicts were orphaned and dismissed findings came back."""

    def test_line_shift_preserves_identity(self):
        with temp_tree({"app/handler.py": FILE_BEFORE}) as repo:
            before = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        with temp_tree({"app/handler.py": FILE_AFTER}) as repo:
            after = build_packet.compute_finding_id(
                result_at(start=6, end=6), repo, fixture_exclusions()
            )
        self.assertEqual(before, after)

    def test_changing_the_fragment_changes_identity(self):
        with temp_tree({"app/handler.py": FILE_BEFORE}) as repo:
            original = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        edited = FILE_BEFORE.replace("exec(cmd)", "exec(shlex.quote(cmd))")
        with temp_tree({"app/handler.py": edited}) as repo:
            changed = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        self.assertNotEqual(original, changed)

    def test_identical_fragments_get_distinct_identities(self):
        text = "a = 1\nexec(cmd)\nb = 2\nexec(cmd)\n"
        with temp_tree({"app/handler.py": text}) as repo:
            first = build_packet.compute_finding_id(
                result_at(start=2, end=2), repo, fixture_exclusions()
            )
            second = build_packet.compute_finding_id(
                result_at(start=4, end=4), repo, fixture_exclusions()
            )
        self.assertNotEqual(first, second)

    def test_multiline_duplicates_with_blank_lines_have_distinct_stable_ids(self):
        text = "prepare(cmd)\n\nexec(cmd)\nseparator()\nprepare(cmd)\nexec(cmd)\n"
        with temp_tree({"app/handler.py": text}) as repo:
            first = build_packet.compute_finding_id(
                result_at(start=1, end=3), repo, fixture_exclusions()
            )
            second = build_packet.compute_finding_id(
                result_at(start=5, end=6), repo, fixture_exclusions()
            )
            self.assertNotEqual(first, second, "distinct regions must not share an identity")
            (repo / "app/handler.py").write_text("# shifted\n\n" + text, encoding="utf-8")
            shifted_first = build_packet.compute_finding_id(
                result_at(start=3, end=5), repo, fixture_exclusions()
            )
            shifted_second = build_packet.compute_finding_id(
                result_at(start=7, end=8), repo, fixture_exclusions()
            )
            self.assertEqual((shifted_first, shifted_second), (first, second))

    def test_indentation_change_preserves_identity(self):
        with temp_tree({"app/handler.py": FILE_BEFORE}) as repo:
            original = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        reindented = FILE_BEFORE.replace("    exec(cmd)", "        exec(cmd)")
        with temp_tree({"app/handler.py": reindented}) as repo:
            same = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        self.assertEqual(original, same)

    def test_scanner_fingerprint_wins_and_needs_no_file(self):
        result = result_at(partialFingerprints={"semgrep.fingerprint": "abc123"})
        with temp_tree({}) as repo:
            fid = build_packet.compute_finding_id(result, repo, fixture_exclusions())
        self.assertTrue(fid.startswith("F-"))

    def test_fingerprint_key_choice_is_deterministic(self):
        a = build_packet.scanner_fingerprint(
            {"partialFingerprints": {"zeta": "1", "alpha": "2"}}
        )
        b = build_packet.scanner_fingerprint(
            {"partialFingerprints": {"alpha": "2", "zeta": "1"}}
        )
        self.assertEqual(a, b)

    def test_preferred_fingerprint_key_wins_over_alphabetical(self):
        fp = build_packet.scanner_fingerprint(
            {"partialFingerprints": {"aaa": "x", "primaryLocationLineHash": "y"}}
        )
        self.assertIn("primaryLocationLineHash", fp)

    def test_excluded_path_refuses_before_reading(self):
        with temp_tree({}) as repo:
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.compute_finding_id(
                    result_at(path="secrets/prod.env", start=1, end=1),
                    repo,
                    fixture_exclusions(),
                )

    def test_excluded_path_refuses_even_with_a_fingerprint(self):
        # The fingerprint path needs no file, so nothing would be leaked. It is
        # still refused: an id for a finding that can never become a packet is
        # a loose end, and the listing promises (no id) for excluded paths.
        with temp_tree({}) as repo:
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.compute_finding_id(
                    result_at(
                        path="secrets/prod.env",
                        start=1,
                        end=1,
                        partialFingerprints={"semgrep.fingerprint": "deadbeef"},
                    ),
                    repo,
                    fixture_exclusions(),
                )

    def test_empty_region_is_reported_clearly(self):
        with temp_tree({"app/handler.py": "\n\n\n"}) as repo:
            with self.assertRaises(ValueError):
                build_packet.compute_finding_id(
                    result_at(start=1, end=2), repo, fixture_exclusions()
                )

    def test_packet_records_the_identity_scheme(self):
        results = build_packet.load_sarif_results(SARIF)
        with temp_tree({"app/handler.py": FILE_BEFORE, "app/db.py": "q = f'{x}'\n"}) as repo:
            packet = build_packet.build_triage_packet(
                results[0], repo, 40, fixture_exclusions()
            )
        self.assertEqual(packet["id_scheme"], build_packet.ID_SCHEME)

    def test_fingerprints_survive_sarif_parsing(self):
        results = build_packet.load_sarif_results(SARIF)
        self.assertEqual(
            results[1]["partialFingerprints"],
            {"semgrep.fingerprint": "abc123def456"},
        )

    def test_real_sarif_input_uses_the_scanner_fingerprint(self):
        # An empty repository: the content path would raise FileNotFoundError,
        # so a returned id proves the fingerprint path actually ran on input
        # that came through load_sarif_results rather than a hand-built dict.
        results = build_packet.load_sarif_results(SARIF)
        with temp_tree({}) as repo:
            fid = build_packet.compute_finding_id(
                results[1], repo, fixture_exclusions()
            )
        self.assertTrue(fid.startswith("F-"))


class TestTriageQueue(unittest.TestCase):
    def items(self):
        results = build_packet.load_sarif_results(SARIF)
        # Annotate without a repo so ids come back None; the filters under test
        # do not depend on identity except through reviewed_ids.
        with temp_tree({}) as repo:
            return build_packet.annotate(results, repo, fixture_exclusions())

    def test_level_filter(self):
        out = build_packet.apply_filters(self.items(), levels=["error"])
        self.assertEqual([i["level"] for i in out], ["error"])

    def test_level_filter_accepts_several(self):
        out = build_packet.apply_filters(self.items(), levels=["error", "note"])
        self.assertEqual(len(out), 2)

    def test_rule_substring_filter(self):
        out = build_packet.apply_filters(self.items(), rule="injection")
        self.assertEqual(len(out), 1)
        self.assertIn("injection", out[0]["rule_id"])

    def test_path_glob_filter(self):
        out = build_packet.apply_filters(self.items(), path_glob="app/*.py")
        self.assertEqual({i["file"] for i in out}, {"app/handler.py", "app/db.py"})

    def test_filters_combine(self):
        out = build_packet.apply_filters(
            self.items(), levels=["error", "warning"], path_glob="app/*.py", limit=1
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["level"], "error")

    def test_sort_is_deterministic_and_severity_first(self):
        out = build_packet.apply_filters(self.items())
        self.assertEqual([i["level"] for i in out], ["error", "warning", "note"])

    def test_unreviewed_filter_hides_findings_with_verdicts(self):
        items = self.items()
        items[0]["finding_id"] = "F-aaaaaaaaaaaa"
        items[1]["finding_id"] = "F-bbbbbbbbbbbb"
        out = build_packet.apply_filters(items, reviewed_ids={"F-aaaaaaaaaaaa"})
        self.assertNotIn("F-aaaaaaaaaaaa", [i["finding_id"] for i in out])

    def test_reviewed_ids_are_read_from_verdict_filenames(self):
        with temp_tree(
            {"verdicts/F-aaaaaaaaaaaa.json": "{}", "verdicts/F-bbbbbbbbbbbb.json": "{}"}
        ) as root:
            found = build_packet.reviewed_finding_ids(root / "verdicts")
        self.assertEqual(found, {"F-aaaaaaaaaaaa", "F-bbbbbbbbbbbb"})

    def test_absent_verdict_directory_is_empty_not_an_error(self):
        with temp_tree({}) as root:
            self.assertEqual(build_packet.reviewed_finding_ids(root / "nope"), set())

    def test_index_caveat_leads_and_the_tally_ends_the_output(self):
        # This block has been reordered twice. The order is a requirement, not
        # a formatting preference, so it gets an assertion of its own.
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "build_packet.py"),
                "--sarif", str(SARIF), "--list",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        self.assertIn("Indices are positions", lines[0])
        self.assertTrue(lines[-1].endswith("shown"), lines[-1])

    def test_json_output_is_machine_readable(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "build_packet.py"),
                "--sarif", str(SARIF), "--list", "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(len(payload), 3)
        for item in payload:
            self.assertIn("finding_id", item)
            self.assertIn("in_scope", item)
            self.assertIn("level", item)
            self.assertIn("rule_id", item)

    def test_empty_sarif_list_json_is_an_empty_array(self):
        with temp_tree({"empty.sarif": '{"version": "2.1.0", "runs": []}'}) as root:
            sarif = root / "empty.sarif"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "build_packet.py"),
                    "--sarif", str(sarif), "--list", "--json",
                ],
                capture_output=True,
                text=True,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), [])

    def test_negative_limit_refuses_and_zero_is_empty(self):
        self.assertEqual(build_packet.apply_filters(self.items(), limit=0), [])
        with self.assertRaisesRegex(
            ValueError, r"--limit must not be negative, got -1"
        ):
            build_packet.apply_filters(self.items(), limit=-1)

    def test_empty_sarif_selection_refuses_with_scan_guidance(self):
        with temp_tree({"empty.sarif": '{"version": "2.1.0", "runs": []}'}) as root:
            sarif = root / "empty.sarif"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "build_packet.py"),
                    "--sarif", str(sarif), "--index", "0",
                ],
                capture_output=True,
                text=True,
            )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            proc.stderr,
            f"No findings in {sarif}. Run `make scan` first.\n",
        )


class TestFindingIdAddressing(unittest.TestCase):
    def run_builder(self, args):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "build_packet.py"), *args],
            capture_output=True,
            text=True,
        )

    def test_unknown_id_is_reported_and_non_zero(self):
        proc = self.run_builder(
            ["--sarif", str(SARIF), "--finding-id", "F-doesnotexist"]
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("No finding with id F-doesnotexist", proc.stderr)

    def test_empty_id_is_explicitly_refused(self):
        proc = self.run_builder(["--sarif", str(SARIF), "--finding-id", ""])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--finding-id must not be empty", proc.stderr)

    def test_id_and_index_together_are_refused(self):
        proc = self.run_builder(
            ["--sarif", str(SARIF), "--finding-id", "F-x", "--index", "0"]
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("pass either --finding-id or --index, not both", proc.stderr)

    def test_make_list_passes_path_glob_as_one_literal_argument(self):
        recorder = (
            "import json\n"
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "Path(os.environ['ARGV_FILE']).write_text(json.dumps(sys.argv[1:]))\n"
        )
        with temp_tree(
            {
                "app/one.py": "\n",
                "app/two.py": "\n",
                "scripts/build_packet.py": recorder,
            }
        ) as root:
            argv_path = root / "argv.json"
            env = {**os.environ, "ARGV_FILE": str(argv_path)}
            proc = subprocess.run(
                [
                    "make",
                    "-f",
                    str(REPO_ROOT / "Makefile"),
                    "list",
                    "SARIF=input.sarif",
                    "PATH_GLOB=app/*.py",
                ],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(
                json.loads(argv_path.read_text(encoding="utf-8")),
                ["--sarif", "input.sarif", "--repo", ".", "--list", "--path", "app/*.py"],
            )

    def test_finding_id_ignores_list_filters_when_building_packet(self):
        finding_id = "F-933b5ec77e80"
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "fixture", "rules": []}},
                    "results": [
                        {
                            "ruleId": "demo.rule",
                            "level": "warning",
                            "message": {"text": "fixture finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app/target.py"},
                                        "region": {"startLine": 2, "endLine": 2},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        with temp_tree({"app/target.py": "# setup\ndanger(user)\n"}) as root:
            sarif_path = root / "input.sarif"
            out = root / "packets"
            sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
            proc = self.run_builder(
                [
                    "--sarif",
                    str(sarif_path),
                    "--repo",
                    str(root),
                    "--out",
                    str(out),
                    "--finding-id",
                    finding_id,
                    "--level",
                    "error",
                    "--limit",
                    "0",
                ]
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            packet = json.loads((out / f"{finding_id}.json").read_text(encoding="utf-8"))
        self.assertEqual(packet["finding_id"], finding_id)
        self.assertEqual(
            packet["location"],
            {"file": "app/target.py", "start_line": 2, "end_line": 2},
        )


if __name__ == "__main__":
    unittest.main()
