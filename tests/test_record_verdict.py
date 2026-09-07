"""Tests for verdict validation and promotion.

decide_state decides what enters the audit trail, and the rationale it returns
is written verbatim into SARIF. A rationale that overstates what was verified
is a defect of the same kind this whole workflow exists to catch.
"""

import csv
import json
import subprocess
import sys
import unittest

import record_verdict
from tests import REPO_ROOT
from tests.helpers import temp_tree, write_log


def make_verdict(**overrides) -> dict:
    """A minimal verdict that passes schema and consistency checks."""
    verdict = {
        "finding_id": "F-000000000001",
        "rule_id": "python.lang.security.audit.exec-detected",
        "verdict": "true_positive",
        "confidence": "medium",
        "evidence_level": "partial",
        "severity": "medium",
        "reasoning": "Read the sink and its immediate callers; path not fully resolved.",
        "reviewer": {"agent": "model-a", "reviewed_at": "2026-09-01T10:00:00+00:00"},
        "location": {"file": "app/handler.py", "start_line": 4, "end_line": 4},
    }
    verdict.update(overrides)
    return verdict


def make_challenge(result: str = "upheld", **overrides) -> dict:
    challenge = {
        "finding_id": "F-000000000001",
        "challenge_result": result,
        "refutation_attempts": [
            {"claim": "input is attacker controlled", "result": "held"}
        ],
        "reasoning": "Re-derived the flow independently; the claim survived.",
        "validator": {"agent": "model-b", "validated_at": "2026-09-01T12:00:00+00:00"},
    }
    challenge.update(overrides)
    return challenge


class TestCheckConsistency(unittest.TestCase):
    def test_clean_verdict_has_no_problems(self):
        self.assertEqual(record_verdict.check_consistency(make_verdict()), [])

    def test_high_confidence_requires_traced(self):
        problems = record_verdict.check_consistency(
            make_verdict(confidence="high", evidence_level="partial")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("evidence_level=traced", problems[0])

    def test_pattern_cannot_be_true_positive(self):
        problems = record_verdict.check_consistency(
            make_verdict(evidence_level="pattern", verdict="true_positive")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("pattern", problems[0])

    def test_traced_requires_data_flow(self):
        problems = record_verdict.check_consistency(
            make_verdict(evidence_level="traced")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("data_flow", problems[0])

    def test_traced_with_data_flow_is_clean(self):
        problems = record_verdict.check_consistency(
            make_verdict(
                evidence_level="traced",
                data_flow=[{"file": "app/handler.py", "description": "sink"}],
            )
        )
        self.assertEqual(problems, [])

    def test_memory_safety_cwe_requires_runtime_proof(self):
        problems = record_verdict.check_consistency(make_verdict(cwe=["CWE-416"]))
        self.assertEqual(len(problems), 1)
        self.assertIn("CWE-416", problems[0])

    def test_blocked_by_scope_forces_needs_human(self):
        problems = record_verdict.check_consistency(
            make_verdict(blocked_by_scope=["policy/secrets/"], verdict="true_positive")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("needs_human", problems[0])


class TestDecideState(unittest.TestCase):
    def test_medium_without_challenge_is_blocked(self):
        state, _ = record_verdict.decide_state(make_verdict(severity="medium"), None)
        self.assertEqual(state, "blocked_needs_challenge")

    def test_empty_challenge_cannot_promote_required_severities(self):
        for severity in ("critical", "high", "medium"):
            with self.subTest(severity=severity):
                state, rationale = record_verdict.decide_state(
                    make_verdict(severity=severity), {}
                )
                self.assertEqual(state, "blocked_needs_challenge")
                self.assertIn("requires adversarial validation", rationale)
                self.assertNotIn("does not require", rationale)

    def test_challenge_without_result_cannot_promote_high(self):
        challenge = make_challenge()
        del challenge["challenge_result"]
        state, rationale = record_verdict.decide_state(
            make_verdict(severity="high"), challenge
        )
        self.assertEqual(state, "blocked_needs_challenge")
        self.assertIn("requires adversarial validation", rationale)

    def test_refuted_challenge_goes_to_human(self):
        state, rationale = record_verdict.decide_state(
            make_verdict(), make_challenge("refuted")
        )
        self.assertEqual(state, "human_review")
        self.assertIn("refuted", rationale)

    def test_inconclusive_challenge_goes_to_human(self):
        state, _ = record_verdict.decide_state(
            make_verdict(), make_challenge("inconclusive")
        )
        self.assertEqual(state, "human_review")

    def test_runtime_proof_parks_the_finding(self):
        state, _ = record_verdict.decide_state(
            make_verdict(requires_runtime_proof=True), make_challenge()
        )
        self.assertEqual(state, "awaiting_proof")

    def test_pattern_evidence_never_confirms(self):
        state, _ = record_verdict.decide_state(
            make_verdict(verdict="false_positive", evidence_level="pattern"),
            make_challenge(),
        )
        self.assertEqual(state, "dismissed")

    def test_needs_human_verdict_goes_to_human(self):
        state, _ = record_verdict.decide_state(
            make_verdict(verdict="needs_human"), make_challenge()
        )
        self.assertEqual(state, "human_review")

    def test_challenged_true_positive_is_confirmed(self):
        self.assertEqual(
            record_verdict.decide_state(
                make_verdict(evidence_level="partial"), make_challenge("upheld")
            ),
            ("confirmed", "true positive upheld under adversarial validation"),
        )

    # --- Red until Task 7 --------------------------------------------------
    # Policy exempts low and info from adversarial validation, so reaching
    # `confirmed` without a challenge is correct. Claiming the finding was
    # "upheld under adversarial validation" when no second pass ran is not:
    # that sentence is written verbatim into reviewed.sarif and the triage log.

    def test_unchallenged_low_says_so_plainly(self):
        self.assertEqual(
            record_verdict.decide_state(
                make_verdict(severity="low", evidence_level="partial"), None
            ),
            (
                "confirmed",
                "true positive; severity=low does not require adversarial "
                "validation under policy",
            ),
        )

    def test_unchallenged_info_dismissal_says_so_plainly(self):
        self.assertEqual(
            record_verdict.decide_state(
                make_verdict(
                    severity="info", verdict="false_positive", evidence_level="partial"
                ),
                None,
            ),
            (
                "dismissed",
                "false positive; severity=info does not require adversarial "
                "validation under policy",
            ),
        )


class TestSarifAccumulation(unittest.TestCase):
    """docs/04 loops record_verdict over many verdicts; each call must keep
    the previous ones. A single-result write silently discards the batch."""

    def result_for(self, fid, state="confirmed"):
        return record_verdict.build_result(
            make_verdict(finding_id=fid), None, state, "rationale text"
        )

    def test_second_finding_does_not_evict_the_first(self):
        merged = record_verdict.merge_result([], self.result_for("F-1"))
        merged = record_verdict.merge_result(merged, self.result_for("F-2"))
        ids = [r["properties"]["finding_id"] for r in merged]
        self.assertEqual(ids, ["F-1", "F-2"])

    def test_rerecording_replaces_rather_than_duplicates(self):
        merged = record_verdict.merge_result([], self.result_for("F-1", "confirmed"))
        merged = record_verdict.merge_result(merged, self.result_for("F-1", "dismissed"))
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["properties"]["state"], "dismissed")

    def test_order_is_deterministic(self):
        merged = record_verdict.merge_result([], self.result_for("F-9"))
        merged = record_verdict.merge_result(merged, self.result_for("F-1"))
        ids = [r["properties"]["finding_id"] for r in merged]
        self.assertEqual(ids, sorted(ids))

    def test_absent_file_yields_empty_list(self):
        with temp_tree({}) as root:
            self.assertEqual(
                record_verdict.load_existing_results(root / "reviewed.sarif"), []
            )

    def test_unparseable_file_refuses_rather_than_overwriting(self):
        with temp_tree({"reviewed.sarif": "{ this is not json"}) as root:
            with self.assertRaises(record_verdict.ValidationError):
                record_verdict.load_existing_results(root / "reviewed.sarif")

    # Two CLI-level tests for this task live in Task 12's
    # TestIndependenceControl instead: --fresh, and the refusal on malformed
    # existing SARIF. Both need --log so they do not write into the real
    # findings/ directory, and --log only exists from Task 12 onward.

    def test_round_trip_through_document(self):
        doc = record_verdict.sarif_document([self.result_for("F-1")])
        with temp_tree({}) as root:
            path = root / "reviewed.sarif"
            path.write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual(len(record_verdict.load_existing_results(path)), 1)


class TestIndependenceControl(unittest.TestCase):
    """docs/04 calls independence the mechanism. A warning is not a mechanism."""

    def run_recorder(self, args, cwd):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "record_verdict.py"), *args],
            capture_output=True,
            text=True,
            cwd=str(cwd),
        )

    def setup_files(self, root):
        verdict = make_verdict(severity="low", evidence_level="partial")
        challenge = make_challenge("upheld")
        (root / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")
        (root / "challenge.json").write_text(json.dumps(challenge), encoding="utf-8")

    def assert_challenge_schema_refused_without_writes(self, document, severity):
        # Exercise the real CLI both with normal imports and with site packages
        # disabled, so the optional validator cannot hide a fallback bypass.
        for python_args in ([], ["-S"]):
            with self.subTest(severity=severity, python_args=python_args), temp_tree({
                "verdict.json": json.dumps(make_verdict(severity=severity)),
                "challenge.json": document,
            }) as root:
                log = root / "triage-log.csv"
                sarif = root / "reviewed.sarif"
                proc = subprocess.run(
                    [
                        sys.executable, *python_args,
                        str(REPO_ROOT / "scripts" / "record_verdict.py"),
                        "--verdict", str(root / "verdict.json"),
                        "--challenge", str(root / "challenge.json"),
                        "--agent", "model-a", "--validator", "model-b",
                        "--log", str(log), "--sarif-out", str(sarif),
                    ],
                    capture_output=True, text=True, cwd=root,
                )
                self.assertFalse(log.exists(), "a refused run must not write the log")
                self.assertFalse(sarif.exists(), "a refused run must not write SARIF")
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("SCHEMA ERROR: challenge.schema.json", proc.stderr)
                self.assertIn("required" if document == "{}" else "object", proc.stderr)

    def test_empty_challenge_is_schema_refused_without_writes(self):
        for severity in ("low", "high"):
            self.assert_challenge_schema_refused_without_writes("{}", severity)

    def test_null_challenge_is_schema_refused_without_writes_low(self):
        self.assert_challenge_schema_refused_without_writes("null", "low")

    def test_null_challenge_is_schema_refused_without_writes_high(self):
        self.assert_challenge_schema_refused_without_writes("null", "high")

    def test_same_model_is_refused_and_writes_nothing(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--challenge", str(root / "challenge.json"),
                    "--agent", "model-a",
                    "--validator", "model-a",
                    "--sarif-out", str(sarif),
                    "--log", str(log),
                ],
                root,
            )
            # Absence is asserted INSIDE the block. temp_tree deletes the whole
            # tree on exit, so exists() afterwards is False no matter what the
            # process did, and the assertion could never fail.
            self.assertFalse(log.exists(), "a refused run must not write the log")
            self.assertFalse(sarif.exists(), "a refused run must not write SARIF")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("REFUSED", proc.stderr)

    def test_missing_agent_is_refused(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(["--verdict", str(root / "verdict.json")], root)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--agent", proc.stderr)

    def test_challenge_without_validator_is_refused(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--challenge", str(root / "challenge.json"),
                    "--agent", "model-a",
                ],
                root,
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--validator", proc.stderr)

    def test_fresh_discards_the_existing_sarif(self):
        # Deferred from Task 8: --fresh is only observable through the CLI, and
        # the recorder's argument set settles in this task.
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            sarif = root / "reviewed.sarif"
            stale = record_verdict.build_result(
                make_verdict(finding_id="F-stale"), None, "confirmed", "old"
            )
            sarif.write_text(
                json.dumps(record_verdict.sarif_document([stale])), encoding="utf-8"
            )
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--agent", "model-a",
                    "--sarif-out", str(sarif),
                    "--log", str(root / "triage-log.csv"),
                    "--fresh",
                ],
                root,
            )
            ids = [
                r["properties"]["finding_id"]
                for r in record_verdict.load_existing_results(sarif)
            ]
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("F-stale", ids)

    def test_single_model_run_without_challenge_is_accepted(self):
        # severity=low needs no challenge, so one model is legitimate here.
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--agent", "model-a",
                    "--sarif-out", str(root / "reviewed.sarif"),
                    "--log", str(root / "triage-log.csv"),
                ],
                root,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_malformed_sarif_refuses_before_touching_the_log(self):
        # Deferred from Task 8 alongside the --fresh test. Regression for the
        # ordering requirement: the log is append-only, so a row written ahead
        # of a SARIF failure could never be withdrawn.
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            sarif.write_text("{ not json", encoding="utf-8")
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--agent", "model-a",
                    "--sarif-out", str(sarif),
                    "--log", str(log),
                ],
                root,
            )
            # Inside the block: see the note in test_same_model_is_refused.
            self.assertFalse(log.exists(), "a refused run must not create the log")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SARIF ERROR", proc.stderr)

    def test_unchallenged_dismissal_suppression_does_not_claim_validation(self):
        with temp_tree({
            "verdict.json": json.dumps(make_verdict(severity="info", verdict="false_positive")),
        }) as root:
            sarif = root / "reviewed.sarif"
            proc = self.run_recorder([
                "--verdict", str(root / "verdict.json"), "--agent", "model-a",
                "--sarif-out", str(sarif), "--log", str(root / "triage-log.csv"),
            ], root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            result = json.loads(sarif.read_text())["runs"][0]["results"][0]
            justification = result["suppressions"][0]["justification"]
            self.assertNotIn("Dismissed after adversarial validation", justification)
            self.assertEqual(justification, "Dismissed after review. false positive; severity=info "
                             "does not require adversarial validation under policy")

    def test_structurally_invalid_sarif_refuses_without_log_growth(self):
        for result in (None, {}, {"properties": None}, {"properties": []}):
            with self.subTest(result=result), temp_tree({}) as root:
                self.setup_files(root)
                log = root / "triage-log.csv"
                write_log(log, [{
                    "finding_id": "F-previous", "initial_verdict": "true_positive",
                    "id_scheme": "content-v1",
                }])
                sarif = root / "reviewed.sarif"
                sarif.write_text(json.dumps(record_verdict.sarif_document([result])), encoding="utf-8")
                before_log, before_sarif = log.read_bytes(), sarif.read_bytes()
                proc = self.run_recorder([
                    "--verdict", str(root / "verdict.json"), "--agent", "model-a",
                    "--sarif-out", str(sarif), "--log", str(log),
                ], root)
                self.assertEqual(log.read_bytes(), before_log, "refusal must not append an audit row")
                self.assertEqual(sarif.read_bytes(), before_sarif)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("SARIF ERROR", proc.stderr)
                self.assertIn("results[0] is not a reviewed finding", proc.stderr)

    def test_distinct_models_are_accepted(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--challenge", str(root / "challenge.json"),
                    "--agent", "model-a",
                    "--validator", "model-b",
                    "--sarif-out", str(root / "reviewed.sarif"),
                    "--log", str(root / "triage-log.csv"),
                ],
                root,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)


class TestLogCompatibility(unittest.TestCase):
    """csv.DictWriter appends happily under a stale header, misaligning every
    column. A silently corrupted audit trail is worse than a refusal."""

    def test_absent_log_is_fine(self):
        with temp_tree({}) as root:
            record_verdict.check_log_compatible(root / "triage-log.csv", "content-v1")

    def test_stale_header_is_refused(self):
        with temp_tree({"triage-log.csv": "reviewed_at,finding_id\n2026-01-01,F-1\n"}) as root:
            with self.assertRaises(record_verdict.ValidationError) as ctx:
                record_verdict.check_log_compatible(root / "triage-log.csv", "content-v1")
            self.assertIn("missing columns", str(ctx.exception))

    def test_current_header_is_accepted(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [])
            record_verdict.check_log_compatible(log, "content-v1")

    def test_foreign_id_scheme_is_refused(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [{"finding_id": "F-1", "id_scheme": "line-v0"}])
            with self.assertRaises(record_verdict.ValidationError) as ctx:
                record_verdict.check_log_compatible(log, "content-v1")
            self.assertIn("line-v0", str(ctx.exception))

    def test_log_carries_self_reported_columns(self):
        self.assertIn("agent_self_reported", record_verdict.LOG_FIELDS)
        self.assertIn("validator_self_reported", record_verdict.LOG_FIELDS)
        self.assertIn("id_scheme", record_verdict.LOG_FIELDS)

    def test_empty_log_file_still_gets_a_header(self):
        # A zero-byte file exists but is not yet a log: an interrupted write or
        # a stray touch leaves one behind. Appending without a header would put
        # a data row where csv.DictReader expects column names, and every
        # column would silently take its name from the first finding.
        with temp_tree({"triage-log.csv": ""}) as root:
            log = root / "triage-log.csv"
            record_verdict.check_log_compatible(log, "content-v1")
            record_verdict.append_log({"finding_id": "F-1"}, log)
            with log.open(encoding="utf-8", newline="") as fh:
                first_line = next(csv.reader(fh))
        self.assertEqual(first_line, record_verdict.LOG_FIELDS)


class TestVerdictRows(unittest.TestCase):
    def test_verdict_rows_are_found(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [{
                "finding_id": "F-000000000001",
                "id_scheme": "content-v1",
                "initial_verdict": "true_positive",
                "reviewed_at": "2026-09-01T10:00:00+00:00",
            }, {
                "finding_id": "F-000000000002",
                "id_scheme": "content-v1",
                "initial_verdict": "false_positive",
                "reviewed_at": "2026-09-01T11:00:00+00:00",
            }])
            rows = record_verdict.verdict_rows(log, "F-000000000001")
        self.assertEqual(
            [row["finding_id"] for row in rows], ["F-000000000001"]
        )

    def test_rows_without_a_verdict_are_not_counted(self):
        # Human-decision rows share the finding_id but decide on a verdict
        # rather than being one, so superseding must not see them.
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [{
                "finding_id": "F-000000000001",
                "human_decision": "accepted",
            }])
            self.assertEqual(record_verdict.verdict_rows(log, "F-000000000001"), [])

    def test_absent_log_has_no_rows(self):
        with temp_tree({}) as root:
            self.assertEqual(
                record_verdict.verdict_rows(root / "absent.csv", "F-1"), []
            )


class TestSupersedeCli(unittest.TestCase):
    """Re-recording must be a deliberate act. The log is append-only, so a
    silent second row would let metrics count one finding as two."""

    def write_verdict(self, root, **overrides):
        verdict = make_verdict(severity="low", evidence_level="partial", **overrides)
        (root / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")

    def run_recorder(self, root, extra=()):
        return subprocess.run(
            [
                sys.executable, str(REPO_ROOT / "scripts" / "record_verdict.py"),
                "--verdict", str(root / "verdict.json"),
                "--agent", "model-a",
                "--log", str(root / "triage-log.csv"),
                "--sarif-out", str(root / "reviewed.sarif"),
                *extra,
            ],
            capture_output=True,
            text=True,
        )

    def test_first_recording_succeeds(self):
        with temp_tree({}) as root:
            self.write_verdict(root)
            proc = self.run_recorder(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_second_recording_without_the_flag_is_refused(self):
        with temp_tree({}) as root:
            self.write_verdict(root)
            self.assertEqual(self.run_recorder(root).returncode, 0)
            proc = self.run_recorder(root)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("--supersede", proc.stderr)
            rows = record_verdict.verdict_rows(
                root / "triage-log.csv", "F-000000000001"
            )
        self.assertEqual(len(rows), 1, "a refused run must not append")

    def test_supersede_appends_and_points_back(self):
        with temp_tree({}) as root:
            self.write_verdict(root)
            self.assertEqual(self.run_recorder(root).returncode, 0)

            revised = make_verdict(
                severity="low", evidence_level="partial", verdict="false_positive"
            )
            revised["reviewer"]["reviewed_at"] = "2026-09-02T10:00:00+00:00"
            (root / "verdict.json").write_text(json.dumps(revised), encoding="utf-8")

            proc = self.run_recorder(root, ["--supersede"])
            self.assertEqual(proc.returncode, 0, proc.stderr)

            record_verdict.append_log({
                "finding_id": "F-000000000001",
                "human_decision": "accepted",
            }, root / "triage-log.csv")

            third = make_verdict(severity="low", evidence_level="partial")
            third["reviewer"]["reviewed_at"] = "2026-09-03T10:00:00+00:00"
            (root / "verdict.json").write_text(json.dumps(third), encoding="utf-8")
            proc = self.run_recorder(root, ["--supersede"])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = record_verdict.verdict_rows(
                root / "triage-log.csv", "F-000000000001"
            )
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1]["supersedes"], "2026-09-01T10:00:00+00:00")
        self.assertEqual(rows[1]["initial_verdict"], "false_positive")
        self.assertEqual(rows[2]["supersedes"], "2026-09-02T10:00:00+00:00")

    def test_duplicate_refusal_precedes_warnings_and_sarif_parsing(self):
        with temp_tree({}) as root:
            self.write_verdict(root)
            self.assertEqual(self.run_recorder(root).returncode, 0)

            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            sarif.write_text("{ malformed", encoding="utf-8")
            log_before = log.read_bytes()
            sarif_before = sarif.read_bytes()

            self.write_verdict(
                root,
                reviewer={
                    "agent": "self-reported-other-model",
                    "reviewed_at": "2026-09-02T10:00:00+00:00",
                },
            )
            proc = self.run_recorder(root)

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("REFUSED", proc.stderr)
            self.assertNotIn("WARNING", proc.stderr)
            self.assertNotIn("SARIF ERROR", proc.stderr)
            self.assertEqual(log.read_bytes(), log_before)
            self.assertEqual(sarif.read_bytes(), sarif_before)


class TestFallbackValidator(unittest.TestCase):
    """The fallback exists so a missing jsonschema degrades the check rather
    than removing it. It degraded further than advertised."""

    SCHEMA = {
        "required": ["name"],
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string", "minLength": 2},
            "count": {"type": "integer"},
            "mode": {"type": "string", "enum": ["a", "b"]},
            "steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {"file": {"type": "string"}},
                },
            },
            "tags": {"type": "array", "items": {"type": "string"}},
        },
    }

    def validate(self, instance):
        record_verdict._fallback_validate(instance, self.SCHEMA, "fixture")

    def test_missing_required_field(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({})

    def test_unknown_field_when_additional_properties_false(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "surprise": 1})

    def test_enum_is_enforced(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "mode": "c"})

    def test_min_length_is_enforced(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "x"})

    def test_valid_instance_passes(self):
        self.validate({"name": "ok", "count": 3, "mode": "a", "tags": ["x"]})

    # --- Gaps closed by this task -----------------------------------------

    def test_boolean_is_not_an_integer(self):
        # bool subclasses int in Python, so isinstance(True, int) is True and
        # `"count": True` slipped through as a valid integer.
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "count": True})

    def test_array_items_are_validated(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "steps": [{"line": 3}]})

    def test_scalar_array_items_are_type_checked(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "tags": [1]})

    def test_unknown_schema_type_is_reported_not_crashed(self):
        with self.assertRaises(record_verdict.ValidationError):
            record_verdict._fallback_validate(
                {"x": 1}, {"properties": {"x": {"type": "int64"}}}, "fixture"
            )

    def test_top_level_non_object_is_reported_not_crashed(self):
        with self.assertRaises(record_verdict.ValidationError):
            record_verdict._fallback_validate(
                [], {"type": "object", "properties": {}}, "fixture"
            )


class TestSchemaDriftGuard(unittest.TestCase):
    """check_consistency compensates for the two conditional rules the
    fallback validator cannot express. If the schema grows a third, this test
    fails and forces someone to decide whether to mirror it."""

    def test_schema_has_exactly_the_conditionals_we_mirror(self):
        schema = json.loads(
            (record_verdict.SCHEMA_DIR / "verdict.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(schema["allOf"]), 2)

    def test_high_confidence_conditional_is_mirrored(self):
        self.assertTrue(
            record_verdict.check_consistency(
                make_verdict(confidence="high", evidence_level="partial")
            )
        )

    def test_pattern_verdict_conditional_is_mirrored(self):
        self.assertTrue(
            record_verdict.check_consistency(
                make_verdict(evidence_level="pattern", verdict="true_positive")
            )
        )


if __name__ == "__main__":
    unittest.main()
