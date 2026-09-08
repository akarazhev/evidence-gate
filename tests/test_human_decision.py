"""Tests for the ground-truth record.

Without a human decision the programme can describe what the pipeline did but
not whether it was right, and that is the question a pilot exists to answer.
"""

import csv
import json
import subprocess
import sys
import unittest

import record_verdict
from tests import REPO_ROOT
from tests.helpers import temp_tree, write_log

SCRIPT = REPO_ROOT / "scripts" / "record_human_decision.py"


def verdict_row(fid="F-000000000001"):
    return {
        "reviewed_at": "2026-09-01T10:00:00+00:00",
        "finding_id": fid,
        "id_scheme": "content-v1",
        "initial_verdict": "true_positive",
        "final_state": "confirmed",
        "severity": "high",
        "agent": "model-a",
        "validator": "model-b",
    }


class TestDecisionRecording(unittest.TestCase):
    def run_script(self, args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args], capture_output=True, text=True
        )

    def test_script_can_be_invoked_directly(self):
        proc = subprocess.run(
            [str(SCRIPT), "--help"], capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--finding-id", proc.stdout)

    def test_unknown_finding_is_refused(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [verdict_row()])
            proc = self.run_script([
                "--finding-id", "F-nope", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log),
                "--sarif", str(root / "reviewed.sarif"),
            ])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("F-nope", proc.stderr)

    def test_invalid_decision_is_refused(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [verdict_row()])
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "maybe",
                "--by", "appsec-oncall", "--log", str(log),
                "--sarif", str(root / "reviewed.sarif"),
            ])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("invalid choice", proc.stderr)

    def test_decision_is_appended_to_the_log(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [verdict_row()])
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "rejected",
                "--by", "appsec-oncall", "--rationale", "sanitiser upstream",
                "--log", str(log), "--sarif", str(root / "reviewed.sarif"),
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with log.open(encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[-1]["human_decision"], "rejected")
        self.assertEqual(rows[-1]["human_decision_by"], "appsec-oncall")
        self.assertEqual(rows[-1]["finding_id"], "F-000000000001")

    def test_stale_log_header_is_refused_and_nothing_is_written(self):
        # A log written before a column existed. Its verdict row is still
        # readable, so the run gets past the "no verdict" check and reaches the
        # log contract, which must refuse rather than append under old names.
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            stale_fields = [f for f in record_verdict.LOG_FIELDS if f != "notes"]
            values = {
                "finding_id": "F-000000000001",
                "initial_verdict": "true_positive",
                "final_state": "confirmed",
                "reviewed_at": "2026-09-01T10:00:00+00:00",
            }
            with log.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=stale_fields)
                writer.writeheader()
                writer.writerow({k: values.get(k, "") for k in stale_fields})
            before = log.read_text(encoding="utf-8")
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log),
                "--sarif", str(root / "reviewed.sarif"),
            ])
            after = log.read_text(encoding="utf-8")
            self.assertEqual(before, after, "a refused run must not append")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("LOG ERROR", proc.stderr)

    def test_malformed_sarif_refuses_and_leaves_the_log_untouched(self):
        # The SARIF is parsed before anything is written, because the triage
        # log is append-only and a row added ahead of a SARIF failure could
        # never be withdrawn.
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            write_log(log, [verdict_row()])
            sarif.write_text("{ not json", encoding="utf-8")
            before = log.read_text(encoding="utf-8")
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log), "--sarif", str(sarif),
            ])
            after = log.read_text(encoding="utf-8")
            self.assertEqual(before, after, "a refused run must not append to the log")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SARIF ERROR", proc.stderr)

    def test_sarif_properties_are_updated(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            write_log(log, [verdict_row()])
            result = record_verdict.build_result(
                {
                    "finding_id": "F-000000000001",
                    "severity": "high",
                    "reasoning": "text",
                    "location": {"file": "app/handler.py", "start_line": 4},
                },
                None,
                "confirmed",
                "rationale",
            )
            sarif.write_text(
                json.dumps(record_verdict.sarif_document([result])), encoding="utf-8"
            )
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log), "--sarif", str(sarif),
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            results = record_verdict.load_existing_results(sarif)
        self.assertEqual(results[0]["properties"]["human_decision"], "accepted")


if __name__ == "__main__":
    unittest.main()
