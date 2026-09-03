"""Tests for programme metrics.

Metric 4 (disagreement rate) is the one that tells you whether the second pass
is doing any work, so its edge cases matter more than the headline numbers.
"""

import unittest

import metrics
from tests.helpers import temp_tree, write_log


def row(**overrides) -> dict:
    base = {
        "reviewed_at": "2026-09-01T10:00:00+00:00",
        "finding_id": "F-000000000001",
        "severity": "medium",
        "evidence_level": "traced",
        "confidence": "high",
        "initial_verdict": "true_positive",
        "challenge_result": "upheld",
        "final_state": "confirmed",
        "minutes_spent": "10",
        "requires_runtime_proof": "False",
        "agent": "model-a",
        "validator": "model-b",
    }
    base.update(overrides)
    return base


class TestCompute(unittest.TestCase):
    def compute(self, rows):
        with temp_tree({"placeholder": ""}) as root:
            log = root / "triage-log.csv"
            write_log(log, rows)
            return metrics.compute(metrics.load_rows(log, None))

    def test_empty_log(self):
        self.assertEqual(metrics.compute([]), {"total": 0})

    def test_missing_log_is_not_an_error(self):
        self.assertEqual(metrics.load_rows(metrics.LOG_PATH.parent / "absent.csv", None), [])

    def test_counts_states(self):
        m = self.compute([row(), row(finding_id="F-2", final_state="dismissed")])
        self.assertEqual(m["total"], 2)
        self.assertEqual(m["decided"], 2)
        self.assertEqual(m["undecided"], 0)

    def test_rate_excludes_undecided_findings(self):
        # Parked findings are not evidence of precision, so they must stay out
        # of the denominator.
        m = self.compute(
            [
                row(),
                row(finding_id="F-2", final_state="dismissed"),
                row(finding_id="F-3", final_state="human_review", challenge_result=""),
            ]
        )
        self.assertEqual(m["decided"], 2)
        self.assertEqual(m["undecided"], 1)
        self.assertEqual(m["false_positive_rate_pct"], 50.0)

    def test_disagreement_rate_over_challenged_only(self):
        m = self.compute(
            [
                row(),
                row(finding_id="F-2", challenge_result="refuted", final_state="human_review"),
            ]
        )
        self.assertEqual(m["disagreement_rate_pct"], 50.0)

    def test_same_model_validations_are_counted(self):
        m = self.compute([row(validator="model-a")])
        self.assertEqual(m["same_model_validations"], 1)

    def test_timings(self):
        m = self.compute([row(minutes_spent="10"), row(finding_id="F-2", minutes_spent="20")])
        self.assertEqual(m["median_minutes"], 15.0)
        self.assertEqual(m["timed_findings"], 2)

    def test_unparseable_timing_is_skipped_not_fatal(self):
        m = self.compute([row(minutes_spent=""), row(finding_id="F-2", minutes_spent="8")])
        self.assertEqual(m["timed_findings"], 1)

    def test_since_filter(self):
        with temp_tree({"placeholder": ""}) as root:
            log = root / "triage-log.csv"
            write_log(
                log,
                [
                    row(reviewed_at="2026-07-01T10:00:00+00:00"),
                    row(finding_id="F-2", reviewed_at="2026-09-01T10:00:00+00:00"),
                ],
            )
            kept = metrics.load_rows(log, "2026-08-01")
        self.assertEqual([r["finding_id"] for r in kept], ["F-2"])


class TestRender(unittest.TestCase):
    def test_empty_render_tells_you_what_to_do(self):
        self.assertIn("No reviews recorded yet", metrics.render({"total": 0}))

    def test_zero_disagreement_raises_the_alarm(self):
        m = metrics.compute(
            [
                dict(row(), final_state="confirmed"),
                dict(row(), finding_id="F-2", final_state="confirmed"),
            ]
        )
        self.assertIn("rubber-stamping", metrics.render(m))


if __name__ == "__main__":
    unittest.main()
