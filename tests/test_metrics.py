"""Tests for programme metrics."""

import unittest

import metrics
from tests.helpers import temp_tree, write_log


def row(**overrides) -> dict:
    base = {
        "reviewed_at": "2026-09-01T10:00:00+00:00", "finding_id": "F-000000000001",
        "severity": "medium", "evidence_level": "traced", "confidence": "high",
        "initial_verdict": "true_positive", "challenge_result": "upheld",
        "final_state": "confirmed", "minutes_spent": "10",
        "requires_runtime_proof": "False", "agent": "model-a", "validator": "model-b",
        "human_decision": "", "human_decision_at": "", "human_decision_by": "",
        "human_rationale": "", "supersedes": "",
    }
    base.update(overrides)
    return base


def compute(rows):
    return metrics.compute(metrics.collapse(rows))


def decision(finding_id, value, reviewed_at="2026-09-02T10:00:00+00:00"):
    return {"finding_id": finding_id, "human_decision": value, "reviewed_at": reviewed_at}


class TestCompute(unittest.TestCase):
    def test_empty_log(self):
        self.assertEqual(metrics.compute([]), {"total": 0})

    def test_missing_log_is_not_an_error(self):
        self.assertEqual(metrics.load_rows(metrics.LOG_PATH.parent / "absent.csv"), [])

    def test_counts_states(self):
        m = compute([row(), row(finding_id="F-2", final_state="dismissed")])
        self.assertEqual((m["total"], m["decided"], m["undecided"]), (2, 2, 0))

    def test_rate_excludes_undecided_findings(self):
        m = compute([row(), row(finding_id="F-2", final_state="dismissed"),
                     row(finding_id="F-3", final_state="human_review", challenge_result="")])
        self.assertEqual(m["dismissal_rate_pct"], 50.0)

    def test_timings(self):
        m = compute([row(minutes_spent="10"), row(finding_id="F-2", minutes_spent="20")])
        self.assertEqual((m["median_minutes"], m["timed_findings"]), (15.0, 2))

    def test_zero_minutes_are_recorded(self):
        records = metrics.collapse([
            row(minutes_spent="0"),
            {"finding_id": "F-000000000001", "human_decision": "accepted",
             "reviewed_at": "2026-09-02T10:00:00+00:00", "minutes_spent": "0"},
        ])
        m = metrics.compute(records)
        self.assertEqual(records[0]["triage_minutes_total"], 0.0)
        self.assertEqual(records[0]["decision_minutes_total"], 0.0)
        self.assertEqual((m["median_minutes"], m["decision_minutes_total"]), (0.0, 0.0))

    def test_since_filter(self):
        with temp_tree({"placeholder": ""}) as root:
            log = root / "triage-log.csv"
            write_log(log, [row(reviewed_at="2026-07-01T10:00:00+00:00"),
                            row(finding_id="F-2", reviewed_at="2026-09-01T10:00:00+00:00")])
            kept = metrics.filter_since(metrics.collapse(metrics.load_rows(log)), "2026-08-01")
        self.assertEqual([r["finding_id"] for r in kept], ["F-2"])


class TestCollapse(unittest.TestCase):
    def test_superseded_verdict_counts_once(self):
        collapsed = metrics.collapse([row(), row(final_state="dismissed", reviewed_at="2026-09-02T10:00:00+00:00", supersedes="old")])
        self.assertEqual((len(collapsed), collapsed[0]["final_state"]), (1, "dismissed"))

    def test_human_decision_row_merges_into_the_finding(self):
        collapsed = metrics.collapse([row(), {"finding_id": "F-000000000001", "human_decision": "rejected", "human_decision_by": "appsec-oncall"}])
        self.assertEqual((collapsed[0]["final_state"], collapsed[0]["human_decision"]), ("confirmed", "rejected"))

    def test_missing_or_malformed_timestamps_have_a_stable_fallback(self):
        rows = [row(final_state="confirmed", reviewed_at="not-a-timestamp"), row(final_state="dismissed", reviewed_at="")]
        self.assertEqual(metrics.collapse(rows), metrics.collapse(list(reversed(rows))))

    def test_revisions_are_counted_from_verdict_rows(self):
        self.assertEqual(compute([row(), row(reviewed_at="2026-09-02T10:00:00+00:00", minutes_spent="")])["revisions"], 1)


class TestCollapseSemantics(unittest.TestCase):
    def test_new_verdict_does_not_inherit_the_old_challenge(self):
        first = row(challenge_result="upheld", validator="model-b")
        second = row(reviewed_at="2026-09-02T10:00:00+00:00", challenge_result="", validator="", supersedes="old")
        collapsed = metrics.collapse([first, second])
        self.assertEqual((collapsed[0]["challenge_result"], collapsed[0]["validator"]), ("", ""))

    def test_decision_survives_a_later_verdict_revision(self):
        collapsed = metrics.collapse([row(), {"finding_id": "F-000000000001", "human_decision": "rejected", "reviewed_at": "2026-09-02T10:00:00+00:00"}, row(reviewed_at="2026-09-03T10:00:00+00:00", final_state="dismissed")])
        self.assertEqual((collapsed[0]["human_decision"], collapsed[0]["final_state"]), ("rejected", "dismissed"))

    def test_equal_timestamps_break_by_log_position(self):
        first, second = row(final_state="confirmed"), row(final_state="dismissed")
        self.assertEqual(metrics.collapse([first, second])[0]["final_state"], "dismissed")
        self.assertEqual(metrics.collapse([second, first])[0]["final_state"], "confirmed")

    def test_triage_minutes_sum_across_revisions(self):
        self.assertEqual(metrics.collapse([row(minutes_spent="10"), row(reviewed_at="2026-09-02T10:00:00+00:00", minutes_spent="4")])[0]["triage_minutes_total"], 14.0)

    def test_decision_minutes_stay_separate(self):
        collapsed = metrics.collapse([row(minutes_spent="10"), {"finding_id": "F-000000000001", "human_decision": "accepted", "minutes_spent": "3", "reviewed_at": "2026-09-02T10:00:00+00:00"}])
        self.assertEqual((collapsed[0]["triage_minutes_total"], collapsed[0]["decision_minutes_total"]), (10.0, 3.0))


class TestSinceSelectsFindings(unittest.TestCase):
    def test_a_finding_enters_whole_or_not_at_all(self):
        records = metrics.collapse([row(reviewed_at="2026-07-01T10:00:00+00:00"), {"finding_id": "F-000000000001", "human_decision": "accepted", "reviewed_at": "2026-09-01T10:00:00+00:00"}])
        kept = metrics.filter_since(records, "2026-08-01")
        self.assertEqual((len(kept), kept[0]["final_state"], kept[0]["human_decision"]), (1, "confirmed", "accepted"))

    def test_untouched_findings_fall_outside_the_window(self):
        self.assertEqual(metrics.filter_since(metrics.collapse([row(reviewed_at="2026-07-01T10:00:00+00:00")]), "2026-08-01"), [])


class TestAgentAccuracy(unittest.TestCase):
    def test_accuracy_uses_only_rows_with_a_decision(self):
        m = compute([row(finding_id="F-1"), decision("F-1", "accepted"), row(finding_id="F-2"), decision("F-2", "accepted"), row(finding_id="F-3"), decision("F-3", "rejected"), row(finding_id="F-4")])
        self.assertEqual((m["human_decisions"], m["agent_accuracy_pct"]), (3, 66.7))

    def test_escalated_is_not_counted_as_right_or_wrong(self):
        self.assertEqual(compute([row(finding_id="F-1"), decision("F-1", "accepted"), row(finding_id="F-2"), decision("F-2", "escalated")])["agent_accuracy_pct"], 100.0)

    def test_human_review_decisions_do_not_inflate_decided_coverage(self):
        m = compute([row(finding_id="F-1"), decision("F-1", "accepted"), row(finding_id="F-2", final_state="dismissed"), row(finding_id="F-3", final_state="human_review"), decision("F-3", "rejected")])
        self.assertEqual((m["human_decisions"], m["human_decision_coverage_pct"], m["agent_accuracy_pct"]), (2, 50.0, 50.0))

    def test_low_coverage_warns_in_the_render(self):
        rows = [row(finding_id=f"F-{i}") for i in range(10)] + [decision("F-0", "accepted")]
        self.assertIn("biased", metrics.render(compute(rows)))

    def test_dismissal_rate_is_no_longer_called_accuracy(self):
        m = compute([row(final_state="dismissed")])
        self.assertIn("dismissal_rate_pct", m)
        self.assertNotIn("false_positive_rate_pct", m)

    def test_render_reports_revisions(self):
        self.assertIn("Verdicts revised         1", metrics.render(compute([row(), row(reviewed_at="2026-09-02T10:00:00+00:00")])))


class TestUndefinedDenominator(unittest.TestCase):
    def test_accuracy_is_withheld_when_nothing_is_decided(self):
        m = compute([row(final_state="human_review", challenge_result="refuted"), {"finding_id": "F-000000000001", "human_decision": "accepted", "reviewed_at": "2026-09-02T10:00:00+00:00"}])
        self.assertEqual(m["decided"], 0)
        self.assertIsNone(m["human_decision_coverage_pct"])
        self.assertIsNone(m["agent_accuracy_pct"])
        self.assertEqual(m["human_decisions"], 1)
        self.assertIn("not computed rather than guessed", metrics.render(m))


class TestRenderSafeguards(unittest.TestCase):
    def test_missing_triage_minutes_explain_the_programme_risk(self):
        rendered = metrics.render(compute([row(minutes_spent="")]))
        self.assertIn("Pass --minutes to record_verdict.py", rendered)
        self.assertIn("primary success measure", rendered)

    def test_zero_disagreement_raises_the_alarm(self):
        self.assertIn("rubber-stamping", metrics.render(compute([row(), row(finding_id="F-2")])))

    def test_high_disagreement_raises_the_alarm(self):
        self.assertIn("High disagreement", metrics.render(compute([
            row(challenge_result="refuted", final_state="human_review"),
            row(finding_id="F-2", challenge_result="refuted", final_state="human_review"),
            row(finding_id="F-3"),
        ])))

    def test_same_model_validation_warns(self):
        self.assertIn("same model", metrics.render(compute([row(validator="model-a")])))

    def test_parked_runtime_proof_is_rendered(self):
        self.assertIn("Parked awaiting proof", metrics.render(compute([
            row(final_state="human_review", requires_runtime_proof="True"),
        ])))


if __name__ == "__main__":
    unittest.main()
