"""Tests for programme metrics."""

import json
import subprocess
import sys
import unittest

import metrics
from tests import REPO_ROOT
from tests.helpers import temp_tree, write_log
from tests.test_record_verdict import make_verdict


def row(**overrides) -> dict:
    base = {
        "reviewed_at": "2020-01-01T00:00:00+00:00",
        "recorded_at": "2026-09-01T10:00:00+00:00", "finding_id": "F-000000000001",
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


def decision(finding_id, value, recorded_at="2026-09-02T10:00:00+00:00"):
    return {"finding_id": finding_id, "human_decision": value, "recorded_at": recorded_at}


class TestRecordedOrder(unittest.TestCase):
    def record(self, root, verdict, supersede=False):
        path = root / "verdict.json"
        path.write_text(json.dumps(verdict), encoding="utf-8")
        proc = subprocess.run([
            sys.executable, str(REPO_ROOT / "scripts/record_verdict.py"),
            "--verdict", str(path), "--agent", "model-a",
            "--log", str(root / "triage-log.csv"),
            "--sarif-out", str(root / "reviewed.sarif"),
            *(["--supersede"] if supersede else []),
        ], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def compare_writer_and_metrics(self, root, expected_state, expected_coverage):
        props = json.loads((root / "reviewed.sarif").read_text())["runs"][0]["results"][0]["properties"]
        records = metrics.collapse(metrics.load_rows(root / "triage-log.csv"))
        self.assertEqual(props["state"], expected_state)
        self.assertEqual(records[0]["final_state"], props["state"],
                         "metrics must name the state the real writer emitted")
        self.assertEqual(bool(records[0].get("human_decision")), bool(props.get("human_decision")),
                         "metrics must agree with the writer about current human consent")
        self.assertEqual(metrics.compute(records)["human_decision_coverage_pct"], expected_coverage)

    def test_later_recording_with_earlier_reviewed_at_matches_sarif(self):
        with temp_tree({}) as root:
            first = make_verdict(severity="low")
            self.record(root, first)
            self.record(root, make_verdict(
                severity="low", verdict="false_positive",
                reviewer={"agent": "model-a", "reviewed_at": "2026-09-01T09:00:00+00:00"},
            ), supersede=True)
            self.compare_writer_and_metrics(root, "dismissed", 0.0)

    def test_revision_recorded_after_decision_clears_consent_in_both_outputs(self):
        with temp_tree({}) as root:
            self.record(root, make_verdict(severity="low"))
            proc = subprocess.run([
                sys.executable, str(REPO_ROOT / "scripts/record_human_decision.py"),
                "--finding-id", "F-000000000001", "--decision", "accepted", "--by", "appsec-oncall",
                "--log", str(root / "triage-log.csv"), "--sarif", str(root / "reviewed.sarif"),
            ], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.compare_writer_and_metrics(root, "confirmed", 100.0)
            self.record(root, make_verdict(
                severity="low", verdict="false_positive",
                reviewer={"agent": "model-a", "reviewed_at": "2026-09-01T11:00:00+00:00"},
            ), supersede=True)
            self.compare_writer_and_metrics(root, "dismissed", 0.0)

    def test_since_uses_recorded_event_time_not_model_self_report(self):
        records = metrics.collapse([
            row(finding_id="F-new", reviewed_at="2020-01-01T00:00:00Z", recorded_at="2026-09-02T00:00:00Z"),
            row(finding_id="F-old", reviewed_at="2099-01-01T00:00:00Z", recorded_at="2026-07-01T00:00:00Z"),
        ])
        self.assertEqual([r["finding_id"] for r in metrics.filter_since(records, "2026-09-01")], ["F-new"])


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
             "recorded_at": "2026-09-02T10:00:00+00:00", "minutes_spent": "0"},
        ])
        m = metrics.compute(records)
        self.assertEqual(records[0]["triage_minutes_total"], 0.0)
        self.assertEqual(records[0]["decision_minutes_total"], 0.0)
        self.assertEqual((m["median_minutes"], m["decision_minutes_total"]), (0.0, 0.0))

    def test_since_filter(self):
        with temp_tree({"placeholder": ""}) as root:
            log = root / "triage-log.csv"
            write_log(log, [row(recorded_at="2026-07-01T10:00:00+00:00"),
                            row(finding_id="F-2", recorded_at="2026-09-01T10:00:00+00:00")])
            kept = metrics.filter_since(metrics.collapse(metrics.load_rows(log)), "2026-08-01")
        self.assertEqual([r["finding_id"] for r in kept], ["F-2"])


class TestCollapse(unittest.TestCase):
    def test_superseded_verdict_counts_once(self):
        collapsed = metrics.collapse([row(), row(final_state="dismissed", recorded_at="2026-09-02T10:00:00+00:00", supersedes="old")])
        self.assertEqual((len(collapsed), collapsed[0]["final_state"]), (1, "dismissed"))

    def test_human_decision_row_merges_into_the_finding(self):
        collapsed = metrics.collapse([row(), {"finding_id": "F-000000000001", "human_decision": "rejected", "human_decision_by": "appsec-oncall", "recorded_at": "2026-09-02T10:00:00+00:00"}])
        self.assertEqual((collapsed[0]["final_state"], collapsed[0]["human_decision"]), ("confirmed", "rejected"))

    def test_missing_or_malformed_timestamps_have_a_stable_fallback(self):
        rows = [row(final_state="confirmed", recorded_at="not-a-timestamp"), row(final_state="dismissed", recorded_at="")]
        self.assertEqual(metrics.collapse(rows)[0]["final_state"], "dismissed")
        self.assertEqual(metrics.collapse(list(reversed(rows)))[0]["final_state"], "confirmed")

    def test_revisions_are_counted_from_verdict_rows(self):
        self.assertEqual(compute([row(), row(recorded_at="2026-09-02T10:00:00+00:00", minutes_spent="")])["revisions"], 1)


class TestCollapseSemantics(unittest.TestCase):
    def test_new_verdict_does_not_inherit_the_old_challenge(self):
        first = row(challenge_result="upheld", validator="model-b")
        second = row(recorded_at="2026-09-02T10:00:00+00:00", challenge_result="", validator="", supersedes="old")
        collapsed = metrics.collapse([first, second])
        self.assertEqual((collapsed[0]["challenge_result"], collapsed[0]["validator"]), ("", ""))

    def test_decision_survives_a_verdict_revision_recorded_before_it(self):
        collapsed = metrics.collapse([row(), decision("F-000000000001", "rejected", "2026-09-03T10:00:00+00:00"), row(recorded_at="2026-09-02T10:00:00+00:00", final_state="dismissed")])
        self.assertEqual((collapsed[0]["human_decision"], collapsed[0]["final_state"]), ("rejected", "dismissed"))

    def test_later_verdict_supersedes_decision_without_erasing_history_or_time(self):
        events = [row(), {
            **decision("F-000000000001", "accepted"), "minutes_spent": "3",
            "human_decision_at": "2026-09-02T10:00:00+00:00",
            "human_decision_by": "appsec-oncall", "human_rationale": "Agreed with confirmation",
        }, row(recorded_at="2026-09-03T10:00:00+00:00", initial_verdict="false_positive",
               final_state="dismissed", minutes_spent="4", supersedes="old")]
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, events)
            before = log.read_bytes()
            records = metrics.collapse(metrics.load_rows(log))
            self.assertFalse(records[0].get("human_decision"), "acceptance of an old verdict is not current consent")
            for key in ("human_decision_at", "human_decision_by", "human_rationale"):
                self.assertFalse(records[0].get(key), key)
            self.assertEqual(log.read_bytes(), before)
            self.assertEqual(len(metrics.load_rows(log)), 3)
        self.assertEqual(records[0]["final_state"], "dismissed")
        self.assertEqual((records[0]["triage_minutes_total"], records[0]["decision_minutes_total"]), (14.0, 3.0))
        m = metrics.compute(records)
        self.assertEqual((m["decided"], m["human_decisions"], m["human_decision_coverage_pct"], m["revisions"]), (1, 0, 0.0, 1))
        self.assertIsNone(m["agent_accuracy_pct"])

    def test_equal_instant_decision_supersession_uses_log_position(self):
        for timestamp in ("2026-09-01T10:00:00+00:00", "2026-09-01T13:00:00+03:00"):
            with self.subTest(timestamp=timestamp):
                accepted = decision("F-000000000001", "accepted", timestamp)
                self.assertFalse(metrics.collapse([accepted, row()])[0].get("human_decision"))
                self.assertEqual(metrics.collapse([row(), accepted])[0]["human_decision"], "accepted")

    def test_decision_and_verdict_order_uses_aware_instants(self):
        accepted = decision("F-000000000001", "accepted", "2026-09-01T12:00:00+03:00")
        self.assertFalse(metrics.collapse([row(), accepted])[0].get("human_decision"))
        earlier = row(recorded_at="2026-09-01T08:00:00Z")
        self.assertEqual(metrics.collapse([accepted, earlier])[0]["human_decision"], "accepted")

    def test_equal_timestamps_break_by_log_position(self):
        first, second = row(final_state="confirmed"), row(final_state="dismissed")
        self.assertEqual(metrics.collapse([first, second])[0]["final_state"], "dismissed")
        self.assertEqual(metrics.collapse([second, first])[0]["final_state"], "confirmed")

    def test_triage_minutes_sum_across_revisions(self):
        self.assertEqual(metrics.collapse([row(minutes_spent="10"), row(recorded_at="2026-09-02T10:00:00+00:00", minutes_spent="4")])[0]["triage_minutes_total"], 14.0)

    def test_decision_minutes_stay_separate(self):
        collapsed = metrics.collapse([row(minutes_spent="10"), {"finding_id": "F-000000000001", "human_decision": "accepted", "minutes_spent": "3", "recorded_at": "2026-09-02T10:00:00+00:00"}])
        self.assertEqual((collapsed[0]["triage_minutes_total"], collapsed[0]["decision_minutes_total"]), (10.0, 3.0))


class TestSinceSelectsFindings(unittest.TestCase):
    def test_a_finding_enters_whole_or_not_at_all(self):
        records = metrics.collapse([row(recorded_at="2026-07-01T10:00:00+00:00"), {"finding_id": "F-000000000001", "human_decision": "accepted", "recorded_at": "2026-09-01T10:00:00+00:00"}])
        kept = metrics.filter_since(records, "2026-08-01")
        self.assertEqual((len(kept), kept[0]["final_state"], kept[0]["human_decision"]), (1, "confirmed", "accepted"))

    def test_untouched_findings_fall_outside_the_window(self):
        self.assertEqual(metrics.filter_since(metrics.collapse([row(recorded_at="2026-07-01T10:00:00+00:00")]), "2026-08-01"), [])


class TestChronologicalTimestamps(unittest.TestCase):
    def test_offset_verdict_winner_is_chronological(self):
        earlier = row(recorded_at="2026-09-01T12:00:00+03:00", final_state="dismissed")
        later = row(recorded_at="2026-09-01T10:00:00+00:00", final_state="confirmed")
        for events in ([earlier, later], [later, earlier]):
            with self.subTest(events=events):
                record = metrics.collapse(events)[0]
                self.assertEqual(record["final_state"], "confirmed")
                self.assertEqual(record["last_event_at"], "2026-09-01T10:00:00+00:00")

    def test_equivalent_and_unqualified_instants_break_by_log_index(self):
        for timestamp in ("2026-09-01T10:00:00", "2026-09-01T10:00:00Z", "2026-09-01T13:00:00+03:00"):
            with self.subTest(timestamp=timestamp):
                first = row(recorded_at=timestamp, final_state="dismissed")
                self.assertEqual(metrics.collapse([first, row()])[0]["final_state"], "confirmed")
                self.assertEqual(metrics.collapse([row(), first])[0]["final_state"], "dismissed")

    def test_invalid_and_missing_instants_sort_before_valid_events(self):
        for timestamp in ("invalid", "", None):
            with self.subTest(timestamp=timestamp):
                invalid = row(recorded_at=timestamp, final_state="dismissed")
                self.assertEqual(metrics.collapse([row(), invalid])[0]["final_state"], "confirmed")
        missing = row(final_state="dismissed")
        del missing["recorded_at"]
        self.assertEqual(metrics.collapse([row(), missing])[0]["final_state"], "confirmed")

    def test_since_cli_compares_aware_instants_and_unqualified_utc(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [
                row(finding_id="F-before", recorded_at="2026-09-01T12:00:00+03:00"),
                row(finding_id="F-equal", recorded_at="2026-09-01T09:30:00Z"),
                row(finding_id="F-naive", recorded_at="2026-09-01T10:00:00"),
                row(finding_id="F-after", recorded_at="2026-09-01T10:00:00+00:00"),
                row(finding_id="F-invalid", recorded_at="invalid"),
                row(finding_id="F-missing", recorded_at=""),
            ])
            for cutoff in ("2026-09-01T11:30:00+02:00", "2026-09-01T09:30:00"):
                with self.subTest(cutoff=cutoff):
                    proc = subprocess.run([
                        sys.executable, str(REPO_ROOT / "scripts/metrics.py"),
                        "--log", str(log), "--since", cutoff, "--json",
                    ], capture_output=True, text=True)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertEqual(json.loads(proc.stdout)["total"], 3)
                    kept = metrics.filter_since(metrics.collapse(metrics.load_rows(log)), cutoff)
                    self.assertEqual({record["finding_id"] for record in kept}, {"F-equal", "F-naive", "F-after"})

    def test_since_uses_explicit_minimum_for_malformed_or_missing_values(self):
        records = [{"finding_id": "F-invalid", "last_event_at": "bad"}, {"finding_id": "F-missing"}]
        self.assertEqual(metrics.filter_since(records, "0001-01-01"), records)
        self.assertEqual(metrics.filter_since(records, "bad"), records)
        self.assertEqual(metrics.filter_since(records, "0001-01-02"), [])


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
        self.assertIn("Verdicts revised         1", metrics.render(compute([row(), row(recorded_at="2026-09-02T10:00:00+00:00")])))


class TestUndefinedDenominator(unittest.TestCase):
    def test_accuracy_is_withheld_when_nothing_is_decided(self):
        m = compute([row(final_state="human_review", challenge_result="refuted"), {"finding_id": "F-000000000001", "human_decision": "accepted", "recorded_at": "2026-09-02T10:00:00+00:00"}])
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
