"""Tests for verdict validation and promotion.

decide_state decides what enters the audit trail, and the rationale it returns
is written verbatim into SARIF. A rationale that overstates what was verified
is a defect of the same kind this whole workflow exists to catch.
"""

import json
import unittest

import record_verdict
from tests.helpers import temp_tree


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
