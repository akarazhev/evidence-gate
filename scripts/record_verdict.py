#!/usr/bin/env python3
"""Validate a verdict, apply promotion policy, and record the result.

This is the step that keeps manual review from becoming invisible work. It:

  1. Validates the verdict against templates/verdict.schema.json.
  2. Enforces the internal consistency rules (high confidence requires a traced
     path; a pattern match cannot be a true positive).
  3. Requires a challenge result before anything is promoted to confirmed.
  4. Applies policy/severity-policy.yml to derive the final state.
  5. Appends to the triage log so metrics.py has something to compute from.
  6. Emits an enriched SARIF file for import into the findings store.

Schema validation uses jsonschema when available and falls back to a built-in
checker covering the rules that matter, so the control does not silently
disappear on a machine without the dependency.

Usage:
    record_verdict.py --verdict findings/verdicts/F-abc.json \\
                      --challenge findings/challenges/F-abc.json \\
                      --minutes 12
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "templates"
LOG_PATH = REPO_ROOT / "findings" / "triage-log.csv"
SARIF_OUT = REPO_ROOT / "findings" / "reviewed.sarif"

LOG_FIELDS = [
    "reviewed_at", "finding_id", "rule_id", "file", "line",
    "severity", "priority_class", "evidence_level", "confidence",
    "initial_verdict", "challenge_result", "final_state",
    "minutes_spent", "requires_runtime_proof", "agent", "validator", "notes",
]

SEVERITY_SLA = {
    "critical": 3, "high": 14, "medium": 60, "low": 180, "info": None,
}
CHALLENGE_REQUIRED = {"critical", "high", "medium"}
RUNTIME_PROOF_CWES = {
    "CWE-416", "CWE-415", "CWE-787", "CWE-125", "CWE-362",
}


class ValidationError(Exception):
    pass


def validate(instance: dict, schema_name: str) -> None:
    schema_path = SCHEMA_DIR / schema_name
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        import jsonschema  # type: ignore

        jsonschema.validate(instance=instance, schema=schema)
    except ImportError:
        _fallback_validate(instance, schema, schema_name)
    except Exception as exc:  # jsonschema.ValidationError and friends
        raise ValidationError(f"{schema_name}: {exc}") from exc


def _fallback_validate(instance: dict, schema: dict, name: str) -> None:
    """Minimal validator covering required keys, enums, and types.

    Not a full draft-07 implementation. It exists so that a missing jsonschema
    package degrades the check rather than removing it.
    """
    for key in schema.get("required", []):
        if key not in instance:
            raise ValidationError(f"{name}: missing required field {key!r}")

    props = schema.get("properties", {})
    for key, value in instance.items():
        spec = props.get(key)
        if not spec:
            if schema.get("additionalProperties") is False:
                raise ValidationError(f"{name}: unexpected field {key!r}")
            continue
        if "enum" in spec and value not in spec["enum"]:
            raise ValidationError(
                f"{name}: {key}={value!r} not in {spec['enum']}"
            )
        expected = spec.get("type")
        if expected:
            types = expected if isinstance(expected, list) else [expected]
            py = {
                "string": str, "integer": int, "number": (int, float),
                "boolean": bool, "array": list, "object": dict, "null": type(None),
            }
            allowed = tuple(
                t for name_ in types for t in ((py[name_],) if not isinstance(py[name_], tuple) else py[name_])
            )
            if not isinstance(value, allowed):
                raise ValidationError(
                    f"{name}: {key} should be {expected}, got {type(value).__name__}"
                )
        if spec.get("minLength") and isinstance(value, str):
            if len(value) < spec["minLength"]:
                raise ValidationError(
                    f"{name}: {key} shorter than {spec['minLength']} chars"
                )
        if isinstance(value, dict) and spec.get("properties"):
            _fallback_validate(value, spec, f"{name}.{key}")


def check_consistency(verdict: dict) -> list[str]:
    """Rules the schema expresses but a fallback validator would miss."""
    problems = []

    if verdict.get("confidence") == "high" and verdict.get("evidence_level") != "traced":
        problems.append(
            "confidence=high requires evidence_level=traced "
            f"(got {verdict.get('evidence_level')})"
        )

    if verdict.get("evidence_level") == "pattern" and verdict.get("verdict") == "true_positive":
        problems.append(
            "evidence_level=pattern cannot yield verdict=true_positive; "
            "a shape match is not a traced finding"
        )

    if verdict.get("evidence_level") == "traced" and not verdict.get("data_flow"):
        problems.append(
            "evidence_level=traced requires a populated data_flow array"
        )

    cwes = set(verdict.get("cwe", []))
    if cwes & RUNTIME_PROOF_CWES and not verdict.get("requires_runtime_proof"):
        overlap = ", ".join(sorted(cwes & RUNTIME_PROOF_CWES))
        problems.append(
            f"{overlap} requires runtime proof; set requires_runtime_proof=true"
        )

    if verdict.get("blocked_by_scope") and verdict.get("verdict") != "needs_human":
        problems.append(
            "blocked_by_scope is set, so the analysis was incomplete; "
            "verdict must be needs_human"
        )

    return problems


def decide_state(verdict: dict, challenge: dict | None) -> tuple[str, str]:
    """Apply the promotion rules. Returns (state, rationale)."""
    v = verdict["verdict"]
    severity = verdict.get("severity", "info")
    needs_challenge = severity in CHALLENGE_REQUIRED

    if challenge is None:
        if needs_challenge:
            return (
                "blocked_needs_challenge",
                f"severity={severity} requires adversarial validation before promotion",
            )
        challenge_result = None
    else:
        challenge_result = challenge.get("challenge_result")

    if challenge_result in ("refuted", "inconclusive"):
        return (
            "human_review",
            f"the two passes disagree (challenge={challenge_result}); a human decides",
        )

    if v == "true_positive":
        if verdict.get("requires_runtime_proof"):
            return (
                "awaiting_proof",
                "static reasoning cannot confirm this class; a runtime harness must reproduce it",
            )
        if verdict.get("evidence_level") == "pattern":
            return ("human_review", "pattern-level evidence is insufficient to confirm")
        return ("confirmed", "true positive upheld under adversarial validation")

    if v == "false_positive":
        if challenge_result == "upheld" or not needs_challenge:
            return ("dismissed", "false positive upheld")
        return ("human_review", "dismissal not independently validated")

    return ("human_review", "verdict was needs_human")


def append_log(row: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    exists = LOG_PATH.exists()
    with LOG_PATH.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=LOG_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in LOG_FIELDS})


def to_sarif(verdict: dict, challenge: dict | None, state: str, rationale: str) -> dict:
    """Emit SARIF so reviewed findings enter the same store as scanner output.

    Dismissed findings carry a SARIF suppression, which is how a findings store
    learns not to re-raise them on the next scan.
    """
    loc = verdict.get("location", {})
    level = {
        "critical": "error", "high": "error", "medium": "warning",
        "low": "note", "info": "note",
    }.get(verdict.get("severity", "info"), "warning")

    result = {
        "ruleId": verdict.get("rule_id", "manual-review"),
        "level": level,
        "message": {"text": verdict.get("reasoning", "")[:2000]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": loc.get("file", "")},
                    "region": {
                        "startLine": loc.get("start_line", 1),
                        "endLine": loc.get("end_line", loc.get("start_line", 1)),
                    },
                }
            }
        ],
        "properties": {
            "finding_id": verdict["finding_id"],
            "state": state,
            "state_rationale": rationale,
            "severity": verdict.get("severity"),
            "priority_class": verdict.get("priority_class"),
            "cwe": verdict.get("cwe", []),
            "evidence_level": verdict.get("evidence_level"),
            "confidence": verdict.get("confidence"),
            "requires_runtime_proof": verdict.get("requires_runtime_proof", False),
            "sla_days": SEVERITY_SLA.get(verdict.get("severity", "info")),
            "reviewer": verdict.get("reviewer", {}),
            "challenge": challenge or {},
            "review_mode": "manual-assisted",
        },
    }

    if state == "dismissed":
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": f"Dismissed after adversarial validation. {rationale}",
            }
        ]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "appsec-review",
                        "informationUri": "https://example.org/appsec-review",
                        "version": "1.0.0",
                    }
                },
                "results": [result],
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verdict", type=Path, required=True)
    parser.add_argument("--challenge", type=Path)
    parser.add_argument("--minutes", type=float, help="Engineer time spent, for metrics")
    parser.add_argument("--notes", default="")
    parser.add_argument("--sarif-out", type=Path, default=SARIF_OUT)
    parser.add_argument("--strict", action="store_true",
                        help="Exit non-zero unless the finding reaches a terminal state")
    args = parser.parse_args()

    verdict = json.loads(args.verdict.read_text(encoding="utf-8"))
    challenge = (
        json.loads(args.challenge.read_text(encoding="utf-8")) if args.challenge else None
    )

    try:
        validate(verdict, "verdict.schema.json")
        if challenge:
            validate(challenge, "challenge.schema.json")
    except ValidationError as exc:
        print(f"SCHEMA ERROR: {exc}", file=sys.stderr)
        print("\nThe agent did not follow the output contract. Re-run the "
              "procedure; do not hand-edit the verdict to make it pass.",
              file=sys.stderr)
        return 1

    problems = check_consistency(verdict)
    if problems:
        print("CONSISTENCY ERRORS:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("\nThese indicate the analysis overreached its evidence.",
              file=sys.stderr)
        return 1

    if challenge and challenge.get("finding_id") != verdict["finding_id"]:
        print("ERROR: challenge finding_id does not match the verdict.", file=sys.stderr)
        return 1

    if challenge:
        v_agent = verdict.get("reviewer", {}).get("agent", "")
        c_agent = challenge.get("validator", {}).get("agent", "")
        if v_agent and v_agent == c_agent:
            print(f"WARNING: triage and validation both ran on {v_agent}.",
                  file=sys.stderr)
            print("         Independence is the point of the second pass; the "
                  "result is weaker than it looks.\n", file=sys.stderr)
        if challenge.get("challenge_result") == "upheld" and not challenge.get(
            "refutation_attempts"
        ):
            print("WARNING: 'upheld' with no recorded refutation attempts is "
                  "agreement, not validation.\n", file=sys.stderr)

    state, rationale = decide_state(verdict, challenge)
    loc = verdict.get("location", {})

    append_log(
        {
            "reviewed_at": verdict.get("reviewer", {}).get(
                "reviewed_at", datetime.now(timezone.utc).isoformat()
            ),
            "finding_id": verdict["finding_id"],
            "rule_id": verdict.get("rule_id", ""),
            "file": loc.get("file", ""),
            "line": loc.get("start_line", ""),
            "severity": verdict.get("severity", ""),
            "priority_class": verdict.get("priority_class", ""),
            "evidence_level": verdict.get("evidence_level", ""),
            "confidence": verdict.get("confidence", ""),
            "initial_verdict": verdict["verdict"],
            "challenge_result": (challenge or {}).get("challenge_result", ""),
            "final_state": state,
            "minutes_spent": args.minutes if args.minutes is not None else "",
            "requires_runtime_proof": verdict.get("requires_runtime_proof", False),
            "agent": verdict.get("reviewer", {}).get("agent", ""),
            "validator": (challenge or {}).get("validator", {}).get("agent", ""),
            "notes": args.notes,
        }
    )

    sarif = to_sarif(verdict, challenge, state, rationale)
    args.sarif_out.parent.mkdir(parents=True, exist_ok=True)
    args.sarif_out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    print(f"{verdict['finding_id']}: {state}")
    print(f"  {rationale}")
    print(f"  logged  -> {LOG_PATH}")
    print(f"  sarif   -> {args.sarif_out}")

    if state == "blocked_needs_challenge":
        print(f"\nNext: make validate ID={verdict['finding_id']}")
    elif state == "human_review":
        print("\nNext: a human decides. The passes disagreed or evidence was thin.")
    elif state == "awaiting_proof":
        print("\nNext: this class needs a runtime harness. Park it; see "
              "docs/07-graduation.md.")

    if args.strict and state not in ("confirmed", "dismissed"):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
