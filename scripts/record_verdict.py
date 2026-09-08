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
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_packet import ID_SCHEME, verdict_digest  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "templates"
LOG_PATH = REPO_ROOT / "findings" / "triage-log.csv"
SARIF_OUT = REPO_ROOT / "findings" / "reviewed.sarif"

LOG_FIELDS = [
    "reviewed_at", "recorded_at", "finding_id", "id_scheme", "rule_id", "file", "line",
    "severity", "priority_class", "evidence_level", "confidence",
    "initial_verdict", "challenge_result", "final_state",
    "minutes_spent", "requires_runtime_proof",
    "agent", "validator",
    "agent_self_reported", "validator_self_reported",
    "human_decision", "human_decision_at", "human_decision_by", "human_rationale",
    "supersedes",
    "notes",
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


def _identity(value: str, flag: str) -> str:
    """Normalise a model identifier supplied by the engineer.

    Independence is decided by comparing these two strings, so a trailing space
    is enough to let one model validate itself. Compared case-folded for the
    same reason: nobody intends Model-B and model-b to be different reviewers.
    """
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{flag} must not be empty")
    return cleaned


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


_JSON_TYPES = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
    "null": type(None),
}


def _type_ok(value, expected) -> bool:
    """JSON-schema type check with Python's bool/int overlap accounted for."""
    names = expected if isinstance(expected, list) else [expected]
    for name_ in names:
        if name_ not in _JSON_TYPES:
            raise ValidationError(f"schema uses unknown type {name_!r}")
        # bool is a subclass of int, so True would satisfy "integer" and
        # "number" without this guard.
        if name_ in ("integer", "number") and isinstance(value, bool):
            continue
        if isinstance(value, _JSON_TYPES[name_]):
            return True
    return False


def _fallback_validate(instance: dict, schema: dict, name: str) -> None:
    """Validate the schema subset used by the verdict and challenge contracts.

    This is not a full draft-07 implementation. It covers required keys,
    enums, types, array items, pattern, minimum, minLength and maxLength: the
    keywords the two shipped schemas actually use. The two conditional rules
    in the verdict schema are enforced separately by check_consistency, and a
    test guards against the schema growing a third.
    """
    if not isinstance(instance, dict):
        raise ValidationError(
            f"{name}: expected a JSON object, got {type(instance).__name__}"
        )

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

        _fallback_check_value(value, spec, f"{name}: {key}")

        if isinstance(value, dict) and spec.get("properties"):
            _fallback_validate(value, spec, f"{name}.{key}")

        if isinstance(value, list) and isinstance(spec.get("items"), dict):
            item_spec = spec["items"]
            for index, item in enumerate(value):
                label = f"{name}.{key}[{index}]"
                if item_spec.get("properties") or item_spec.get("required"):
                    if not isinstance(item, dict):
                        raise ValidationError(f"{label}: expected an object")
                    _fallback_validate(item, item_spec, label)
                else:
                    _fallback_check_value(item, item_spec, label)


def _fallback_check_value(value, spec: dict, label: str) -> None:
    if "enum" in spec and value not in spec["enum"]:
        raise ValidationError(f"{label}={value!r} not in {spec['enum']}")

    if "type" in spec and not _type_ok(value, spec["type"]):
        raise ValidationError(
            f"{label} should be {spec['type']}, got {type(value).__name__}"
        )

    if isinstance(value, str):
        if "minLength" in spec and len(value) < spec["minLength"]:
            raise ValidationError(
                f"{label} shorter than {spec['minLength']} chars"
            )
        if "maxLength" in spec and len(value) > spec["maxLength"]:
            raise ValidationError(
                f"{label} longer than {spec['maxLength']} chars"
            )
        if "pattern" in spec and re.search(spec["pattern"], value) is None:
            raise ValidationError(
                f"{label}={value!r} does not match {spec['pattern']!r}"
            )

    if "minimum" in spec and isinstance(value, (int, float)):
        if value < spec["minimum"]:
            raise ValidationError(
                f"{label}={value!r} is below minimum {spec['minimum']}"
            )



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

    cwes = {value.strip().upper() for value in verdict.get("cwe", [])}
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


def _unchallenged_note(verdict_label: str, severity: str) -> str:
    """Rationale for a finding that policy exempts from adversarial validation.

    Deliberately distinct from the challenged wording. Only critical, high and
    medium require a challenge; reporting a low finding as "upheld under
    adversarial validation" would write a false statement into reviewed.sarif
    and the triage log, where it outlives everyone who remembers the context.

    Required severities cannot reach this helper: decide_state blocks a
    missing challenge result before choosing any unchallenged rationale.
    """
    return (
        f"{verdict_label}; severity={severity} does not require adversarial "
        "validation under policy"
    )


def decide_state(verdict: dict, challenge: dict | None) -> tuple[str, str]:
    """Apply the promotion rules. Returns (state, rationale)."""
    v = verdict["verdict"]
    severity = verdict.get("severity", "info")
    needs_challenge = severity in CHALLENGE_REQUIRED

    # Drive off the result, not the container. An empty challenge object is not
    # a challenge: it is falsy enough to skip schema validation in main, yet not
    # None enough to reach the blocked branch, so a high finding was promoted to
    # confirmed under a rationale claiming policy did not require validation.
    challenge_result = (challenge or {}).get("challenge_result")

    if needs_challenge and challenge_result is None:
        return (
            "blocked_needs_challenge",
            f"severity={severity} requires adversarial validation before promotion",
        )

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
        if challenge_result == "upheld":
            return ("confirmed", "true positive upheld under adversarial validation")
        return ("confirmed", _unchallenged_note("true positive", severity))

    if v == "false_positive":
        if challenge_result == "upheld":
            return ("dismissed", "false positive upheld")
        if not needs_challenge:
            return ("dismissed", _unchallenged_note("false positive", severity))
        return ("human_review", "dismissal not independently validated")

    return ("human_review", "verdict was needs_human")


def append_log(row: dict, path: Path = LOG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Key the header on content, not on existence. A file that exists but is
    # empty is not a log yet, and appending to it without a header would put a
    # data row in the header position, where csv.DictReader would read it as
    # the column names and corrupt every row that follows.
    has_header = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=LOG_FIELDS)
        if not has_header:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in LOG_FIELDS})


def check_log_compatible(path: Path, id_scheme: str) -> None:
    """Refuse a log whose shape, identity scheme or rows we cannot rely on.

    Checked to the depth collapse() actually uses: it groups by finding_id,
    orders by recorded_at, and tells verdict rows from decision rows by which
    of two fields is populated. A row failing any of those is not skipped and
    not coerced. A metric computed from data the reader had to guess at is
    worse than no metric, because it gets quoted with the same confidence.
    """
    if not path.exists():
        return

    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if header is None:
            # Empty file: nothing to compare against, and append_log will lay
            # down the header on the next write. The two functions have to
            # agree about what an empty file means, or a row lands where the
            # header belongs.
            return

        if header != LOG_FIELDS:
            missing = [f for f in LOG_FIELDS if f not in header] or ["none"]
            extra = [f for f in header if f not in LOG_FIELDS] or ["none"]
            raise ValidationError(
                f"{path} has an incompatible header.\n"
                f"  missing columns: {', '.join(missing)}\n"
                f"  unexpected columns: {', '.join(extra)}\n"
                "Archive the existing findings/ directory, or migrate the log, "
                "before recording new verdicts."
            )

        for line_number, row in enumerate(
            csv.DictReader(fh, fieldnames=header), start=2
        ):
            if any(value is None for value in row.values()):
                raise ValidationError(
                    f"{path} row {line_number} is truncated; every log column "
                    "must have a value"
                )

            finding_id = row["finding_id"]
            if not finding_id or any(char.isspace() for char in finding_id):
                raise ValidationError(
                    f"{path} row {line_number} has invalid finding_id "
                    f"{finding_id!r}; it must be non-empty and contain no whitespace"
                )

            recorded_at = row["recorded_at"]
            try:
                recorded = datetime.fromisoformat(
                    recorded_at.replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise ValidationError(
                    f"{path} row {line_number} has invalid recorded_at "
                    f"{recorded_at!r}; expected an ISO-8601 timestamp with timezone"
                ) from exc
            if recorded.tzinfo is None or recorded.utcoffset() is None:
                raise ValidationError(
                    f"{path} row {line_number} has naive recorded_at "
                    f"{recorded_at!r}; a timezone is required"
                )

            scheme = row["id_scheme"]
            if not scheme or scheme != id_scheme:
                raise ValidationError(
                    f"{path} row {line_number} has id_scheme {scheme!r}; "
                    f"expected {id_scheme!r}"
                )

            for field in ("initial_verdict", "human_decision"):
                marker = row[field]
                if marker and not marker.strip():
                    raise ValidationError(
                        f"{path} row {line_number} has whitespace-only {field}; "
                        "event markers must be empty or meaningful"
                    )

            # collapse() branches on the raw strings. Whitespace-only values
            # are refused above so these exact predicates now classify a row
            # identically in the contract and its consumer.
            is_verdict = bool(row["initial_verdict"])
            is_decision = bool(row["human_decision"])
            if is_verdict == is_decision:
                raise ValidationError(
                    f"{path} row {line_number} must populate exactly one of "
                    "initial_verdict and human_decision"
                )


def verdict_rows(path: Path, finding_id: str) -> list[dict]:
    """Previously recorded verdicts for one finding.

    Human-decision rows share the finding_id but carry no initial_verdict, so
    they are excluded here: superseding a verdict is a different act from
    deciding on one.
    """
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as fh:
        return [
            row
            for row in csv.DictReader(fh)
            if row.get("finding_id") == finding_id and row.get("initial_verdict")
        ]


def build_result(verdict: dict, challenge: dict | None, state: str, rationale: str) -> dict:
    """Build one SARIF result for a reviewed finding.

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
            "id_scheme": ID_SCHEME,
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
                "justification": f"Dismissed after review. {rationale}",
            }
        ]

    return result


def sarif_document(results: list[dict]) -> dict:
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
                "results": results,
            }
        ],
    }


def load_existing_results(path: Path) -> list[dict]:
    """Read previously recorded results so a new one joins them.

    A file we cannot parse is a refusal, not a licence to overwrite: the
    reviewed SARIF is the audit trail's current-state view, and silently
    discarding it would lose every earlier verdict.
    """
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ValidationError(
            f"Cannot read {path}: {exc}. Refusing to overwrite a file that "
            "cannot be parsed. Move it aside, or pass --fresh to start over."
        ) from exc
    if (
        not isinstance(data, dict)
        or "version" not in data
        or not isinstance(data.get("runs"), list)
    ):
        raise ValidationError(
            f"{path} is not a SARIF document this tool wrote: no version, or "
            "runs is not a list. Refusing to replace a file we cannot "
            "interpret. Move it aside, or pass --fresh."
        )

    if not data["runs"]:
        return []

    results = data["runs"][0].get("results", [])
    if not isinstance(results, list):
        raise ValidationError(f"{path}: runs[0].results is not a list.")

    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ValidationError(f"{path}: results[{index}] is not an object.")
        properties = result.get("properties")
        if not isinstance(properties, dict):
            raise ValidationError(
                f"{path}: results[{index}] has no properties object."
            )
        finding_id = properties.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            # Checked to this depth on purpose: merge_result sorts and matches
            # on this field, so anything else crashes the sort - after the log
            # has already been appended to.
            raise ValidationError(
                f"{path}: results[{index}].properties.finding_id is "
                f"{finding_id!r}, not a non-empty string."
            )

    return results


def merge_result(existing: list[dict], result: dict) -> list[dict]:
    """Replace the result with the same finding_id, or append it."""
    fid = result["properties"]["finding_id"]
    merged = [
        r for r in existing if r.get("properties", {}).get("finding_id") != fid
    ]
    merged.append(result)
    merged.sort(key=lambda r: r.get("properties", {}).get("finding_id", ""))
    return merged


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verdict", type=Path, required=True)
    parser.add_argument("--challenge", type=Path)
    parser.add_argument("--agent", required=True,
                        help="Model identifier for the triage pass, supplied by the engineer")
    parser.add_argument("--validator",
                        help="Model identifier for the validation pass; required with --challenge")
    parser.add_argument("--log", type=Path, default=LOG_PATH,
                        help="Triage log to append to")
    parser.add_argument("--minutes", type=float, help="Engineer time spent, for metrics")
    parser.add_argument("--notes", default="")
    parser.add_argument("--sarif-out", type=Path, default=SARIF_OUT)
    parser.add_argument("--fresh", action="store_true",
                        help="Discard the existing reviewed SARIF instead of adding to it")
    parser.add_argument("--supersede", action="store_true",
                        help="Record a revision of a verdict already in the log")
    parser.add_argument("--strict", action="store_true",
                        help="Exit non-zero unless the finding reaches a terminal state")
    args = parser.parse_args()

    try:
        args.agent = _identity(args.agent, "--agent")
        if args.validator is not None:
            args.validator = _identity(args.validator, "--validator")
    except ValueError as exc:
        parser.error(str(exc))

    if args.challenge and not args.validator:
        parser.error("--validator is required when --challenge is given")

    if args.validator and args.challenge is None:
        parser.error(
            "--validator without --challenge would record a validator that "
            "validated nothing"
        )

    if args.validator and args.agent.casefold() == args.validator.casefold():
        print("REFUSED: triage and validation ran on the same model.\n", file=sys.stderr)
        print(f"  agent:     {args.agent}", file=sys.stderr)
        print(f"  validator: {args.validator}\n", file=sys.stderr)
        print(
            "Independence is the mechanism, not a preference. A second pass on the\n"
            "same model inherits the same blind spots and produces agreement rather\n"
            "than validation. Nothing was written.",
            file=sys.stderr,
        )
        return 2

    try:
        check_log_compatible(args.log, ID_SCHEME)
    except ValidationError as exc:
        print(f"LOG ERROR: {exc}", file=sys.stderr)
        return 1

    verdict = json.loads(args.verdict.read_text(encoding="utf-8"))
    challenge_supplied = args.challenge is not None
    challenge = (
        json.loads(args.challenge.read_text(encoding="utf-8"))
        if challenge_supplied
        else None
    )

    try:
        validate(verdict, "verdict.schema.json")
        # Presence of the flag decides this, never the parsed value. A file
        # containing `null` parses to None and `{}` parses to a falsy dict;
        # both looked like "no challenge" and sailed past the schema while the
        # log recorded a validator for a challenge that was never checked.
        if challenge_supplied:
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

    if challenge_supplied:
        expected = verdict_digest(verdict)
        supplied = challenge.get("verdict_digest")
        if supplied != expected:
            print(f"REFUSED: challenge was built for a different verdict.\n",
                  file=sys.stderr)
            print(f"  challenge carries: {supplied}", file=sys.stderr)
            print(f"  this verdict is:   {expected}\n", file=sys.stderr)
            print("A challenge refutes one revision, not a finding. Re-run the "
                  "validation pass against the verdict you are recording.",
                  file=sys.stderr)
            return 2

    prior = verdict_rows(args.log, verdict["finding_id"])
    if prior and not args.supersede:
        print(
            f"REFUSED: {verdict['finding_id']} already has a verdict recorded "
            f"at {prior[-1].get('reviewed_at', 'an unknown time')}.\n",
            file=sys.stderr,
        )
        print(
            "Pass --supersede to record a revision. The log stays append-only:\n"
            "the earlier row remains and the new one points back at it.",
            file=sys.stderr,
        )
        return 2

    # The model fills reviewer.agent in its own output, and models are
    # unreliable about their own identity. The engineer's value is authoritative;
    # a mismatch is worth surfacing but is not grounds to refuse.
    self_reported = verdict.get("reviewer", {}).get("agent", "")
    if self_reported and self_reported != args.agent:
        print(
            f"WARNING: verdict self-reports agent {self_reported!r}, engineer "
            f"supplied {args.agent!r}.\n",
            file=sys.stderr,
        )
    if challenge:
        validator_self = challenge.get("validator", {}).get("agent", "")
        if validator_self and validator_self != args.validator:
            print(
                f"WARNING: challenge self-reports validator {validator_self!r}, "
                f"engineer supplied {args.validator!r}.\n",
                file=sys.stderr,
            )
        if challenge.get("challenge_result") == "upheld" and not challenge.get(
            "refutation_attempts"
        ):
            print("WARNING: 'upheld' with no recorded refutation attempts is "
                  "agreement, not validation.\n", file=sys.stderr)

    state, rationale = decide_state(verdict, challenge)
    loc = verdict.get("location", {})

    # Parse the existing SARIF before writing anything. The triage log is
    # append-only, so a row written ahead of a SARIF failure could never be
    # withdrawn and the two artefacts would disagree permanently.
    try:
        existing = [] if args.fresh else load_existing_results(args.sarif_out)
    except ValidationError as exc:
        print(f"SARIF ERROR: {exc}", file=sys.stderr)
        return 1

    append_log(
        {
            "reviewed_at": verdict.get("reviewer", {}).get(
                "reviewed_at", datetime.now(timezone.utc).isoformat()
            ),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "finding_id": verdict["finding_id"],
            "id_scheme": ID_SCHEME,
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
            "agent": args.agent,
            "validator": args.validator or "",
            "agent_self_reported": verdict.get("reviewer", {}).get("agent", ""),
            "validator_self_reported": (challenge or {}).get("validator", {}).get(
                "agent", ""
            ),
            "supersedes": prior[-1].get("reviewed_at", "") if prior else "",
            "notes": args.notes,
        },
        args.log,
    )

    results = merge_result(existing, build_result(verdict, challenge, state, rationale))
    args.sarif_out.parent.mkdir(parents=True, exist_ok=True)
    args.sarif_out.write_text(json.dumps(sarif_document(results), indent=2), encoding="utf-8")

    print(f"{verdict['finding_id']}: {state}")
    print(f"  {rationale}")
    print(f"  logged  -> {args.log}")
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
