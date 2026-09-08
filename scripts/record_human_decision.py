#!/usr/bin/env python3
"""Record the human's decision on a reviewed finding.

CLAUDE.md opens by saying every verdict is a recommendation that a human
accepts, rejects, or escalates. Nothing recorded that decision, so the
programme had no ground truth: metrics could describe what the pipeline did,
but never whether it was right.

The subject of the decision is the pipeline's final_state, not the agent's
original verdict. Two people reading this field differently would make the
number meaningless, so it is stated here and in docs/04.

There is deliberately no JSON schema for this input. The schemas in templates/
are output contracts for a model. A human typing at a terminal is validated by
argparse and an enum; adding a schema here would blur a line worth keeping.

Do not put personal data in --by. The triage log is committed (docs/03), so a
name or an email address becomes a permanent part of repository history. Use a
role or a work handle.

Usage:
    record_human_decision.py --finding-id F-abc --decision rejected \\
                             --by appsec-oncall --rationale "sanitiser upstream"
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from record_verdict import (  # noqa: E402
    ID_SCHEME,
    LOG_PATH,
    SARIF_OUT,
    ValidationError,
    append_log,
    check_log_compatible,
    load_existing_results,
    sarif_document,
    verdict_rows,
)

DECISIONS = ("accepted", "rejected", "escalated")


def latest_verdict_row(path: Path, finding_id: str) -> dict | None:
    """The most recent recorded verdict for a finding, if there is one.

    Delegates to record_verdict.verdict_rows so that "what counts as a verdict
    row" is defined once. Two copies of that predicate would drift the moment
    a new row type appears.
    """
    rows = verdict_rows(path, finding_id)
    return rows[-1] if rows else None


def find_sarif_result(results: list[dict], finding_id: str) -> dict | None:
    for result in results:
        if result.get("properties", {}).get("finding_id") == finding_id:
            return result
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finding-id", required=True)
    parser.add_argument(
        "--decision",
        required=True,
        choices=DECISIONS,
        help="Whether the human accepts the pipeline's final state",
    )
    parser.add_argument(
        "--by",
        required=True,
        help="Role or work handle. Not a name or an email address: "
        "the triage log is committed.",
    )
    parser.add_argument("--rationale", default="")
    parser.add_argument("--minutes", type=float)
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    parser.add_argument("--sarif", type=Path, default=SARIF_OUT)
    args = parser.parse_args()

    verdict_row = latest_verdict_row(args.log, args.finding_id)
    if verdict_row is None:
        print(
            f"REFUSED: no recorded verdict for {args.finding_id} in {args.log}.",
            file=sys.stderr,
        )
        print(
            "\nRecord the verdict first. A decision with nothing to decide on "
            "would sit in the log describing nothing.",
            file=sys.stderr,
        )
        return 2

    # Same log contract as record_verdict, invoked rather than reimplemented.
    # A stale header would file this row's values under old column names, and a
    # foreign identity scheme means the ids already in the log do not mean what
    # this row's id means.
    try:
        check_log_compatible(args.log, ID_SCHEME)
    except ValidationError as exc:
        print(f"LOG ERROR: {exc}", file=sys.stderr)
        return 1

    # Parse the SARIF before writing anything. The triage log is append-only,
    # so a row written before a SARIF failure could never be taken back and the
    # two artefacts would disagree permanently.
    try:
        results = load_existing_results(args.sarif)
    except ValidationError as exc:
        print(f"SARIF ERROR: {exc}", file=sys.stderr)
        return 1
    target = find_sarif_result(results, args.finding_id)

    decided_at = datetime.now(timezone.utc).isoformat()
    append_log(
        {
            "reviewed_at": decided_at,
            "finding_id": args.finding_id,
            "id_scheme": verdict_row.get("id_scheme", ""),
            "rule_id": verdict_row.get("rule_id", ""),
            "file": verdict_row.get("file", ""),
            "line": verdict_row.get("line", ""),
            "severity": verdict_row.get("severity", ""),
            "final_state": verdict_row.get("final_state", ""),
            "minutes_spent": args.minutes if args.minutes is not None else "",
            "human_decision": args.decision,
            "human_decision_at": decided_at,
            "human_decision_by": args.by,
            "human_rationale": args.rationale,
        },
        args.log,
    )

    if target is not None:
        target["properties"].update(
            {
                "human_decision": args.decision,
                "human_decision_at": decided_at,
                "human_decision_by": args.by,
                "human_rationale": args.rationale,
            }
        )
        args.sarif.write_text(
            json.dumps(sarif_document(results), indent=2), encoding="utf-8"
        )

    print(f"{args.finding_id}: {args.decision} by {args.by}")
    print(f"  logged -> {args.log}")
    if target is not None:
        print(f"  sarif  -> {args.sarif}")
    else:
        print(f"  note: {args.finding_id} is not in {args.sarif}; log updated only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
