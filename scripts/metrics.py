#!/usr/bin/env python3
"""Compute program metrics from the triage log.

Four numbers decide whether this workflow earns its place. Everything else is
interesting but not decisive:

  1. Triage time per finding      - the primary effect; should fall
  2. False-positive rate          - whether developers keep trusting it
  3. Confirmed findings           - whether the drop in FP came from real signal
  4. Disagreement rate            - whether the second pass is doing any work

Metric 4 is the one teams forget. If triage and validation always agree, the
validation pass is a rubber stamp and the accuracy gain is illusory.

Usage:
    metrics.py
    metrics.py --since 2026-08-01
    metrics.py --json
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = REPO_ROOT / "findings" / "triage-log.csv"


def load_rows(path: Path, since: str | None) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if since:
        cutoff = datetime.fromisoformat(since)
        kept = []
        for row in rows:
            stamp = (row.get("reviewed_at") or "").replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(stamp)
                if dt.replace(tzinfo=None) >= cutoff:
                    kept.append(row)
            except ValueError:
                continue
        return kept
    return rows


def compute(rows: list[dict]) -> dict:
    total = len(rows)
    if total == 0:
        return {"total": 0}

    states = Counter(r["final_state"] for r in rows)
    initial = Counter(r["initial_verdict"] for r in rows)
    challenges = Counter(r["challenge_result"] for r in rows if r["challenge_result"])
    evidence = Counter(r["evidence_level"] for r in rows if r["evidence_level"])
    severity = Counter(
        r["severity"] for r in rows if r["severity"] and r["final_state"] == "confirmed"
    )

    times = []
    for r in rows:
        try:
            times.append(float(r["minutes_spent"]))
        except (ValueError, TypeError, KeyError):
            continue

    decided = states["confirmed"] + states["dismissed"]
    challenged = sum(challenges.values())
    disagreements = challenges["refuted"] + challenges["inconclusive"]

    # FP rate measured over decided findings only. Including undecided findings
    # in the denominator flatters the number, because parked findings are not
    # evidence of precision.
    fp_rate = (states["dismissed"] / decided * 100) if decided else None

    same_model = sum(
        1 for r in rows
        if r.get("agent") and r.get("validator") and r["agent"] == r["validator"]
    )

    return {
        "total": total,
        "states": dict(states),
        "initial_verdicts": dict(initial),
        "challenge_results": dict(challenges),
        "evidence_levels": dict(evidence),
        "confirmed_by_severity": dict(severity),
        "decided": decided,
        "undecided": total - decided,
        "false_positive_rate_pct": round(fp_rate, 1) if fp_rate is not None else None,
        "median_minutes": round(statistics.median(times), 1) if times else None,
        "mean_minutes": round(statistics.mean(times), 1) if times else None,
        "total_hours": round(sum(times) / 60, 1) if times else None,
        "timed_findings": len(times),
        "challenge_coverage_pct": round(challenged / total * 100, 1) if total else 0,
        "disagreement_rate_pct": (
            round(disagreements / challenged * 100, 1) if challenged else None
        ),
        "same_model_validations": same_model,
        "runtime_proof_parked": sum(
            1 for r in rows if str(r.get("requires_runtime_proof", "")).lower() == "true"
        ),
    }


def render(m: dict) -> str:
    if m["total"] == 0:
        return ("No reviews recorded yet.\n\n"
                "Run a triage, record the verdict, then come back.")

    out = []
    add = out.append

    add("=" * 58)
    add("  APPSEC REVIEW METRICS")
    add("=" * 58)
    add("")
    add(f"  Findings reviewed        {m['total']}")
    add(f"  Reached a decision       {m['decided']}  "
        f"({m['decided'] / m['total'] * 100:.0f}%)")
    add(f"  Still open               {m['undecided']}")
    add("")

    add("-" * 58)
    add("  1. TRIAGE TIME  (target: falling)")
    add("-" * 58)
    if m["median_minutes"] is not None:
        add(f"  Median                   {m['median_minutes']} min")
        add(f"  Mean                     {m['mean_minutes']} min")
        add(f"  Engineer time total      {m['total_hours']} h "
            f"over {m['timed_findings']} findings")
    else:
        add("  No timings recorded. Pass --minutes to record_verdict.py;")
        add("  without it this metric cannot be computed and the")
        add("  programme has no primary success measure.")
    add("")

    add("-" * 58)
    add("  2. FALSE-POSITIVE RATE  (of decided findings)")
    add("-" * 58)
    if m["false_positive_rate_pct"] is not None:
        add(f"  Dismissed as FP          {m['false_positive_rate_pct']}%")
        add(f"  Confirmed real           {100 - m['false_positive_rate_pct']:.1f}%")
    else:
        add("  Nothing decided yet.")
    add("")

    add("-" * 58)
    add("  3. CONFIRMED FINDINGS  (is the signal real?)")
    add("-" * 58)
    if m["confirmed_by_severity"]:
        order = ["critical", "high", "medium", "low", "info"]
        for sev in order:
            if sev in m["confirmed_by_severity"]:
                add(f"  {sev:<24} {m['confirmed_by_severity'][sev]}")
    else:
        add("  None confirmed yet.")
    if m["runtime_proof_parked"]:
        add(f"  Parked awaiting proof    {m['runtime_proof_parked']}")
    add("")

    add("-" * 58)
    add("  4. VALIDATION INDEPENDENCE  (is pass 2 doing work?)")
    add("-" * 58)
    add(f"  Challenge coverage       {m['challenge_coverage_pct']}%")
    if m["disagreement_rate_pct"] is not None:
        rate = m["disagreement_rate_pct"]
        add(f"  Disagreement rate        {rate}%")
        if rate == 0:
            add("")
            add("  ! Zero disagreement. Either the validation pass is")
            add("    rubber-stamping, or it runs on the same model and")
            add("    inherits the same blind spots. Investigate before")
            add("    trusting the false-positive number above.")
        elif rate > 40:
            add("")
            add("  ! High disagreement. The triage prompt or the trust")
            add("    boundaries in CLAUDE.md are probably underspecified.")
    else:
        add("  No challenges recorded.")
    if m["same_model_validations"]:
        add("")
        add(f"  ! {m['same_model_validations']} validation(s) ran on the same")
        add("    model as the triage. Independence is the point.")
    add("")

    add("-" * 58)
    add("  EVIDENCE QUALITY")
    add("-" * 58)
    for level in ("traced", "partial", "pattern"):
        if level in m["evidence_levels"]:
            count = m["evidence_levels"][level]
            add(f"  {level:<24} {count}  ({count / m['total'] * 100:.0f}%)")
    add("")
    add("  A low 'traced' share means the agent is not being given")
    add("  enough context to follow data flows end to end.")
    add("")

    add("=" * 58)
    add("  Graduation criteria: docs/07-graduation.md")
    add("=" * 58)
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    parser.add_argument("--since", help="ISO date, e.g. 2026-08-01")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    rows = load_rows(args.log, args.since)
    m = compute(rows)

    if args.json:
        print(json.dumps(m, indent=2))
    else:
        print(render(m))
    return 0


if __name__ == "__main__":
    sys.exit(main())
