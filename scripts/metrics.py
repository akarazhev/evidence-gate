#!/usr/bin/env python3
"""Compute triage, dismissal, validation, and human-accuracy metrics."""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = REPO_ROOT / "findings" / "triage-log.csv"
DECISION_FIELDS = (
    "human_decision", "human_decision_at", "human_decision_by", "human_rationale",
)


def load_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _is_verdict_row(row: dict) -> bool:
    return bool(row.get("initial_verdict"))


def _minutes(row: dict) -> float | None:
    try:
        return float(row["minutes_spent"])
    except (KeyError, TypeError, ValueError):
        return None


def _moment(value: str) -> datetime:
    """Parse a log timestamp into an aware datetime, UTC when unqualified.

    Sorting these as strings is wrong: 12:00+03:00 sorts after 10:00+00:00 yet
    happens an hour earlier. The log mixes offsets as soon as two reviewers work
    in different zones.
    """
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def collapse(rows: list[dict]) -> list[dict]:
    """Collapse append-only events with verdict replacement and decision patches."""
    verdicts: dict[str, dict] = {}
    decisions: dict[str, dict] = {}
    verdict_at: dict[str, tuple[datetime, int]] = {}
    decision_at: dict[str, tuple[datetime, int]] = {}
    triage_minutes: dict[str, list[float]] = {}
    decision_minutes: dict[str, list[float]] = {}
    verdict_rows_seen: Counter = Counter()
    last_event: dict[str, str] = {}
    for index, row in sorted(enumerate(rows), key=lambda pair: (_moment(pair[1].get("reviewed_at", "")), pair[0])):
        finding_id = row.get("finding_id")
        if not finding_id:
            continue
        last_event[finding_id] = row.get("reviewed_at", "")
        event_key = (_moment(row.get("reviewed_at", "")), index)
        minutes = _minutes(row)
        if _is_verdict_row(row):
            verdicts[finding_id] = {key: value for key, value in row.items() if key not in DECISION_FIELDS}
            verdict_at[finding_id] = event_key
            verdict_rows_seen[finding_id] += 1
            if minutes is not None:
                triage_minutes.setdefault(finding_id, []).append(minutes)
        elif row.get("human_decision"):
            decisions[finding_id] = {key: row.get(key, "") for key in DECISION_FIELDS}
            decision_at[finding_id] = event_key
            if minutes is not None:
                decision_minutes.setdefault(finding_id, []).append(minutes)

    records = []
    for finding_id in sorted(verdicts.keys() | decisions.keys()):
        record = dict(verdicts.get(finding_id, {}))
        decision = decisions.get(finding_id)
        if decision and finding_id in verdict_at and decision_at[finding_id] < verdict_at[finding_id]:
            # A verdict recorded after the decision supersedes it: the human
            # accepted a different state than the one that now stands.
            decision = None
        record.update(decision or {})
        record["finding_id"] = finding_id
        record["last_event_at"] = last_event.get(finding_id, "")
        triage = triage_minutes.get(finding_id, [])
        decision = decision_minutes.get(finding_id, [])
        record["triage_minutes_total"] = sum(triage) if triage else None
        record["decision_minutes_total"] = sum(decision) if decision else None
        record["revision_count"] = max(0, verdict_rows_seen[finding_id] - 1)
        records.append(record)
    return records


def filter_since(records: list[dict], since: str | None) -> list[dict]:
    if not since:
        return records
    cutoff = _moment(since)
    kept = []
    for record in records:
        moment = _moment(record.get("last_event_at", ""))
        if moment >= cutoff:
            kept.append(record)
    return kept


def compute(rows: list[dict]) -> dict:
    total = len(rows)
    if not total:
        return {"total": 0}
    states = Counter(row.get("final_state", "") for row in rows)
    initial = Counter(row.get("initial_verdict", "") for row in rows)
    challenges = Counter(row.get("challenge_result", "") for row in rows if row.get("challenge_result"))
    evidence = Counter(row.get("evidence_level", "") for row in rows if row.get("evidence_level"))
    severity = Counter(row.get("severity", "") for row in rows if row.get("severity") and row.get("final_state") == "confirmed")
    times = [row["triage_minutes_total"] for row in rows if row.get("triage_minutes_total") is not None]
    decision_times = [row["decision_minutes_total"] for row in rows if row.get("decision_minutes_total") is not None]
    decided = states["confirmed"] + states["dismissed"]
    decisions = Counter(row.get("human_decision") for row in rows if row.get("human_decision"))
    judged = decisions["accepted"] + decisions["rejected"]
    covered = sum(1 for row in rows if row.get("human_decision") and row.get("final_state") in ("confirmed", "dismissed"))
    dismissal = states["dismissed"] / decided * 100 if decided else None
    coverage = covered / decided * 100 if decided else None
    accuracy = decisions["accepted"] / judged * 100 if judged and decided else None
    challenged = sum(challenges.values())
    return {
        "total": total, "states": dict(states), "initial_verdicts": dict(initial),
        "challenge_results": dict(challenges), "evidence_levels": dict(evidence),
        "confirmed_by_severity": dict(severity), "decided": decided, "undecided": total - decided,
        "dismissal_rate_pct": round(dismissal, 1) if dismissal is not None else None,
        "revisions": sum(row.get("revision_count", 0) for row in rows),
        "human_decisions": sum(decisions.values()), "human_decision_breakdown": dict(decisions),
        "human_decision_coverage_pct": round(coverage, 1) if coverage is not None else None,
        "agent_accuracy_pct": round(accuracy, 1) if accuracy is not None else None,
        "median_minutes": round(statistics.median(times), 1) if times else None,
        "mean_minutes": round(statistics.mean(times), 1) if times else None,
        "total_hours": round(sum(times) / 60, 1) if times else None, "timed_findings": len(times),
        "decision_minutes_total": round(sum(decision_times), 1) if decision_times else None,
        "challenge_coverage_pct": round(challenged / total * 100, 1),
        "disagreement_rate_pct": round((challenges["refuted"] + challenges["inconclusive"]) / challenged * 100, 1) if challenged else None,
        "same_model_validations": sum(1 for row in rows if row.get("agent") and row.get("validator") and row["agent"] == row["validator"]),
        "runtime_proof_parked": sum(1 for row in rows if str(row.get("requires_runtime_proof", "")).lower() == "true"),
    }


def render(m: dict) -> str:
    if m["total"] == 0:
        return "No reviews recorded yet.\n\nRun a triage, record the verdict, then come back."
    out: list[str] = []
    add = out.append
    add("=" * 58); add("  APPSEC REVIEW METRICS"); add("=" * 58); add("")
    add(f"  Findings reviewed        {m['total']}")
    add(f"  Reached a decision       {m['decided']}  ({m['decided'] / m['total'] * 100:.0f}%)")
    add(f"  Still open               {m['undecided']}"); add("")
    add("-" * 58); add("  1. TRIAGE TIME  (target: falling)"); add("-" * 58)
    if m["median_minutes"] is not None:
        add(f"  Median                   {m['median_minutes']} min")
        add(f"  Mean                     {m['mean_minutes']} min")
        add(f"  Engineer time total      {m['total_hours']} h over {m['timed_findings']} findings")
    else:
        add("  No timings recorded. Pass --minutes to record_verdict.py;")
        add("  without it this metric cannot be computed and the")
        add("  programme has no primary success measure.")
    if m["decision_minutes_total"] is not None:
        add(f"  Human decision time      {m['decision_minutes_total']} min (separate from triage)")
    add("")
    add("-" * 58); add("  2. DISMISSAL RATE  (of decided findings)"); add("-" * 58)
    if m["dismissal_rate_pct"] is None:
        add("  Nothing decided yet.")
    else:
        add(f"  Dismissed by the pipeline {m['dismissal_rate_pct']}%")
        add("  This is what the pipeline did, not how often it was right.")
        add("  Accuracy is section 5 and needs human decisions.")
    add("")
    add("-" * 58); add("  3. CONFIRMED FINDINGS  (is the signal real?)"); add("-" * 58)
    if m["confirmed_by_severity"]:
        for level in ("critical", "high", "medium", "low", "info"):
            if level in m["confirmed_by_severity"]: add(f"  {level:<24} {m['confirmed_by_severity'][level]}")
    else: add("  None confirmed yet.")
    if m["runtime_proof_parked"]:
        add(f"  Parked awaiting proof    {m['runtime_proof_parked']}")
    add("")
    add("-" * 58); add("  4. VALIDATION INDEPENDENCE  (is pass 2 doing work?)"); add("-" * 58)
    add(f"  Challenge coverage       {m['challenge_coverage_pct']}%")
    if m["disagreement_rate_pct"] is not None:
        rate = m["disagreement_rate_pct"]
        add(f"  Disagreement rate        {rate}%")
        if rate == 0:
            add(""); add("  ! Zero disagreement. Either the validation pass is")
            add("    rubber-stamping, or it runs on the same model and")
            add("    inherits the same blind spots. Investigate before")
            add("    trusting the dismissal number above.")
        elif rate > 40:
            add(""); add("  ! High disagreement. The triage prompt or the trust")
            add("    boundaries in CLAUDE.md are probably underspecified.")
    else:
        add("  No challenges recorded.")
    if m["same_model_validations"]:
        add(""); add(f"  ! {m['same_model_validations']} validation(s) ran on the same")
        add("    model as the triage. Independence is the point.")
    add("")
    add("-" * 58); add("  5. AGENT ACCURACY  (ground truth)"); add("-" * 58)
    if m["human_decisions"]:
        add(f"  Human decisions recorded {m['human_decisions']}")
        for name in ("accepted", "rejected", "escalated"):
            if name in m["human_decision_breakdown"]: add(f"  {name:<24} {m['human_decision_breakdown'][name]}")
        if m["human_decision_coverage_pct"] is None:
            add("  ! No findings have reached a decided state, so coverage and")
            add("    accuracy have no denominator. The counts above stand; the")
            add("    rates are not computed rather than guessed.")
        else:
            add(f"  Coverage                 {m['human_decision_coverage_pct']}%")
            if m["agent_accuracy_pct"] is not None: add(f"  Agent accuracy           {m['agent_accuracy_pct']}%")
            if m["human_decision_coverage_pct"] < 50: add("  ! Accuracy rests on a biased subset.")
    else: add("  No human decisions recorded.")
    if m["revisions"]: add(f"  Verdicts revised         {m['revisions']}")
    add("")
    add("-" * 58); add("  EVIDENCE QUALITY"); add("-" * 58)
    for level in ("traced", "partial", "pattern"):
        if level in m["evidence_levels"]:
            count = m["evidence_levels"][level]
            add(f"  {level:<24} {count}  ({count / m['total'] * 100:.0f}%)")
    add(""); add("  A low 'traced' share means the agent is not being given")
    add("  enough context to follow data flows end to end.")
    add(""); add("=" * 58); add("  Graduation criteria: docs/07-graduation.md"); add("=" * 58)
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, default=LOG_PATH); parser.add_argument("--since"); parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    m = compute(filter_since(collapse(load_rows(args.log)), args.since))
    print(json.dumps(m, indent=2) if args.json else render(m))
    return 0


if __name__ == "__main__": sys.exit(main())
