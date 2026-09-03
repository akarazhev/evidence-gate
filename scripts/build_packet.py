#!/usr/bin/env python3
"""Build a self-contained review packet from a SARIF finding.

The packet is what you hand to the agent. Building it with a script rather than
by hand does three things: it enforces the scope policy before any code is
exposed, it keeps the context narrow (which improves reasoning quality as well as
reducing what leaves the perimeter), and it makes the review reproducible by
someone else later.

Usage:
    build_packet.py --sarif findings/raw.sarif --index 0
    build_packet.py --sarif findings/raw.sarif --list
    build_packet.py --challenge --verdict findings/verdicts/<id>.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_scope import (  # noqa: E402
    ScopeViolation,
    check_path,
    load_policy,
    matches as check_scope_matches,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTEXT_LINES = 40
ID_SCHEME = "content-v1"

# Keys we trust first when a scanner emits several. Order is significance, not
# preference for its own sake: these are the ones scanners document as stable.
FINGERPRINT_PREFERENCE = ("primaryLocationLineHash", "semgrep.fingerprint")


def _digest(material: str) -> str:
    return f"F-{hashlib.sha256(material.encode()).hexdigest()[:12]}"


def scanner_fingerprint(result: dict) -> str | None:
    """The scanner's own stable identifier for this finding, when it emits one.

    SARIF 2.1.0 defines fingerprints and partialFingerprints for exactly this
    purpose, so preferring them means inheriting the scanner's notion of
    identity rather than inventing a competing one. Key selection is
    deterministic: a preferred key if present, otherwise the first in sorted
    order, so two runs over the same result always agree.
    """
    for container in ("fingerprints", "partialFingerprints"):
        prints = result.get(container)
        if not isinstance(prints, dict) or not prints:
            continue
        for key in FINGERPRINT_PREFERENCE:
            if key in prints:
                return f"{container}:{key}:{prints[key]}"
        key = sorted(prints)[0]
        return f"{container}:{key}:{prints[key]}"
    return None


def normalize_snippet(text: str) -> str:
    """Drop indentation and blank lines so reformatting does not reset identity."""
    stripped = (line.strip() for line in text.splitlines())
    return "\n".join(line for line in stripped if line)


def occurrence_index(file_text: str, start_line: int, end_line: int, target: str) -> int:
    """How many identical normalized snippets appear before this one.

    Without it, two identical fragments in one file would collapse into a
    single id. Stable under line shifts: inserting lines above moves the
    finding and its earlier duplicates by the same amount, so the count holds.
    """
    lines = file_text.splitlines()
    span = max(1, end_line - start_line + 1)
    count = 0
    for i in range(0, max(0, start_line - 1)):
        if normalize_snippet("\n".join(lines[i:i + span])) == target:
            count += 1
    return count


def compute_finding_id(
    result: dict, repo: Path, exclusions: list[dict] | None = None
) -> str:
    """Identity that survives edits elsewhere in the file.

    Guarantee: inserting or deleting lines above the finding does not change
    the id, so verdicts and SARIF suppressions survive ordinary refactoring.

    Non-guarantee, and deliberately so: editing the flagged fragment itself
    changes the id. Changed code deserves a fresh review.

    Known limitation: identity combines the fragment with how many identical
    fragments precede it, so reordering identical fragments within one file
    swaps their ids.

    Raises ScopeViolation for an excluded path, before either identity path
    runs. The content path would otherwise read a file the policy forbids, and
    the fingerprint path — which needs no file — would hand back an id for a
    finding that can never be turned into a packet. One rule for both keeps the
    control uniform and the listing honest.
    """
    rule_id = result["rule_id"]
    path = result["file"]

    check_path(path, exclusions)

    fingerprint = scanner_fingerprint(result)
    if fingerprint:
        return _digest(f"{rule_id}:{path}:{fingerprint}")

    target_file = repo / path
    if not target_file.exists():
        raise FileNotFoundError(
            f"Source file not found: {target_file}. Run the scan from the "
            "repository root."
        )

    text = target_file.read_text(encoding="utf-8", errors="replace")
    start, end = result["start_line"], result["end_line"]
    snippet = normalize_snippet("\n".join(text.splitlines()[start - 1:end]))
    if not snippet:
        raise ValueError(
            f"Cannot derive an identity for {path}:{start}-{end}: the flagged "
            "region is empty or whitespace only."
        )
    index = occurrence_index(text, start, end, snippet)
    return _digest(f"{rule_id}:{path}:{snippet}:{index}")


def load_sarif_results(sarif_path: Path) -> list[dict]:
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = []
    for run in data.get("runs", []):
        tool = (
            run.get("tool", {}).get("driver", {}).get("name", "unknown")
        )
        # Rule metadata lives separately from results in SARIF; index it once.
        rules = {
            rule.get("id"): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            locations = result.get("locations", [])
            if not locations:
                continue
            phys = locations[0].get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            results.append(
                {
                    "tool": tool,
                    "rule_id": rule_id,
                    "rule_description": (
                        rule.get("fullDescription", {}).get("text")
                        or rule.get("shortDescription", {}).get("text")
                        or result.get("message", {}).get("text", "")
                    ),
                    "message": result.get("message", {}).get("text", ""),
                    "level": result.get("level", "warning"),
                    "file": artifact,
                    "start_line": region.get("startLine", 1),
                    "end_line": region.get("endLine", region.get("startLine", 1)),
                    # Verbatim SARIF spelling: these are passed straight to
                    # scanner_fingerprint, and renaming them here would add a
                    # mapping layer whose only job is to be kept in sync.
                    "fingerprints": result.get("fingerprints") or {},
                    "partialFingerprints": result.get("partialFingerprints") or {},
                    "code_flows": _extract_code_flows(result),
                }
            )
    return results


def _extract_code_flows(result: dict) -> list[dict]:
    """Pull the scanner's dataflow trace, when it provides one.

    Semgrep and CodeQL both emit codeFlows for taint rules. Passing the scanner's
    own trace to the agent gives it a starting hypothesis to verify rather than
    forcing it to rediscover the path.
    """
    flows = []
    for flow in result.get("codeFlows", []):
        for thread in flow.get("threadFlows", []):
            steps = []
            for loc in thread.get("locations", []):
                phys = loc.get("location", {}).get("physicalLocation", {})
                steps.append(
                    {
                        "file": phys.get("artifactLocation", {}).get("uri", ""),
                        "line": phys.get("region", {}).get("startLine"),
                        "message": loc.get("location", {})
                        .get("message", {})
                        .get("text", ""),
                    }
                )
            if steps:
                flows.append({"steps": steps})
    return flows


def read_context(file_path: Path, start: int, end: int, window: int) -> str | None:
    if not file_path.exists():
        return None
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    lo = max(0, start - window - 1)
    hi = min(len(lines), end + window)
    numbered = [f"{i + 1:>6} | {lines[i]}" for i in range(lo, hi)]
    return "\n".join(numbered)


def build_triage_packet(
    result: dict, repo: Path, window: int, exclusions: list[dict] | None = None
) -> dict:
    # Scope check before any file content is read, identity included. This
    # ordering is the point: compute_finding_id opens the source file.
    if exclusions is None:
        exclusions, _ = load_policy()
    candidates = [result["file"]] + [
        step["file"] for flow in result["code_flows"] for step in flow["steps"]
    ]
    for path in candidates:
        if path:
            check_path(path, exclusions)

    fid = compute_finding_id(result, repo, exclusions)

    target = repo / result["file"]
    context = read_context(target, result["start_line"], result["end_line"], window)
    if context is None:
        raise FileNotFoundError(
            f"Source file not found: {target}. Run the scan from the repository root."
        )

    flow_context = []
    seen = set()
    for flow in result["code_flows"]:
        for step in flow["steps"]:
            key = (step["file"], step["line"])
            if key in seen or not step["file"] or step["file"] == result["file"]:
                continue
            seen.add(key)
            snippet = read_context(repo / step["file"], step["line"], step["line"], 12)
            if snippet:
                flow_context.append(
                    {
                        "file": step["file"],
                        "line": step["line"],
                        "scanner_note": step["message"],
                        "code": snippet,
                    }
                )

    return {
        "packet_type": "triage",
        "finding_id": fid,
        "id_scheme": ID_SCHEME,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "procedure": "prompts/triage-finding.md",
        "scanner": {
            "tool": result["tool"],
            "rule_id": result["rule_id"],
            "rule_description": result["rule_description"],
            "message": result["message"],
            "level": result["level"],
        },
        "location": {
            "file": result["file"],
            "start_line": result["start_line"],
            "end_line": result["end_line"],
        },
        "target_code": context,
        "scanner_dataflow": result["code_flows"],
        "dataflow_context": flow_context,
        "instructions": (
            "Follow prompts/triage-finding.md. The scanner dataflow is a "
            "hypothesis to verify, not evidence. You may request additional "
            "files by path; they will be scope-checked before being provided. "
            "Output JSON conforming to templates/verdict.schema.json and nothing else."
        ),
    }


def build_challenge_packet(verdict: dict) -> dict:
    return {
        "packet_type": "challenge",
        "finding_id": verdict["finding_id"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "procedure": "prompts/adversarial-validate.md",
        "original_verdict": verdict,
        "instructions": (
            "Your goal is to REFUTE the verdict above. Run this in a fresh "
            "session on a different model from the one in original_verdict.reviewer.agent. "
            "Re-derive the data flow yourself; do not trust the prior trace. "
            "Record every refutation you attempt and whether it held. "
            "Output JSON conforming to templates/challenge.schema.json and nothing else."
        ),
    }


# error first, because that is the order a reviewer wants to work in.
LEVEL_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}


def annotate(results: list[dict], repo: Path, exclusions: list[dict]) -> list[dict]:
    """Attach identity and scope status to each result."""
    annotated = []
    for result in results:
        item = dict(result)
        try:
            item["finding_id"] = compute_finding_id(result, repo, exclusions)
        except (ScopeViolation, FileNotFoundError, ValueError):
            # Excluded, absent, or unidentifiable. Never read an excluded file
            # just to print a label for it.
            item["finding_id"] = None
        item["in_scope"] = _in_scope(result["file"], exclusions)
        annotated.append(item)
    return annotated


def reviewed_finding_ids(verdict_dir: Path) -> set[str]:
    """Ids that already have a verdict on disk, taken from filenames."""
    if not verdict_dir.exists():
        return set()
    return {path.stem for path in verdict_dir.glob("*.json")}


def apply_filters(
    items: list[dict],
    levels: list[str] | None = None,
    rule: str | None = None,
    path_glob: str | None = None,
    reviewed_ids: set[str] | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Narrow the queue using what the SARIF actually carries.

    Filtering is on scanner `level`, rule id and path — never on policy
    severity or priority class. Those are assigned by the agent during triage
    and do not exist yet at listing time; mapping SARIF levels onto them here
    would manufacture a confidence nobody earned.
    """
    out = list(items)
    if levels:
        wanted = {level.strip().lower() for level in levels if level.strip()}
        out = [item for item in out if item["level"].lower() in wanted]
    if rule:
        out = [item for item in out if rule.lower() in item["rule_id"].lower()]
    if path_glob:
        out = [item for item in out if check_scope_matches(item["file"], path_glob)]
    if reviewed_ids is not None:
        out = [item for item in out if item["finding_id"] not in reviewed_ids]
    out.sort(
        key=lambda item: (
            LEVEL_ORDER.get(item["level"].lower(), 9),
            item["file"],
            item["start_line"],
        )
    )
    if limit is not None:
        # A negative limit would slice from the end and silently return a
        # different set than asked for. Refuse rather than guess.
        if limit < 0:
            raise ValueError(f"--limit must not be negative, got {limit}")
        out = out[:limit]
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sarif", type=Path, help="SARIF input")
    parser.add_argument("--index", type=int, help="Finding index from --list")
    parser.add_argument("--list", action="store_true", help="List findings")
    parser.add_argument("--challenge", action="store_true", help="Build a challenge packet")
    parser.add_argument("--verdict", type=Path, help="Verdict JSON for --challenge")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--context-lines", type=int, default=DEFAULT_CONTEXT_LINES)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "findings" / "packets")
    parser.add_argument("--level", help="Comma-separated SARIF levels, e.g. error,warning")
    parser.add_argument("--rule", help="Substring match on the rule id")
    parser.add_argument("--path", dest="path_glob", help="Glob on the file path")
    parser.add_argument(
        "--unreviewed", action="store_true", help="Hide findings that already have a verdict on disk"
    )
    parser.add_argument("--limit", type=int, help="Show at most N findings")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Machine-readable output")
    parser.add_argument(
        "--verdicts",
        type=Path,
        default=REPO_ROOT / "findings" / "verdicts",
        help="Where recorded verdicts live, for --unreviewed",
    )
    args = parser.parse_args()

    if args.challenge:
        if not args.verdict:
            parser.error("--challenge requires --verdict")
        verdict = json.loads(args.verdict.read_text(encoding="utf-8"))
        packet = build_challenge_packet(verdict)
        args.out.mkdir(parents=True, exist_ok=True)
        path = args.out / f"{packet['finding_id']}-challenge.json"
        path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
        print(f"Challenge packet: {path}")
        print("Open a FRESH session on a DIFFERENT model, load "
              "prompts/adversarial-validate.md plus this packet.")
        return 0

    if not args.sarif:
        parser.error("--sarif is required")
    if not args.sarif.exists():
        print(f"SARIF not found: {args.sarif}. Run `make scan` first.", file=sys.stderr)
        return 1

    results = load_sarif_results(args.sarif)

    if args.list or args.index is None:
        exclusions, _ = load_policy()
        items = annotate(results, args.repo, exclusions)
        shown = apply_filters(
            items,
            levels=args.level.split(",") if args.level else None,
            rule=args.rule,
            path_glob=args.path_glob,
            reviewed_ids=reviewed_finding_ids(args.verdicts) if args.unreviewed else None,
            limit=args.limit,
        )

        if args.as_json:
            print(json.dumps(shown, indent=2))
            return 0

        for i, item in enumerate(shown):
            flag = "" if item["in_scope"] else "  [OUT OF SCOPE]"
            label = item["finding_id"] or "(no id)"
            print(f"  [{i:>3}] {label}  {item['level']:<8} "
                  f"{item['file']}:{item['start_line']}{flag}")
            print(f"        {item['rule_id']}")

        # Footer, not header: on a real repository the list is hundreds of
        # lines, and a header scrolls away before the reader reaches the end.
        # "already reviewed" is the intersection with this SARIF - counting
        # every file in the verdict directory would fold in findings from other
        # scans and report a number nobody can reconcile.
        on_disk = reviewed_finding_ids(args.verdicts)
        present = {item["finding_id"] for item in items if item["finding_id"]}
        reviewed = len(present & on_disk)
        print(f"\n{len(results)} finding(s) in SARIF, {reviewed} already "
              f"reviewed, {len(shown)} shown")
        print("\nIndices are positions in this filtered list and change when the")
        print("filters change. Use the id for anything you want to reproduce:")
        print("  make triage ID=<finding-id>   or   make triage N=<index>")
        return 0

    exclusions, _ = load_policy()
    items = annotate(results, args.repo, exclusions)
    shown = apply_filters(
        items,
        levels=args.level.split(",") if args.level else None,
        rule=args.rule,
        path_glob=args.path_glob,
        reviewed_ids=reviewed_finding_ids(args.verdicts) if args.unreviewed else None,
        limit=args.limit,
    )

    if not results:
        print(f"No findings in {args.sarif}. Run `make scan` first.", file=sys.stderr)
        return 1

    if not 0 <= args.index < len(shown):
        print(f"Index out of range (0..{len(shown) - 1})", file=sys.stderr)
        return 1

    try:
        packet = build_triage_packet(
            shown[args.index], args.repo, args.context_lines, exclusions
        )
    except ScopeViolation as exc:
        print("REFUSED: finding touches an excluded path.\n", file=sys.stderr)
        print(f"  path:    {exc.path}", file=sys.stderr)
        print(f"  pattern: {exc.pattern}", file=sys.stderr)
        print(f"  reason:  {exc.reason}", file=sys.stderr)
        print("\nThis finding must be reviewed without agent assistance.", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"{packet['finding_id']}.json"
    path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
    print(f"Packet: {path}")
    print(f"Finding: {packet['finding_id']}  {packet['location']['file']}"
          f":{packet['location']['start_line']}")
    print("\nLoad prompts/triage-finding.md plus this packet into the agent.")
    print(f"Save the verdict to findings/verdicts/{packet['finding_id']}.json")
    return 0


def _in_scope(path: str, exclusions: list[dict] | None = None) -> bool:
    try:
        check_path(path, exclusions)
        return True
    except ScopeViolation:
        return False


if __name__ == "__main__":
    sys.exit(main())
