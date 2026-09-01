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
from check_scope import ScopeViolation, check_path, load_policy  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTEXT_LINES = 40


def finding_id(rule_id: str, file_path: str, line: int) -> str:
    """Stable ID so the same finding keeps its identity across rescans."""
    digest = hashlib.sha256(f"{rule_id}:{file_path}:{line}".encode()).hexdigest()
    return f"F-{digest[:12]}"


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


def build_triage_packet(result: dict, repo: Path, window: int) -> dict:
    fid = finding_id(result["rule_id"], result["file"], result["start_line"])

    # Scope check before any file content is read. This ordering is the point.
    exclusions, _ = load_policy()
    candidates = [result["file"]] + [
        step["file"] for flow in result["code_flows"] for step in flow["steps"]
    ]
    for path in candidates:
        if path:
            check_path(path, exclusions)

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
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    if args.challenge:
        if not args.verdict:
            parser.error("--challenge requires --verdict")
        verdict = json.loads(args.verdict.read_text(encoding="utf-8"))
        packet = build_challenge_packet(verdict)
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
    if not results:
        print("No findings in SARIF.")
        return 0

    if args.list or args.index is None:
        print(f"{len(results)} finding(s):\n")
        for i, r in enumerate(results):
            fid = finding_id(r["rule_id"], r["file"], r["start_line"])
            flag = "" if _in_scope(r["file"]) else "  [OUT OF SCOPE]"
            print(f"  [{i:>3}] {fid}  {r['level']:<8} {r['file']}:{r['start_line']}{flag}")
            print(f"        {r['rule_id']}")
        print("\nBuild a packet with: make triage N=<index>")
        return 0

    if not 0 <= args.index < len(results):
        print(f"Index out of range (0..{len(results) - 1})", file=sys.stderr)
        return 1

    try:
        packet = build_triage_packet(results[args.index], args.repo, args.context_lines)
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

    path = args.out / f"{packet['finding_id']}.json"
    path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
    print(f"Packet: {path}")
    print(f"Finding: {packet['finding_id']}  {packet['location']['file']}"
          f":{packet['location']['start_line']}")
    print("\nLoad prompts/triage-finding.md plus this packet into the agent.")
    print(f"Save the verdict to findings/verdicts/{packet['finding_id']}.json")
    return 0


def _in_scope(path: str) -> bool:
    try:
        check_path(path)
        return True
    except ScopeViolation:
        return False


if __name__ == "__main__":
    sys.exit(main())
