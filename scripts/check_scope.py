#!/usr/bin/env python3
"""Enforce policy/excluded-paths.yml.

This is the control that makes the manual workflow's data-handling claim real.
Every packet builder calls it. A path matching an exclusion is refused, not
warned about, because a warning in a terminal at 18:00 on a Friday is not a
control.

Deliberately dependency-free: it parses the small YAML subset used by the policy
file itself, so a missing PyYAML can never silently disable the check.

Usage:
    check_scope.py PATH [PATH ...]        exit 0 if all allowed, 2 if any refused
    check_scope.py --list                 print active exclusion patterns
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path

POLICY_PATH = Path(__file__).resolve().parent.parent / "policy" / "excluded-paths.yml"


class ScopeViolation(Exception):
    """Raised when a path is covered by an exclusion."""

    def __init__(self, path: str, pattern: str, reason: str):
        self.path = path
        self.pattern = pattern
        self.reason = reason
        super().__init__(f"{path} matches excluded pattern {pattern!r} ({reason})")


def _parse_policy(text: str) -> tuple[list[dict], list[str]]:
    """Parse the narrow YAML subset used by excluded-paths.yml.

    Recognizes two top-level keys: a list of `- pattern:` mappings under
    `exclusions`, and a list of bare strings under `scan_noise`. Anything else is
    ignored. Written by hand rather than with PyYAML so that an environment
    without the dependency fails loudly at parse time instead of quietly
    skipping the policy.
    """
    exclusions: list[dict] = []
    scan_noise: list[str] = []
    section = None
    current: dict | None = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        if not line.startswith((" ", "\t", "-")):
            key = line.split(":", 1)[0].strip()
            if current is not None:
                exclusions.append(current)
                current = None
            section = key
            continue

        stripped = line.strip()

        if section == "exclusions":
            if stripped.startswith("- "):
                if current is not None:
                    exclusions.append(current)
                current = {}
                stripped = stripped[2:].strip()
            if current is not None and ":" in stripped:
                k, v = stripped.split(":", 1)
                current[k.strip()] = v.strip().strip("\"'")
        elif section == "scan_noise":
            if stripped.startswith("- "):
                scan_noise.append(stripped[2:].strip().strip("\"'"))

    if current is not None:
        exclusions.append(current)

    return [e for e in exclusions if e.get("pattern")], scan_noise


def load_policy(policy_path: Path = POLICY_PATH) -> tuple[list[dict], list[str]]:
    if not policy_path.exists():
        raise FileNotFoundError(
            f"Policy file missing: {policy_path}. Refusing to proceed without it."
        )
    return _parse_policy(policy_path.read_text(encoding="utf-8"))


def _matches(path: str, pattern: str) -> bool:
    """gitignore-flavoured glob matching.

    A trailing slash means "this directory and everything under it". A pattern
    without a slash matches at any depth, mirroring gitignore behaviour, so
    `**/.env` and `.env` both catch a nested file.
    """
    # Strip a leading "./" as a prefix, not as a character set. lstrip("./")
    # would eat the leading dot of a dotfile and turn ".env" into "env",
    # silently defeating every dotfile exclusion in the policy.
    norm = path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/")

    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        cleaned = prefix.replace("**/", "")
        return (
            norm.startswith(prefix + "/")
            or f"/{cleaned}/" in f"/{norm}"
            or norm.startswith(cleaned + "/")
        )

    if fnmatch.fnmatch(norm, pattern):
        return True
    # `**/x` should also match a top-level `x`
    if pattern.startswith("**/") and fnmatch.fnmatch(norm, pattern[3:]):
        return True
    # A bare pattern matches at any depth
    if "/" not in pattern and fnmatch.fnmatch(Path(norm).name, pattern):
        return True
    return False


def check_path(path: str, exclusions: list[dict] | None = None) -> None:
    """Raise ScopeViolation if `path` is excluded. Returns None when allowed."""
    if exclusions is None:
        exclusions, _ = load_policy()
    for rule in exclusions:
        if _matches(path, rule["pattern"]):
            raise ScopeViolation(
                path, rule["pattern"], rule.get("reason", "no reason recorded")
            )


def is_allowed(path: str, exclusions: list[dict] | None = None) -> bool:
    try:
        check_path(path, exclusions)
        return True
    except ScopeViolation:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Paths to check")
    parser.add_argument("--list", action="store_true", help="Print active patterns")
    args = parser.parse_args()

    exclusions, scan_noise = load_policy()

    if args.list:
        print(f"Exclusions ({len(exclusions)}) - must not enter agent context:")
        for rule in exclusions:
            owner = rule.get("owner", "unowned")
            print(f"  {rule['pattern']:<40} {owner:<16} {rule.get('reason', '')}")
        print(f"\nScan noise ({len(scan_noise)}) - skipped by scanners only:")
        for pattern in scan_noise:
            print(f"  {pattern}")
        return 0

    if not args.paths:
        parser.error("provide at least one path, or --list")

    violations = []
    for path in args.paths:
        try:
            check_path(path, exclusions)
        except ScopeViolation as exc:
            violations.append(exc)

    if violations:
        print("REFUSED. These paths must not be placed in agent context:\n", file=sys.stderr)
        for v in violations:
            print(f"  {v.path}", file=sys.stderr)
            print(f"    pattern: {v.pattern}", file=sys.stderr)
            print(f"    reason:  {v.reason}\n", file=sys.stderr)
        return 2

    print(f"OK: {len(args.paths)} path(s) within scope")
    return 0


if __name__ == "__main__":
    sys.exit(main())
