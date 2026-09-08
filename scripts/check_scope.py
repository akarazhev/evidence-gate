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
KNOWN_SECTIONS = ("exclusions", "scan_noise")


class ScopeViolation(Exception):
    """Raised when a path is covered by an exclusion."""

    def __init__(self, path: str, pattern: str, reason: str):
        self.path = path
        self.pattern = pattern
        self.reason = reason
        super().__init__(f"{path} matches excluded pattern {pattern!r} ({reason})")


class PolicyValidationError(ValueError):
    """Raised when the exclusion policy cannot safely be interpreted."""


def _parse_policy(text: str) -> tuple[list[dict], list[str]]:
    """Parse the narrow YAML subset used by excluded-paths.yml.

    Written by hand rather than with PyYAML so a missing dependency cannot
    silently disable the policy. That reasoning applies just as much to a
    typo: `exclusion:` for `exclusions:` used to parse to zero rules and let
    every excluded path through, which is the same failure the hand-rolled
    parser exists to prevent. Unrecognised sections and rules without a
    pattern are refusals now, not omissions.
    """
    exclusions: list[dict] = []
    scan_noise: list[str] = []
    section = None
    current: dict | None = None
    exclusion_index = 0

    def finish_rule() -> None:
        nonlocal current
        if current is None:
            return
        if not current.get("pattern"):
            raise PolicyValidationError(
                f"exclusions entry {exclusion_index} has no pattern"
            )
        exclusions.append(current)
        current = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        if not line.startswith((" ", "\t", "-")):
            key = line.split(":", 1)[0].strip()
            finish_rule()
            if key not in KNOWN_SECTIONS:
                allowed = ", ".join(KNOWN_SECTIONS)
                raise PolicyValidationError(
                    f"unknown top-level policy section {key!r}; "
                    f"expected one of: {allowed}"
                )
            section = key
            continue

        stripped = line.strip()

        if section == "exclusions":
            if stripped == "-" or stripped.startswith("- "):
                finish_rule()
                exclusion_index += 1
                current = {}
                stripped = stripped[1:].strip()
            if current is not None and ":" in stripped:
                k, v = stripped.split(":", 1)
                current[k.strip()] = v.strip().strip("\"'")
        elif section == "scan_noise":
            if stripped.startswith("- "):
                scan_noise.append(stripped[2:].strip().strip("\"'"))

    finish_rule()

    return exclusions, scan_noise


def load_policy(policy_path: Path = POLICY_PATH) -> tuple[list[dict], list[str]]:
    if not policy_path.exists():
        raise FileNotFoundError(
            f"Policy file missing: {policy_path}. Refusing to proceed without it."
        )
    exclusions, scan_noise = _parse_policy(policy_path.read_text(encoding="utf-8"))
    if not exclusions:
        raise PolicyValidationError(
            "a policy that excludes nothing is not a policy, it is a disabled control"
        )
    return exclusions, scan_noise


def _matches(path: str, pattern: str) -> bool:
    """gitignore-flavoured glob matching.

    A trailing slash means "this directory and everything under it". A pattern
    without a slash matches at any depth, mirroring gitignore behaviour, so
    `**/.env` and `.env` both catch a nested file.

    Matching is case-insensitive and platform-independent. macOS APFS and
    Windows NTFS are case-insensitive by default, so `.ENV` names the same file
    as `.env`; a case-sensitive glob would let the second spelling walk past
    every dotfile exclusion. fnmatch.fnmatch is not an option here because it
    defers to os.path.normcase, which makes the answer depend on the operating
    system the reviewer happens to be using.
    """
    # Strip a leading "./" as a prefix, not as a character set. lstrip("./")
    # would eat the leading dot of a dotfile and turn ".env" into "env",
    # silently defeating every dotfile exclusion in the policy.
    norm = path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/").lower()
    pattern = pattern.lower()

    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        cleaned = prefix.replace("**/", "")
        return (
            norm.startswith(prefix + "/")
            or f"/{cleaned}/" in f"/{norm}"
            or norm.startswith(cleaned + "/")
        )

    if fnmatch.fnmatchcase(norm, pattern):
        return True
    # `**/x` should also match a top-level `x`
    if pattern.startswith("**/") and fnmatch.fnmatchcase(norm, pattern[3:]):
        return True
    # A bare pattern matches at any depth
    if "/" not in pattern and fnmatch.fnmatchcase(Path(norm).name, pattern):
        return True
    return False


def matches(path: str, pattern: str) -> bool:
    """Public entry point for the policy's glob matcher.

    Exposed so the triage queue can filter paths with exactly the semantics the
    exclusion policy uses, rather than growing a second, subtly different one.
    """
    return _matches(path, pattern)


def check_path(path: str, exclusions: list[dict] | None = None) -> None:
    """Raise ScopeViolation if `path` is excluded. Returns None when allowed."""
    if exclusions is None:
        exclusions, _ = load_policy()
    for rule in exclusions:
        if _matches(path, rule["pattern"]):
            raise ScopeViolation(
                path, rule["pattern"], rule.get("reason", "no reason recorded")
            )


def resolve_within(
    repo: Path, relative: str, exclusions: list[dict] | None = None
) -> Path:
    """Resolve a repository-relative path, refusing what the policy excludes.

    The lexical check alone is not enough. A symlink sitting at an allowed path
    can point at an excluded file, and reading it puts exactly the content the
    policy forbids into a packet: a link at app/handler.py pointing to
    ../secrets/token.txt produced a packet containing the secret.

    So the resolved target is checked as well, and a target outside the
    repository is refused outright. The policy describes paths within the
    repository and cannot speak for anything beyond it.
    """
    check_path(relative, exclusions)

    root = repo.resolve()
    target = (root / relative).resolve()
    try:
        inside = target.relative_to(root)
    except ValueError:
        raise ScopeViolation(
            relative,
            "<outside repository>",
            f"resolves to {target}, which is outside {root}",
        )

    check_path(str(inside), exclusions)
    return target


def is_allowed(path: str, exclusions: list[dict] | None = None) -> bool:
    try:
        check_path(path, exclusions)
        return True
    except ScopeViolation:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Paths to check")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Repository root")
    parser.add_argument("--list", action="store_true", help="Print active patterns")
    args = parser.parse_args()

    try:
        exclusions, scan_noise = load_policy()
    except (FileNotFoundError, PolicyValidationError) as exc:
        print(f"POLICY ERROR: {exc}", file=sys.stderr)
        return 2

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
            resolve_within(args.repo, path, exclusions)
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
