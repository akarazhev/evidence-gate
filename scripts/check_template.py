#!/usr/bin/env python3
"""Refuse to proceed while CLAUDE.md is still the shipped template.

The evidence standard rests on CLAUDE.md naming this repository's entry points
and trust boundaries. Until it does, "traced" means nothing, because the agent
cannot know what an attacker controls.

Same shape as check_scope refusing without a policy file: a control that cannot
read its input refuses, rather than reporting success. A shell `if grep` cannot
express that - it folds "no matches" and "no such file" into one branch - which
is why this is a script.

Exit codes:
    0  no placeholders remain
    2  placeholders remain, or the file is missing or unreadable
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = REPO_ROOT / "CLAUDE.md"
PLACEHOLDER = re.compile(r"<[A-Za-z][^>]*>")


def find_placeholders(text: str) -> list[tuple[int, str]]:
    """Line numbers and contents of every line still carrying a placeholder."""
    return [
        (number, line.strip())
        for number, line in enumerate(text.splitlines(), start=1)
        if PLACEHOLDER.search(line)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=TEMPLATE_PATH)
    args = parser.parse_args()

    try:
        text = args.path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"REFUSED: cannot read {args.path}: {exc}", file=sys.stderr)
        print(
            "\nThis check exists to prove the file describes this repository. "
            "It cannot prove that about a file it cannot read.",
            file=sys.stderr,
        )
        return 2

    placeholders = find_placeholders(text)
    if placeholders:
        print(f"REFUSED: {args.path} still has template placeholders:\n", file=sys.stderr)
        for number, line in placeholders:
            print(f"  {number:>4}  {line}", file=sys.stderr)
        print(
            "\nFill in trust boundaries, entry points and accepted patterns for "
            "this repository. Until then the evidence standard is hollow: the "
            "agent cannot know what an attacker controls.",
            file=sys.stderr,
        )
        return 2

    print(f"{args.path}: no unfilled placeholders")
    return 0


if __name__ == "__main__":
    sys.exit(main())
