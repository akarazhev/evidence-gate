#!/usr/bin/env python3
"""Refuse to proceed while CLAUDE.md still has shipped placeholders.

This check proves only that recognizable template placeholders are absent. It
cannot decide whether replacement prose names the real entry points and trust
boundaries; that semantic review remains a human responsibility.

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
PLACEHOLDER = re.compile(r"<[A-Za-z][^>]*>", re.DOTALL)


def find_placeholders(text: str) -> list[tuple[int, str]]:
    """Line numbers and first lines of every placeholder still in the file.

    Searched over the whole text, not line by line: the template wraps its
    placeholders across lines, and a per-line pattern never closes on them. The
    line-by-line version reported two of the eight in CLAUDE.md.
    """
    found = []
    for match in PLACEHOLDER.finditer(text):
        line_number = text.count("\n", 0, match.start()) + 1
        first_line = match.group(0).splitlines()[0]
        found.append((line_number, first_line.strip()))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=TEMPLATE_PATH)
    args = parser.parse_args()

    try:
        text = args.path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"REFUSED: cannot read {args.path}: {exc}", file=sys.stderr)
        print(
            "\nThis check cannot establish that placeholders are absent from "
            "a file it cannot read.",
            file=sys.stderr,
        )
        return 2

    placeholders = find_placeholders(text)
    if placeholders:
        print(f"REFUSED: {args.path} still has template placeholders:\n", file=sys.stderr)
        for number, line in placeholders:
            print(f"  {number:>4}  {line}", file=sys.stderr)
        print(
            "\nReplace every placeholder, then have a person verify that the "
            "resulting entry points, trust boundaries and accepted patterns "
            "are accurate for this repository.",
            file=sys.stderr,
        )
        return 2

    print(f"{args.path}: no unfilled placeholders")
    return 0


if __name__ == "__main__":
    sys.exit(main())
