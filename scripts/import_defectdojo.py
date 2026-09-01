#!/usr/bin/env python3
"""Placeholder import hook for teams using DefectDojo.

Wire this to the organization's DefectDojo authentication and import settings.
The reviewed SARIF file is `findings/reviewed.sarif`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engagement", required=True)
    parser.add_argument("--sarif", type=Path, default=Path("findings/reviewed.sarif"))
    args = parser.parse_args()

    if not args.sarif.exists():
        print(f"SARIF not found: {args.sarif}", file=sys.stderr)
        return 1

    print(
        "DefectDojo import is not configured in this template. "
        f"Engagement={args.engagement}, sarif={args.sarif}"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
