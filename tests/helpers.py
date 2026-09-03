"""Shared test helpers.

Fixtures live under tests/fixtures/ rather than reusing policy/ from the
repository root. A test suite that reads the live policy file breaks every
time the policy is edited, and a suite that breaks on unrelated edits stops
being run.
"""

from __future__ import annotations

import contextlib
import tempfile
from pathlib import Path

from tests import REPO_ROOT

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture_exclusions(name: str = "policy-basic.yml") -> list[dict]:
    """Load the exclusion rules from a fixture policy file."""
    import check_scope

    exclusions, _ = check_scope.load_policy(FIXTURES / name)
    return exclusions


def fixture_scan_noise(name: str = "policy-basic.yml") -> list[str]:
    import check_scope

    _, scan_noise = check_scope.load_policy(FIXTURES / name)
    return scan_noise


@contextlib.contextmanager
def temp_tree(files: dict[str, str]):
    """Materialise a throwaway file tree and yield its root.

    Keys are repository-relative paths, values are file contents. Parent
    directories are created automatically.

    The tree is deleted when the block exits. Assert the ABSENCE of a file
    inside the block, never after it: `assertFalse(p.exists())` on the outside
    passes whether or not the code under test wrote the file, which turns a
    no-partial-write control into a test that cannot fail. Capturing a value
    inside and asserting on it outside is fine.
    """
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        for rel, content in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        yield root


def write_log(path: Path, rows: list[dict]) -> None:
    """Write a triage log using whatever columns record_verdict declares today.

    Reading LOG_FIELDS from the module rather than hardcoding it here means
    later tasks can add columns without breaking every metrics test.
    """
    import csv

    import record_verdict

    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=record_verdict.LOG_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in record_verdict.LOG_FIELDS})


__all__ = ["REPO_ROOT", "FIXTURES", "fixture_exclusions", "fixture_scan_noise", "temp_tree", "write_log"]
