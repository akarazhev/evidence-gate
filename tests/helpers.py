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
    """
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        for rel, content in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        yield root


__all__ = ["REPO_ROOT", "FIXTURES", "fixture_exclusions", "fixture_scan_noise", "temp_tree"]
