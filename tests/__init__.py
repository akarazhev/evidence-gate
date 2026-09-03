"""Test package for appsec-review.

`scripts/` is a directory of standalone tools, not an importable package:
`build_packet.py` reaches `check_scope` by putting its own directory on
sys.path. Tests must reproduce that layout or the imports diverge from what
the tools actually do at runtime.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = str(REPO_ROOT / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)
