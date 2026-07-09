"""pushIOC()-only IOC emission gate."""
from __future__ import annotations

import os
import sys

_SCRIPTS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

from check_pushioc import ALLOWLIST, scan_bare_pushioc  # noqa: E402

from build.gate_sources import gate_js_files, read_js  # noqa: E402


def check_pushioc_only(*, test_api: bool = False) -> list[str]:
    violations: list[str] = []
    for rel in gate_js_files(test_api=test_api):
        if rel in ALLOWLIST:
            continue
        violations.extend(scan_bare_pushioc(rel, read_js(rel)))
    return violations