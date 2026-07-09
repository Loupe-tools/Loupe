"""pushIOC()-only IOC emission gate."""
from __future__ import annotations

import os
import sys

_SCRIPTS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

from check_pushioc import ALLOWLIST, scan_bare_pushioc  # noqa: E402

from build.gate_sources import gate_js_files, read_js, iter_js_under_root  # noqa: E402


def check_pushioc_only(*, test_api: bool = False, root: str | None = None) -> list[str]:
    violations: list[str] = []
    if root:
        for rel, txt in iter_js_under_root(root):
            if rel in ALLOWLIST:
                continue
            violations.extend(scan_bare_pushioc(rel, txt))
        return violations
    for rel in gate_js_files(test_api=test_api):
        if rel in ALLOWLIST:
            continue
        violations.extend(scan_bare_pushioc(rel, read_js(rel)))
    return violations