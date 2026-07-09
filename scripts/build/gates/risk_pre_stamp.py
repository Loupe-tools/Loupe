"""Risk pre-stamping gate — escalateRisk() chokepoint only."""
from __future__ import annotations

import re

from build.gate_sources import gate_js_files, is_comment_line, read_js, iter_js_under_root

_RISK_PRE_STAMP_RE = re.compile(
    r"""\.risk\s*=\s*['"](low|medium|high|critical|info)['"]"""
)
_ALLOWLIST = frozenset({'src/constants.js'})


def check_risk_pre_stamping(root: str | None = None) -> list[str]:
    violations: list[str] = []
    if root:
        for rel, text in iter_js_under_root(root):
            if rel in _ALLOWLIST:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if is_comment_line(line):
                    continue
                if _RISK_PRE_STAMP_RE.search(line):
                    violations.append(f'{rel}:{lineno}: {line.strip()}')
        return violations
    for rel in gate_js_files():
        if rel in _ALLOWLIST:
            continue
        text = read_js(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if is_comment_line(line):
                continue
            if _RISK_PRE_STAMP_RE.search(line):
                violations.append(f'{rel}:{lineno}: {line.strip()}')
    return violations