"""Bare-string IOC type gate — IOC.* constants only."""
from __future__ import annotations

import re

from build.gate_sources import gate_js_files, is_comment_line, read_js

_BARE_IOC_TYPE_RE = re.compile(
    r"""\btype:\s*['"][A-Za-z][A-Za-z _]*['"][^}\n]*?\bseverity\s*:"""
)
_ALLOWLIST = frozenset({'src/constants.js'})


def check_bare_ioc_types() -> list[str]:
    violations: list[str] = []
    for rel in gate_js_files():
        if rel in _ALLOWLIST:
            continue
        text = read_js(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if is_comment_line(line):
                continue
            if _BARE_IOC_TYPE_RE.search(line):
                violations.append(f'{rel}:{lineno}: {line.strip()}')
    return violations