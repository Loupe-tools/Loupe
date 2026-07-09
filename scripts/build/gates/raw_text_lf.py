"""_rawText LF-normalisation gate — lfNormalize() chokepoint."""
from __future__ import annotations

import re

from build.gate_sources import gate_js_files, is_comment_line, read_js

_RAW_TEXT_LHS_RE = re.compile(r"\._rawText\s*=\s*(.+?)\s*;?\s*$")
_ALLOWLIST = frozenset({'src/constants.js'})


def check_raw_text_lf() -> list[str]:
    violations: list[str] = []
    for rel in gate_js_files():
        if rel in _ALLOWLIST:
            continue
        text = read_js(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if is_comment_line(line):
                continue
            m = _RAW_TEXT_LHS_RE.search(line)
            if not m:
                continue
            rhs = m.group(1).lstrip()
            if not rhs.startswith('lfNormalize('):
                violations.append(f'{rel}:{lineno}: {line.strip()}')
    return violations