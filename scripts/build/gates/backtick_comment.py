"""Backtick comment terminator gate — `*/` inside block-comment backtick spans."""
from __future__ import annotations

import re

from build.gate_sources import gate_js_files, read_js

_BACKTICK_COMMENT_TERM_RE = re.compile(r"`[^`\n]*\*/[^`\n]*`")


def check_backtick_comment() -> list[str]:
    violations: list[str] = []
    for rel in gate_js_files():
        text = read_js(rel)
        in_block = False
        for lineno, line in enumerate(text.splitlines(), start=1):
            i = 0
            line_in_block = in_block
            while i < len(line):
                if not in_block:
                    j = line.find('/*', i)
                    if j < 0:
                        break
                    in_block = True
                    i = j + 2
                else:
                    j = line.find('*/', i)
                    if j < 0:
                        break
                    in_block = False
                    i = j + 2

            if (line_in_block or in_block) and _BACKTICK_COMMENT_TERM_RE.search(line):
                if '// loupe-allow:backtick-comment-term' in line:
                    continue
                violations.append(f'{rel}:{lineno}: {line.strip()}')
    return violations