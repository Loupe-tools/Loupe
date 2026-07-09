"""Silent empty-catch gate for the file-load chain."""
from __future__ import annotations

import re

from build.gate_sources import is_comment_line, read_js

_LOAD_CHAIN_FILES = ('src/app/app-load.js', 'src/app/app-yara.js')
_SILENT_CATCH_RE = re.compile(r"\bcatch\s*\([^)]*\)\s*\{\s*\}")


def check_silent_catch() -> list[str]:
    violations: list[str] = []
    for rel in _LOAD_CHAIN_FILES:
        text = read_js(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if is_comment_line(line):
                continue
            if '// loupe-allow:silent-catch' in line:
                continue
            if _SILENT_CATCH_RE.search(line):
                violations.append(f'{rel}:{lineno}: {line.strip()}')
    return violations