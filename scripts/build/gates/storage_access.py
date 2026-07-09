"""localStorage access gate — safeStorage chokepoint."""
from __future__ import annotations

import re

from build.gate_sources import gate_js_files, is_comment_line, read_js, iter_js_under_root

_LOCAL_STORAGE_RE = re.compile(r"\blocalStorage\b")
_ALLOWLIST = frozenset({'src/storage.js'})


def check_storage_access(root: str | None = None) -> list[str]:
    violations: list[str] = []
    if root:
        for rel, txt in iter_js_under_root(root):
            if rel in _ALLOWLIST:
                continue
            for lineno, line in enumerate(txt.splitlines(), start=1):
                if is_comment_line(line):
                    continue
                if '// loupe-allow:safe-storage' in line:
                    continue
                if _LOCAL_STORAGE_RE.search(line):
                    violations.append(f'{rel}:{lineno}: {line.strip()}')
        return violations
    for rel in gate_js_files():
        if rel in _ALLOWLIST:
            continue
        text = read_js(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if is_comment_line(line):
                continue
            if '// loupe-allow:safe-storage' in line:
                continue
            if _LOCAL_STORAGE_RE.search(line):
                violations.append(f'{rel}:{lineno}: {line.strip()}')
    return violations