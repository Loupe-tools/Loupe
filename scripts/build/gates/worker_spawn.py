"""Worker spawn allow-list gate."""
from __future__ import annotations

import re

from build.gate_sources import gate_js_files, is_comment_line, read_js

_NEW_WORKER_RE = re.compile(r"\bnew\s+Worker\s*\(")


def _is_worker_allowlisted(rel: str) -> bool:
    if rel == 'src/worker-manager.js':
        return True
    return rel.startswith('src/workers/') and rel.endswith('.worker.js')


def check_worker_spawn() -> list[str]:
    violations: list[str] = []
    for rel in gate_js_files():
        if _is_worker_allowlisted(rel):
            continue
        text = read_js(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if is_comment_line(line):
                continue
            if _NEW_WORKER_RE.search(line):
                violations.append(f'{rel}:{lineno}: {line.strip()}')
    return violations