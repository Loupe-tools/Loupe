"""Worker spawn allow-list gate."""
from __future__ import annotations

import re

from build.gate_sources import gate_js_files, is_comment_line, read_js, iter_js_under_root

_NEW_WORKER_RE = re.compile(r"\bnew\s+Worker\s*\(")


def _is_worker_allowlisted(rel: str) -> bool:
    if rel == 'src/worker-manager.js':
        return True
    return rel.startswith('src/workers/') and rel.endswith('.worker.js')


def check_worker_spawn(root: str | None = None) -> list[str]:
    violations: list[str] = []
    if root:
        for rel, txt in iter_js_under_root(root):
            if _is_worker_allowlisted(rel):
                continue
            for lineno, line in enumerate(txt.splitlines(), start=1):
                if is_comment_line(line):
                    continue
                if _NEW_WORKER_RE.search(line):
                    violations.append(f'{rel}:{lineno}: {line.strip()}')
        return violations
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