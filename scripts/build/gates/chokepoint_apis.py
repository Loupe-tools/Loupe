"""Chokepoint API allow-list gate (Worker, localStorage, createObjectURL)."""
from __future__ import annotations

import os
import re

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO = os.path.dirname(_BASE)
SRC = os.path.join(REPO, 'src')

_NEW_WORKER_RE = re.compile(r'\bnew\s+Worker\s*\(')
_LOCAL_STORAGE_RE = re.compile(r'\blocalStorage\b')
_CREATE_OBJECT_URL_RE = re.compile(r'\bURL\.createObjectURL\s*\(')

_WORKER_ALLOW = {
    'src/worker-manager.js',
}
_WORKER_SUFFIX = '.worker.js'

_STORAGE_ALLOW = {
    'src/storage.js',
}

# Inline FOUC bootstrap in build.py HTML shell is out of scope; host sources
# must route downloads / blob URLs through the canonical helpers.
_CREATE_OBJECT_URL_ALLOW = {
    'src/file-download.js',
    'src/worker-manager.js',
    'src/qr-decoder.js',
    'src/renderers/image-renderer.js',
}


def _iter_src_js(root: str | None = None) -> list[tuple[str, str]]:
    """Walk src/ yielding (rel, text) for all .js.

    We intentionally use os.walk (not gate_js_files from build.gate_sources)
    because gate_js_files() only returns EARLY+APP lists and deliberately
    excludes src/workers/*.worker.js (they are inlined as data strings for
    Worker(blob:) construction, never top-level <script> sources). The
    chokepoint rules (new Worker, localStorage, createObjectURL) must still
    be enforced inside the worker bodies.
    """
    out: list[tuple[str, str]] = []
    base = root or REPO
    src = os.path.join(base, 'src')
    for r, _dirs, files in os.walk(src):
        for fname in files:
            if not fname.endswith('.js'):
                continue
            abs_path = os.path.join(r, fname)
            rel = os.path.relpath(abs_path, base).replace(os.sep, '/')
            with open(abs_path, encoding='utf-8') as fh:
                out.append((rel, fh.read()))
    return out


def _worker_allowed(rel: str) -> bool:
    if rel in _WORKER_ALLOW:
        return True
    return rel.startswith('src/workers/') and rel.endswith(_WORKER_SUFFIX)


def check_chokepoint_apis(root: str | None = None) -> list[str]:
    violations: list[str] = []
    for rel, text in _iter_src_js(root):
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            if '// loupe-allow:safe-storage' in line:
                continue
            if _NEW_WORKER_RE.search(line) and not _worker_allowed(rel):
                violations.append(f'{rel}:{lineno}: new Worker outside allow-list')
            if _LOCAL_STORAGE_RE.search(line) and rel not in _STORAGE_ALLOW:
                violations.append(f'{rel}:{lineno}: direct localStorage access')
            if _CREATE_OBJECT_URL_RE.search(line) and rel not in _CREATE_OBJECT_URL_ALLOW:
                violations.append(f'{rel}:{lineno}: URL.createObjectURL outside allow-list')
    return violations