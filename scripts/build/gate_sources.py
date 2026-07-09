"""Shared JS source lists for build gates."""
from __future__ import annotations

import os

from build.js_sources import APP_JS_FILES, EARLY_JS_FILES

_SCRIPTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(_SCRIPTS)
_TEST_API_FILE = 'src/app/app-test-api.js'


def gate_js_files(*, test_api: bool = False) -> list[str]:
    """Return EARLY_JS_FILES + APP_JS_FILES (optionally with test-api mixin)."""
    files = list(EARLY_JS_FILES) + list(APP_JS_FILES)
    if (test_api or os.path.isfile(os.path.join(REPO, _TEST_API_FILE))) and (
        _TEST_API_FILE not in files
    ):
        files.append(_TEST_API_FILE)
    return files


def read_js(rel: str) -> str:
    with open(os.path.join(REPO, rel), encoding='utf-8') as fh:
        return fh.read()


def is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith('//') or stripped.startswith('*')


def iter_js_under_root(root: str) -> list[tuple[str, str]]:
    """Walk <root>/src collecting (rel, text) for .js files.

    Used by gate positive-case tests that pass root= to check_*().
    Always uses 'with open' and normalizes rel to /-separated.
    Returns only files that could be read.
    """
    out: list[tuple[str, str]] = []
    src = os.path.join(root, 'src')
    for r, _dirs, files in os.walk(src):
        for fn in files:
            if not fn.endswith('.js'):
                continue
            abs_path = os.path.join(r, fn)
            rel = os.path.relpath(abs_path, root).replace(os.sep, '/')
            try:
                with open(abs_path, encoding='utf-8') as fh:
                    out.append((rel, fh.read()))
            except Exception:
                # Skip unreadable in test fixtures; do not mask real bugs in live runs.
                continue
    return out