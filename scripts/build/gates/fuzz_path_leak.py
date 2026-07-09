"""Built bundle must not contain fuzz-harness path substrings."""
from __future__ import annotations

import os

from build.gate_sources import REPO

_MARKERS = ('tests/fuzz/helpers/', 'tests/fuzz/targets/')
_DEFAULT_BUNDLE = os.path.join(REPO, 'docs', 'index.html')


def check_fuzz_path_leak(bundle_path: str | None = None) -> list[str]:
    path = bundle_path or _DEFAULT_BUNDLE
    if not os.path.isfile(path):
        return [f'{path}: bundle not found (run build first)']
    with open(path, encoding='utf-8') as fh:
        bundle = fh.read()
    return [f'{path}: leaked fuzz harness path {m}' for m in _MARKERS if m in bundle]