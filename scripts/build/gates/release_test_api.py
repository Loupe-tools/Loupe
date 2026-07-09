"""Release bundle must not contain test-API markers."""
from __future__ import annotations

import os

from build.gate_sources import REPO

_MARKERS = ('__LOUPE_TEST_API__', '__loupeTest')
_DEFAULT_BUNDLE = os.path.join(REPO, 'docs', 'index.html')


def check_release_test_api(bundle_path: str | None = None) -> list[str]:
    path = bundle_path or _DEFAULT_BUNDLE
    if not os.path.isfile(path):
        return [f'{path}: release bundle not found (run build first)']
    with open(path, encoding='utf-8') as fh:
        bundle = fh.read()
    return [f'{path}: leaked test-API marker {m}' for m in _MARKERS if m in bundle]