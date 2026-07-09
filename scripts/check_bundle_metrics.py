#!/usr/bin/env python3
"""CLI wrapper for bundle_metrics.py (opt-in make.py step).

Derives app_count from LOUPE_ESBUILD env to match build.py emission
(Approach A). vendor_count is hardcoded at 11 (see build.py:1198-1258
for the list; follow-on: extract VENDOR_FILES in js_sources.py).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build.bundle_metrics import DEFAULT_BUNDLE, DEFAULT_OUT, measure_bundle  # noqa: E402


def _derive_app_count() -> int:
    # Match build.py detection (see _ESBUILD_MODE / _USE_ESBUILD_FULL at build.py:770-773)
    esbuild = os.environ.get('LOUPE_ESBUILD', '')
    minify = os.environ.get('LOUPE_ESBUILD_MINIFY') == '1'
    if esbuild == 'full' and minify:
        return 1
    return 4


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    bundle = Path(args[0]) if args else DEFAULT_BUNDLE
    if not bundle.is_absolute():
        bundle = Path(__file__).resolve().parent.parent / bundle
    out = Path(args[1]) if len(args) > 1 else DEFAULT_OUT
    if not bundle.is_file():
        print(f'ERROR  bundle not found: {bundle}', file=sys.stderr)
        return 1
    app_count = _derive_app_count()
    report = measure_bundle(bundle, app_count=app_count, vendor_count=11)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(__import__('json').dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'OK    {report["bundle"]}: {report["total_bytes"]} bytes ({report["total_kb"]} KB)')
    for sec in report['sections'][:6]:
        print(f'      {sec["name"]}: {sec["bytes"]} bytes')
    if len(report['sections']) > 6:
        print(f'      … {len(report["sections"]) - 6} more section(s)')
    print(f'      → {out.relative_to(Path(__file__).resolve().parent.parent)}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())