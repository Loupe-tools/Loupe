"""Emit bundle size breakdown for docs/index.html (build artefact)."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DEFAULT_BUNDLE = REPO / 'docs' / 'index.html'
DEFAULT_OUT = REPO / 'dist' / 'bundle-metrics.json'

_SCRIPT_RE = re.compile(r'<script>(.*?)</script>', re.DOTALL)


def _script_sections(html: str, *, theme_present=True, early_present=True,
                    app_count=4, vendor_count=11) -> list[tuple[str, int]]:
    """Return (label, byte_length) for each inline script block.

    Callers know the build mode; this function does not guess.
    Concat: theme=1, early=1, app=4, vendor=11  → 17 blocks.
    esbuild-full: theme=1, early=1, app=1, vendor=11 → 14 blocks.
    """
    blocks = _SCRIPT_RE.findall(html)
    expected = (1 if theme_present else 0) + (1 if early_present else 0) \
        + app_count + vendor_count
    if len(blocks) != expected:
        # Don't silently mis-label; surface the mismatch.
        raise ValueError(
            f'bundle has {len(blocks)} <script> blocks, expected {expected} '
            f'(theme={theme_present}, early={early_present}, '
            f'app={app_count}, vendor={vendor_count})'
        )
    labels = []
    idx = 0
    if theme_present:
        labels.append('script_theme_bootstrap'); idx += 1
    if early_present:
        labels.append('script_early_drop'); idx += 1
    for i in range(app_count):
        labels.append('script_app_full' if app_count == 1
                      else f'script_app_block_{i + 1}')
        idx += 1
    for i in range(vendor_count):
        labels.append(f'script_vendor_{i + 1}')
        idx += 1
    return [(labels[i], len(blocks[i].encode('utf-8'))) for i in range(len(blocks))]


def measure_bundle(path: Path, *, theme_present=True, early_present=True,
                    app_count=4, vendor_count=11) -> dict:
    p = path.resolve()
    html = p.read_text(encoding='utf-8')
    total = len(html.encode('utf-8'))
    sections = _script_sections(html, theme_present=theme_present,
                                early_present=early_present,
                                app_count=app_count, vendor_count=vendor_count)
    return {
        'bundle': str(p.relative_to(REPO)),
        'total_bytes': total,
        'total_kb': round(total / 1024, 1),
        'sections': [{'name': n, 'bytes': b, 'kb': round(b / 1024, 1)} for n, b in sections],
    }


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    bundle = Path(args[0]) if args else DEFAULT_BUNDLE
    if not bundle.is_absolute():
        bundle = REPO / bundle
    out = Path(args[1]) if len(args) > 1 else DEFAULT_OUT
    if not bundle.is_file():
        print(f'ERROR  bundle not found: {bundle}', file=sys.stderr)
        return 1
    report = measure_bundle(bundle)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'OK    {report["bundle"]}: {report["total_bytes"]} bytes ({report["total_kb"]} KB)')
    for sec in report['sections'][:6]:
        print(f'      {sec["name"]}: {sec["bytes"]} bytes')
    if len(report['sections']) > 6:
        print(f'      … {len(report["sections"]) - 6} more section(s)')
    print(f'      → {out.relative_to(REPO)}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())