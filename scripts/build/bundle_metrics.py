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


def _script_sections(html: str) -> list[tuple[str, int]]:
    """Return (label, byte_length) for each inline script block."""
    blocks = _SCRIPT_RE.findall(html)
    labels = []
    if len(blocks) >= 1:
        labels.append('script_early_drop')
    # App blocks: concat emits 4; esbuild full emits 1 after early_drop
    app_count = max(0, len(blocks) - 1 - 10)  # vendors ~10 scripts at end
    vendor_start = len(blocks) - 10 if len(blocks) > 11 else len(blocks)
    for i in range(1, len(blocks)):
        if i < vendor_start:
            if app_count == 1:
                labels.append('script_app_full')
            else:
                labels.append(f'script_app_block_{i}')
        else:
            labels.append(f'script_vendor_{i - vendor_start + 1}')
    # Pad / trim labels to match block count
    while len(labels) < len(blocks):
        labels.append(f'script_{len(labels)}')
    return [(labels[i], len(blocks[i].encode('utf-8'))) for i in range(len(blocks))]


def measure_bundle(path: Path) -> dict:
    html = path.read_text(encoding='utf-8')
    total = len(html.encode('utf-8'))
    sections = _script_sections(html)
    return {
        'bundle': str(path.relative_to(REPO)),
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