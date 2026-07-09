"""Codegen worker shim mirror blocks from canonical host sources."""
from __future__ import annotations

import re
import sys
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

from check_shim_parity import (  # noqa: E402
    CANON,
    MIRRORS,
    _extract_const,
    _extract_fn,
    _extract_ioc_table,
    _extract_parser_limit,
)

MARKER_START = '// @loupe-codegen:start'
MARKER_END = '// @loupe-codegen:end'


def _render_ioc_table(table: dict[str, str], key_order: list[str]) -> str:
    lines = ['const IOC = Object.freeze({']
    for key in key_order:
        if key in table:
            lines.append(f"  {key}: '{table[key]}',")
    lines.append('});')
    return '\n'.join(lines)


def _ioc_key_order(canon_src: str) -> list[str]:
    head = re.compile(r'^const\s+IOC\s*=\s*Object\.freeze\s*\(\s*\{', re.MULTILINE)
    m = head.search(canon_src)
    if not m:
        return []
    i = m.end()
    depth = 1
    while i < len(canon_src) and depth:
        c = canon_src[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
        i += 1
    body = canon_src[m.end():i - 1]
    order: list[str] = []
    entry_re = re.compile(r"""^([A-Z_][A-Z0-9_]*)\s*:""")
    for line in body.splitlines():
        s = re.sub(r'//.*$', '', line).strip().rstrip(',')
        if not s:
            continue
        em = entry_re.match(s)
        if em:
            order.append(em.group(1))
    return order


def render_mirror_block(manifest: dict) -> str:
    canon_path = manifest.get('canon', CANON)
    canon_src = Path(canon_path).read_text(encoding='utf-8')
    chunks: list[str] = []

    if manifest.get('ioc_table'):
        table = _extract_ioc_table(canon_src)
        if table is None:
            raise RuntimeError(f'failed to parse IOC table from {canon_path}')
        chunks.append(_render_ioc_table(table, _ioc_key_order(canon_src)))

    for name in manifest.get('parser_limits', []):
        expr = _extract_parser_limit(canon_src, name)
        if expr is None:
            raise RuntimeError(f'missing PARSER_LIMITS.{name} in {canon_path}')
        if name == 'MAX_UNCOMPRESSED' and len(manifest.get('parser_limits', [])) == 1:
            chunks.append(
                'const PARSER_LIMITS = Object.freeze({\n'
                f'  {name}: {expr},  // generated from constants.js\n'
                '});'
            )
        else:
            chunks.append(f'// PARSER_LIMITS.{name} = {expr}')

    for name in manifest.get('consts', []):
        body = _extract_const(canon_src, name)
        if body is None:
            raise RuntimeError(f'missing const {name} in {canon_path}')
        chunks.append(f'const {name} = {body};')

    for name in manifest.get('fns', []):
        body = _extract_fn(canon_src, name)
        if body is None:
            raise RuntimeError(f'missing function {name} in {canon_path}')
        chunks.append(body)

    return '\n\n'.join(chunks) + '\n'


def splice_codegen(shim_path: Path, generated: str) -> str:
    text = shim_path.read_text(encoding='utf-8')
    if MARKER_START not in text or MARKER_END not in text:
        raise RuntimeError(f'{shim_path}: missing codegen markers')
    start = text.index(MARKER_START)
    end = text.index(MARKER_END, start)
    end_line = text.index('\n', end)
    if end_line < 0:
        end_line = len(text)
    else:
        end_line += 1
    return (
        text[:start + len(MARKER_START) + 1]
        + generated
        + MARKER_END
        + '\n'
        + text[end_line:]
    )


def check_all() -> list[str]:
    errors: list[str] = []
    for manifest in MIRRORS:
        shim_path = Path(manifest['path'])
        if MARKER_START not in shim_path.read_text(encoding='utf-8'):
            errors.append(f'{shim_path}: missing {MARKER_START} marker')
            continue
        try:
            expected = render_mirror_block(manifest)
            actual_region = _extract_codegen_region(shim_path.read_text(encoding='utf-8'))
            if _normalise(expected) != _normalise(actual_region):
                errors.append(f'{shim_path}: codegen drift (run scripts/gen_worker_shims.py --write)')
        except RuntimeError as exc:
            errors.append(str(exc))
    return errors


def _extract_codegen_region(text: str) -> str:
    start = text.index(MARKER_START)
    end = text.index(MARKER_END, start)
    region = text[start + len(MARKER_START):end]
    return region.strip() + '\n'


def _normalise(s: str) -> str:
    out = []
    for line in s.splitlines():
        stripped = line.strip()
        if stripped.startswith('//'):
            continue
        m = re.search(r'(?<!:)\s+//.*$', stripped)
        if m:
            stripped = stripped[: m.start()].rstrip()
        out.append(stripped)
    joined = ' '.join(out)
    return re.sub(r'\s+', ' ', joined).strip()


def write_all() -> list[Path]:
    written: list[Path] = []
    for manifest in MIRRORS:
        shim_path = Path(manifest['path'])
        generated = render_mirror_block(manifest)
        new_text = splice_codegen(shim_path, generated)
        if new_text != shim_path.read_text(encoding='utf-8'):
            shim_path.write_text(new_text, encoding='utf-8')
            written.append(shim_path)
    return written