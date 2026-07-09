"""Load and validate ``scripts/dispatch-manifest.toml``.

Minimal TOML reader for the Loupe dispatch manifest schema only —
stdlib-only, Python 3.8+, no third-party deps. Supports:

  • ``[[dispatch]]`` tables with string / integer fields
  • ``#`` line comments and blank lines
  • Quoted strings (single or double quotes)
  • Integer literals (including ``inf`` for unlimited caps)
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(BASE, 'dispatch-manifest.toml')

_DISPATCH_HEADER_RE = re.compile(r'^\s*\[\[dispatch\]\]\s*$')
_KV_RE = re.compile(
    r"""^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"""
    r"""(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|(-?\d+)|inf)\s*$"""
)
# Capture groups: 1=key, 2=double-quoted, 3=single-quoted, 4=integer; bare inf has none.


@dataclass(frozen=True)
class DispatchEntry:
    id: str
    class_name: str
    module: str
    max_bytes: int
    alias_of: Optional[str] = None
    dispatch_override: bool = False


def _parse_value(m: re.Match) -> object:
    """Extract RHS from a ``key = value`` regex match (group 1 = key)."""
    if m.group(2) is not None:
        return m.group(2)
    if m.group(3) is not None:
        return m.group(3)
    if m.group(4) is not None:
        return int(m.group(4))
    return float('inf')


def load_manifest(path: str = MANIFEST_PATH) -> list[DispatchEntry]:
    """Parse the dispatch manifest. Raises ``ValueError`` on malformed input."""
    with open(path, encoding='utf-8') as fh:
        lines = fh.readlines()

    entries: list[DispatchEntry] = []
    current: dict[str, object] = {}

    def _flush() -> None:
        if not current:
            return
        for key in ('id', 'class', 'module'):
            if key not in current:
                raise ValueError(
                    f"dispatch-manifest.toml: [[dispatch]] missing required '{key}'"
                )
        max_bytes = current.get('max_bytes', float('inf'))
        if not isinstance(max_bytes, (int, float)):
            raise ValueError('dispatch-manifest.toml: max_bytes must be integer or inf')
        alias = current.get('alias_of')
        override = bool(current.get('dispatch_override', False))
        entries.append(DispatchEntry(
            id=str(current['id']),
            class_name=str(current['class']),
            module=str(current['module']),
            max_bytes=int(max_bytes) if max_bytes != float('inf') else 2**63 - 1,
            alias_of=str(alias) if alias else None,
            dispatch_override=override,
        ))
        current.clear()

    for lineno, raw in enumerate(lines, start=1):
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if _DISPATCH_HEADER_RE.match(line):
            _flush()
            continue
        if re.match(r'^\s*dispatch_override\s*=', line):
            val_s = line.split('=', 1)[1].strip().lower()
            current['dispatch_override'] = val_s in ('true', '1', 'yes')
            continue
        m = _KV_RE.match(line)
        if not m:
            raise ValueError(
                f"dispatch-manifest.toml:{lineno}: unparseable line: {raw.strip()}"
            )
        key = m.group(1)
        current[key] = _parse_value(m)

    _flush()

    if not entries:
        raise ValueError('dispatch-manifest.toml: no [[dispatch]] entries found')

    ids = [e.id for e in entries]
    if len(ids) != len(set(ids)):
        dupes = sorted({x for x in ids if ids.count(x) > 1})
        raise ValueError(f"dispatch-manifest.toml: duplicate dispatch ids: {dupes}")

    return entries


def manifest_ids(entries: list[DispatchEntry] | None = None) -> set[str]:
    entries = entries or load_manifest()
    return {e.id for e in entries}