"""Timeline composite `_sources` contract gate."""
from __future__ import annotations

import os
import re

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO = os.path.dirname(_BASE)
SRC = os.path.join(REPO, 'src')

CANONICAL_COLS_LEN = 9

# Frozen merge-eligible kinds — must match `TIMELINE_MERGE_ELIGIBLE_KINDS` in
# `src/constants.js` byte-for-byte on member strings.
EXPECTED_MERGE_KINDS = frozenset({
    'csv', 'tsv', 'log',
    'evtx',
    'syslog3164', 'syslog5424',
    'zeek', 'jsonl', 'cloudtrail',
    'cef', 'leef', 'logfmt',
    'w3c', 'apache-error', 'access-log',
    'sqlite', 'db',
})

# Files allowed to assign composite-registry fields on TimelineView.
_SOURCES_ASSIGN_ALLOW = {
    os.path.join('src', 'app', 'timeline', 'timeline-view.js'),
}
_SOURCE_OF_ROW_ASSIGN_ALLOW = {
    os.path.join('src', 'app', 'timeline', 'timeline-view.js'),
}
_SOURCE_ENABLED_BITMAP_ASSIGN_ALLOW = {
    os.path.join('src', 'app', 'timeline', 'timeline-view.js'),
    os.path.join('src', 'app', 'timeline', 'timeline-sources-bar.js'),
}

_ASSIGN_RE = {
    '_sources': re.compile(r'\._sources\s*='),
    '_sourceOfRow': re.compile(r'\._sourceOfRow\s*='),
    '_sourceEnabledBitmap': re.compile(r'\._sourceEnabledBitmap\s*='),
}


def _read_constants() -> str:
    with open(os.path.join(REPO, 'src', 'constants.js'), encoding='utf-8') as fh:
        return fh.read()


def _extract_canonical_cols_len(text: str) -> int | None:
    m = re.search(
        r'const\s+TIMELINE_CANONICAL_COLS\s*=\s*Object\.freeze\s*\(\s*\[',
        text,
    )
    if not m:
        return None
    i = m.end()
    depth = 1
    while i < len(text) and depth:
        c = text[i]
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
        i += 1
    body = text[m.end():i - 1]
    entries = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith('//')]
    return len(entries)


def _extract_merge_kinds(text: str) -> set[str] | None:
    m = re.search(
        r'const\s+TIMELINE_MERGE_ELIGIBLE_KINDS\s*=\s*Object\.freeze\s*\(\s*new\s+Set\s*\(\s*\[',
        text,
    )
    if not m:
        return None
    i = m.end()
    depth = 1
    while i < len(text) and depth:
        c = text[i]
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
        i += 1
    body = text[m.end():i - 1]
    kinds = set(re.findall(r"'([^']+)'", body))
    return kinds


def _scan_assignments(field: str, allow: set[str]) -> list[str]:
    pat = _ASSIGN_RE[field]
    violations: list[str] = []
    timeline_root = os.path.join(SRC, 'app', 'timeline')
    for root, _dirs, files in os.walk(timeline_root):
        for fname in files:
            if not fname.endswith('.js'):
                continue
            abs_path = os.path.join(root, fname)
            rel = os.path.relpath(abs_path, REPO)
            with open(abs_path, encoding='utf-8') as fh:
                text = fh.read()
            for lineno, line in enumerate(text.splitlines(), start=1):
                stripped = line.lstrip()
                if stripped.startswith('//') or stripped.startswith('*'):
                    continue
                if pat.search(line) and rel not in allow:
                    violations.append(f'{rel}:{lineno}: illegal `.{field}` assignment')
    return violations


def check_timeline_contract() -> list[str]:
    violations: list[str] = []
    constants = _read_constants()

    cols_len = _extract_canonical_cols_len(constants)
    if cols_len is None:
        violations.append('src/constants.js: TIMELINE_CANONICAL_COLS not found')
    elif cols_len != CANONICAL_COLS_LEN:
        violations.append(
            f'src/constants.js: TIMELINE_CANONICAL_COLS length {cols_len} '
            f'!= expected {CANONICAL_COLS_LEN}'
        )

    kinds = _extract_merge_kinds(constants)
    if kinds is None:
        violations.append('src/constants.js: TIMELINE_MERGE_ELIGIBLE_KINDS not found')
    else:
        missing = sorted(EXPECTED_MERGE_KINDS - kinds)
        extra = sorted(kinds - EXPECTED_MERGE_KINDS)
        if missing:
            violations.append(
                'src/constants.js: TIMELINE_MERGE_ELIGIBLE_KINDS missing: '
                + ', '.join(missing)
            )
        if extra:
            violations.append(
                'src/constants.js: TIMELINE_MERGE_ELIGIBLE_KINDS unexpected: '
                + ', '.join(extra)
            )

    violations.extend(_scan_assignments('_sources', _SOURCES_ASSIGN_ALLOW))
    violations.extend(_scan_assignments('_sourceOfRow', _SOURCE_OF_ROW_ASSIGN_ALLOW))
    violations.extend(_scan_assignments('_sourceEnabledBitmap', _SOURCE_ENABLED_BITMAP_ASSIGN_ALLOW))

    return violations