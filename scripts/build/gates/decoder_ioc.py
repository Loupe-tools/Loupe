"""Decoder IOC chokepoint gate."""
from __future__ import annotations

import os
import re

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO = os.path.dirname(_BASE)
DECODERS_DIR = os.path.join(REPO, 'src', 'decoders')

# Module scope (alongside the `forbidden` list):
_EMIT_RX = re.compile(
    r'_patternIocs\s*[:=]\s*|'      # `:` (object literal) OR `=` (assignment)
    r'\bpatternIocs\.push\s*\('     # `.push(` form (with or without leading _)
)
# Strip // and /* */ comments before the DecoderIoc substring check so an
# inline `// via DecoderIoc` cannot satisfy the gate.
_COMMENT_RX = re.compile(r'//.*?$|/\*.*?\*/', re.M | re.S)


def _check_emission_sites(text: str, rel: str) -> list[str]:
    """Every _patternIocs emission must call DecoderIoc within ~8 lines."""
    violations = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith('//') or stripped.startswith('*'):
            continue
        if not _EMIT_RX.search(line):
            continue
        # Look in a window around the emission site (the expression may wrap
        # across a few lines). 8 lines is generous; all current sites are 1.
        lo = max(0, i - 1)
        hi = min(len(lines), i + 8)
        window = '\n'.join(lines[lo:hi])
        # Strip comments so `// via DecoderIoc` can't spoof compliance.
        window_no_comments = _COMMENT_RX.sub('', window)
        if 'DecoderIoc' not in window_no_comments:
            violations.append(
                f'{rel}:{i + 1}: _patternIocs emission must call DecoderIoc '
                f'(within 8 lines of the emission site)'
            )
    return violations


def check_decoder_ioc(root: str | None = None) -> list[str]:
    violations: list[str] = []
    repo = root or REPO
    decoders_dir = os.path.join(repo, 'src', 'decoders')

    # Decoders must never push directly into host findings buckets.
    forbidden = [
        (re.compile(r'\.interestingStrings\.push\s*\('), 'interestingStrings.push'),
        (re.compile(r'\.externalRefs\.push\s*\('), 'externalRefs.push'),
        (re.compile(r'\bpushIOC\s*\('), 'pushIOC (use candidate iocs → _mergeEncodedFindingIocs)'),
    ]

    if os.path.isdir(decoders_dir):
        for fname in sorted(os.listdir(decoders_dir)):
            if not fname.endswith('.js'):
                continue
            path = os.path.join(decoders_dir, fname)
            rel = os.path.join('src', 'decoders', fname)
            with open(path, encoding='utf-8') as fh:
                text = fh.read()
            for lineno, line in enumerate(text.splitlines(), start=1):
                stripped = line.lstrip()
                if stripped.startswith('//') or stripped.startswith('*'):
                    continue
                for pat, label in forbidden:
                    if pat.search(line):
                        violations.append(f'{rel}:{lineno}: forbidden {label}')
            violations.extend(_check_emission_sites(text, rel))

    # Merge chokepoint: only app-load.js may define or call _mergeEncodedFindingIocs.
    for walk_root, _dirs, files in os.walk(os.path.join(repo, 'src')):
        for fname in files:
            if not fname.endswith('.js'):
                continue
            abs_path = os.path.join(walk_root, fname)
            rel = os.path.relpath(abs_path, repo).replace(os.sep, '/')
            if rel == os.path.join('src', 'app', 'app-load.js'):
                continue
            with open(abs_path, encoding='utf-8') as fh:
                text = fh.read()
            for lineno, line in enumerate(text.splitlines(), start=1):
                stripped = line.lstrip()
                if stripped.startswith('//') or stripped.startswith('*'):
                    continue
                if '_mergeEncodedFindingIocs' in line:
                    violations.append(
                        f'{rel}:{lineno}: references _mergeEncodedFindingIocs outside app-load.js'
                    )

    return violations