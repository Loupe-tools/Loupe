"""Decoder IOC chokepoint gate."""
from __future__ import annotations

import os
import re

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO = os.path.dirname(_BASE)
DECODERS_DIR = os.path.join(REPO, 'src', 'decoders')


def check_decoder_ioc() -> list[str]:
    violations: list[str] = []

    # Decoders must never push directly into host findings buckets.
    forbidden = [
        (re.compile(r'\.interestingStrings\.push\s*\('), 'interestingStrings.push'),
        (re.compile(r'\.externalRefs\.push\s*\('), 'externalRefs.push'),
        (re.compile(r'\bpushIOC\s*\('), 'pushIOC (use candidate iocs → _mergeEncodedFindingIocs)'),
    ]

    if os.path.isdir(DECODERS_DIR):
        for fname in sorted(os.listdir(DECODERS_DIR)):
            if not fname.endswith('.js'):
                continue
            path = os.path.join(DECODERS_DIR, fname)
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
            if '_patternIocs' in text and 'hasUnresolvedSentinel' not in text and 'DecoderIoc' not in text:
                violations.append(
                    f'{rel}: uses _patternIocs without hasUnresolvedSentinel or DecoderIoc gate'
                )

    # Merge chokepoint: only app-load.js may define or call _mergeEncodedFindingIocs.
    for root, _dirs, files in os.walk(os.path.join(REPO, 'src')):
        for fname in files:
            if not fname.endswith('.js'):
                continue
            rel = os.path.relpath(os.path.join(root, fname), REPO)
            if rel == os.path.join('src', 'app', 'app-load.js'):
                continue
            with open(os.path.join(root, fname), encoding='utf-8') as fh:
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