"""Renderer IOC emission contract gate."""
from __future__ import annotations

import os
import re

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO = os.path.dirname(_BASE)
RENDERERS_DIR = os.path.join(REPO, 'src', 'renderers')

_FORBIDDEN = [
    (re.compile(r'\brefs\.push\s*\(\s*\{[^}]*\btype\s*:\s*IOC\.'), 'refs.push IOC shape'),
    (re.compile(r'\bexternalRefs\.push\s*\('), 'externalRefs.push'),
    (re.compile(r'\binterestingStrings\.push\s*\('), 'interestingStrings.push'),
    (
        re.compile(r'\bexternalRefs\s*=\s*[^;]*\bdetections\b[^;]*\.map\s*\('),
        'externalRefs = detections.map (use mirrorDetectionsToExternalRefs)',
    ),
    (
        re.compile(r'\bexternalRefs\s*=\s*[^;]*\.map\s*\(\s*\w+\s*=>\s*\(\s*\{\s*type\s*:\s*IOC\.'),
        'externalRefs = *.map IOC rows (use pushIOC / mirrorDetectionsToExternalRefs)',
    ),
]


def check_renderer_ioc() -> list[str]:
    violations: list[str] = []
    if not os.path.isdir(RENDERERS_DIR):
        return violations
    for fname in sorted(os.listdir(RENDERERS_DIR)):
        if not fname.endswith('.js'):
            continue
        rel = os.path.join('src', 'renderers', fname)
        with open(os.path.join(RENDERERS_DIR, fname), encoding='utf-8') as fh:
            text = fh.read()
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            for pat, label in _FORBIDDEN:
                if pat.search(line):
                    violations.append(f'{rel}:{lineno}: forbidden {label}')
    return violations