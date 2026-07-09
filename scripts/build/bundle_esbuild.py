"""Optional esbuild IIFE bundler (build-time only).

Concat remains the default release path. Set ``LOUPE_ESBUILD=1`` to
exercise this module from ``scripts/build.py`` during the experimental
cutover. Requires ``npx esbuild`` on PATH.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
VENDOR = REPO / 'vendor'


def bundle_iife(entry_files: list[Path], *, define: dict[str, str] | None = None) -> str:
    """Bundle ``entry_files`` into one IIFE script via esbuild."""
    if not entry_files:
        raise ValueError('entry_files must be non-empty')
    for p in entry_files:
        if not p.is_file():
            raise FileNotFoundError(p)

    # Materialise a virtual entry that imports each concat slice in order.
    import_stmts = '\n'.join(
        f"import '{p.resolve().as_posix()}';" for p in entry_files
    )
    entry = REPO / 'dist' / '.esbuild-entry.mjs'
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(import_stmts + '\n', encoding='utf-8')

    out = REPO / 'dist' / '.esbuild-bundle.js'
    cmd = [
        'npx', '--yes', 'esbuild@0.25.0',
        str(entry),
        '--bundle',
        '--format=iife',
        '--global-name=LoupeBundle',
        '--platform=browser',
        '--target=es2020',
        f'--outfile={out}',
        '--log-level=warning',
    ]
    for key, val in (define or {}).items():
        cmd.append(f'--define:{key}={val}')

    env = os.environ.copy()
    proc = subprocess.run(cmd, cwd=str(REPO), env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr or proc.stdout or 'esbuild failed')
        raise RuntimeError(f'esbuild exited {proc.returncode}')
    return out.read_text(encoding='utf-8')


def esbuild_available() -> bool:
    try:
        proc = subprocess.run(
            ['npx', '--yes', 'esbuild@0.25.0', '--version'],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def bundle_esm_for_tests(entry_files: list[str], *, expose: list[str] | None = None) -> str:
    """Bundle test modules as a Node CJS-friendly IIFE for unit tests."""
    paths = [REPO / rel for rel in entry_files]
    body = bundle_iife(paths)
    names = expose or []
    footer = '\n'.join(
        f"try {{ globalThis[{json.dumps(n)}] = typeof {n} !== 'undefined' ? {n} : undefined; }} catch (_) {{}}"
        for n in names
    )
    return body + '\n' + footer + '\n'