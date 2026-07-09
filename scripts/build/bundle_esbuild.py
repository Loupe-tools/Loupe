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


def _run_esbuild(cmd: list[str]) -> str:
    out = REPO / 'dist' / '.esbuild-out.js'
    full_cmd = cmd + [f'--outfile={out}', '--log-level=warning']
    env = os.environ.copy()
    proc = subprocess.run(full_cmd, cwd=str(REPO), env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr or proc.stdout or 'esbuild failed')
        raise RuntimeError(f'esbuild exited {proc.returncode}')
    return out.read_text(encoding='utf-8')


def minify_concat_script(source: str, *, define: dict[str, str] | None = None) -> str:
    """Minify a pre-concatenated script while preserving flat global scope.

    Loupe's ``src/`` tree relies on implicit cross-file globals (concat
    semantics). Import-graph bundling breaks that, so the release path
    concatenates first, then runs esbuild as a single-file transform.
    """
    entry = REPO / 'dist' / '.esbuild-concat-entry.js'
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(source, encoding='utf-8')
    cmd = [
        'npx', '--yes', 'esbuild@0.25.0',
        str(entry),
        '--platform=browser',
        '--target=es2020',
        '--minify-whitespace',
        '--minify-syntax',
    ]
    for key, val in (define or {}).items():
        cmd.append(f'--define:{key}={val}')
    return _run_esbuild(cmd)


def bundle_iife(
    entry_files: list[Path],
    *,
    define: dict[str, str] | None = None,
    minify: bool = False,
) -> str:
    """Bundle ``entry_files`` into one IIFE script via esbuild (legacy bisect).

    Prefer ``minify_concat_script`` for the full-app path — import-graph
    bundling isolates module scope and breaks Loupe's implicit globals.
    """
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

    cmd = [
        'npx', '--yes', 'esbuild@0.25.0',
        str(entry),
        '--bundle',
        '--format=iife',
        '--platform=browser',
        '--target=es2020',
    ]
    if minify:
        cmd.extend(['--minify-whitespace', '--minify-syntax'])
    for key, val in (define or {}).items():
        cmd.append(f'--define:{key}={val}')
    return _run_esbuild(cmd)


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