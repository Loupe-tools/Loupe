#!/usr/bin/env python3
"""Build pipeline orchestrator (experimental).

Today this module only runs pre-build gates. The concat bundle in
``scripts/build.py`` remains authoritative until the esbuild cutover
lands in a later phase.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
REPO = SCRIPTS.parent

# Gates that must pass before concatenation. Order is intentional:
# cheap static checks first, manifest sync before bundle emit.
PRE_BUILD_GATES: tuple[tuple[str, str], ...] = (
    ('verify', 'verify_vendored.py'),
    ('regex', 'check_regex_safety.py'),
    ('parity', 'check_shim_parity.py'),
    ('yara-lint', 'lint_yara.py'),
    ('dispatch-sync', 'check_renderer_dispatch_sync.py'),
)


def run_gate(name: str, script: str) -> int:
    path = SCRIPTS / script
    if not path.is_file():
        print(f'ERROR  {script} not found', file=sys.stderr)
        return 2
    print(f'── gate: {name} '.ljust(60, '─'))
    return subprocess.call([sys.executable, str(path)], cwd=str(REPO))


def run_pre_build_gates() -> int:
    for name, script in PRE_BUILD_GATES:
        rc = run_gate(name, script)
        if rc != 0:
            return rc
    print('OK    all pre-build gates passed')
    return 0


def main(argv: list[str] | None = None) -> int:
    _ = argv
    return run_pre_build_gates()


if __name__ == '__main__':
    sys.exit(main())