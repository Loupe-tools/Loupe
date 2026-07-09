#!/usr/bin/env python3
"""Build pipeline orchestrator — pre-build gates derived from make.py."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
REPO = SCRIPTS.parent
_MAKE_PY = REPO / 'make.py'


def _load_make():
    spec = importlib.util.spec_from_file_location('loupe_make', _MAKE_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'failed to load make.py from {_MAKE_PY}')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def pre_build_step_ids() -> tuple[str, ...]:
    """Canonical pre-build gate step ids — mirrors make.py TEST_PIPELINE_GATES."""
    return tuple(_load_make().TEST_PIPELINE_GATES)


def pre_build_gates() -> tuple[tuple[str, str, list[str]], ...]:
    """(step_id, script_rel, extra_args) for each pre-build gate."""
    make = _load_make()
    return tuple(
        (step_id, make.STEPS[step_id][1], list(make.STEPS[step_id][2]))
        for step_id in make.TEST_PIPELINE_GATES
    )


def gate_script_path(script: str) -> Path:
    """Resolve a STEPS script path the same way run_gate does."""
    return REPO / script


def run_gate(name: str, script: str, extra: list[str] | None = None) -> int:
    path = gate_script_path(script)
    if not path.is_file():
        print(f'ERROR  {script} not found', file=sys.stderr)
        return 2
    print(f'── gate: {name} '.ljust(60, '─'))
    cmd = [sys.executable, str(path)] + list(extra or [])
    return subprocess.call(cmd, cwd=str(REPO))


def run_pre_build_gates() -> int:
    for name, script, extra in pre_build_gates():
        rc = run_gate(name, script, extra)
        if rc != 0:
            return rc
    print('OK    all pre-build gates passed')
    return 0


def main(argv: list[str] | None = None) -> int:
    _ = argv
    return run_pre_build_gates()


if __name__ == '__main__':
    sys.exit(main())