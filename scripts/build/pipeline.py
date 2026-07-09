#!/usr/bin/env python3
"""Build pipeline orchestrator — pre-build gates shared with make.py."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
REPO = SCRIPTS.parent

# Must match make.py TEST_PIPELINE_GATES script names (order intentional).
PRE_BUILD_GATES: tuple[tuple[str, str], ...] = (
    ('verify', 'verify_vendored.py'),
    ('regex', 'check_regex_safety.py'),
    ('shim-codegen', 'gen_worker_shims.py'),
    ('parity', 'check_shim_parity.py'),
    ('yara-lint', 'lint_yara.py'),
    ('dispatch-sync', 'check_renderer_dispatch_sync.py'),
    ('decoder-ioc', 'check_decoder_ioc.py'),
    ('timeline-contract', 'check_timeline_contract.py'),
    ('renderer-ioc', 'check_renderer_ioc.py'),
    ('chokepoint-apis', 'check_chokepoint_apis.py'),
    ('risk-pre-stamp', 'check_risk_pre_stamp.py'),
    ('bare-ioc-types', 'check_bare_ioc_types.py'),
    ('pushioc-only', 'check_pushioc_only.py'),
    ('raw-text-lf', 'check_raw_text_lf.py'),
    ('worker-spawn', 'check_worker_spawn.py'),
    ('silent-catch', 'check_silent_catch.py'),
    ('storage-access', 'check_storage_access.py'),
    ('extend-app', 'check_extend_app.py'),
    ('backtick-comment', 'check_backtick_comment.py'),
    ('gate-tests', 'run_gate_tests.py'),
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