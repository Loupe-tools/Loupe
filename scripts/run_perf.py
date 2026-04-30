#!/usr/bin/env python3
"""run_perf.py — execute the Timeline performance harness.

Thin wrapper around `scripts/run_tests_e2e.py` that:
  1. Sets `LOUPE_PERF=1` so the perf spec un-skips itself.
  2. Forwards `--rows`, `--runs`, `--seed`, `--report` as
     `LOUPE_PERF_*` environment variables.
  3. Passes `--workers=1` and `tests/perf/` as the spec selector
     so `playwright test` only runs the perf suite, serially.

The perf spec lives at `tests/perf/timeline-100k.spec.ts` and is
otherwise wired through the same `dist/test-deps/` rig as the e2e
suite — same Playwright pin, same Chromium, same test-bundle build
(`docs/index.test.html`).

Usage
-----
    python scripts/run_perf.py                         # 100 K rows × 3 runs
    python scripts/run_perf.py --rows 10000 --runs 1   # smoke run
    python scripts/run_perf.py --rows 1000000          # stress (1 M rows; high RAM)
    python scripts/run_perf.py --report dist/perf-after.json --runs 5

Notes
-----
* The fixture is generated on demand by
  `scripts/misc/generate_sample_csv.py` and cached at
  `dist/loupe-perf-<rows>-seed<seed>.csv`. First run takes ~30 s for
  100 K rows, then the cache is hit on subsequent runs.
* The full per-run JSON report lands at
  `dist/perf-report.json` (override with `--report`). A Markdown
  summary table is printed to stdout regardless.
* `LOUPE_PERF=1` is the gate the spec self-checks; setting it via
  this wrapper means `python make.py test-e2e` continues to skip the
  perf suite (which is what we want — perf is opt-in).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN_TESTS_E2E = os.path.join(BASE, 'scripts', 'run_tests_e2e.py')


def main() -> int:
    p = argparse.ArgumentParser(
        description='Run the Loupe Timeline performance harness.',
    )
    p.add_argument('--rows', type=int, default=100_000,
                   help='Row count for the generated CSV (default: 100000)')
    p.add_argument('--runs', type=int, default=3,
                   help='Number of fresh-page runs to average over (default: 3)')
    p.add_argument('--seed', type=int, default=42,
                   help='Seed for the deterministic generator (default: 42)')
    p.add_argument('--report', type=str,
                   default=os.path.join(BASE, 'dist', 'perf-report.json'),
                   help='Path for the JSON report (default: dist/perf-report.json)')
    p.add_argument('--phase-timeout-ms', type=int, default=180_000,
                   help='Per-phase timeout budget in ms (default: 180000)')
    p.add_argument('--poll-ms', type=int, default=50,
                   help='Page-state poll interval in ms (default: 50)')
    p.add_argument('--ui', action='store_true',
                   help='Pass --ui to playwright test (interactive runner)')
    p.add_argument('--debug', action='store_true',
                   help='Pass --debug to playwright test (single-test debug)')
    args, extra = p.parse_known_args()

    env = os.environ.copy()
    env['LOUPE_PERF'] = '1'
    env['LOUPE_PERF_ROWS'] = str(args.rows)
    env['LOUPE_PERF_RUNS'] = str(args.runs)
    env['LOUPE_PERF_SEED'] = str(args.seed)
    env['LOUPE_PERF_REPORT'] = os.path.abspath(args.report)
    env['LOUPE_PERF_PHASE_TIMEOUT_MS'] = str(args.phase_timeout_ms)
    env['LOUPE_PERF_POLL_MS'] = str(args.poll_ms)

    # The perf spec is the only thing in tests/perf/ today; selecting
    # the directory keeps the rest of the e2e suite from running. We
    # also force `--workers=1` so two perf runs don't compete for
    # Chromium memory if a future spec lands alongside this one.
    cmd = [sys.executable, RUN_TESTS_E2E, 'tests/perf/', '--workers=1']
    if args.ui:
        cmd.append('--ui')
    if args.debug:
        cmd.append('--debug')
    cmd.extend(extra)

    print(f'[perf] $ LOUPE_PERF=1 LOUPE_PERF_ROWS={args.rows} LOUPE_PERF_RUNS={args.runs} '
          + ' '.join(cmd[1:]), flush=True)
    return subprocess.call(cmd, cwd=BASE, env=env)


if __name__ == '__main__':
    sys.exit(main())
