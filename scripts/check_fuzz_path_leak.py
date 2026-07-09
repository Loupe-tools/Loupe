#!/usr/bin/env python3
"""CLI for fuzz-harness path leak gate."""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gate_sources import REPO  # noqa: E402
from build.gates.fuzz_path_leak import check_fuzz_path_leak  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description='Check bundle for fuzz harness paths')
    parser.add_argument(
        '--bundle', default=os.path.join(REPO, 'docs', 'index.html'),
        help='Path to built bundle (default: docs/index.html)',
    )
    args = parser.parse_args()
    violations = check_fuzz_path_leak(args.bundle)
    if not violations:
        print('OK    bundle has no fuzz harness paths')
        return 0
    print(f'FAIL  fuzz path leak: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())