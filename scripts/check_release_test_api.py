#!/usr/bin/env python3
"""CLI for release-bundle test-API leak gate."""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gate_sources import REPO  # noqa: E402
from build.gates.release_test_api import check_release_test_api  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description='Check release bundle for test-API markers')
    parser.add_argument(
        '--bundle', default=os.path.join(REPO, 'docs', 'index.html'),
        help='Path to release bundle (default: docs/index.html)',
    )
    args = parser.parse_args()
    violations = check_release_test_api(args.bundle)
    if not violations:
        print('OK    release bundle has no test-API markers')
        return 0
    print(f'FAIL  test-API leak: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())