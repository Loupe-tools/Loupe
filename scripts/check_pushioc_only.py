#!/usr/bin/env python3
"""CLI for pushIOC()-only IOC emission gate."""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.pushioc_only import check_pushioc_only  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description='Check pushIOC-only chokepoint')
    parser.add_argument(
        '--test-api', action='store_true',
        help='Include src/app/app-test-api.js in the scan',
    )
    args = parser.parse_args()
    violations = check_pushioc_only(test_api=args.test_api)
    if not violations:
        print('OK    pushIOC-only gate satisfied')
        return 0
    print(f'FAIL  pushIOC-only violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())