#!/usr/bin/env python3
"""CLI for chokepoint API allow-list gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.chokepoint_apis import check_chokepoint_apis  # noqa: E402


def main() -> int:
    violations = check_chokepoint_apis()
    if not violations:
        print('OK    chokepoint APIs satisfied')
        return 0
    print(f'FAIL  chokepoint API violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())