#!/usr/bin/env python3
"""CLI for timeline composite contract gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.timeline_contract import check_timeline_contract  # noqa: E402


def main() -> int:
    violations = check_timeline_contract()
    if not violations:
        print('OK    timeline composite contract satisfied')
        return 0
    print(f'FAIL  timeline contract violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())