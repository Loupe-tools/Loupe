#!/usr/bin/env python3
"""CLI for backtick block-comment terminator gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.backtick_comment import check_backtick_comment  # noqa: E402


def main() -> int:
    violations = check_backtick_comment()
    if not violations:
        print('OK    backtick comment gate satisfied')
        return 0
    print(f'FAIL  backtick comment violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())