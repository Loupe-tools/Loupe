#!/usr/bin/env python3
"""CLI for silent empty-catch gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.silent_catch import check_silent_catch  # noqa: E402


def main() -> int:
    violations = check_silent_catch()
    if not violations:
        print('OK    silent-catch gate satisfied')
        return 0
    print(f'FAIL  silent-catch violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())