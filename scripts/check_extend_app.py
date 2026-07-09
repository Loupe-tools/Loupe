#!/usr/bin/env python3
"""CLI for extendApp() mixin gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.extend_app import check_extend_app  # noqa: E402


def main() -> int:
    violations = check_extend_app()
    if not violations:
        print('OK    extendApp mixin gate satisfied')
        return 0
    print(f'FAIL  extendApp violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())