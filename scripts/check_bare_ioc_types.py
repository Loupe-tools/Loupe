#!/usr/bin/env python3
"""CLI for bare-string IOC type gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.bare_ioc_types import check_bare_ioc_types  # noqa: E402


def main() -> int:
    violations = check_bare_ioc_types()
    if not violations:
        print('OK    bare IOC type gate satisfied')
        return 0
    print(f'FAIL  bare IOC type violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())