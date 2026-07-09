#!/usr/bin/env python3
"""CLI for localStorage / safeStorage gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.storage_access import check_storage_access  # noqa: E402


def main() -> int:
    violations = check_storage_access()
    if not violations:
        print('OK    storage access gate satisfied')
        return 0
    print(f'FAIL  storage access violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())