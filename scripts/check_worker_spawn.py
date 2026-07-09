#!/usr/bin/env python3
"""CLI for worker spawn allow-list gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.worker_spawn import check_worker_spawn  # noqa: E402


def main() -> int:
    violations = check_worker_spawn()
    if not violations:
        print('OK    worker spawn allow-list satisfied')
        return 0
    print(f'FAIL  worker spawn violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())