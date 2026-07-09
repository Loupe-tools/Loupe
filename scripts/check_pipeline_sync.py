#!/usr/bin/env python3
"""CLI for pipeline orchestration sync gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.pipeline_sync import check_pipeline_sync  # noqa: E402


def main() -> int:
    violations = check_pipeline_sync()
    if not violations:
        print('OK    pipeline sync: make.py STEPS align with build.pipeline')
        return 0
    print(f'FAIL  pipeline sync violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())