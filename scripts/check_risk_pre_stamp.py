#!/usr/bin/env python3
"""CLI for risk pre-stamping gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.risk_pre_stamp import check_risk_pre_stamping  # noqa: E402


def main() -> int:
    violations = check_risk_pre_stamping()
    if not violations:
        print('OK    risk pre-stamping gate satisfied')
        return 0
    print(f'FAIL  risk pre-stamping violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())