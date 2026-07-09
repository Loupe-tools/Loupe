#!/usr/bin/env python3
"""CLI for _rawText LF-normalisation gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.raw_text_lf import check_raw_text_lf  # noqa: E402


def main() -> int:
    violations = check_raw_text_lf()
    if not violations:
        print('OK    _rawText LF-normalisation gate satisfied')
        return 0
    print(f'FAIL  _rawText LF violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())