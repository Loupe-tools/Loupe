#!/usr/bin/env python3
"""CLI for decoder IOC chokepoint gate."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.decoder_ioc import check_decoder_ioc  # noqa: E402


def main() -> int:
    violations = check_decoder_ioc()
    if not violations:
        print('OK    decoder IOC chokepoints satisfied')
        return 0
    print(f'FAIL  decoder IOC violations: {len(violations)}', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())