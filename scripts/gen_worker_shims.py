#!/usr/bin/env python3
"""Codegen / verify worker shim mirrors from constants.js."""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.codegen_shims import check_all, write_all  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--write',
        action='store_true',
        help='rewrite shim codegen regions from canonical constants.js',
    )
    args = parser.parse_args()

    if args.write:
        written = write_all()
        if written:
            for p in written:
                print(f'WROTE {p}')
        else:
            print('OK    worker shims already match codegen output')
        return 0

    errors = check_all()
    if not errors:
        print('OK    worker shim codegen regions match constants.js')
        return 0
    print(f'FAIL  worker shim codegen drift: {len(errors)}', file=sys.stderr)
    for e in errors:
        print(f'  • {e}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())