#!/usr/bin/env python3
"""Run unit tests for build-gate modules under scripts/test_*.py."""
from __future__ import annotations

import os
import sys
import unittest

BASE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.discover(BASE, pattern='test_*.py')
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())