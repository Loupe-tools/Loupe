#!/usr/bin/env python3
"""Unit tests for chokepoint API gate."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.chokepoint_apis import check_chokepoint_apis  # noqa: E402


class TestChokepointApisGate(unittest.TestCase):
    def test_live_tree_clean(self) -> None:
        self.assertEqual(check_chokepoint_apis(), [])


if __name__ == '__main__':
    unittest.main()