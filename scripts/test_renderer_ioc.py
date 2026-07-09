#!/usr/bin/env python3
"""Unit tests for renderer IOC gate."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.renderer_ioc import check_renderer_ioc  # noqa: E402


class TestRendererIocGate(unittest.TestCase):
    def test_live_tree_clean(self) -> None:
        self.assertEqual(check_renderer_ioc(), [])


if __name__ == '__main__':
    unittest.main()