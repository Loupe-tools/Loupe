#!/usr/bin/env python3
"""Unit tests for pipeline sync gate."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.pipeline_sync import check_pipeline_sync  # noqa: E402


class TestPipelineSyncGate(unittest.TestCase):
    def test_live_tree_clean(self) -> None:
        self.assertEqual(check_pipeline_sync(), [])


if __name__ == '__main__':
    unittest.main()