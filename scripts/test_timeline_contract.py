#!/usr/bin/env python3
"""Unit tests for timeline contract gate."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.timeline_contract import (  # noqa: E402
    CANONICAL_COLS_LEN,
    EXPECTED_MERGE_KINDS,
    check_timeline_contract,
)


class TestTimelineContractGate(unittest.TestCase):
    def test_live_tree_clean(self) -> None:
        self.assertEqual(check_timeline_contract(), [])

    def test_frozen_constants_shape(self) -> None:
        self.assertEqual(CANONICAL_COLS_LEN, 9)
        self.assertIn('evtx', EXPECTED_MERGE_KINDS)
        self.assertNotIn('pcap', EXPECTED_MERGE_KINDS)


if __name__ == '__main__':
    unittest.main()