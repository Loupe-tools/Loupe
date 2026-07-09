#!/usr/bin/env python3
"""Unit tests for timeline contract gate."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.timeline_contract import (  # noqa: E402
    CANONICAL_COLS_LEN,
    _extract_merge_kinds,
    _read_constants,
    check_timeline_contract,
)


class TestTimelineContractGate(unittest.TestCase):
    def test_live_tree_clean(self) -> None:
        self.assertEqual(check_timeline_contract(), [])

    def test_merge_kinds_from_constants(self) -> None:
        self.assertEqual(CANONICAL_COLS_LEN, 9)
        kinds = _extract_merge_kinds(_read_constants())
        self.assertIsNotNone(kinds)
        assert kinds is not None
        self.assertIn('evtx', kinds)
        self.assertNotIn('pcap', kinds)


if __name__ == '__main__':
    unittest.main()