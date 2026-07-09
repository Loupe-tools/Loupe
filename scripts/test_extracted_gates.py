#!/usr/bin/env python3
"""Unit tests for gates extracted from scripts/build.py."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.backtick_comment import check_backtick_comment  # noqa: E402
from build.gates.bare_ioc_types import check_bare_ioc_types  # noqa: E402
from build.gates.extend_app import check_extend_app  # noqa: E402
from build.gates.fuzz_path_leak import check_fuzz_path_leak  # noqa: E402
from build.gates.pushioc_only import check_pushioc_only  # noqa: E402
from build.gates.raw_text_lf import check_raw_text_lf  # noqa: E402
from build.gates.release_test_api import check_release_test_api  # noqa: E402
from build.gates.risk_pre_stamp import check_risk_pre_stamping  # noqa: E402
from build.gates.silent_catch import check_silent_catch  # noqa: E402
from build.gates.storage_access import check_storage_access  # noqa: E402
from build.gates.worker_spawn import check_worker_spawn  # noqa: E402
from build.gate_sources import REPO  # noqa: E402


class TestExtractedGates(unittest.TestCase):
    def test_live_tree_source_gates_clean(self) -> None:
        self.assertEqual(check_risk_pre_stamping(), [])
        self.assertEqual(check_bare_ioc_types(), [])
        self.assertEqual(check_pushioc_only(), [])
        self.assertEqual(check_raw_text_lf(), [])
        self.assertEqual(check_worker_spawn(), [])
        self.assertEqual(check_silent_catch(), [])
        self.assertEqual(check_storage_access(), [])
        self.assertEqual(check_extend_app(), [])
        self.assertEqual(check_backtick_comment(), [])

    def test_release_bundle_gates_when_built(self) -> None:
        bundle = os.path.join(REPO, 'docs', 'index.html')
        if not os.path.isfile(bundle):
            self.skipTest('docs/index.html not built')
        self.assertEqual(check_release_test_api(bundle), [])
        self.assertEqual(check_fuzz_path_leak(bundle), [])


if __name__ == '__main__':
    unittest.main()