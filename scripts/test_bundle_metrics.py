#!/usr/bin/env python3
"""Unit tests for bundle_metrics (section labelling contract)."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.bundle_metrics import _script_sections, measure_bundle  # noqa: E402


REPO = Path(__file__).resolve().parent.parent
DEFAULT_BUNDLE = REPO / 'docs' / 'index.html'


def _mk_html(n_theme: int, n_early: int, n_app: int, n_vendor: int) -> str:
    parts = []
    for _ in range(n_theme):
        parts.append('<script>theme</script>')
    for _ in range(n_early):
        parts.append('<script>early</script>')
    for _ in range(n_app):
        parts.append('<script>app</script>')
    for _ in range(n_vendor):
        parts.append('<script>vendor</script>')
    return ''.join(parts)


class TestBundleMetricsSections(unittest.TestCase):
    def test_script_sections_concat_17_blocks(self) -> None:
        html = _mk_html(1, 1, 4, 11)
        secs = _script_sections(html, app_count=4, vendor_count=11)
        names = [n for n, _ in secs]
        self.assertEqual(len(names), 17)
        self.assertEqual(names[0], 'script_theme_bootstrap')
        self.assertEqual(names[1], 'script_early_drop')
        self.assertEqual(names[2:6], ['script_app_block_1', 'script_app_block_2', 'script_app_block_3', 'script_app_block_4'])
        self.assertEqual(names[6], 'script_vendor_1')
        self.assertEqual(names[-1], 'script_vendor_11')

    def test_script_sections_esbuild_full_14_blocks(self) -> None:
        html = _mk_html(1, 1, 1, 11)
        secs = _script_sections(html, app_count=1, vendor_count=11)
        names = [n for n, _ in secs]
        self.assertEqual(len(names), 14)
        self.assertEqual(names[:3], ['script_theme_bootstrap', 'script_early_drop', 'script_app_full'])
        self.assertEqual(names[3], 'script_vendor_1')
        self.assertEqual(names[-1], 'script_vendor_11')
        # exact list per plan
        expected = ['script_theme_bootstrap', 'script_early_drop', 'script_app_full'] + \
                   [f'script_vendor_{i}' for i in range(1, 12)]
        self.assertEqual(names, expected)

    def test_script_sections_wrong_count_raises(self) -> None:
        html = _mk_html(1, 1, 1, 11)  # 14
        with self.assertRaises(ValueError) as ctx:
            _script_sections(html, app_count=4, vendor_count=11)  # expect 17
        msg = str(ctx.exception)
        self.assertIn('bundle has 14 <script> blocks, expected 17', msg)
        self.assertIn('app=4', msg)

    def test_script_sections_minimal_synthetic(self) -> None:
        # tiny 14-block shape
        html = '<script>t</script><script>e</script>' + '<script>a</script>' + '<script>v</script>' * 11
        names = [n for n, _ in _script_sections(html, theme_present=True, early_present=True, app_count=1, vendor_count=11)]
        self.assertEqual(names, ['script_theme_bootstrap', 'script_early_drop', 'script_app_full'] +
                         [f'script_vendor_{i}' for i in range(1, 12)])

    def test_live_tree_integration(self) -> None:
        if not DEFAULT_BUNDLE.is_file():
            self.skipTest('docs/index.html not present (run python make.py build)')
        # Derive app_count from the *actual* block count in the on-disk bundle.
        # This makes the test robust when docs/ was produced by either build mode
        # (env may not match the file that is present).
        import re as _re
        html = DEFAULT_BUNDLE.read_text(encoding='utf-8')
        n_blocks = len(_re.findall(r'<script>(.*?)</script>', html, _re.DOTALL))
        if n_blocks == 14:
            app_c = 1
        elif n_blocks == 17:
            app_c = 4
        else:
            self.skipTest(f'unexpected block count {n_blocks} in docs/index.html')
        report = measure_bundle(DEFAULT_BUNDLE, app_count=app_c, vendor_count=11)
        names = [s['name'] for s in report['sections']]
        # must include the canonical labels (order not asserted, presence is)
        self.assertIn('script_theme_bootstrap', names)
        self.assertIn('script_early_drop', names)
        if app_c == 1:
            self.assertIn('script_app_full', names)
            self.assertNotIn('script_app_block_1', names)
        else:
            self.assertIn('script_app_block_1', names)
            self.assertIn('script_app_block_4', names)
        self.assertIn('script_vendor_1', names)
        self.assertIn('script_vendor_11', names)
        # no stray labels
        expected_set = {'script_theme_bootstrap', 'script_early_drop'}
        if app_c == 1:
            expected_set.add('script_app_full')
        else:
            expected_set.update({f'script_app_block_{i}' for i in range(1, 5)})
        expected_set.update({f'script_vendor_{i}' for i in range(1, 12)})
        self.assertEqual(set(names), expected_set)


if __name__ == '__main__':
    unittest.main()
