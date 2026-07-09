#!/usr/bin/env python3
"""Unit tests for dispatch manifest loader + sync gate."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS)

from build.manifest import load_manifest  # noqa: E402
from build.gates.dispatch_sync import check_dispatch_sync  # noqa: E402


class TestManifestLoader(unittest.TestCase):
    def test_load_live_manifest(self) -> None:
        entries = load_manifest()
        self.assertGreaterEqual(len(entries), 50)
        ids = {e.id for e in entries}
        self.assertIn('zip', ids)
        self.assertIn('plaintext', ids)

    def test_parse_inf_and_override(self) -> None:
        toml = """
[[dispatch]]
id = "folder"
class = "FolderRenderer"
module = "src/renderers/folder-renderer.js"
max_bytes = inf
dispatch_override = true
"""
        with tempfile.NamedTemporaryFile('w', suffix='.toml', delete=False) as fh:
            fh.write(toml)
            path = fh.name
        try:
            entries = load_manifest(path)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].id, 'folder')
            self.assertTrue(entries[0].dispatch_override)
            self.assertGreater(entries[0].max_bytes, 10**15)
        finally:
            os.unlink(path)


class TestDispatchSync(unittest.TestCase):
    def test_live_tree_in_sync(self) -> None:
        violations = check_dispatch_sync()
        self.assertEqual(violations, [], '\n'.join(violations))


if __name__ == '__main__':
    unittest.main()