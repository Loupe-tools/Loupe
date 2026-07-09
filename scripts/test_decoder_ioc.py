#!/usr/bin/env python3
"""Unit tests for decoder IOC gate."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates.decoder_ioc import check_decoder_ioc  # noqa: E402


class TestDecoderIocGate(unittest.TestCase):
    def test_live_tree_clean(self) -> None:
        self.assertEqual(check_decoder_ioc(), [])


class TestDecoderIocGatePositiveCases(unittest.TestCase):
    def _write(self, tree: str, rel: str, text: str) -> str:
        path = os.path.join(tree, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(text)
        return path

    def test_catches_bare_patternIocs_object(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', '_patternIocs: [{url:"https://evil.invalid/",severity:"high"}];\n')
            v = check_decoder_ioc(t)
            self.assertTrue(any('x.js' in vv and '_patternIocs emission must call DecoderIoc' in vv for vv in v))

    def test_accepts_DecoderIoc_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', '_patternIocs: DecoderIoc.pattern("https://good.invalid/", "high");\n')
            self.assertEqual(check_decoder_ioc(t), [])

    def test_catches_assignment_form(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', 'candidate._patternIocs = [{url:"x",severity:"high"}];\n')
            v = check_decoder_ioc(t)
            self.assertTrue(any('_patternIocs emission must call DecoderIoc' in vv for vv in v))

    def test_accepts_multiline_with_DecoderIoc_in_window(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', '_patternIocs:\n  DecoderIoc.patternList([ "https://a.invalid/" ])\n')
            self.assertEqual(check_decoder_ioc(t), [])

    def test_catches_inline_comment_spoof(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', '_patternIocs: [{url:"https://x.invalid/"}] // via DecoderIoc\n')
            v = check_decoder_ioc(t)
            self.assertTrue(any('_patternIocs emission must call DecoderIoc' in vv for vv in v))

    def test_catches_plain_patternIocs_push(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', 'patternIocs.push({url:"https://x.invalid/",severity:"high"});\n')
            v = check_decoder_ioc(t)
            self.assertTrue(any('_patternIocs emission must call DecoderIoc' in vv or 'forbidden' in vv for vv in v))

    def test_ignores_commented_emission(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', '// _patternIocs: bare emission\n')
            self.assertEqual(check_decoder_ioc(t), [])

    def test_catches_forbidden_bare_pushes(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', 'findings.interestingStrings.push({});\nfindings.externalRefs.push({});\npushIOC(f, {});\n')
            v = check_decoder_ioc(t)
            self.assertTrue(any('interestingStrings.push' in vv for vv in v))
            self.assertTrue(any('externalRefs.push' in vv for vv in v))
            self.assertTrue(any('pushIOC (use candidate' in vv for vv in v))

    def test_clean_compliant(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', '_patternIocs: [DecoderIoc.pattern("https://c2.invalid/")]\n')
            self.assertEqual(check_decoder_ioc(t), [])


if __name__ == '__main__':
    unittest.main()