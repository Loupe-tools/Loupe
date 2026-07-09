#!/usr/bin/env python3
"""Positive violation cases for build gates (synthetic fixtures under temp root)."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build.gates import (
    decoder_ioc,
    chokepoint_apis,
    renderer_ioc,
    pushioc_only,
    risk_pre_stamp,
    bare_ioc_types,
    raw_text_lf,
    worker_spawn,
    silent_catch,
    storage_access,
    extend_app,
    backtick_comment,
)
# dispatch_sync root threading is partial (complex manifest subcheck); covered in live + follow-up


class TestGateViolations(unittest.TestCase):
    def _write(self, tree: str, rel: str, text: str) -> str:
        path = os.path.join(tree, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(text)
        return path

    # decoder_ioc
    def test_decoder_ioc_catches_bare_pushioc(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', 'pushIOC(f, {type: "url", value: "https://x.invalid/"});\n')
            self.assertTrue(decoder_ioc.check_decoder_ioc(root=t))

    def test_decoder_ioc_catches_assignment_form(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', 'candidate._patternIocs = [{url:"x",severity:"high"}];\n')
            self.assertTrue(decoder_ioc.check_decoder_ioc(root=t))

    def test_decoder_ioc_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/decoders/x.js', '_patternIocs: DecoderIoc.pattern("https://x.invalid/", "high");\n')
            self.assertEqual(decoder_ioc.check_decoder_ioc(root=t), [])

    # risk pre stamp
    def test_risk_pre_stamp_catches_direct_risk_write(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'findings.risk = "high";\n')
            self.assertTrue(risk_pre_stamp.check_risk_pre_stamping(root=t))

    def test_risk_pre_stamp_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'escalateRisk(findings, "high");\n')
            self.assertEqual(risk_pre_stamp.check_risk_pre_stamping(root=t), [])

    # bare ioc types
    def test_bare_ioc_types_catches_string_type(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'pushIOC(f, {type: "url", value: "https://x.invalid/", severity: "high"});\n')
            self.assertTrue(bare_ioc_types.check_bare_ioc_types(root=t))

    def test_bare_ioc_types_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'pushIOC(f, {type: IOC.URL, value: "https://x.invalid/"});\n')
            self.assertEqual(bare_ioc_types.check_bare_ioc_types(root=t), [])

    # pushioc only
    def test_pushioc_only_catches_bare_findings_push(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'findings.interestingStrings.push({v:1});\n')
            self.assertTrue(pushioc_only.check_pushioc_only(root=t))

    def test_pushioc_only_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'pushIOC(f, {type: IOC.URL, value: "u"});\n')
            self.assertEqual(pushioc_only.check_pushioc_only(root=t), [])

    # raw text lf
    def test_raw_text_lf_catches_missing_lfNormalize(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'container._rawText = "a\\r\\nb";\n')
            self.assertTrue(raw_text_lf.check_raw_text_lf(root=t))

    def test_raw_text_lf_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'container._rawText = lfNormalize("a\\nb");\n')
            self.assertEqual(raw_text_lf.check_raw_text_lf(root=t), [])

    # worker spawn
    def test_worker_spawn_catches_new_worker_outside_allow(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'new Worker("blob:xxx");\n')
            self.assertTrue(worker_spawn.check_worker_spawn(root=t))

    def test_worker_spawn_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/worker-manager.js', 'new Worker(__BUNDLE__);\n')
            self.assertEqual(worker_spawn.check_worker_spawn(root=t), [])

    # silent catch
    def test_silent_catch_catches_empty_catch(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/app/app-load.js', 'try { x(); } catch(e) {}\n')
            self.assertTrue(silent_catch.check_silent_catch(root=t))

    def test_silent_catch_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/app/app-load.js', 'try { x(); } catch(e) { report(e); }\n')
            self.assertEqual(silent_catch.check_silent_catch(root=t), [])

    # storage
    def test_storage_access_catches_direct_localStorage(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'localStorage.setItem("k", "v");\n')
            self.assertTrue(storage_access.check_storage_access(root=t))

    def test_storage_access_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/storage.js', 'safeStorage.set("k","v");\n')
            self.assertEqual(storage_access.check_storage_access(root=t), [])

    # extend app
    def test_extend_app_catches_bare_object_assign_app_prototype(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'Object.assign(App.prototype, {foo(){}});\n')
            self.assertTrue(extend_app.check_extend_app(root=t))

    def test_extend_app_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/app/app-core.js', 'extendApp(App, {foo(){}});\n')
            self.assertEqual(extend_app.check_extend_app(root=t), [])

    # backtick comment
    def test_backtick_comment_catches_star_slash_in_backtick(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', '/*\n` a */ b `\n*/\n')
            self.assertTrue(backtick_comment.check_backtick_comment(root=t))

    def test_backtick_comment_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'const s = `/* ok */`;\n')
            self.assertEqual(backtick_comment.check_backtick_comment(root=t), [])

    # chokepoint (uses its walk)
    def test_chokepoint_catches_createobjecturl_outside(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/renderers/x.js', 'URL.createObjectURL(blob);\n')
            self.assertTrue(chokepoint_apis.check_chokepoint_apis(root=t))

    def test_chokepoint_clean(self):
        with tempfile.TemporaryDirectory() as t:
            self._write(t, 'src/file-download.js', 'URL.createObjectURL(b);\n')
            self.assertEqual(chokepoint_apis.check_chokepoint_apis(root=t), [])


if __name__ == '__main__':
    unittest.main()
