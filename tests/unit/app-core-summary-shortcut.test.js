// app-core-summary-shortcut.test.js
//
// Global Ctrl/Cmd+Enter shortcut → fires the ⚡ Summary toolbar button.
//
// Why a static-text test: the global keydown listener in
// `app-core.js` is attached inside `_setup()` to `document` and reads
// `viewer-toolbar` / `btn-copy-analysis` from the live DOM. Reproducing
// that wiring at runtime would need a near-complete `App` boot. Mirror
// the static-assert style used elsewhere in tests/unit (e.g.
// `timeline-view-popovers-extract-selected-srcvalues.test.js`) and pin
// the contract by source-text inspection — invariants we MUST keep
// stable for the keybind to remain "first class":
//
//   1. The branch is OUTSIDE/ABOVE the input-or-modifier early-return
//      so it fires from focused inputs/textareas too.
//   2. It guards on `e.ctrlKey || e.metaKey` (Mac uses Cmd) and
//      `e.key === 'Enter'`, with NO `shiftKey` / `altKey` qualifiers
//      mixing in (so the user gets a clean Ctrl+Enter, not Ctrl+Shift+
//      Enter, etc.).
//   3. It no-ops when the viewer toolbar is hidden (no file loaded),
//      to avoid silent clipboard writes on the drop-zone.
//   4. It forwards to `#btn-copy-analysis` via `.click()` rather than
//      calling `_copyAnalysis()` directly — keeps disabled-state and
//      future button-level decoration on a single path.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const APP_CORE = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'app-core.js'),
  'utf8'
);

// Slice from the document.addEventListener('keydown', …) inside _setup
// so unrelated modifier-key handling elsewhere in the file (e.g. drag
// guards) can't satisfy the regex.
function globalKeydownSlice(src) {
  const anchor = src.indexOf("document.addEventListener('keydown'");
  assert.notEqual(anchor, -1,
    'expected `document.addEventListener(\'keydown\', …)` in app-core.js');
  // Handler body fits within ~50 lines.
  const end = src.indexOf('\n    });\n', anchor);
  assert.notEqual(end, -1,
    'expected to locate the end of the global keydown handler');
  return src.slice(anchor, end + 9);
}

const KEYDOWN = globalKeydownSlice(APP_CORE);

test('global keydown handler matches Ctrl/Cmd+Enter', () => {
  assert.match(KEYDOWN, /\(e\.ctrlKey \|\| e\.metaKey\) && e\.key === 'Enter'/,
    'expected `(e.ctrlKey || e.metaKey) && e.key === \'Enter\'` guard');
  // No shift/alt mixed in — Ctrl+Enter is the canonical chord.
  assert.match(KEYDOWN, /e\.key === 'Enter' && !e\.altKey && !e\.shiftKey/,
    'expected !shiftKey && !altKey qualifiers so the chord is clean');
});

test('Ctrl+Enter branch sits ABOVE the input-or-modifier early return', () => {
  // The single-letter shortcuts (S/Y/N/F/…) are gated by an early-return
  // on `INPUT|TEXTAREA|altKey|ctrlKey|metaKey`. Ctrl+Enter must be
  // matched BEFORE that guard so it fires from any focused field.
  const ctrlEnterIdx = KEYDOWN.indexOf("e.key === 'Enter'");
  const earlyReturnIdx = KEYDOWN.indexOf("e.target.tagName === 'INPUT'");
  assert.notEqual(ctrlEnterIdx, -1, 'Ctrl+Enter branch missing');
  assert.notEqual(earlyReturnIdx, -1, 'INPUT/TEXTAREA early-return missing');
  assert.ok(ctrlEnterIdx < earlyReturnIdx,
    'Ctrl+Enter branch must precede the input/modifier early-return');
});

test('Ctrl+Enter is a no-op when viewer toolbar is hidden', () => {
  // Branch must read `#viewer-toolbar` and bail when missing or
  // `.hidden`. Otherwise hitting the chord on the drop-zone would
  // silently clipboard-write garbage.
  assert.match(KEYDOWN,
    /document\.getElementById\('viewer-toolbar'\)[\s\S]*?classList\.contains\('hidden'\)/,
    'expected viewer-toolbar hidden guard inside the Ctrl+Enter branch');
});

test('Ctrl+Enter forwards via #btn-copy-analysis click', () => {
  // We forward to `.click()` on the actual toolbar button so future
  // button-level state (disabled, focus ring, telemetry) lives in one
  // place. Calling `_copyAnalysis()` directly would bypass that.
  assert.match(KEYDOWN,
    /getElementById\('btn-copy-analysis'\)[\s\S]*?\.click\(\)/,
    'expected `#btn-copy-analysis` click forwarder');
  // And the branch must call preventDefault so the chord doesn't bubble
  // (e.g. into a textarea where Ctrl+Enter could otherwise insert a
  // newline depending on the field).
  assert.match(KEYDOWN, /e\.preventDefault\(\)/,
    'Ctrl+Enter branch must call preventDefault');
});

test('toolbar button title advertises the shortcut', () => {
  // The HTML for `#btn-copy-analysis` lives in scripts/build.py. Pin
  // the title text so a future toolbar reshuffle keeps users
  // discoverable of the new keybind.
  const BUILD = readFileSync(
    join(__dirname, '..', '..', 'scripts', 'build.py'),
    'utf8'
  );
  assert.match(BUILD,
    /id="btn-copy-analysis"[^>]*title="[^"]*Ctrl\+Enter[^"]*"/,
    'expected #btn-copy-analysis title to mention Ctrl+Enter');
});

test('Help tab lists the Ctrl+Enter shortcut', () => {
  // Discoverability surface — analysts hit `?` / `H` to see the full
  // table.
  const SETTINGS = readFileSync(
    join(__dirname, '..', '..', 'src', 'app', 'app-settings.js'),
    'utf8'
  );
  assert.match(SETTINGS, /<kbd class="help-kbd">Ctrl\+Enter<\/kbd>/,
    'expected a Ctrl+Enter row in the Help tab keyboard table');
});
