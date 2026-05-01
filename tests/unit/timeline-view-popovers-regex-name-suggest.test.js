// timeline-view-popovers-regex-name-suggest.test.js
//
// Manual Regex extract dialog — auto-suggested column-name placeholder.
//
// Background: the Name field's static placeholder used to be the literal
// string "auto", and the only path that wrote a real placeholder was
// `handlePick()` (click-to-pick). Hand-typing a regex left the placeholder
// stale, so the user saw "auto" while the Extract handler quietly fell
// back to `${colName} (regex)` — i.e. the field never matched the saved
// column name. The user reported this directly.
//
// The fix introduces a `_suggestRegexName()` closure that derives a name
// from (in order):
//   1. preset-pattern match → preset label
//   2. last click-pick classifier label → `<col>.<label>`
//   3. consensus class of capture-group values from the live preview
//      (this is what gives a hand-typed pattern a sensible name)
//   4. leading literal token sniffed from the pattern → `<col>.<token>`
//   5. fallback `<col>.regex`
// `refreshSuggestedName()` writes the result to `nameEl.placeholder`, and
// the Extract click handler now uses the placeholder as a fallback before
// the legacy `${colName} (regex)` sentinel.
//
// Sibling refactor: the standalone "Test" button was removed (its only
// useful role was forcing a re-run after a preset change — handled
// directly by the preset handler now), and the preset handler explicitly
// calls `runTest()` so the preview + name suggestion update together.
//
// Static-text assertions only — same style as
// `timeline-view-popovers-extract-selected-srcvalues.test.js`.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const POPOVERS = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-popovers.js'),
  'utf8'
);

// ── Helper presence ────────────────────────────────────────────────────────

test('_suggestRegexName helper is defined inside the regex dialog', () => {
  assert.match(POPOVERS, /const _suggestRegexName = \(\) => \{/,
    'expected `const _suggestRegexName = () => {` closure helper');
});

test('refreshSuggestedName writes only to nameEl.placeholder', () => {
  // Crucial invariant: the helper never sets `.value`, so a name the
  // user typed can't be clobbered by a later refresh.
  assert.match(POPOVERS,
    /const refreshSuggestedName = \(\) => \{\s*try \{ nameEl\.placeholder = _suggestRegexName\(\); \}/,
    'expected refreshSuggestedName → nameEl.placeholder = _suggestRegexName()');
  // Negative: no programmatic `nameEl.value = …` writes (preset / pick
  // / refresh must use placeholder only). Strip line comments first so
  // the explanatory comment in the closure prelude doesn't trip us.
  const stripped = POPOVERS.replace(/\/\/[^\n]*/g, '');
  assert.equal((stripped.match(/nameEl\.value\s*=[^=]/g) || []).length, 0,
    'no code path may assign to nameEl.value');
});

// ── Resolution-order branches ─────────────────────────────────────────────

test('suggestion order: preset match → preset label', () => {
  assert.match(POPOVERS,
    /for \(const p of TL_REGEX_PRESETS\) \{\s*if \(p\.pattern === pattern && \(p\.flags \|\| ''\) === flags\) return p\.label;/,
    'expected preset-pattern match branch returning preset label');
});

test('suggestion order: click-pick label → `<col>.<label>`', () => {
  assert.match(POPOVERS,
    /if \(_lastPickLabel\) \{\s*return `\$\{colName\}\.\$\{_lastPickLabel\.replace\(\/\\s\+\/g, '_'\)\}`;/,
    'expected last-pick-label branch using <col>.<label>');
});

test('suggestion order: consensus capture-class from preview', () => {
  assert.match(POPOVERS, /const _consensusCaptureLabel = \(caps\) => \{/,
    'expected `_consensusCaptureLabel` helper');
  assert.match(POPOVERS,
    /const consensus = _consensusCaptureLabel\(_lastCapturedPreview\);\s*if \(consensus\) return `\$\{colName\}\.\$\{consensus/,
    'expected consensus branch using <col>.<consensus>');
});

test('suggestion order: leading-literal token sniffed from pattern', () => {
  assert.match(POPOVERS, /const _sniffPatternToken = \(src\) => \{/,
    'expected `_sniffPatternToken` helper');
  assert.match(POPOVERS,
    /const tok = _sniffPatternToken\(pattern\);\s*if \(tok\) return `\$\{colName\}\.\$\{tok\}`;/,
    'expected token-sniff branch using <col>.<token>');
});

test('suggestion fallback: <col>.regex', () => {
  // The legacy `<col> (regex)` form is preserved only as the final
  // safety-net inside the Extract click handler — the helper itself
  // returns the dotted form.
  assert.match(POPOVERS, /return `\$\{colName\}\.regex`;/,
    'expected `<col>.regex` fallback inside _suggestRegexName');
});

// ── Wiring ─────────────────────────────────────────────────────────────────

test('runTest feeds _lastCapturedPreview and refreshes suggestion', () => {
  // The successful tail of runTest must (a) snapshot captured strings
  // for the consensus branch and (b) re-run refreshSuggestedName.
  assert.match(POPOVERS,
    /_lastCapturedPreview = hits\.map\(h => h\.cap\);\s*refreshSuggestedName\(\);/,
    'expected runTest tail to update _lastCapturedPreview + refreshSuggestedName');
  // Each early return must also clear the cache and refresh — otherwise
  // a stale capture-class consensus survives an invalid pattern.
  assert.ok(
    POPOVERS.split('_lastCapturedPreview = []').length >= 4,
    'expected `_lastCapturedPreview = []` cleared in every runTest early-return path');
});

test('handlePick records classifier label instead of writing placeholder', () => {
  assert.match(POPOVERS, /_lastPickLabel = cls\.label \|\| '';/,
    'expected handlePick to set _lastPickLabel from the classifier');
  // Negative: the inline `nameEl.placeholder = …` write that handlePick
  // used to do is gone — placeholder is now driven solely by refreshSuggestedName.
  assert.doesNotMatch(POPOVERS,
    /nameEl\.placeholder = `\$\{colName\}\.\$\{cls\.label/,
    'handlePick must no longer write to nameEl.placeholder directly');
});

test('column change clears the click-pick label', () => {
  // `<col>.<label>` is column-scoped — switching columns must invalidate
  // the stored pick so a stale hint cannot bleed across columns.
  assert.match(POPOVERS,
    /colSel\.addEventListener\('change', \(\) => \{\s*_lastPickLabel = '';/,
    'expected colSel change handler to reset _lastPickLabel');
});

test('preset change calls runTest (live preview + name refresh)', () => {
  // Pre-fix bug: `nameEl.value = p.label` + no runTest left the preview
  // stale until the next keystroke, AND the preset label only landed in
  // .value (clobbering anything the user typed). The new handler clears
  // the pick label and re-runs the preview so suggestion + status update
  // together.
  assert.match(POPOVERS,
    /presetSel\.addEventListener\('change', \(\) => \{[\s\S]{0,800}_lastPickLabel = '';[\s\S]{0,800}runTest\(\);[\s\S]{0,80}\}\s*\}\);/,
    'expected preset handler to clear _lastPickLabel and call runTest');
});

// ── Removed Test button ────────────────────────────────────────────────────

test('the standalone Test button is gone', () => {
  // Functionality is now covered by the live preview + preset handler;
  // the button was redundant for every input that already fired
  // `runTestDebounced` and confusing for users who didn't realise
  // typing was enough.
  assert.doesNotMatch(POPOVERS, /data-act="regex-test"/,
    'expected `data-act="regex-test"` button + listener to be removed');
  assert.doesNotMatch(POPOVERS, />Test</,
    'expected the visible "Test" button label to be gone');
});

// ── Extract click handler — placeholder fallback ──────────────────────────

test('Extract click falls back to nameEl.placeholder before legacy sentinel', () => {
  // The fallback chain is now: user value → suggested placeholder →
  // legacy "<col> (regex)". Without the placeholder leg the saved name
  // wouldn't match what the user saw in the field.
  assert.match(POPOVERS,
    /const suggested = \(nameEl\.placeholder \|\| ''\)\.trim\(\);\s*const name = \(nameEl\.value \|\| ''\)\.trim\(\)\s*\|\| suggested\s*\|\| `\$\{colName\} \(regex\)`;/,
    'expected user-value → placeholder → legacy "(regex)" fallback chain');
});

// ── Initial-paint contract ────────────────────────────────────────────────

test('dialog open seeds the Name placeholder', () => {
  // Without an initial refresh the user opens the dialog and sees the
  // literal static placeholder ("auto") until they interact with it.
  assert.match(POPOVERS,
    /renderClickerSamples\(\);\s*refreshSuggestedName\(\);\s*\},/,
    'expected refreshSuggestedName() called once at end of dialog open');
});
