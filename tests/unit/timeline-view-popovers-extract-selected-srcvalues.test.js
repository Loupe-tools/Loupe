// timeline-view-popovers-extract-selected-srcvalues.test.js
//
// Extract Values dialog "Extract selected" — Auto-tab apply path.
//
// Background: the click handler at `[data-act="auto-extract"]` in
// `timeline-view-popovers.js` used to walk the user-ticked proposals in
// arbitrary `_selection` order and call `_addJsonExtractedColNoRender`
// / `_addRegexExtractNoRender` directly with NO `srcValues`. On a
// 100k-row CSV with several JSON-leaf picks all rooted at the same
// source column, that means N × rowCount calls into
// `_cellAt → RowStore.getCell → _decodeAsciiSlice` — the dominant cost
// in the Firefox profile (`_decodeAsciiSlice` ~18 s of a 21 s click,
// observed as a ~5 s page hang).
//
// Fix: mirror the silent best-effort apply pump (`applyStep` in
// `timeline-view-autoextract.js`):
//   (1) group `pick` by `sourceCol` into `bySource = new Map()` so
//       per-column decode work amortises across every proposal in the
//       group;
//   (2) per group, materialise the source column once into a
//       length-rowCount string array and thread it through
//       `_applyAutoProposal(p, srcValues)` — which forwards
//       `srcValues` to whichever helper handles the proposal kind;
//   (3) suppress per-call `_persistRegexExtracts()` for the duration
//       of the apply loop and call it ONCE at the end if any
//       regex-kind proposals were applied. Otherwise N regex picks =
//       N redundant localStorage writes.
//
// All assertions are static-text — pattern matches the
// `timeline-view-autoextract-srcvalues-cache.test.js` style and avoids
// stubbing the entire dataset/render pipeline.

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
const DRAWER = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-drawer.js'),
  'utf8'
);

// Narrow the file to the Auto-tab Extract-selected click handler so
// later tests can't be satisfied by some unrelated `Map` literal
// elsewhere in the popovers mixin (Manual-tab clicker, Add-Sus, etc).
function autoExtractHandlerSlice(src) {
  const start = src.indexOf('autoExtractBtn.addEventListener(\'click\'');
  assert.notEqual(start, -1,
    'expected `autoExtractBtn.addEventListener(\'click\', …)` in popovers');
  // Find the matching closing `});` — the handler body is short and
  // self-contained; scan for the first `\n    });\n` after start.
  const end = src.indexOf('\n    });\n', start);
  assert.notEqual(end, -1,
    'expected to locate the end of the autoExtractBtn click handler');
  return src.slice(start, end + 9);
}

const HANDLER = autoExtractHandlerSlice(POPOVERS);

// ── Grouping ───────────────────────────────────────────────────────────────

test('Extract-selected groups picks by sourceCol via insertion-ordered Map', () => {
  // Without grouping, each proposal triggers a fresh per-row
  // `_cellAt` walk over the source column. The Map preserves
  // insertion order so within-group rank survives the regrouping.
  assert.match(HANDLER, /const bySource = new Map\(\);/,
    'expected `bySource = new Map()` in the Auto-tab Extract-selected handler');
  assert.match(HANDLER,
    /for \(const p of pick\) \{[\s\S]*?bySource\.get\(p\.sourceCol\)/,
    'expected the bucket-fill loop to key on `p.sourceCol`');
});

// ── Per-group decode + threading ───────────────────────────────────────────

test('Extract-selected materialises the source column once per group', () => {
  // The fill is a tight `for (let i = 0; i < n; i++) srcValues[i] =
  // store.getCell(i, sourceCol);` — one decode pass that all proposals
  // in the bucket share. Anything that re-decodes per proposal
  // regresses to the legacy O(N·R) cost. (P3-H: the per-cell read was
  // hoisted from `this._cellAt` to `store.getCell` to skip the
  // dataset dispatch hop — `_autoExtractScan` only emits proposals
  // for base columns, so `sourceCol` is always in `[0, baseLen)` and
  // the extracted-col branch in `dataset.cellAt` is unreachable.)
  assert.match(HANDLER,
    /for \(const \[sourceCol, bucket\] of bySource\) \{[\s\S]*?const srcValues = new Array\(n\);[\s\S]*?const store = this\.store;\s*for \(let i = 0; i < n; i\+\+\) srcValues\[i\] = store\.getCell\(i, sourceCol\);/,
    'expected per-group `srcValues = new Array(n)` decoded via `store.getCell` (hoisted ref)');
});

test('Extract-selected dispatches each proposal via _applyAutoProposal(p, srcValues)', () => {
  // Reusing `_applyAutoProposal` keeps the dialog and the silent
  // best-effort pump on a single per-kind dispatch — a future
  // proposal kind only needs to touch `_applyAutoProposal`. Threading
  // `srcValues` is what makes the optimisation effective.
  assert.match(HANDLER,
    /this\._applyAutoProposal\(p, srcValues\);/,
    'expected `this._applyAutoProposal(p, srcValues)` inside the per-group loop');
});

// ── Persist batching ───────────────────────────────────────────────────────

test('Extract-selected wraps the apply loop in a _suppressRegexPersist gate', () => {
  // Set + finally-clear so an exception inside the loop can't leave
  // the flag stuck `true` on the view (which would silently break
  // future Manual-tab Regex extracts that DO want their persist call).
  assert.match(HANDLER,
    /this\._suppressRegexPersist = true;/,
    'expected `this._suppressRegexPersist = true` before the apply loop');
  assert.match(HANDLER,
    /\}\s*finally\s*\{\s*this\._suppressRegexPersist = false;\s*\}/,
    'expected `_suppressRegexPersist = false` cleared in a `finally` block');
});

test('Extract-selected calls _persistRegexExtracts() exactly once after the loop', () => {
  // One persist for every regex-kind pick combined. Gated on
  // `sawRegex` so a pure-JSON pick set doesn't write the file's
  // regex-list back to localStorage unnecessarily.
  assert.match(HANDLER,
    /if \(sawRegex\) \{[\s\S]*?this\._persistRegexExtracts\(\);/,
    'expected a single `_persistRegexExtracts()` call gated on `sawRegex` after the loop');
});

// ── Drawer side: helper honours the suppression flag ──────────────────────

test('_addRegexExtractNoRender skips the persist when _suppressRegexPersist is set', () => {
  // The dialog can only batch the persist if the helper actually
  // checks the flag. Direct callers (Manual-tab Regex Extract,
  // persisted-regex replay, drawer pick) leave the flag falsy and
  // get the per-call persist behaviour unchanged.
  assert.match(DRAWER,
    /if \(!this\._suppressRegexPersist\) this\._persistRegexExtracts\(\);/,
    'expected `_addRegexExtractNoRender` to gate `_persistRegexExtracts()` on `!this._suppressRegexPersist`');
});
