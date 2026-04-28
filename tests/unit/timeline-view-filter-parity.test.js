'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-filter-parity.test.js — pin the B2c split.
//
// B2c hoists the 14-method filter + chart-data pipeline out of
// `timeline-view.js` into `timeline-view-filter.js`. The mixin
// attaches them via `Object.assign(TimelineView.prototype, {...})`.
//
// Pins:
//   • each method's `methodName(args) {` definition is GONE from
//     `timeline-view.js` (call sites `this.methodName(...)` are
//     unaffected by the indentation-anchored regex)
//   • each method appears EXACTLY once in
//     `timeline-view-filter.js`
//   • the `_computeChartData` hot loop survives byte-identical
//     (perf-critical — chart paint depends on it)
//   • build order: filter mixin loads after timeline-view.js
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const VIEW = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view.js'),
  'utf8',
);
const MIXIN = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-filter.js'),
  'utf8',
);
const BUILD = fs.readFileSync(
  path.join(REPO_ROOT, 'scripts/build.py'),
  'utf8',
);

const FILTER_METHODS = [
  '_parseAllTimestamps', '_computeDataRange',
  '_applyQueryString', '_recomputeFilter',
  '_susMarksResolved', '_rebuildSusBitmap', '_rebuildDetectionBitmap',
  '_applyWindowOnly',
  '_computeColumnStatsSync', '_computeColumnStatsAsync',
  '_distinctValuesFor', '_indexIgnoringColumn',
  '_bucketMs', '_computeChartData',
];

// ── Removal asserts ────────────────────────────────────────────────────────

test('timeline-view.js no longer defines any filter-pipeline method', () => {
  for (const name of FILTER_METHODS) {
    // Match `  methodName(` at start of line, indented EXACTLY two
    // spaces — the original definition shape inside `class TimelineView`.
    // A call site (`this.methodName(`) is indented further, so this
    // regex distinguishes definitions from callers.
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      VIEW,
      re,
      `${name} must be moved to timeline-view-filter.js (no class-method definition left in timeline-view.js)`,
    );
  }
});

// ── Presence asserts ───────────────────────────────────────────────────────

test('timeline-view-filter.js attaches via Object.assign(TimelineView.prototype, ...)', () => {
  assert.match(
    MIXIN,
    /Object\.assign\(\s*TimelineView\.prototype\s*,\s*\{/,
    'mixin must use `Object.assign(TimelineView.prototype, {...})`',
  );
});

test('timeline-view-filter.js defines every filter-pipeline method exactly once', () => {
  for (const name of FILTER_METHODS) {
    // Object-literal shorthand inside the mixin: `  methodName(` at
    // start of line indented two spaces.
    const re = new RegExp(`^  ${name}\\s*\\(`, 'gm');
    const matches = MIXIN.match(re) || [];
    assert.equal(
      matches.length,
      1,
      `${name} must appear exactly once in timeline-view-filter.js (got ${matches.length})`,
    );
  }
});

// ── Body anchors — perf-critical hot loops survive byte-identical ──────────

test('_computeChartData hot loop survives byte-identical', () => {
  // The bucketer's main loop body — if a refactor flipped any of these
  // lines, chart paint would silently break (empty chart, or wrong
  // bucket counts).
  assert.match(
    MIXIN,
    /for \(let i = 0; i < idx\.length; i\+\+\) \{\s*\n\s*const di = idx\[i\];\s*\n\s*const t = times\[di\];/,
    '_computeChartData main bucket loop body is missing or modified',
  );
  // The sus-bucket overlay loop — gated on `_susAny && _susBitmap &&
  // predicateIdx === _filteredIdx`. If this conditional changes, sus
  // overlay disappears or paints on the wrong predicate.
  assert.match(
    MIXIN,
    /this\._susAny && this\._susBitmap && predicateIdx === this\._filteredIdx/,
    '_computeChartData susBuckets gating expression has changed',
  );
});

test('_recomputeFilter identity-index fast path survives', () => {
  // Identity index reuse is a 4 MB allocation savings on 1 M rows;
  // pin it so a careless rewrite doesn't reintroduce the per-call
  // allocation.
  assert.match(
    MIXIN,
    /if \(!this\._identityIdx \|\| this\._identityIdx\.length !== n\)/,
    '_recomputeFilter identity-index reuse is missing',
  );
});

test('_applyWindowOnly cancels pending column-stats rAF', () => {
  // The cancellation prevents a wasted ~50 K-row chunk per filter
  // keystroke — pin so a future revert lights up.
  assert.match(
    MIXIN,
    /cancelAnimationFrame\(this\._colStatsRaf\)/,
  );
});

// ── Build order ────────────────────────────────────────────────────────────

test('scripts/build.py registers timeline-view-filter.js after timeline-view.js', () => {
  const viewIdx = BUILD.indexOf("'src/app/timeline/timeline-view.js'");
  const filterIdx = BUILD.indexOf("'src/app/timeline/timeline-view-filter.js'");
  assert.notEqual(viewIdx, -1);
  assert.notEqual(filterIdx, -1);
  assert.ok(filterIdx > viewIdx, 'filter mixin must load AFTER timeline-view.js');
});

// ── TimelineDataset invariant — moved bodies still respect dataset ─────────

test('moved filter bodies still read parallel arrays via this._timeMs / this.store (no _evtxEvents leakage)', () => {
  // The B1 invariant tests in `timeline-dataset.test.js` cover the
  // canonical paths. This test adds a B2c-specific check: the moved
  // filter pipeline must continue to read `this._timeMs` directly
  // (the typed-array slot the constructor allocates) — that's the
  // intentional shape, NOT a regression. Pin that the moved file
  // doesn't accidentally inline a `this._dataset.timeMs` round-trip
  // (would be slower) or `this._evtxEvents` (would be wrong).
  // Strip comments to avoid matching this test's own explanation.
  const stripped = MIXIN
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
    .replace(/`[\s\S]*?`/g, '``')
    .replace(/"[^"\n]*"/g, '""')
    .replace(/'[^'\n]*'/g, "''");
  // The moved methods must NOT touch `_evtxEvents` directly — the
  // bodies use `this.store` and `this._timeMs` exclusively, plus the
  // cached `_filteredIdx` etc. A bare `this._evtxEvents` reference
  // would be a new code smell (B1 migration).
  assert.doesNotMatch(
    stripped,
    /this\._evtxEvents\b/,
    'timeline-view-filter.js must not read this._evtxEvents — use the dataset / store',
  );
});
