'use strict';
// timeline-view-filter-p3b-incremental-stats.test.js — pin the P3-B
// incremental column-stats path.
//
// Background: `_computeColumnStatsAsync` historically ran over ALL
// columns × ALL filtered rows whenever `_colStats` was null. Every
// time the auto-extract apply pump appended a new column it called
// `_recomputeFilter` → `_applyWindowOnly`, which blanket-nulled
// `_colStats`. So the post-pump terminus paid for a full O(rows×cols)
// recompute, even though only the newly-extracted columns were
// missing — base + already-existing extracted column stats were
// still valid because `_filteredIdx` hadn't changed in content.
//
// P3-B adds:
//   • `_applyWindowOnly` snapshots `_colStatsIdxRef = _filteredIdx`
//     and ONLY nulls `_colStats` when the index reference has
//     actually changed (i.e. a real filter / window change). When
//     it's identity-stable (the common case during a pump:
//     `_filteredIdx === _identityIdx`), `_colStats` is preserved.
//   • `_extendColumnStatsAsync(idx, fromCol, generation)` is a thin
//     wrapper around `_computeColumnStatsAsyncInternal(idx, gen,
//     fromCol, toCol)` that returns stats for ONLY the new column
//     range, ready to be appended onto the existing `_colStats`.
//   • The rAF 'columns' task in timeline-view.js detects the
//     `_colStats.length < this.columns.length` case and routes
//     through the extension path instead of a full recompute.

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const FILTER_SRC = fs.readFileSync(
  path.resolve(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-filter.js'),
  'utf8',
);
const VIEW_SRC = fs.readFileSync(
  path.resolve(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view.js'),
  'utf8',
);

// ── _applyWindowOnly preserves stats when filter is identity-stable ─

test('filter P3-B: _applyWindowOnly tracks _colStatsIdxRef for incremental reuse', () => {
  // The reference snapshot — set every time the function runs so
  // subsequent calls can compare and detect a real change.
  assert.match(FILTER_SRC, /this\._colStatsIdxRef\s*=\s*this\._filteredIdx\s*;/,
    '_applyWindowOnly must snapshot `this._filteredIdx` into `_colStatsIdxRef`');
});

test('filter P3-B: _colStats is preserved when filteredIdx is identity-stable', () => {
  // The "skip null" branch — keep `_colStats` if the previous index
  // ref matches the current one AND the existing stats array is no
  // longer than the current column count (i.e. only appended cols).
  assert.match(FILTER_SRC, /const\s+filterStable\s*=\s*!!this\._colStats[\s\S]+?prevIdxRef\s*===\s*this\._filteredIdx[\s\S]+?this\._colStats\.length\s*<=\s*this\.columns\.length\s*;/,
    '_applyWindowOnly must declare a `filterStable` predicate that combines ref-equality + col-count ≤');
  assert.match(FILTER_SRC, /if \(!filterStable\) \{\s*\n\s*this\._colStats\s*=\s*null;\s*\n\s*\}/,
    '_applyWindowOnly must only null `_colStats` when filterStable is false');
});

// ── _extendColumnStatsAsync exists with the documented shape ────────

test('filter P3-B: _extendColumnStatsAsync(idx, fromCol, generation) exists', () => {
  assert.match(FILTER_SRC, /_extendColumnStatsAsync\(idx,\s*fromCol,\s*generation\)\s*\{/,
    'expected `_extendColumnStatsAsync(idx, fromCol, generation) { ... }` mixin method');
});

test('filter P3-B: extension path delegates to _computeColumnStatsAsyncInternal with [fromCol, toCol)', () => {
  // Both `_extendColumnStatsAsync` and `_computeColumnStatsAsync`
  // delegate to the shared internal that takes a column range —
  // this is what makes the per-column slicing work without
  // duplicating the chunked-yield body.
  assert.match(FILTER_SRC, /_computeColumnStatsAsyncInternal\(idx,\s*generation,\s*fromCol,\s*this\.columns\.length\)/,
    '_extendColumnStatsAsync must delegate to _computeColumnStatsAsyncInternal with the full column count as toCol');
  assert.match(FILTER_SRC, /_computeColumnStatsAsyncInternal\(idx,\s*generation,\s*0,\s*this\.columns\.length\)/,
    '_computeColumnStatsAsync must delegate with fromCol=0 (compute all columns)');
});

test('filter P3-B: internal computes only [fromCol, toCol) into a span-sized stats array', () => {
  // The internal is the only place that actually iterates rows × cols.
  // Pin: it computes a `span = toCol - fromCol` and allocates a
  // span-sized stats array (NOT cols-sized, which would index
  // out-of-bounds when fromCol > 0).
  assert.match(FILTER_SRC, /const\s+span\s*=\s*toCol\s*-\s*fromCol\s*;/,
    'internal must declare `const span = toCol - fromCol;`');
  assert.match(FILTER_SRC, /const\s+stats\s*=\s*new\s+Array\(span\)\s*;/,
    'internal must allocate `stats = new Array(span)` (span-sized, not cols-sized)');
  assert.match(FILTER_SRC, /for \(let c = fromCol;\s*c < toCol;\s*c\+\+\)/,
    'internal must iterate `for (let c = fromCol; c < toCol; c++)` over the requested range');
});

test('filter P3-B: the per-row inner loop indexes stats by `c - fromCol`', () => {
  // Inside the inner column loop the stat Map is at `stats[c - fromCol]`
  // because `stats` is span-sized. If a refactor reverts to `stats[c]`
  // the extension path silently writes past the end (or starts
  // reading garbage on the second extension).
  assert.match(FILTER_SRC, /stats\[c - fromCol\]/,
    'inner loop must index stats with `c - fromCol`, not `c`');
});

// ── rAF 'columns' task routes to the extension path on append ───────

test('view P3-B: rAF columns task takes the extension path when stats exist but cols grew', () => {
  // The rAF body must check `this._colStats && this._colStats.length
  // < totalCols` and call `_extendColumnStatsAsync(idx, fromCol, gen)`
  // with `fromCol = this._colStats.length`.
  assert.match(VIEW_SRC, /if \(this\._colStats && this\._colStats\.length < totalCols\) \{/,
    'rAF columns task must branch on `_colStats.length < totalCols`');
  assert.match(VIEW_SRC, /const\s+fromCol\s*=\s*this\._colStats\.length\s*;/,
    'rAF columns task must derive `fromCol` from the existing stats length');
  assert.match(VIEW_SRC, /this\._extendColumnStatsAsync\(idx,\s*fromCol,\s*gen\)/,
    'rAF columns task must call `_extendColumnStatsAsync(idx, fromCol, gen)`');
});

test('view P3-B: extension result is appended onto the existing _colStats in place', () => {
  // The append loop must mutate the existing array (NOT replace it),
  // otherwise downstream readers holding a reference to the old
  // array see stale data.
  assert.match(VIEW_SRC, /for \(let c = 0; c < result\.length; c\+\+\) this\._colStats\.push\(result\[c\]\)\s*;/,
    'rAF columns task must push extension results onto the existing `_colStats`, not replace it');
});

test('view P3-B: full-recompute branch is preserved as the cold fallback', () => {
  // When `_colStats` is null entirely (real filter change, store
  // swap, view reset) we still go through the legacy path. Pin
  // both the sync (small) and async (large) branches.
  assert.match(VIEW_SRC, /if \(!this\._colStats\) \{/,
    'rAF columns task must keep the cold-path `if (!this._colStats)` branch');
  assert.match(VIEW_SRC, /this\._computeColumnStatsAsync\(idx,\s*gen\)\.then/,
    'rAF columns task must keep the full-recompute call to _computeColumnStatsAsync');
  assert.match(VIEW_SRC, /this\._computeColumnStatsSync\(idx\)/,
    'rAF columns task must keep the small-dataset _computeColumnStatsSync call');
});
