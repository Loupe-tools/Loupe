// timeline-view-extract-colstats-extend.test.js
//
// Cold-cache extend path for the Extract Values dialog (Auto tab →
// Extract Selected). The post-click async tail used to run a full
// O(rows × totalCols) `_computeColumnStatsAsync` sweep — ~1.4 s on a
// 100k-row CSV. The fix:
//
//   1. The dialog's click handler stamps `this._colStatsExtractAdvance`
//      with the count of newly-appended extracted columns just before
//      `_rebuildExtractedStateAndRender`.
//   2. The 'columns' render task in `timeline-view.js` reads the hint.
//      When `_colStats` is null AND `advance > 0`, it computes stats
//      synchronously for the trailing `advance` columns only (small
//      slice; extracted-col reads are O(1) per row from the
//      pre-materialised `values` array), seeds a sparse `_colStats`,
//      and re-renders. The base-col stats fill in via a follow-up
//      `_computeColumnStatsAsyncInternal(idx, gen, 0, baseEnd)` call.
//   3. The hint is consumed exactly once — every branch of the render
//      task clears it so a future cold cache without an extract-apply
//      hint takes the legacy full sweep.
//   4. `_computeColumnStatsSync` accepts an optional `(fromCol, toCol)`
//      range and returns parallel stats for `[fromCol, toCol)`,
//      mirroring `_computeColumnStatsAsyncInternal`'s contract.
//
// Static-text pins on the source files — no view bootstrap. Matches the
// style of `timeline-view-autoextract-srcvalues-cache.test.js` and the
// sibling popovers test.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const VIEW = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view.js'),
  'utf8'
);
const FILTER = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-filter.js'),
  'utf8'
);
const POPOVERS = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-popovers.js'),
  'utf8'
);

// ── Constructor initialises the hint slot ──────────────────────────────────

test('TimelineView constructor initialises _colStatsExtractAdvance to 0', () => {
  // Without an explicit init, the first read in the 'columns' render
  // task would be `undefined | 0 === 0` (still safe), but pinning the
  // explicit init makes intent clear and prevents a future refactor
  // from accidentally tripping a `typeof === 'undefined'` test.
  assert.match(VIEW, /this\._colStatsExtractAdvance = 0;/,
    'expected `this._colStatsExtractAdvance = 0` in constructor');
});

// ── Dialog click handler stamps the hint ───────────────────────────────────

test('Extract-selected click handler stamps _colStatsExtractAdvance with `added`', () => {
  // The hint MUST be set BEFORE `_rebuildExtractedStateAndRender` so
  // the 'columns' render task scheduled inside the rebuild can read
  // it. The conditional gate (`added > 0`) avoids stamping when every
  // pick was a duplicate (no structural change → don't perturb the
  // legacy render flow).
  assert.match(POPOVERS,
    /if \(added > 0\) this\._colStatsExtractAdvance = added;\s*this\._rebuildExtractedStateAndRender\(\);/,
    'expected `_colStatsExtractAdvance = added` set immediately before `_rebuildExtractedStateAndRender()`');
});

// ── Render task: cold-cache + advance branch ───────────────────────────────

test('columns render task has a cold-cache extract-apply branch', () => {
  // The branch is gated on `!_colStats && advance > 0 && advance <= totalCols`.
  // Anything else would either (a) trigger when the warm extend path
  // should have, or (b) try to compute a slice larger than the column
  // set (which would deadlock on `baseEnd === totalCols - advance`
  // going negative). Pin all three conjuncts.
  assert.match(VIEW,
    /const advance = this\._colStatsExtractAdvance \| 0;\s*if \(!this\._colStats && advance > 0 && advance <= totalCols\)/,
    'expected gate `!_colStats && advance > 0 && advance <= totalCols`');
});

test('cold-cache extract-apply branch computes the trailing slice synchronously', () => {
  // The branch calls `_computeColumnStatsSync(idx, baseEnd, totalCols)`
  // — a range form of the sync helper that returns stats for
  // `[baseEnd, totalCols)` only. `baseEnd` is `totalCols - advance`.
  // Synchronous because:
  //   (a) the slice is small (advance × rowCount cell reads on
  //       extracted cols, which are O(1) array indexes, NOT the
  //       O(rowCount × bytes-per-cell) ASCII decode the base-col path
  //       pays);
  //   (b) the user explicitly requested these columns, so seeing the
  //       new cards paint immediately is the highest-value feedback.
  assert.match(VIEW,
    /const baseEnd = totalCols - advance;[\s\S]*?this\._computeColumnStatsSync\(idx, baseEnd, totalCols\)/,
    'expected `_computeColumnStatsSync(idx, baseEnd, totalCols)` for the trailing slice');
});

test('cold-cache branch seeds sparse _colStats and renders', () => {
  // Renderer at `_paintColumnCards` (line 599 of timeline-view-render-grid.js)
  // tolerates missing entries via
  // `(stats && stats[c]) || { total: 0, distinct: 0, values: [] }`.
  // Seeding `new Array(totalCols)` and only filling
  // `[baseEnd, totalCols)` lets the new column cards paint while base
  // cards show empty placeholders (which fill in once the async
  // base-col sweep resolves).
  assert.match(VIEW,
    /const seeded = new Array\(totalCols\);[\s\S]*?seeded\[baseEnd \+ c\] = newColsSlice\[c\];/,
    'expected sparse `seeded = new Array(totalCols)` filled at `[baseEnd, totalCols)`');
  assert.match(VIEW, /this\._colStats = seeded;\s*this\._renderColumns\(\);/,
    'expected `_colStats = seeded; _renderColumns()` immediately after the slice computes');
});

test('cold-cache branch schedules base-col fill async', () => {
  // The base-col follow-up uses `_computeColumnStatsAsyncInternal`
  // restricted to `[0, baseEnd)`. Same generation contract as the
  // legacy path — a newer filter mid-sweep returns null and we bail.
  // Splicing in place preserves the trailing extracted-col stats
  // computed synchronously above.
  assert.match(VIEW,
    /this\._computeColumnStatsAsyncInternal\(idx, gen, 0, baseEnd\)/,
    'expected base-col follow-up to call `_computeColumnStatsAsyncInternal(idx, gen, 0, baseEnd)`');
  assert.match(VIEW,
    /for \(let c = 0; c < result\.length; c\+\+\) \{\s*this\._colStats\[c\] = result\[c\];\s*\}\s*this\._renderColumns\(\);/,
    'expected in-place splice into `_colStats[c]` (preserving trailing slots) followed by `_renderColumns()`');
});

test('cold-cache branch consumes the hint exactly once', () => {
  // Three branches in the columns render task — warm extend, cold
  // extract-apply, full sweep — must each clear `_colStatsExtractAdvance`
  // so a stale hint can't trigger an unintended cold-extend path on a
  // future render. Count the resets: at least three `= 0;` assignments
  // after the constructor's init.
  const matches = VIEW.match(/this\._colStatsExtractAdvance = 0;/g) || [];
  assert.ok(matches.length >= 4,
    `expected at least 4 resets of \`_colStatsExtractAdvance\` (constructor + warm-extend + cold-extract + full-sweep + final no-op); got ${matches.length}`);
});

// ── Reset path clears the hint too ────────────────────────────────────────

test('reset path clears _colStatsExtractAdvance alongside _colStats', () => {
  // Reset wipes extracted cols entirely. A stale hint surviving this
  // would tell the next render to compute "the trailing N new cols"
  // when there are no new cols — at best a no-op, at worst a sliced
  // compute over the wrong column range. The reset block in
  // `timeline-view.js` already nulls `_colStats` and bumps
  // `_colStatsGen`; the hint reset belongs alongside.
  // Match `_colStats = null; _colStatsGen++;` followed (allowing
  // intervening comment lines) by `_colStatsExtractAdvance = 0;`.
  assert.match(VIEW,
    /this\._colStats = null;\s*this\._colStatsGen\+\+;[\s\S]{0,400}?this\._colStatsExtractAdvance = 0;/,
    'expected `_colStatsExtractAdvance = 0` shortly after `_colStats = null; _colStatsGen++;` in the reset path');
});

// ── _computeColumnStatsSync gains an optional range ───────────────────────

test('_computeColumnStatsSync accepts (idx, fromCol, toCol)', () => {
  // The signature change is the public surface that the cold-cache
  // branch above relies on. Without it, the sync helper would compute
  // every column and the optimisation would still pay the full sweep
  // cost (just inline rather than yielded).
  assert.match(FILTER,
    /_computeColumnStatsSync\(idx, fromCol, toCol\) \{/,
    'expected `_computeColumnStatsSync(idx, fromCol, toCol)` signature');
});

test('_computeColumnStatsSync default range is the full column set', () => {
  // Backward-compat: every existing caller invokes `_computeColumnStatsSync(idx)`.
  // The defaults must cover the legacy "all columns" semantics or the
  // small-dataset full-compute branch (and the export path that
  // builds top-values lists) would silently return empty arrays.
  assert.match(FILTER,
    /const lo = \(fromCol == null\) \? 0 : fromCol;\s*const hi = \(toCol == null\) \? totalCols : toCol;/,
    'expected `(fromCol == null) ? 0 : fromCol` / `(toCol == null) ? totalCols : toCol` defaults');
});

test('_computeColumnStatsSync returns stats parallel to [fromCol, toCol)', () => {
  // Output array length is `toCol - fromCol`, indexed 0..span. The
  // cold-cache branch relies on this when seeding
  // `seeded[baseEnd + c] = newColsSlice[c]` — `c` is 0..advance, so
  // the result must be 0-indexed against the slice, not the full
  // column set.
  assert.match(FILTER,
    /const span = hi - lo;\s*const stats = new Array\(span\);/,
    'expected `span = hi - lo` and `stats = new Array(span)` (parallel to slice)');
  assert.match(FILTER,
    /stats\[c - lo\]\.set\(v, \(stats\[c - lo\]\.get\(v\) \|\| 0\) \+ 1\);/,
    'expected stats indexed by `c - lo` (0-indexed against the slice)');
});
