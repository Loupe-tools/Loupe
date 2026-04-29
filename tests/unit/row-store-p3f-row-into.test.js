'use strict';
// row-store-p3f-row-into.test.js — pin the P3-F row-major fast path
// for column-stats / wide-row hot loops.
//
// Background: `_computeColumnStatsAsync` in timeline-view-filter.js
// previously called `self._cellAt(di, c)` once per cell. Each call
// went through `Dataset.cellAt` → `RowStore.getCell`, which did a
// binary search over the chunk-row-start array on EVERY cell. For a
// 1 M-row × 30-col grid that's 30M binary searches.
//
// P3-F adds:
//   • `RowStore.getRowInto(rowIdx, out)` — writes `colCount` cells
//     into a caller-supplied array, allocating nothing. Hoists the
//     chunk binary-search outside the column loop.
//   • `Dataset.rowInto(origRow, out)` — same shape, but covers
//     extracted virtual columns too (those use a direct array index
//     so are already O(1); the only saving is for the base columns).
//   • `_computeColumnStatsAsync` now uses a reusable `rowScratch`
//     array and calls `dataset.rowInto(di, rowScratch)` once per row.
//
// These tests pin: (1) the new methods exist with the documented
// shape, (2) they fail-soft on OOB rows (mirror `getCell`/`cellAt`
// semantics), (3) the migration of the stats loop is in place, and
// (4) round-trip parity with the old `getCell` path.

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/row-store.js'], {
  expose: ['RowStore', 'RowStoreBuilder'],
});
const { RowStore, RowStoreBuilder } = ctx;

const ROW_STORE_SRC = fs.readFileSync(
  path.resolve(__dirname, '..', '..', 'src', 'row-store.js'), 'utf8');
const DATASET_SRC = fs.readFileSync(
  path.resolve(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-dataset.js'),
  'utf8');
const FILTER_SRC = fs.readFileSync(
  path.resolve(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-filter.js'),
  'utf8');

// ── Source-shape pins ─────────────────────────────────────────────────

test('row-store P3-F: RowStore declares getRowInto(rowIdx, out)', () => {
  assert.match(ROW_STORE_SRC, /\bgetRowInto\s*\(\s*rowIdx\s*,\s*out\s*\)\s*\{/,
    'RowStore must define getRowInto(rowIdx, out) for the row-major fast path');
});

test('row-store P3-F: getRow delegates to getRowInto (no duplicated cell loop)', () => {
  // Avoid the two implementations drifting — getRow is now just a thin
  // allocate-and-fill wrapper around getRowInto.
  assert.match(ROW_STORE_SRC, /getRow\s*\(\s*rowIdx\s*\)\s*\{[^}]*this\.getRowInto\(rowIdx,\s*out\)/,
    'getRow must delegate to getRowInto so the two implementations cannot drift');
});

test('row-store P3-F: getRowInto contains the ASCII fast path AND the TextDecoder fallback', () => {
  // Same chunk-level allAscii dispatch the old getRow had — must be
  // preserved or the W3 ASCII fast-path regression bug is back.
  // Locate the *definition* (not the call site inside getRow) by
  // matching the method header line specifically.
  const m = ROW_STORE_SRC.match(/^\s*getRowInto\(rowIdx,\s*out\)\s*\{/m);
  assert.ok(m, 'could not locate getRowInto definition');
  const fnIdx = ROW_STORE_SRC.indexOf(m[0]);
  const slice = ROW_STORE_SRC.slice(fnIdx, fnIdx + 2000);
  assert.match(slice, /chunk\.allAscii/,
    'getRowInto must dispatch on chunk.allAscii for the ASCII fast path');
  assert.match(slice, /_decodeAsciiSlice\(/,
    'getRowInto must call _decodeAsciiSlice for the ASCII fast path');
  assert.match(slice, /this\._decoder/,
    'getRowInto must fall back to TextDecoder for non-ASCII chunks');
});

test('row-store P3-F: Dataset declares rowInto(origRow, out)', () => {
  assert.match(DATASET_SRC, /\browInto\s*\(\s*origRow\s*,\s*out\s*\)\s*\{/,
    'TimelineDataset must define rowInto(origRow, out) for the row-major fast path');
});

test('row-store P3-F: Dataset.rowInto delegates to RowStore.getRowInto', () => {
  // This is the whole point — base columns must come from the store's
  // amortised row read, not `cellAt` per column.
  const fnIdx = DATASET_SRC.indexOf('rowInto(origRow, out)');
  assert.ok(fnIdx > 0, 'could not locate Dataset.rowInto');
  const slice = DATASET_SRC.slice(fnIdx, fnIdx + 1000);
  assert.match(slice, /this\._store\.getRowInto\(origRow,\s*out\)/,
    'Dataset.rowInto must delegate to RowStore.getRowInto for base cols');
});

test('row-store P3-F: _computeColumnStatsAsync uses rowInto + a reusable scratch buffer', () => {
  // The migration must (a) allocate the scratch once, (b) call
  // dataset.rowInto inside the per-row loop, NOT dataset.cellAt /
  // self._cellAt for every column.
  // The scratch must be sized to cover every column index the inner
  // loop touches. After P3-B parameterised the column range as
  // `[fromCol, toCol)`, sizing by `toCol` is the natural upper bound
  // (the loop reads `rowScratch[c]` for `c < toCol`). The pre-P3-B
  // shape was `new Array(cols)`. Either is acceptable.
  assert.match(FILTER_SRC, /const\s+rowScratch\s*=\s*ds\s*\?\s*new\s+Array\((?:cols|toCol)\)\s*:\s*null\s*;/,
    '_computeColumnStatsAsync must allocate rowScratch once outside the row loop, sized to cols or toCol');
  assert.match(FILTER_SRC, /ds\.rowInto\(di,\s*rowScratch\)\s*;/,
    '_computeColumnStatsAsync must call dataset.rowInto(di, rowScratch) per row');
});

// ── Behaviour parity ──────────────────────────────────────────────────

function makeStore() {
  const cols = ['a', 'b', 'c', 'd', 'e'];
  const b = new RowStoreBuilder(cols);
  // Push enough rows across multiple chunks so the binary search has
  // something to distinguish between.
  for (let i = 0; i < 5000; i++) {
    b.addRow([`a${i}`, `b${i}`, `c${i}`, `d${i}`, `e${i}`]);
  }
  return b.finalize();
}

test('row-store P3-F: getRowInto fills out array identically to getCell', () => {
  const store = makeStore();
  const scratch = new Array(store.colCount);
  for (const r of [0, 1, 13, 999, 1000, 1001, 4998, 4999]) {
    store.getRowInto(r, scratch);
    for (let c = 0; c < store.colCount; c++) {
      assert.equal(scratch[c], store.getCell(r, c),
        `mismatch at row=${r} col=${c}`);
    }
  }
});

test('row-store P3-F: getRowInto on OOB row fills the output with empty strings', () => {
  const store = makeStore();
  const scratch = ['old', 'old', 'old', 'old', 'old'];
  store.getRowInto(-1, scratch);
  assert.deepEqual(scratch, ['', '', '', '', '']);
  store.getRowInto(99999, scratch);
  assert.deepEqual(scratch, ['', '', '', '', '']);
});

test('row-store P3-F: getRow remains identical to a freshly-allocated getRowInto', () => {
  // Sanity: the wrapper stays in lockstep with the in-place fast path.
  const store = makeStore();
  for (const r of [0, 7, 1234, 4999]) {
    const a = store.getRow(r);
    const b = new Array(store.colCount);
    store.getRowInto(r, b);
    assert.deepEqual(a, b);
  }
});

test('row-store P3-F: getRowInto handles UTF-8 cells identically to getCell', () => {
  const cols = ['α', 'β'];
  const b = new RowStoreBuilder(cols);
  b.addRow(['héllo', 'wörld']);
  b.addRow(['日本語', '中文']);
  const store = b.finalize();
  const scratch = new Array(2);
  store.getRowInto(0, scratch);
  assert.deepEqual(scratch, ['héllo', 'wörld']);
  store.getRowInto(1, scratch);
  assert.deepEqual(scratch, ['日本語', '中文']);
});

test('row-store P3-F: getRowInto leaves out[c >= colCount] untouched', () => {
  // Callers may pass a larger scratch (e.g. base + extracted cols
  // shape). getRowInto must not stomp on those slots.
  const store = makeStore();
  const scratch = ['untouched1', 'untouched2', 'untouched3', 'untouched4', 'untouched5',
    'extra1', 'extra2'];
  store.getRowInto(42, scratch);
  assert.equal(scratch[5], 'extra1');
  assert.equal(scratch[6], 'extra2');
});
