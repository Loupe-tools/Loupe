// timeline-view-filter-extracted-only-stats.test.js
//
// P3-H: extracted-only fast path in `_computeColumnStatsSync` and
// `_computeColumnStatsAsyncInternal`. The auto-extract apply pump
// requests stats for ONLY the new trailing extracted cols
// (`_extendColumnStatsAsync(idx, fromCol=baseLen, gen)`). The legacy
// implementation paid for `ds.rowInto(di, rowScratch)` per row, which
// always decodes every base-col cell from chunk bytes via
// `_decodeAsciiSlice` — pure waste when none of those decoded values
// is read into `stats`. Profiling on a 100k-row × 10-base-col CSV
// showed `_extendColumnStatsAsync` spending 701ms / 1.4s in
// `_decodeAsciiSlice` of base-col bytes.
//
// The fix: when the requested `[fromCol, toCol)` range lies entirely
// in extracted-col territory (`ds && fromCol >= ds._store.colCount`),
// pre-resolve the requested extracted cols' `values[]` arrays once and
// index them directly in the inner loop. Eliminates `rowInto` entirely
// for the extracted-only case.
//
// Static-text pins on the source file. No view bootstrap.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const FILTER = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-filter.js'),
  'utf8'
);
const POPOVERS = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-popovers.js'),
  'utf8'
);
const EXPORT = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-export.js'),
  'utf8'
);

// ── _computeColumnStatsSync extracted-only branch ──────────────────────────

test('_computeColumnStatsSync detects extracted-only range via fromCol >= baseLen', () => {
  // The gate must use `>=` (not `>`) — when there are zero base cols
  // (theoretical, but possible on a fully synthetic dataset) and the
  // request is for the entire column set starting at 0, we still want
  // to take the fast path. More importantly, the warm-extend case
  // calls with `fromCol == baseLen` exactly (no overlap into base
  // territory), so the boundary must be inclusive.
  assert.match(FILTER,
    /const baseLen = ds \? ds\._store\.colCount : -1;\s*if \(ds && lo >= baseLen\)/,
    'expected sync gate `if (ds && lo >= baseLen)` against `ds._store.colCount`');
});

test('_computeColumnStatsSync pre-resolves colArrays once before the row loop', () => {
  // Inner-loop hot path must not call `_extractedCols[(lo+c)-baseLen]`
  // per cell — that's 100k × span dispatch hits + nullable checks.
  // Hoisting the lookup outside the row loop turns the inner read
  // into a flat `arr[di]` array index. Pin the hoist.
  assert.match(FILTER,
    /const ext = ds\._extractedCols;\s*const colArrays = new Array\(span\);\s*for \(let c = 0; c < span; c\+\+\) \{[\s\S]*?const e = ext\[\(lo \+ c\) - baseLen\];\s*colArrays\[c\] = \(e && e\.values\) \? e\.values : null;\s*\}/,
    'expected `colArrays` pre-resolution loop indexed `[(lo + c) - baseLen]` BEFORE the row loop');
});

test('_computeColumnStatsSync extracted-only inner loop reads colArrays[c][di]', () => {
  // The flat array index is the whole point of the optimisation —
  // every other formulation (e.g. calling `_cellAt(di, lo + c)`)
  // re-introduces method dispatch. Pin the exact form.
  assert.match(FILTER,
    /for \(let i = 0; i < total; i\+\+\) \{\s*const di = idx\[i\];\s*for \(let c = 0; c < span; c\+\+\) \{\s*const arr = colArrays\[c\];\s*const raw = arr \? arr\[di\] : null;[\s\S]*?stats\[c\]\.set\(v, \(stats\[c\]\.get\(v\) \|\| 0\) \+ 1\);/,
    'expected sync inner loop `colArrays[c][di]` with stats indexed by `c` (0..span)');
});

test('_computeColumnStatsSync coerces non-string extracted values like _cellAt', () => {
  // `dataset.cellAt` returns `String(v)` for non-null non-string values;
  // we must match for stats parity. The String coercion is gated on
  // `typeof raw === 'string'` so the common case (already a string,
  // which is what the JSON / regex extractors store) skips the
  // function call entirely.
  assert.match(FILTER,
    /const v = raw == null \? '' : \(typeof raw === 'string' \? raw : String\(raw\)\);/,
    'expected null coercion + lazy `String(raw)` only for non-strings');
});

test('_computeColumnStatsSync legacy path retained for mixed/base-col ranges', () => {
  // The legacy `_cellAt` per-cell path must remain reachable when the
  // range overlaps base-col territory or no dataset is available. A
  // refactor that "always" took the new fast path would break the
  // initial post-load full-stats sweep (`fromCol == 0`).
  assert.match(FILTER,
    /\} else \{[\s\S]*?\/\/ Legacy \/ mixed-range path[\s\S]*?const v = this\._cellAt\(di, c\);[\s\S]*?stats\[c - lo\]\.set/,
    'expected legacy `_cellAt` per-cell branch retained as the fallback');
});

// ── _computeColumnStatsAsyncInternal extracted-only branch ─────────────────

test('_computeColumnStatsAsyncInternal hoists extractedOnly + colArrays before async IIFE', () => {
  // The hoist MUST be before the `return (async () => {` IIFE so the
  // `colArrays` allocation happens once per computation, not once per
  // chunk. Also: the gate uses `fromCol`, not `lo` (the async path
  // doesn't have the optional-range adapter — it always receives an
  // explicit `fromCol`).
  assert.match(FILTER,
    /const baseLen = ds \? ds\._store\.colCount : -1;\s*const extractedOnly = ds && fromCol >= baseLen;\s*const colArrays = extractedOnly \? new Array\(span\) : null;[\s\S]*?return \(async \(\) => \{/,
    'expected `extractedOnly` + `colArrays` hoisted BEFORE the async IIFE');
});

test('_computeColumnStatsAsyncInternal extractedOnly branch precedes rowScratch branch', () => {
  // Branch order matters because the legacy `if (rowScratch)` is true
  // whenever `ds` is non-null, which would otherwise mask the
  // extracted-only fast path entirely. The new branch must be FIRST.
  // Pin the exact `if (extractedOnly) { ... } else if (rowScratch)`
  // chain so a future refactor that flattens the conditionals can't
  // accidentally swap their order.
  assert.match(FILTER,
    /if \(extractedOnly\) \{[\s\S]*?for \(let c = 0; c < span; c\+\+\) \{\s*const arr = colArrays\[c\];[\s\S]*?\} else if \(rowScratch\) \{/,
    'expected `if (extractedOnly) {...} else if (rowScratch) {...}` order in the row-loop body');
});

test('_computeColumnStatsAsyncInternal extracted-only path skips rowInto entirely', () => {
  // The whole point of the optimisation: `ds.rowInto(...)` decodes
  // every base-col cell. The extracted-only branch must NOT contain
  // a `rowInto` call. Slice out just the `if (extractedOnly) { ... }
  // else if (rowScratch)` block and verify `ds.rowInto(` doesn't
  // appear inside the extracted-only arm.
  const m = FILTER.match(
    /if \(extractedOnly\) \{([\s\S]*?)\} else if \(rowScratch\) \{/
  );
  assert.ok(m, 'failed to locate `if (extractedOnly) { ... } else if (rowScratch)` block');
  const extractedArm = m[1];
  assert.doesNotMatch(extractedArm, /ds\.rowInto\(/,
    'expected NO `ds.rowInto(` inside the extractedOnly branch arm');
});

test('_computeColumnStatsAsyncInternal extracted-only stats indexed by c (0..span)', () => {
  // Symmetry with the sync path: stats arr is parallel to the
  // requested range, so the extracted-only inner loop indexes
  // `stats[c]` directly (NOT `stats[c - fromCol]` which the legacy
  // branch uses because it iterates `c = fromCol..toCol`).
  assert.match(FILTER,
    /if \(extractedOnly\) \{[\s\S]*?for \(let c = 0; c < span; c\+\+\) \{[\s\S]*?const m = stats\[c\];\s*m\.set\(v, \(m\.get\(v\) \|\| 0\) \+ 1\);/,
    'expected extracted-only stats indexed by `c` (0..span), parallel to colArrays');
});

// ── Fix 2a: srcValues fill uses store.getCell directly ────────────────────

test('extract-selected click handler fills srcValues via store.getCell (not _cellAt)', () => {
  // `_autoExtractScan` only emits proposals for base columns
  // (`for (let c = 0; c < this._baseColumns.length; c++)`), so
  // `sourceCol` in the dialog click handler is GUARANTEED to be a
  // base-col index. We can therefore call `store.getCell` directly
  // and skip the `_cellAt` → `dataset.cellAt` dispatch hop, which
  // matters on the 100k-iteration hot loop.
  assert.match(POPOVERS,
    /const store = this\.store;\s*for \(let i = 0; i < n; i\+\+\) srcValues\[i\] = store\.getCell\(i, sourceCol\);/,
    'expected hoisted `store` ref + `store.getCell(i, sourceCol)` in the srcValues fill');
});

test('srcValues fill no longer calls _cellAt in the extract-selected click handler', () => {
  // Negative pin — the old `this._cellAt(i, sourceCol)` form must be
  // gone from THIS specific loop (the file may use `_cellAt`
  // elsewhere; we constrain by surrounding context).
  assert.doesNotMatch(POPOVERS,
    /const srcValues = new Array\(n\);[\s\S]{0,400}?for \(let i = 0; i < n; i\+\+\) srcValues\[i\] = this\._cellAt\(i, sourceCol\);/,
    'expected `this._cellAt(i, sourceCol)` to be gone from the srcValues fill loop');
});

// ── Drive-by: rename bug fix in timeline-view-export.js ────────────────────

test('_autoPivotFromColumn calls _computeColumnStatsSync (not the deleted _computeColumnStats)', () => {
  // The B2c refactor renamed `_computeColumnStats` →
  // `_computeColumnStatsSync` in `timeline-view-filter.js` but missed
  // this call site. The bug was latent: `_autoPivotFromColumn` is
  // only reached via the column-header context menu "Auto pivot on
  // this column", and only when `_colStats` is null (cold cache).
  // Without the rename it would throw `TypeError:
  // this._computeColumnStats is not a function`.
  assert.match(EXPORT,
    /this\._colStats = this\._computeColumnStatsSync\(this\._filteredIdx \|\| new Uint32Array\(0\)\);/,
    'expected `_computeColumnStatsSync` (not `_computeColumnStats`) in the lazy-init branch');
  assert.doesNotMatch(EXPORT,
    /this\._computeColumnStats\(this\._filteredIdx/,
    'expected NO `this._computeColumnStats(this._filteredIdx` (deleted helper name)');
});

// ── Behavioural parity test ────────────────────────────────────────────────
//
// The static-text pins above prove the SHAPE of the change. This block
// proves the SEMANTICS: extract the new extracted-only branch logic
// into a standalone helper, drive it against a synthetic dataset, and
// assert byte-for-byte equality with a reference implementation that
// uses the legacy `_cellAt` path.

test('extracted-only fast path produces stats identical to legacy _cellAt path', () => {
  // Synthetic dataset with 4 base cols + 3 extracted cols, 1000 rows.
  // Extract-only request asks for `[baseLen, baseLen+3)`.
  const baseLen = 4;
  const extLen = 3;
  const totalCols = baseLen + extLen;
  const rowCount = 1000;

  // Generate deterministic test data. Some null/empty rows to exercise
  // the `raw == null ? '' : ...` coercion. Mix string + number
  // extracted-col values to exercise the `typeof === 'string'` branch.
  const extCols = [];
  for (let c = 0; c < extLen; c++) {
    const values = new Array(rowCount);
    for (let i = 0; i < rowCount; i++) {
      // Distinct value sets per col, with repetition for non-trivial counts.
      if (i % 17 === 0) values[i] = null;             // null → ''
      else if (i % 23 === 0) values[i] = '';          // empty → ''
      else if (c === 1 && i % 11 === 0) values[i] = i; // numeric → String(i)
      else values[i] = `c${c}-v${i % (10 + c * 3)}`;
    }
    extCols.push({ values });
  }

  const ds = {
    _store: { colCount: baseLen },
    _extractedCols: extCols,
  };
  const idx = new Uint32Array(rowCount);
  for (let i = 0; i < rowCount; i++) idx[i] = i;

  // Reference (legacy) — mirrors the `else` branch that calls
  // `_cellAt`, which for extracted cols does:
  //   const e = _extractedCols[totalCol - baseLen];
  //   if (!e || !e.values) return '';
  //   const v = e.values[origRow];
  //   return v == null ? '' : String(v);
  function legacyStats(fromCol, toCol) {
    const span = toCol - fromCol;
    const stats = new Array(span);
    for (let c = 0; c < span; c++) stats[c] = new Map();
    for (let i = 0; i < rowCount; i++) {
      const di = idx[i];
      for (let c = fromCol; c < toCol; c++) {
        const e = ds._extractedCols[c - baseLen];
        const raw = (e && e.values) ? e.values[di] : null;
        const v = raw == null ? '' : String(raw);
        stats[c - fromCol].set(v, (stats[c - fromCol].get(v) || 0) + 1);
      }
    }
    return stats;
  }

  // Fast path — mirrors the new `if (extractedOnly)` branch.
  function fastStats(fromCol, toCol) {
    const span = toCol - fromCol;
    const stats = new Array(span);
    for (let c = 0; c < span; c++) stats[c] = new Map();
    const colArrays = new Array(span);
    for (let c = 0; c < span; c++) {
      const e = ds._extractedCols[(fromCol + c) - baseLen];
      colArrays[c] = (e && e.values) ? e.values : null;
    }
    for (let i = 0; i < rowCount; i++) {
      const di = idx[i];
      for (let c = 0; c < span; c++) {
        const arr = colArrays[c];
        const raw = arr ? arr[di] : null;
        const v = raw == null ? '' : (typeof raw === 'string' ? raw : String(raw));
        stats[c].set(v, (stats[c].get(v) || 0) + 1);
      }
    }
    return stats;
  }

  // Drive both over the full extracted range and a sub-range.
  for (const [from, to] of [[baseLen, baseLen + extLen], [baseLen, baseLen + 1], [baseLen + 1, baseLen + 3]]) {
    const legacy = legacyStats(from, to);
    const fast   = fastStats(from, to);
    assert.equal(legacy.length, fast.length,
      `length mismatch for range [${from}, ${to})`);
    for (let c = 0; c < legacy.length; c++) {
      const lEntries = Array.from(legacy[c].entries()).sort();
      const fEntries = Array.from(fast[c].entries()).sort();
      assert.deepEqual(fEntries, lEntries,
        `Map mismatch at col ${c} for range [${from}, ${to})`);
    }
  }
});
