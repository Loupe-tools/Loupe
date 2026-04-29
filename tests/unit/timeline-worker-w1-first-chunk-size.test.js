'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-worker-w1-first-chunk-size.test.js — pin the W1 worker
// dynamic-first-chunk optimisation.
//
// CONTEXT — what W1 does and why:
//   The streaming worker (`src/workers/timeline.worker.js`) packs row
//   batches of `WORKER_CHUNK_ROWS` (50 000) before transferring them
//   to the host via `_postRowsChunk(...)`. The host's `'rows-chunk'`
//   handler (`src/app/timeline/timeline-router.js`) constructs the
//   `RowStoreBuilder` on the FIRST chunk, then calls `addChunk` for
//   each subsequent one. That one-time construction sits on the
//   critical path between the worker shipping its first batch and
//   the host starting any RowStore-dependent work.
//
//   On a 100k-row CSV the worker takes ~6.7 s to fully parse the file,
//   yet the *first* `'rows-chunk'` doesn't arrive at the host until
//   ~50 000 rows have been parsed AND packed (~3 s in). Smaller first
//   batch → host setup happens ~10× sooner → more parallel overlap
//   between worker parse + host RowStoreBuilder construction.
//
//   The fix: introduce `WORKER_FIRST_CHUNK_ROWS = 5_000` and ship the
//   FIRST batch at that smaller threshold. Subsequent batches revert
//   to the steady-state 50 000 to keep postMessage overhead bounded.
//
// What this test pins (static-text only — runtime overlap behaviour
// is covered by the e2e timeline-router tests + the existing
// row-store builder integration tests):
//   • `WORKER_FIRST_CHUNK_ROWS` constant exists, value 5_000.
//   • `WORKER_CHUNK_ROWS` constant remains at 50_000 (no regression
//     to the steady-state target).
//   • All four ingest paths (CSV body, CLF body, EVTX, SQLite) use
//     the small threshold for the first flush and the full threshold
//     thereafter.
//   • The CSV/CLF shared `flushBatch` flips `firstBatchPending`
//     after the first successful flush.
//
// Static checks mirror the pattern in
// `timeline-view-autoextract-pump-suppress-columns.test.js`.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const WORKER_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/workers/timeline.worker.js'), 'utf8');

// ── Constants ──────────────────────────────────────────────────────────────

test('WORKER_CHUNK_ROWS steady-state target is 50_000 (no regression)', () => {
  // The steady-state target matches `RowStoreBuilder._chunkRowsTarget`
  // so host-side chunk boundaries are identical to a sync `addRow`
  // build. Don't change this without a coordinated update to
  // `src/row-store.js`.
  assert.ok(
    /const\s+WORKER_CHUNK_ROWS\s*=\s*50_000\s*;/.test(WORKER_SRC),
    'expected `const WORKER_CHUNK_ROWS = 50_000;` in timeline.worker.js'
  );
});

test('WORKER_FIRST_CHUNK_ROWS exists and is 5_000', () => {
  // Small first batch (10× smaller than steady-state) lets the host
  // construct `RowStoreBuilder` ~10× sooner. Don't make this larger
  // without re-measuring — the win is wholly from earlier host setup.
  // Don't make it smaller without re-measuring either — too small and
  // postMessage overhead dominates the saving.
  assert.ok(
    /const\s+WORKER_FIRST_CHUNK_ROWS\s*=\s*5_000\s*;/.test(WORKER_SRC),
    'expected `const WORKER_FIRST_CHUNK_ROWS = 5_000;` in ' +
    'timeline.worker.js (W1 first-batch threshold)'
  );
});

// ── CSV/CLF shared `flushBatch` flips firstBatchPending ─────────────────────

test('flushBatch clears firstBatchPending after the first successful flush', () => {
  // The CSV/CLF paths share `_parseCsv`'s `flushBatch` closure. The
  // first call posts at WORKER_FIRST_CHUNK_ROWS; subsequent calls
  // must use WORKER_CHUNK_ROWS. Pin the flip.
  assert.ok(
    /firstBatchPending\s*=\s*false\s*;/.test(WORKER_SRC),
    'expected `firstBatchPending = false;` assignment inside ' +
    'flushBatch (W1: switch from small to steady-state threshold ' +
    'after first flush)'
  );
});

test('currentBatchThreshold returns the right constant for each phase', () => {
  // The threshold helper must return WORKER_FIRST_CHUNK_ROWS while
  // `firstBatchPending` is true, WORKER_CHUNK_ROWS otherwise. Pin
  // the literal ternary so a refactor can't silently invert it or
  // hardcode the steady-state target.
  const re = /firstBatchPending\s*\?\s*WORKER_FIRST_CHUNK_ROWS\s*:\s*WORKER_CHUNK_ROWS/;
  assert.ok(re.test(WORKER_SRC),
    'expected `firstBatchPending ? WORKER_FIRST_CHUNK_ROWS : ' +
    'WORKER_CHUNK_ROWS` ternary in `currentBatchThreshold` helper');
});

test('CSV/CLF ingest loops use currentBatchThreshold(), not the bare constant', () => {
  // Both `ingestRows` (CSV) and the inline CLF tokenisation loop
  // must consult the dynamic threshold so they fire flushBatch at
  // 5_000 the first time and 50_000 thereafter.
  const matches = WORKER_SRC.match(
    /pendingRows\.length\s*>=\s*currentBatchThreshold\(\)/g);
  assert.ok(matches && matches.length >= 2,
    `expected >= 2 \`pendingRows.length >= currentBatchThreshold()\` ` +
    `checks (one in ingestRows / CSV, one in the CLF loop), got ` +
    `${matches ? matches.length : 0}`);

  // And the bare `pendingRows.length >= WORKER_CHUNK_ROWS` must NOT
  // appear — it would skip the small-first-batch path entirely.
  assert.ok(
    !/pendingRows\.length\s*>=\s*WORKER_CHUNK_ROWS/.test(WORKER_SRC),
    'expected NO `pendingRows.length >= WORKER_CHUNK_ROWS` left in ' +
    'timeline.worker.js — must use currentBatchThreshold() instead'
  );
});

// ── EVTX + SQLite paths share the P3-G `_makeRowStreamer` helper ──────────

test('EVTX and SQLite paths use the shared _makeRowStreamer helper', () => {
  // P3-G consolidated the two duplicated EVTX/SQLite "first-flush"
  // patterns behind a single `_makeRowStreamer(colCount)` helper that
  // encapsulates the W1 small-first-batch + steady-state cadence.
  // The W1 contract is unchanged — just expressed in one place rather
  // than two — so we pin the helper exists and is used by both
  // non-CSV parse paths.
  assert.match(WORKER_SRC, /function\s+_makeRowStreamer\s*\(\s*colCount\s*\)/,
    'expected `function _makeRowStreamer(colCount)` to be the canonical ' +
    'home of the W1 first-batch / steady-state threshold logic');

  // The helper itself must implement the dynamic threshold (one
  // ternary survives, but inside the helper rather than duplicated
  // across the EVTX and SQLite paths).
  const ternaries = WORKER_SRC.match(
    /firstFlush\s*\?\s*WORKER_FIRST_CHUNK_ROWS\s*:\s*WORKER_CHUNK_ROWS/g);
  assert.ok(ternaries && ternaries.length === 1,
    `expected exactly 1 \`firstFlush ? WORKER_FIRST_CHUNK_ROWS : ` +
    `WORKER_CHUNK_ROWS\` ternary (inside _makeRowStreamer), got ` +
    `${ternaries ? ternaries.length : 0}`);

  // Both call sites must use the helper.
  const callSites = WORKER_SRC.match(/_makeRowStreamer\(colCount\)/g);
  assert.ok(callSites && callSites.length >= 2,
    `expected >= 2 _makeRowStreamer(colCount) call sites (EVTX + SQLite), ` +
    `got ${callSites ? callSites.length : 0}`);

  // EVTX/SQLite must not retain the bare `pending.length >=
  // WORKER_CHUNK_ROWS` check — that would always defer the first
  // flush to 50 000 rows.
  assert.ok(
    !/pending\.length\s*>=\s*WORKER_CHUNK_ROWS/.test(WORKER_SRC),
    'expected NO `pending.length >= WORKER_CHUNK_ROWS` literal in ' +
    'EVTX/SQLite paths — must go through _makeRowStreamer'
  );
});
