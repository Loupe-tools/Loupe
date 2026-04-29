'use strict';
// timeline-worker-p3g-row-streamer.test.js — pin the P3-G refactor
// that consolidated the EVTX + SQLite duplicated first-flush logic
// into a single `_makeRowStreamer(colCount)` helper.
//
// W1 had introduced a small-first-batch threshold so the host could
// land its `RowStoreBuilder` setup early; W4 added the `_postColumns`
// helper for the same reason. Each renderer's stream-out loop ended
// up with a slightly different `firstFlush` discipline:
//
//   • CSV / CLF — closure-shared `firstBatchPending` flag flipped
//     by `flushBatch()`, accessed via `currentBatchThreshold()`.
//   • EVTX / SQLite — local `let firstFlush = true;` plus an inline
//     `threshold = firstFlush ? FIRST : STEADY` ternary, manually
//     reset in three places.
//
// P3-G keeps the CSV / CLF scheme (its threshold logic is interleaved
// with header detection, padding, and truncation that don't fit a
// generic helper) but factors EVTX + SQLite behind:
//
//     const stream = _makeRowStreamer(colCount);
//     for (...) stream.push(row);
//     stream.flush();
//
// Saving ~30 lines of duplication and one minor source of drift
// between the two paths.

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const WORKER_SRC = fs.readFileSync(
  path.resolve(__dirname, '..', '..', 'src', 'workers', 'timeline.worker.js'),
  'utf8',
);

test('worker P3-G: _makeRowStreamer helper exists with the documented signature', () => {
  assert.match(WORKER_SRC, /function\s+_makeRowStreamer\s*\(\s*colCount\s*\)\s*\{/,
    'expected `function _makeRowStreamer(colCount) {` declaration');
});

test('worker P3-G: helper exposes push() and flush()', () => {
  // Pin the contract — call sites depend on these names.
  const startIdx = WORKER_SRC.indexOf('function _makeRowStreamer(colCount)');
  assert.ok(startIdx > 0, 'could not locate _makeRowStreamer');
  const endIdx = WORKER_SRC.indexOf('\n}', startIdx);
  assert.ok(endIdx > startIdx, 'could not locate _makeRowStreamer body end');
  const body = WORKER_SRC.slice(startIdx, endIdx);
  assert.match(body, /push\s*\(\s*row\s*\)\s*\{/,
    '_makeRowStreamer must expose push(row)');
  assert.match(body, /flush\s*\(\s*\)\s*\{/,
    '_makeRowStreamer must expose flush()');
});

test('worker P3-G: helper preserves the W1 dynamic threshold (FIRST → STEADY)', () => {
  // The helper must contain the threshold ternary internally — the
  // first batch fires at WORKER_FIRST_CHUNK_ROWS, subsequent at
  // WORKER_CHUNK_ROWS.
  const startIdx = WORKER_SRC.indexOf('function _makeRowStreamer(colCount)');
  const endIdx = WORKER_SRC.indexOf('\n}', startIdx);
  const body = WORKER_SRC.slice(startIdx, endIdx);
  assert.match(body, /WORKER_FIRST_CHUNK_ROWS/,
    'helper must reference WORKER_FIRST_CHUNK_ROWS for the small first batch');
  assert.match(body, /WORKER_CHUNK_ROWS/,
    'helper must reference WORKER_CHUNK_ROWS for steady-state batches');
  assert.match(body, /firstFlush\s*\?\s*WORKER_FIRST_CHUNK_ROWS\s*:\s*WORKER_CHUNK_ROWS/,
    'helper must dispatch with `firstFlush ? FIRST : STEADY`');
});

test('worker P3-G: EVTX path uses the helper, no inline pending/firstFlush', () => {
  // _parseEvtx must call _makeRowStreamer and consume it via push/flush.
  const bodyStart = WORKER_SRC.search(/(?:async\s+)?function\s+_parseEvtx/);
  assert.ok(bodyStart >= 0, 'could not locate _parseEvtx body start');
  // Find the next top-level function declaration as the body's end.
  const nextFn = WORKER_SRC.indexOf('function _parseSqlite', bodyStart);
  const evtxBody = WORKER_SRC.slice(bodyStart, nextFn);
  assert.match(evtxBody, /_makeRowStreamer\(colCount\)/,
    '_parseEvtx must construct stream via _makeRowStreamer(colCount)');
  assert.match(evtxBody, /stream\.push\(/,
    '_parseEvtx must push rows via stream.push(...)');
  assert.match(evtxBody, /stream\.flush\(\)/,
    '_parseEvtx must call stream.flush() once iteration completes');
  assert.doesNotMatch(evtxBody, /let\s+firstFlush\s*=\s*true/,
    '_parseEvtx must not retain its old local firstFlush variable');
  assert.doesNotMatch(evtxBody, /pending\.length\s*>=\s*WORKER_/,
    '_parseEvtx must not retain its old inline pending.length threshold check');
});

test('worker P3-G: SQLite path uses the helper, no inline pending/firstFlush', () => {
  const sqliteIdx = WORKER_SRC.indexOf('function _parseSqlite');
  assert.ok(sqliteIdx > 0, 'could not locate _parseSqlite');
  // Scan to the dispatcher (`self.onmessage`) which follows.
  const nextFn = WORKER_SRC.indexOf('self.onmessage', sqliteIdx);
  const sqliteBody = WORKER_SRC.slice(sqliteIdx, nextFn);
  assert.match(sqliteBody, /_makeRowStreamer\(colCount\)/,
    '_parseSqlite must construct stream via _makeRowStreamer(colCount)');
  assert.match(sqliteBody, /stream\.push\(/,
    '_parseSqlite must push rows via stream.push(...)');
  assert.match(sqliteBody, /stream\.flush\(\)/,
    '_parseSqlite must call stream.flush() once iteration completes');
  assert.doesNotMatch(sqliteBody, /let\s+firstFlush\s*=\s*true/,
    '_parseSqlite must not retain its old local firstFlush variable');
  assert.doesNotMatch(sqliteBody, /pending\.length\s*>=\s*WORKER_/,
    '_parseSqlite must not retain its old inline pending.length threshold check');
});

test('worker P3-G: CSV / CLF closure-shared scheme is intentionally untouched', () => {
  // CSV / CLF can't move to the helper because their per-row work
  // (header detection, padOrTrimCells, row-cap truncation) interleaves
  // with the threshold check. Pin that the existing closure-shared
  // `firstBatchPending` + `currentBatchThreshold` discipline survives.
  assert.match(WORKER_SRC, /let\s+firstBatchPending\s*=\s*true\s*;/,
    'CSV / CLF path must keep its `firstBatchPending` flag');
  assert.match(WORKER_SRC, /const\s+currentBatchThreshold\s*=\s*\(\)\s*=>/,
    'CSV / CLF path must keep its `currentBatchThreshold()` helper');
});
