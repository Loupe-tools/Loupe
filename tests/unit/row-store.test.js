'use strict';
// row-store.test.js — RowStore + RowStoreBuilder + packRowChunk.
//
// RowStore is the flat-buffer container that replaced the legacy
// `string[][]` accumulator the Timeline pipeline used. It is performance-
// critical (every `getCell` call sits on the hot path of sort, filter,
// IOC scan, scrubber bucketing, and stack-pivot grouping) and shared
// between the timeline worker and four GridViewer consumers (csv /
// sqlite / evtx renderers + timeline-view sync fallback). A subtle
// off-by-one in offsets / chunk-boundary math would silently corrupt
// every cell read at the boundary, so this test is exhaustive on
// access patterns rather than minimal.
//
// Coverage:
//   • `RowStore.fromStringMatrix` — bulk static factory used by every
//     non-streaming caller (sqlite, evtx, csv sync fallback).
//   • `RowStore.fromChunks` — used by `timeline-router.js` after
//     receiving the worker's pre-packed chunks via postMessage.
//   • `RowStore.empty` — the zero-row sentinel.
//   • `RowStoreBuilder.addRow` — non-streaming incremental build.
//   • `RowStoreBuilder.addChunk` — streaming chunk intake.
//   • Mixed `addRow` + `addChunk` — order preservation across paths.
//   • Automatic chunk-flush thresholds (row count + byte cap).
//   • `getCell` invariants — OOB rows / cols, nullish cells, decoder
//     reuse safety, UTF-8 multibyte fidelity.
//   • `getRow` materialisation parity with the input.
//   • `colIndex` lazy cache + `-1` miss.
//   • `byteLength` accounting.
//   • Binary-search row→chunk lookup across many chunks.
//   • `packRowChunk` produces fresh ArrayBuffers (transferable from a
//     worker) and round-trips identically through `fromChunks`.
//   • Defensive errors: mismatched offsets length, post-finalize misuse.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// row-store.js has no external dependencies — it's pure class +
// function definitions. We still load it through the bundle harness
// (rather than `require()`) to mirror its real "evaluated as inline
// script" semantics in the production build.
const ctx = loadModules(['src/row-store.js'], {
  expose: ['RowStore', 'RowStoreBuilder', 'packRowChunk'],
});
const { RowStore, RowStoreBuilder, packRowChunk } = ctx;

// ── Smoke ──────────────────────────────────────────────────────────────────

test('RowStore exports are present', () => {
  assert.equal(typeof RowStore, 'function');
  assert.equal(typeof RowStoreBuilder, 'function');
  assert.equal(typeof packRowChunk, 'function');
});

// ── packRowChunk — primitive layer the worker uses directly ────────────────

test('packRowChunk produces fresh ArrayBuffers and a valid offsets array', () => {
  const cols = ['a', 'b', 'c'];
  const rows = [
    ['1', '2', '3'],
    ['hello', '', 'world'],
    ['', '', ''],
  ];
  const { bytes, offsets, rowCount } = packRowChunk(rows, cols.length);
  assert.equal(rowCount, 3);
  assert.ok(bytes instanceof ctx.Uint8Array);
  assert.ok(offsets instanceof ctx.Uint32Array);
  // offsets layout: rowCount * (colCount + 1) entries.
  assert.equal(offsets.length, 3 * 4);
  // First cell of row 0 starts at byte 0 — invariant.
  assert.equal(offsets[0], 0);
  // Last offset equals total payload length.
  assert.equal(offsets[offsets.length - 1], bytes.byteLength);
  // Empty cells produce equal start / end offsets.
  // row 1, col 1 ('') → offsets[1*4 + 1] === offsets[1*4 + 2]
  assert.equal(offsets[1 * 4 + 1], offsets[1 * 4 + 2]);
});

test('packRowChunk handles UTF-8 multibyte characters correctly', () => {
  const rows = [
    ['café', '🚀', 'naïve'],
    ['\u{1F600}', 'plain', '日本語'],
  ];
  const { bytes, offsets } = packRowChunk(rows, 3);
  // café = 5 bytes (c=1, a=1, f=1, é=2)
  assert.equal(offsets[1] - offsets[0], 5);
  // 🚀 = 4 bytes (surrogate pair → 1 UTF-8 code point of length 4)
  assert.equal(offsets[2] - offsets[1], 4);
});

test('packRowChunk treats null, undefined, and "" as zero-length cells', () => {
  const rows = [
    [null, undefined, ''],
    ['a', 'b', 'c'],
  ];
  const { bytes, offsets, rowCount } = packRowChunk(rows, 3);
  assert.equal(rowCount, 2);
  // Row 0 produces three zero-length cells → all four offsets equal.
  assert.equal(offsets[0], offsets[1]);
  assert.equal(offsets[1], offsets[2]);
  assert.equal(offsets[2], offsets[3]);
  // Row 1 produces 'abc' (3 bytes).
  assert.equal(offsets[4 + 0], 0);
  assert.equal(offsets[4 + 3], 3);
  assert.equal(bytes.byteLength, 3);
});

test('packRowChunk on a defensive null-row produces empty cells, not a throw', () => {
  // Defensive: `_parseCsv` should never produce a sparse rows array,
  // but if it ever did, we want zero-length cells rather than a crash.
  const rows = [null, ['a', 'b']];
  const { offsets, rowCount } = packRowChunk(rows, 2);
  assert.equal(rowCount, 2);
  // First row: all empty.
  assert.equal(offsets[0], 0);
  assert.equal(offsets[1], 0);
  assert.equal(offsets[2], 0);
});

// ── RowStore.fromStringMatrix — basic round-trip ───────────────────────────

test('RowStore.fromStringMatrix round-trips simple string data', () => {
  const cols = ['name', 'age', 'city'];
  const rows = [
    ['Alice', '30', 'London'],
    ['Bob', '25', 'Paris'],
    ['Charlie', '40', 'Tokyo'],
  ];
  const store = RowStore.fromStringMatrix(cols, rows);
  assert.equal(store.rowCount, 3);
  assert.equal(store.colCount, 3);
  assert.deepEqual(store.columns, cols);
  for (let r = 0; r < rows.length; r++) {
    for (let c = 0; c < cols.length; c++) {
      assert.equal(store.getCell(r, c), rows[r][c]);
    }
  }
});

test('RowStore.fromStringMatrix preserves UTF-8 cells', () => {
  const cols = ['emoji', 'jp', 'accented'];
  const rows = [
    ['🚀🎉', '日本語テキスト', 'café résumé'],
    ['👨‍💻', 'こんにちは', 'naïve façade'],
  ];
  const store = RowStore.fromStringMatrix(cols, rows);
  for (let r = 0; r < rows.length; r++) {
    for (let c = 0; c < cols.length; c++) {
      assert.equal(store.getCell(r, c), rows[r][c]);
    }
  }
});

// ── getCell invariants ─────────────────────────────────────────────────────

test('getCell returns "" for OOB row index', () => {
  const store = RowStore.fromStringMatrix(['a'], [['x']]);
  assert.equal(store.getCell(-1, 0), '');
  assert.equal(store.getCell(1, 0), '');
  assert.equal(store.getCell(999, 0), '');
});

test('getCell returns "" for OOB column index', () => {
  const store = RowStore.fromStringMatrix(['a', 'b'], [['x', 'y']]);
  assert.equal(store.getCell(0, -1), '');
  assert.equal(store.getCell(0, 2), '');
  assert.equal(store.getCell(0, 999), '');
});

test('getCell returns "" for null / undefined / empty cells uniformly', () => {
  const store = RowStore.fromStringMatrix(
    ['a', 'b', 'c', 'd'],
    [[null, undefined, '', 'present']],
  );
  assert.equal(store.getCell(0, 0), '');
  assert.equal(store.getCell(0, 1), '');
  assert.equal(store.getCell(0, 2), '');
  assert.equal(store.getCell(0, 3), 'present');
});

test('getCell can be called repeatedly on the same row/col without state leak', () => {
  // The RowStore reuses a single TextDecoder across calls. Confirm
  // back-to-back decodes on the same cell return identical strings —
  // this would catch a future fast-path that accidentally cached a
  // mutable buffer view.
  const store = RowStore.fromStringMatrix(['a'], [['hello']]);
  for (let i = 0; i < 100; i++) {
    assert.equal(store.getCell(0, 0), 'hello');
  }
});

// ── getRow ─────────────────────────────────────────────────────────────────

test('getRow materialises a fresh string[] matching the input', () => {
  const cols = ['x', 'y', 'z'];
  const rows = [
    ['1', '2', '3'],
    [null, 'middle', undefined],
    ['', '', ''],
  ];
  const store = RowStore.fromStringMatrix(cols, rows);
  assert.deepEqual(store.getRow(0), ['1', '2', '3']);
  assert.deepEqual(store.getRow(1), ['', 'middle', '']);
  assert.deepEqual(store.getRow(2), ['', '', '']);
});

test('getRow on OOB index returns an empty-cell row of correct length', () => {
  const store = RowStore.fromStringMatrix(['a', 'b'], [['x', 'y']]);
  const oob = store.getRow(99);
  assert.equal(oob.length, 2);
  assert.deepEqual(oob, ['', '']);
});

test('getRow returns a fresh array each call (callers may mutate)', () => {
  const store = RowStore.fromStringMatrix(['a'], [['x']]);
  const a = store.getRow(0);
  const b = store.getRow(0);
  assert.notEqual(a, b);  // distinct array identities
  a[0] = 'mutated';
  assert.equal(store.getCell(0, 0), 'x');  // store unaffected
  assert.equal(b[0], 'x');                 // second snapshot unaffected
});

// ── colIndex ───────────────────────────────────────────────────────────────

test('colIndex returns matching index, or -1 for unknown', () => {
  const store = RowStore.fromStringMatrix(
    ['Timestamp', 'Event ID', 'Channel'],
    [],
  );
  assert.equal(store.colIndex('Timestamp'), 0);
  assert.equal(store.colIndex('Event ID'), 1);
  assert.equal(store.colIndex('Channel'), 2);
  assert.equal(store.colIndex('missing'), -1);
});

test('colIndex on a duplicate header returns the FIRST occurrence', () => {
  // Real-world CSVs sometimes repeat a header (e.g. exporting the same
  // field twice). The contract is "first match wins", matching the
  // legacy `findIndex` pattern in every renderer.
  const store = RowStore.fromStringMatrix(['a', 'b', 'a'], []);
  assert.equal(store.colIndex('a'), 0);
});

// ── empty store ────────────────────────────────────────────────────────────

test('RowStore.empty produces a zero-row store with the expected columns', () => {
  const store = RowStore.empty(['x', 'y']);
  assert.equal(store.rowCount, 0);
  assert.equal(store.colCount, 2);
  assert.deepEqual(store.columns, ['x', 'y']);
  assert.equal(store.getCell(0, 0), '');
  assert.equal(store.byteLength, 0);
});

// ── byteLength accounting ──────────────────────────────────────────────────

test('byteLength sums payload + offsets across every chunk', () => {
  const store = RowStore.fromStringMatrix(['a', 'b'], [['hi', 'world']]);
  // 'hi' (2) + 'world' (5) = 7 payload bytes
  // offsets: 1 row × (2+1) = 3 entries × 4 bytes = 12
  // → byteLength === 7 + 12 = 19.
  assert.equal(store.byteLength, 19);
});

// ── Builder — addRow path ──────────────────────────────────────────────────

test('RowStoreBuilder.addRow + finalize matches fromStringMatrix output', () => {
  const cols = ['c1', 'c2'];
  const rows = [['a', 'b'], ['c', 'd'], ['e', 'f']];
  const a = RowStore.fromStringMatrix(cols, rows);
  const builder = new RowStoreBuilder(cols);
  for (const r of rows) builder.addRow(r);
  const b = builder.finalize();
  assert.equal(b.rowCount, a.rowCount);
  for (let r = 0; r < rows.length; r++) {
    for (let c = 0; c < cols.length; c++) {
      assert.equal(b.getCell(r, c), a.getCell(r, c));
    }
  }
});

test('RowStoreBuilder.rowCount tracks pending rows live', () => {
  const builder = new RowStoreBuilder(['a']);
  assert.equal(builder.rowCount, 0);
  builder.addRow(['x']);
  assert.equal(builder.rowCount, 1);
  builder.addRow(['y']);
  assert.equal(builder.rowCount, 2);
  builder.finalize();
});

// ── Builder — chunk-flush thresholds ───────────────────────────────────────

test('RowStoreBuilder flushes a chunk when row count threshold is reached', () => {
  // Force a tiny threshold so we observe the flush deterministically.
  const builder = new RowStoreBuilder(['a'], { chunkRowsTarget: 3 });
  for (let i = 0; i < 7; i++) builder.addRow([String(i)]);
  const store = builder.finalize();
  assert.equal(store.rowCount, 7);
  // Should have flushed after row 3 and row 6, leaving 1 pending → 3
  // chunks total (3 + 3 + 1).
  assert.equal(store.chunks.length, 3);
  assert.equal(store.chunks[0].rowCount, 3);
  assert.equal(store.chunks[1].rowCount, 3);
  assert.equal(store.chunks[2].rowCount, 1);
});

test('RowStoreBuilder flushes a chunk when byte soft cap is exceeded', () => {
  // 32-byte payload per row × 4 rows ≈ 128 bytes; cap is 64 bytes.
  const builder = new RowStoreBuilder(['a'], { chunkBytesSoftCap: 64 });
  for (let i = 0; i < 4; i++) builder.addRow(['x'.repeat(32)]);
  const store = builder.finalize();
  assert.equal(store.rowCount, 4);
  // First row alone fits; second row pushes past 64 → flush. Pattern
  // depends on the exact cap arithmetic, but we should see ≥ 2 chunks.
  assert.ok(store.chunks.length >= 2);
});

// ── Builder — addChunk path ────────────────────────────────────────────────

test('RowStoreBuilder.addChunk accepts pre-packed chunks (the worker path)', () => {
  const cols = ['a', 'b'];
  const chunk = packRowChunk([['1', '2'], ['3', '4']], cols.length);
  const builder = new RowStoreBuilder(cols);
  builder.addChunk(chunk);
  const store = builder.finalize();
  assert.equal(store.rowCount, 2);
  assert.equal(store.getCell(0, 0), '1');
  assert.equal(store.getCell(1, 1), '4');
});

test('Mixed addRow + addChunk preserves insertion order across paths', () => {
  const cols = ['v'];
  const builder = new RowStoreBuilder(cols);
  builder.addRow(['a']);
  builder.addRow(['b']);
  // Pre-pack a chunk for c, d.
  builder.addChunk(packRowChunk([['c'], ['d']], 1));
  builder.addRow(['e']);
  builder.addChunk(packRowChunk([['f']], 1));
  const store = builder.finalize();
  assert.equal(store.rowCount, 6);
  assert.deepEqual(
    [0, 1, 2, 3, 4, 5].map(r => store.getCell(r, 0)),
    ['a', 'b', 'c', 'd', 'e', 'f'],
  );
});

test('addChunk with mismatched offsets length throws synchronously', () => {
  const builder = new RowStoreBuilder(['a', 'b']);
  // colCount=2 → stride=3; for rowCount=1 we need 3 offsets. Pass 4.
  assert.throws(
    () => builder.addChunk({
      bytes: new ctx.Uint8Array(0),
      offsets: new ctx.Uint32Array(4),
      rowCount: 1,
    }),
    /offsets length 4 does not match/,
  );
});

// ── Post-finalize misuse ───────────────────────────────────────────────────

test('addRow after finalize throws', () => {
  const builder = new RowStoreBuilder(['a']);
  builder.addRow(['x']);
  builder.finalize();
  assert.throws(() => builder.addRow(['y']), /already finalized/);
});

test('addChunk after finalize throws', () => {
  const builder = new RowStoreBuilder(['a']);
  builder.finalize();
  assert.throws(
    () => builder.addChunk(packRowChunk([['x']], 1)),
    /already finalized/,
  );
});

test('finalize() called twice throws', () => {
  const builder = new RowStoreBuilder(['a']);
  builder.finalize();
  assert.throws(() => builder.finalize(), /already finalized/);
});

// ── Multi-chunk binary search ──────────────────────────────────────────────

test('row→chunk lookup is correct across many chunks', () => {
  // Force ~10 small chunks so the binary search has work to do.
  // Each chunk has 5 rows, so row 0 → chunk 0, row 4 → chunk 0,
  // row 5 → chunk 1, row 49 → chunk 9.
  const cols = ['idx'];
  const builder = new RowStoreBuilder(cols, { chunkRowsTarget: 5 });
  for (let i = 0; i < 50; i++) builder.addRow([String(i)]);
  const store = builder.finalize();
  assert.equal(store.chunks.length, 10);
  // Boundary checks at every chunk transition.
  for (let i = 0; i < 50; i++) {
    assert.equal(store.getCell(i, 0), String(i),
      'cell mismatch at row ' + i + ' (chunk-boundary regression)');
  }
});

// ── fromChunks — host-receives-from-worker path ────────────────────────────

test('RowStore.fromChunks accepts an array of pre-packed chunks', () => {
  const cols = ['a', 'b'];
  const chunks = [
    packRowChunk([['1', '2'], ['3', '4']], 2),
    packRowChunk([['5', '6']], 2),
    packRowChunk([['7', '8'], ['9', '10'], ['11', '12']], 2),
  ];
  const store = RowStore.fromChunks(cols, chunks);
  assert.equal(store.rowCount, 6);
  assert.equal(store.chunks.length, 3);
  // Spot-check rows in each chunk.
  assert.equal(store.getCell(0, 0), '1');
  assert.equal(store.getCell(2, 1), '6');
  assert.equal(store.getCell(5, 1), '12');
});

test('RowStore.fromChunks rejects a chunk with mis-sized offsets', () => {
  // colCount=1 → stride=2; rowCount=2 needs offsets.length=4. Pass 3.
  assert.throws(
    () => RowStore.fromChunks(['x'], [{
      bytes: new ctx.Uint8Array(0),
      offsets: new ctx.Uint32Array(3),
      rowCount: 2,
    }]),
    /offsets length 3 does not match/,
  );
});

// ── Worker-transfer simulation ─────────────────────────────────────────────

test('packRowChunk output is structurally compatible with postMessage transfer', () => {
  // Simulate the worker→main handoff: pack, then "transfer" by reading
  // off the underlying ArrayBuffers, then re-wrap on the host side and
  // round-trip into a RowStore. The real production code would include
  // `bytes.buffer` and `offsets.buffer` in the transfer list — here we
  // just confirm the buffers are independently valid.
  const cols = ['a', 'b'];
  const rows = [['hello', 'world'], ['foo', 'bar']];
  const packed = packRowChunk(rows, cols.length);
  // Independent ArrayBuffer instances (not views into a shared buffer).
  assert.notEqual(packed.bytes.buffer, packed.offsets.buffer);
  // Round-trip via fromChunks — exactly what the host does.
  const store = RowStore.fromChunks(cols, [packed]);
  assert.equal(store.getCell(0, 0), 'hello');
  assert.equal(store.getCell(1, 1), 'bar');
});

// ── ASCII fast-path ────────────────────────────────────────────────────────
//
// `packRowChunk` flags pure-7-bit-ASCII chunks via `allAscii: true`. The
// flag is honoured by `RowStore.getCell` / `getRow` to skip TextDecoder
// and use a `String.fromCharCode.apply` fast path instead. The tests
// below verify (a) the flag is set correctly, (b) decoded output is
// identical regardless of which path is taken, (c) chunk-boundary mixed
// stores correctly switch paths per-chunk, and (d) older chunk shapes
// missing the flag still load (back-compat).

test('packRowChunk flags pure-ASCII chunks as allAscii=true', () => {
  const rows = [
    ['hello', 'world', '12345'],
    ['/var/log/syslog', '2026-04-28T12:00:00', '8.8.8.8'],
    ['', null, undefined],
  ];
  const chunk = packRowChunk(rows, 3);
  assert.equal(chunk.allAscii, true);
});

test('packRowChunk flags multibyte chunks as allAscii=false', () => {
  // A single non-ASCII byte anywhere in the chunk is enough to force
  // the slow path. Use 'café' (é = 0xC3 0xA9) to confirm the high-bit
  // detection rather than anything more exotic.
  const rows = [
    ['hello', 'world'],
    ['café', 'ascii'],
  ];
  const chunk = packRowChunk(rows, 2);
  assert.equal(chunk.allAscii, false);
});

test('packRowChunk: a single emoji forces allAscii=false', () => {
  const chunk = packRowChunk([['🚀']], 1);
  assert.equal(chunk.allAscii, false);
});

test('packRowChunk: empty rows + nullish cells keep allAscii=true', () => {
  // Vacuously true — no bytes emitted means no high bit observed.
  const chunk = packRowChunk([[null, undefined, '']], 3);
  assert.equal(chunk.allAscii, true);
});

test('ASCII fast-path getCell output matches TextDecoder slow-path output', () => {
  // Same string content, packed two ways: one through the canonical
  // packer (sets allAscii=true) and one with allAscii forcibly cleared
  // so the slow path runs. Both must produce identical results across
  // every cell.
  const rows = [
    ['Alice', '30', 'London'],
    ['Bob', '25', 'Paris'],
    ['', 'middle', ''],
    ['SYSTEM', 'NT AUTHORITY', '/var/log'],
  ];
  const fast = RowStore.fromStringMatrix(['a', 'b', 'c'], rows);
  // Hand-build a parallel store with allAscii forced false.
  const packed = packRowChunk(rows, 3);
  packed.allAscii = false;
  const slow = RowStore.fromChunks(['a', 'b', 'c'], [packed]);
  for (let r = 0; r < rows.length; r++) {
    for (let c = 0; c < 3; c++) {
      assert.equal(
        fast.getCell(r, c),
        slow.getCell(r, c),
        'fast/slow mismatch at (' + r + ',' + c + ')',
      );
      assert.equal(fast.getCell(r, c), rows[r][c] == null ? '' : rows[r][c]);
    }
  }
});

test('ASCII fast-path getRow output matches TextDecoder slow-path output', () => {
  // Same matrix, two stores. `getRow` has an independent code path
  // that must stay parity with `getCell`.
  const rows = [
    ['1', 'foo', 'bar'],
    [null, '', 'baz'],
    ['SYSTEM', 'NT AUTHORITY', '/var/log/auth'],
  ];
  const fast = RowStore.fromStringMatrix(['a', 'b', 'c'], rows);
  const packed = packRowChunk(rows, 3);
  packed.allAscii = false;
  const slow = RowStore.fromChunks(['a', 'b', 'c'], [packed]);
  for (let r = 0; r < rows.length; r++) {
    assert.deepEqual(
      fast.getRow(r),
      slow.getRow(r),
      'fast/slow getRow mismatch at row ' + r,
    );
  }
});

test('multibyte chunks still decode correctly via TextDecoder slow path', () => {
  const rows = [
    ['café', 'naïve', 'résumé'],
    ['🚀', '日本語', '😀'],
    ['Москва', 'Αθήνα', 'القاهرة'],
  ];
  const store = RowStore.fromStringMatrix(['a', 'b', 'c'], rows);
  for (let r = 0; r < rows.length; r++) {
    for (let c = 0; c < 3; c++) {
      assert.equal(store.getCell(r, c), rows[r][c]);
    }
  }
  // And confirm the chunk really did flag itself as non-ASCII (so we
  // know we exercised the slow path, not the fast).
  assert.equal(store.chunks[0].allAscii, false);
});

test('mixed-encoding stores preserve per-chunk allAscii decisions across the seam', () => {
  // First chunk pure ASCII, second chunk multibyte — exercises the
  // chunk-boundary dispatch in `getCell` / `getRow`. Force tiny chunks
  // to guarantee the seam lands where we expect.
  const cols = ['a'];
  const builder = new RowStoreBuilder(cols, { chunkRowsTarget: 2 });
  builder.addRow(['hello']);
  builder.addRow(['world']);
  // Chunk flush boundary lands here.
  builder.addRow(['café']);
  builder.addRow(['🚀']);
  const store = builder.finalize();
  assert.equal(store.chunks.length, 2);
  assert.equal(store.chunks[0].allAscii, true);
  assert.equal(store.chunks[1].allAscii, false);
  // Round-trip every row.
  assert.equal(store.getCell(0, 0), 'hello');
  assert.equal(store.getCell(1, 0), 'world');
  assert.equal(store.getCell(2, 0), 'café');
  assert.equal(store.getCell(3, 0), '🚀');
});

test('back-compat: fromChunks accepts chunks missing the allAscii flag', () => {
  // Simulate an older worker bundle that produces chunks without the
  // flag. Strip it and confirm `fromChunks` rescans the bytes,
  // populates the flag, and reads cells correctly.
  const cols = ['a', 'b'];
  const packed = packRowChunk([['hi', 'there'], ['foo', 'bar']], 2);
  // Pre-flag-era shape — strip the property entirely, mirroring an
  // older builder that simply doesn't set it.
  delete packed.allAscii;
  const store = RowStore.fromChunks(cols, [packed]);
  // Rescan should have populated the flag (these cells are pure ASCII).
  assert.equal(store.chunks[0].allAscii, true);
  assert.equal(store.getCell(0, 0), 'hi');
  assert.equal(store.getCell(1, 1), 'bar');
});

test('back-compat: addChunk accepts chunks missing the allAscii flag', () => {
  const cols = ['a'];
  const packed = packRowChunk([['café'], ['naïve']], 1);
  // Strip the flag; `addChunk` must rescan and detect multibyte content.
  delete packed.allAscii;
  const builder = new RowStoreBuilder(cols);
  builder.addChunk(packed);
  const store = builder.finalize();
  assert.equal(store.chunks[0].allAscii, false);
  assert.equal(store.getCell(0, 0), 'café');
  assert.equal(store.getCell(1, 0), 'naïve');
});

test('ASCII fast-path handles the long-cell branch (>4 KB ASCII payload)', () => {
  // The fast-path chunks `String.fromCharCode.apply` output to 4 KB
  // pieces above this threshold. Confirm a 12 KB pure-ASCII cell
  // round-trips cleanly across the chunked-concatenation branch.
  const big = 'A'.repeat(12 * 1024);
  const store = RowStore.fromStringMatrix(['a'], [[big]]);
  assert.equal(store.chunks[0].allAscii, true);
  const got = store.getCell(0, 0);
  assert.equal(got.length, big.length);
  assert.equal(got, big);
});

// ── Stress: 1 000 rows across many chunks ──────────────────────────────────

test('1 000-row store with forced 100-row chunks reads cleanly end-to-end', () => {
  const cols = ['n', 's'];
  const rows = [];
  for (let i = 0; i < 1000; i++) {
    rows.push([String(i), 'row-' + i]);
  }
  const builder = new RowStoreBuilder(cols, { chunkRowsTarget: 100 });
  for (const r of rows) builder.addRow(r);
  const store = builder.finalize();
  assert.equal(store.rowCount, 1000);
  assert.equal(store.chunks.length, 10);
  // Spot-check edges and boundaries.
  for (const r of [0, 1, 99, 100, 101, 499, 500, 998, 999]) {
    assert.equal(store.getCell(r, 0), String(r));
    assert.equal(store.getCell(r, 1), 'row-' + r);
  }
});
