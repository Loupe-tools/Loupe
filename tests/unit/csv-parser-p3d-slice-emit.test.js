'use strict';
// csv-parser-p3d-slice-emit.test.js — pin the P3-D allocator-hygiene
// rewrite of CsvRenderer.parseChunk.
//
// Background: Phase 3 perf pass. The hot inner loop used to do
// `cur += text[i]` once per content character, which on V8/SpiderMonkey
// allocates a cons-string per iteration and forces a flatten on read,
// generating measurable GC pressure inside the worker (~50 ms wall on
// a 50 MB CSV per Firefox profile).
//
// The replacement tracks `chunkStart` — the index in the current chunk
// where the active run of plain-content chars began — and emits one
// `text.slice(chunkStart, i)` per "boundary" event (delim, NL, quote
// toggle, `""` escape). This collapses N allocations per cell to one
// and lets V8's hidden-class machinery elide the ropes entirely.
//
// These tests exist so a future "clean up the parser" refactor doesn't
// silently revert to per-char string concat without anyone noticing
// (the result would be functionally correct, just slow).

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  ['src/constants.js', 'src/renderers/csv-renderer.js'],
  { expose: ['CsvRenderer'] },
);
const { CsvRenderer } = ctx;

const SRC = fs.readFileSync(
  path.resolve(__dirname, '..', '..', 'src', 'renderers', 'csv-renderer.js'),
  'utf8',
);

// ── Source-shape pins ─────────────────────────────────────────────────

test('csv-parser P3-D: parseChunk declares a chunkStart index', () => {
  // The slice-on-emit strategy needs a single integer that tracks where
  // the currently-buffered run of content chars began. If a future
  // edit deletes the variable, the per-char concat regression is back.
  assert.match(SRC, /\blet\s+chunkStart\s*=\s*-1\s*;/,
    'parseChunk must declare `let chunkStart = -1;` as the slice-run cursor');
});

test('csv-parser P3-D: parseChunk defines a flushRun helper that emits one slice', () => {
  // The helper appends `text.slice(chunkStart, upto)` to `cur` and
  // resets the cursor. Pinning the exact shape stops a refactor from
  // splitting it into a non-equivalent inline body.
  assert.match(SRC, /const\s+flushRun\s*=\s*\(upto\)\s*=>/,
    'parseChunk must define `const flushRun = (upto) => …` to emit pending slice runs');
  assert.match(SRC, /cur\s*\+=\s*text\.slice\(chunkStart,\s*upto\)\s*;/,
    'flushRun must concatenate `text.slice(chunkStart, upto)` onto `cur`');
  assert.match(SRC, /chunkStart\s*=\s*-1\s*;/,
    'flushRun must reset chunkStart back to -1 after flushing');
});

test('csv-parser P3-D: every boundary in the hot loop calls flushRun before mutating cur/cells', () => {
  // The four boundary kinds are: closing-quote, escaped-double-quote,
  // unquoted NL, unquoted delim. Each must call flushRun(i) before
  // pushing/extending `cur`, otherwise the buffered run is dropped.
  const flushSites = (SRC.match(/flushRun\(i\)\s*;/g) || []).length;
  assert.ok(flushSites >= 4,
    `expected ≥ 4 flushRun(i) call sites in the hot loop, found ${flushSites}`);
});

test('csv-parser P3-D: per-char `cur += text[i]` allocations are gone from parseChunk', () => {
  // The previous implementation had two `cur += text[i]; i++;` lines —
  // one inside the quoted branch and one inside the unquoted branch.
  // Both should now be replaced by `if (chunkStart < 0) chunkStart = i;`.
  // Scope the check to parseChunk only: the legacy `_splitQuoted` helper
  // at the bottom of the file is unused by all three pipelines but still
  // present for back-compat.
  const startMarker = 'static parseChunk(text, fromIdx, state, delim, opts) {';
  const endMarker = '_parse(text, delim, startOffset) {';
  const start = SRC.indexOf(startMarker);
  const end = SRC.indexOf(endMarker);
  assert.ok(start > 0 && end > start,
    'could not locate parseChunk body for region scan');
  // Strip line comments before the substring check — the rationale
  // comment at the top of parseChunk legitimately quotes the old
  // `cur += text[i]` pattern as the thing we're avoiding.
  const body = SRC.slice(start, end);
  const codeOnly = body.replace(/\/\/.*$/gm, '');
  assert.doesNotMatch(codeOnly, /cur\s*\+=\s*text\[i\]/,
    'parseChunk must no longer accumulate cell content via `cur += text[i]`');
});

test('csv-parser P3-D: parseChunk flushes the in-flight slice run before persisting state', () => {
  // The trailing `flushRun(i);` ensures any pending content chars get
  // folded into `cur` before the function captures `state.cur` for
  // resumption on the next chunk. Without it, a chunk boundary inside
  // an unterminated cell would lose the partial content.
  assert.match(SRC, /flushRun\(i\)\s*;\s*\n\s*let\s+endedInQuotes/,
    'parseChunk must call flushRun(i) immediately before the partial-row flush block');
});

// ── Behaviour parity (slice path must match the old concat path) ──────
// These are functional regression checks: for every kind of input that
// previously exercised `cur += text[i]`, the slice path must produce
// byte-identical cells.

function parseAll(text, delim) {
  const state = CsvRenderer.initParserState();
  const r = CsvRenderer.parseChunk(text, 0, state, delim, {
    baseOffset: 0, maxRows: 0, flush: true,
  });
  return host(r.rows);
}

test('csv-parser P3-D: long unquoted cells round-trip identically', () => {
  // The slice path's main job is the unquoted-content branch.
  const long = 'x'.repeat(8192);
  const text = `${long},${long}\n${long},${long}\n`;
  const rows = parseAll(text, ',');
  assert.equal(rows.length, 2);
  assert.equal(rows[0][0], long);
  assert.equal(rows[0][1], long);
  assert.equal(rows[1][0], long);
  assert.equal(rows[1][1], long);
});

test('csv-parser P3-D: long quoted cells with embedded newlines round-trip identically', () => {
  // Inside-quotes branch — was the second `cur += text[i]` site.
  const long = 'a'.repeat(2000) + '\n' + 'b'.repeat(2000) + '\n' + 'c'.repeat(2000);
  const text = `"${long}",end\n`;
  const rows = parseAll(text, ',');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].length, 2);
  assert.equal(rows[0][0], long);
  assert.equal(rows[0][1], 'end');
});

test('csv-parser P3-D: doubled-quote escapes flush the run before appending the literal `"`', () => {
  // The `""` → `"` escape is the trickiest case: it must flushRun
  // *before* appending the literal `"` to `cur`, otherwise the buffered
  // pre-escape content is silently dropped.
  const text = '"hello ""world"" goodbye",ok\n';
  const rows = parseAll(text, ',');
  assert.equal(rows[0][0], 'hello "world" goodbye');
  assert.equal(rows[0][1], 'ok');
});

test('csv-parser P3-D: chunk boundary inside an unterminated quoted cell preserves all content', () => {
  // Two-call resume — pins the trailing flushRun(i) that persists the
  // in-flight slice run into state.cur before the function returns.
  const chunkA = '"first half of the cell ';
  const chunkB = 'second half of the cell"\n';
  const state = CsvRenderer.initParserState();
  const a = CsvRenderer.parseChunk(chunkA, 0, state, ',', {
    baseOffset: 0, maxRows: 0, flush: false,
  });
  assert.equal(a.rows.length, 0, 'no full row should emit before the closing quote');
  const b = CsvRenderer.parseChunk(chunkB, 0, state, ',', {
    baseOffset: chunkA.length, maxRows: 0, flush: true,
  });
  const rows = host(b.rows);
  assert.equal(rows.length, 1);
  assert.equal(rows[0][0], 'first half of the cell second half of the cell');
});

test('csv-parser P3-D: rows with mixed quoted + unquoted cells produce identical output', () => {
  // The slice path must coexist with the no-quote fast path (the
  // `text.indexOf("\\n", i)` branch at the top of the loop). Lines
  // with at least one quote fall through to the slice path; lines
  // without any fall through to the fast path. Both must agree.
  const text = [
    'a,b,c',
    '"x,y",z,"w"',
    'plain,row,here',
    '"multi\nline",end,col3',
  ].join('\n') + '\n';
  const rows = parseAll(text, ',');
  assert.deepEqual(rows[0], ['a', 'b', 'c']);
  assert.deepEqual(rows[1], ['x,y', 'z', 'w']);
  assert.deepEqual(rows[2], ['plain', 'row', 'here']);
  assert.deepEqual(rows[3], ['multi\nline', 'end', 'col3']);
});
