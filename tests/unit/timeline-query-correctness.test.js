'use strict';
// timeline-query-correctness.test.js — pins the query-engine correctness
// + safety fixes from the timeline audit:
//
//   • M5  sticky `y` (and global `g`) regex flags are rejected by the
//         tokenizer so `col ~ /pat/y` can't silently anchor matches.
//   • M6  `eq` / `ne` are case-insensitive + whitespace-trimmed (so a
//         click-pivot built from the displayed cell text matches the
//         canonical cell regardless of case/whitespace), consistent with
//         `contains`.
//   • M7  parenthesised nesting is depth-capped → a clean parse error
//         instead of a call-stack overflow.
//   • M15 the any-column / bareword predicate matches per cell (no
//         cross-column join), preserving the original semantics.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-helpers.js',
  'src/app/timeline/timeline-query.js',
], { expose: ['_tlTokenize', '_tlParseQuery', '_tlCompileAst'] });
const { _tlTokenize, _tlParseQuery, _tlCompileAst } = ctx;

// Minimal fake TimelineView: a fixed 2-column grid.
function makeView(columns, rows) {
  return {
    columns,
    _cellAt(di, ci) {
      const r = rows[di];
      return r && r[ci] != null ? String(r[ci]) : '';
    },
    _susBitmap: null,
    _detectionBitmap: null,
  };
}

function compile(query, view) {
  const toks = _tlTokenize(query);
  const ast = _tlParseQuery(toks, () => view.columns);
  return _tlCompileAst(ast, view);
}

// ── M5: sticky / global regex flags rejected ────────────────────────────────

test('M5: regex tokenizer accepts imsu but stops before a sticky `y` flag', () => {
  // `/foo/y` — the `y` must NOT be absorbed into the flags. The tokenizer
  // stops the flag-scan at `y`, leaving it as a separate bareword token.
  const toks = _tlTokenize('col ~ /foo/y').filter(t => t.kind !== 'WS');
  const re = toks.find(t => t.kind === 'REGEX');
  assert.ok(re, 'a REGEX token is produced');
  assert.strictEqual(re.value.flags, '', 'sticky `y` is not included in regex flags');
});

test('M5: imsu flags are still accepted', () => {
  const toks = _tlTokenize('col ~ /foo/im').filter(t => t.kind !== 'WS');
  const re = toks.find(t => t.kind === 'REGEX');
  assert.strictEqual(re.value.flags, 'im');
});

// ── M6: eq / ne case-insensitive + trimmed ──────────────────────────────────

test('M6: `=` matches case-insensitively', () => {
  const view = makeView(['User', 'Action'], [['Administrator', 'login'], ['bob', 'logout']]);
  const pred = compile('User=administrator', view);
  assert.strictEqual(pred(0), true, 'Administrator === administrator (case-insensitive)');
  assert.strictEqual(pred(1), false);
});

test('M6: `=` matches despite surrounding whitespace in the cell', () => {
  const view = makeView(['EventID', 'x'], [['  4624  ', 'a'], ['4625', 'b']]);
  const pred = compile('EventID=4624', view);
  assert.strictEqual(pred(0), true, 'trimmed cell "4624" === "4624"');
  assert.strictEqual(pred(1), false);
});

test('M6: `!=` is the negation of the case-insensitive equality', () => {
  const view = makeView(['User', 'x'], [['ADMIN', 'a'], ['guest', 'b']]);
  const pred = compile('User!=admin', view);
  assert.strictEqual(pred(0), false);
  assert.strictEqual(pred(1), true);
});

// ── M15: any-column predicate matches within a single cell ───────────────────

test('M15: bareword matches a substring inside any one column', () => {
  const view = makeView(['A', 'B'], [['hello world', 'xyz'], ['nothing', 'here']]);
  const pred = compile('world', view);
  assert.strictEqual(pred(0), true);
  assert.strictEqual(pred(1), false);
});

test('M15: bareword does NOT match across a column boundary', () => {
  // "ab" split as "a" | "b" across two columns must not match — the old
  // join('\n') approach could only ever match within a column too, and
  // the per-cell scan preserves that.
  const view = makeView(['A', 'B'], [['a', 'b']]);
  const pred = compile('ab', view);
  assert.strictEqual(pred(0), false);
});

test('M15: any-column match is case-insensitive', () => {
  const view = makeView(['A', 'B'], [['FooBar', 'q']]);
  const pred = compile('foobar', view);
  assert.strictEqual(pred(0), true);
});

// ── M7: parenthesis depth cap ────────────────────────────────────────────────

test('M7: deeply nested parens throw a clean parse error, not a stack overflow', () => {
  const cols = ['A', 'B'];
  const deep = '('.repeat(5000) + 'A:x' + ')'.repeat(5000);
  assert.throws(
    () => _tlParseQuery(_tlTokenize(deep), () => cols),
    (e) => {
      // Must be our parse error (carries `userMsg`), not a RangeError.
      assert.ok(!(e instanceof RangeError), 'should not be a call-stack RangeError');
      assert.match(String(e.userMsg || e.message), /nested too deeply/);
      return true;
    },
  );
});

test('M7: modest nesting still parses fine', () => {
  const cols = ['A', 'B'];
  const q = '(((A:x OR B:y)))';
  const ast = _tlParseQuery(_tlTokenize(q), () => cols);
  assert.ok(ast && ast.k, 'parses to a real AST node');
});
