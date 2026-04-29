// timeline-drawer-jsonpath-fastpath.test.js
//
// `_jsonPathGetWithStar` fast-path parity.
//
// Background: this helper is the hot loop of the Extract Values dialog
// apply path — `_addJsonExtractedColNoRender` calls it `rowCount` times
// per JSON-leaf pick. On a 100k-row CSV the Firefox profile attributed
// ~460 ms / 1.81 s of click time to it (per-segment array allocation
// for a simple deterministic path that never fans out).
//
// The fast path: when the supplied `path` contains no `[*]` wildcard
// and no `[N]` indexed-array segment, every step is a plain object-key
// read with at most one survivor. Walk inline with `cur?.[seg]` and
// skip the cur/next array bookkeeping. Slow path behaviour preserved
// exactly when the fast-path gate fails.
//
// These tests load the file via the sibling timeline mixin pattern
// (`Object.assign(TimelineView.prototype, {...})` — same as
// `timeline-view-autoextract-srcvalues-cache.test.js`) and exercise
// the helper through a minimal stub. We assert FAST and SLOW paths
// return identical results for every shape we care about.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const DRAWER = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-drawer.js'),
  'utf8'
);

// ── Static-text pins: fast-path is wired in, slow-path still present ──────

test('_jsonPathGetWithStar pre-scans for wildcard/indexed segments', () => {
  // The `simple` flag is the gate that selects the inline walker. A
  // refactor that drops the pre-scan would silently lose the
  // optimisation across every JSON-leaf pick.
  assert.match(DRAWER, /let simple = true;/,
    'expected `let simple = true;` pre-scan flag');
  assert.match(DRAWER, /seg === '\[\*\]'/,
    'expected the pre-scan to detect `[*]` wildcard segments');
  assert.match(DRAWER, /charCodeAt\(0\) === 91/,
    'expected the pre-scan to detect indexed-array `[N]` segments via char-code 91 (`[`)');
});

test('_jsonPathGetWithStar inline walker is the simple-path body', () => {
  // Pin the actual hot loop: the fast path uses a tight `for` loop
  // over `path`, reads `cur[path[i]]`, and bails on null/undefined or
  // object-typed final value. Anything else loses the perf win.
  assert.match(DRAWER,
    /if \(simple\) \{\s*let cur = value;\s*for \(let i = 0; i < path\.length; i\+\+\) \{\s*if \(cur == null \|\| typeof cur !== 'object'\) return undefined;\s*cur = cur\[path\[i\]\];/,
    'expected the inline simple-path walker to read `cur[path[i]]` and gate on `typeof cur !== \'object\'`');
});

test('_jsonPathGetWithStar slow-path still handles wildcard/indexed segments', () => {
  // The pre-existing slow-path body must remain intact for paths the
  // fast-path skips. Otherwise wildcard JSON paths (`["users","[*]","email"]`)
  // would silently break on apply.
  assert.match(DRAWER, /if \(seg === '\[\*\]' && Array\.isArray\(v\)\)/,
    'expected slow-path `[*]` wildcard handling');
  assert.match(DRAWER, /if \(\/\^\\\[\\d\+\\\]\$\/\.test\(seg\) && Array\.isArray\(v\)\)/,
    'expected slow-path `[N]` indexed-array handling');
});

// ── Behavioural parity: load helper into a TimelineView stub and run it ──

// Extract just the helper block. It's the body of
// `_jsonPathGetWithStar(value, path) { ... }` — find the `{`/`}` pair.
function extractHelper(src) {
  const sigIdx = src.indexOf('_jsonPathGetWithStar(value, path) {');
  assert.notEqual(sigIdx, -1, 'expected `_jsonPathGetWithStar(value, path) {` in drawer');
  const bodyStart = src.indexOf('{', sigIdx);
  // Walk braces to find matching close.
  let depth = 0;
  let i = bodyStart;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) break;
    }
  }
  return src.slice(bodyStart, i + 1);
}

const HELPER_BODY = extractHelper(DRAWER);

// Eval the body as a standalone function (no `this` use — the helper
// is pure). Pass `(value, path)`. Use `new Function` to keep this
// test free of dependencies on the rest of the timeline mixin chain.
//
// CSP note: this is TEST code only — runs under `node --test`, never
// reaches the browser. The build's `default-src 'none'` CSP forbids
// `new Function` in shipped JS, but tests are exempt by definition.
//
// eslint-disable-next-line no-new-func
const jsonPathGetWithStar = new Function('value', 'path', HELPER_BODY);

// Reference implementation: the original slow-path body, untouched.
// If the fast path drifts from this, the parity tests below catch it.
function jsonPathGetWithStarSlow(value, path) {
  let cur = [value];
  for (const seg of path) {
    const next = [];
    for (const v of cur) {
      if (v == null) continue;
      if (seg === '[*]' && Array.isArray(v)) {
        for (const el of v) next.push(el);
      } else if (/^\[\d+\]$/.test(seg) && Array.isArray(v)) {
        next.push(v[Number(seg.slice(1, -1))]);
      } else if (typeof v === 'object') {
        next.push(v[seg]);
      }
    }
    cur = next;
    if (!cur.length) return undefined;
  }
  for (const v of cur) {
    if (v != null && typeof v !== 'object') return v;
  }
  return undefined;
}

// Parity matrix — every case must produce identical output. Most
// exercise the fast path; the wildcard / indexed cases force the slow
// path so we know the gate is wired correctly.
const CASES = [
  // Simple deterministic paths (FAST PATH)
  { name: 'top-level string', value: { name: 'alice' }, path: ['name'], expect: 'alice' },
  { name: 'nested object', value: { user: { name: 'bob' } }, path: ['user', 'name'], expect: 'bob' },
  { name: 'three-deep', value: { a: { b: { c: 42 } } }, path: ['a', 'b', 'c'], expect: 42 },
  { name: 'missing key returns undefined', value: { a: 1 }, path: ['b'], expect: undefined },
  { name: 'mid-path null returns undefined', value: { a: null }, path: ['a', 'b'], expect: undefined },
  { name: 'mid-path primitive returns undefined', value: { a: 'str' }, path: ['a', 'b'], expect: undefined },
  { name: 'leaf object returns undefined', value: { a: { b: { c: 1 } } }, path: ['a', 'b'], expect: undefined },
  { name: 'leaf array returns undefined', value: { a: [1, 2, 3] }, path: ['a'], expect: undefined },
  { name: 'array via length key', value: { a: [1, 2, 3] }, path: ['a', 'length'], expect: 3 },
  { name: 'numeric value', value: { a: 0 }, path: ['a'], expect: 0 },
  { name: 'false value', value: { a: false }, path: ['a'], expect: false },
  { name: 'null leaf returns undefined', value: { a: null }, path: ['a'], expect: undefined },
  { name: 'undefined leaf returns undefined', value: { a: undefined }, path: ['a'], expect: undefined },
  { name: 'empty path on primitive', value: 'hello', path: [], expect: 'hello' },
  { name: 'empty path on object', value: { a: 1 }, path: [], expect: undefined },
  { name: 'empty path on null', value: null, path: [], expect: undefined },
  { name: 'empty path on number', value: 42, path: [], expect: 42 },

  // Wildcard / indexed segments (SLOW PATH)
  { name: 'wildcard fan-out', value: { items: [{ name: 'a' }, { name: 'b' }] }, path: ['items', '[*]', 'name'], expect: 'a' },
  { name: 'wildcard with no array', value: { items: { name: 'x' } }, path: ['items', '[*]', 'name'], expect: undefined },
  { name: 'indexed array element', value: { items: [{ id: 1 }, { id: 2 }] }, path: ['items', '[1]', 'id'], expect: 2 },
  { name: 'indexed array OOB', value: { items: [{ id: 1 }] }, path: ['items', '[5]', 'id'], expect: undefined },
  { name: 'wildcard finds first non-null leaf', value: { xs: [null, 'first', 'second'] }, path: ['xs', '[*]'], expect: 'first' },
  { name: 'wildcard with all object children', value: { xs: [{ a: 1 }, { a: 2 }] }, path: ['xs', '[*]'], expect: undefined },
];

for (const { name, value, path, expect } of CASES) {
  test(`parity: ${name}`, () => {
    const fast = jsonPathGetWithStar(value, path);
    const slow = jsonPathGetWithStarSlow(value, path);
    assert.deepStrictEqual(slow, expect,
      `slow-path reference disagrees with expected (test bug)`);
    assert.deepStrictEqual(fast, slow,
      `fast path diverged from slow path on ${name}: fast=${JSON.stringify(fast)}, slow=${JSON.stringify(slow)}`);
  });
}

// Hot-path realism: the helper is called many times with the SAME
// path array. Confirm we don't accidentally mutate `path`.
test('helper does not mutate the path array', () => {
  const path = ['user', 'name'];
  const before = path.slice();
  jsonPathGetWithStar({ user: { name: 'x' } }, path);
  assert.deepStrictEqual(path, before, 'path array must not be mutated');
});
