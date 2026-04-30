'use strict';
// ════════════════════════════════════════════════════════════════════════════
// app-test-api-perf-state.test.js — pin the shape and read-only contract
// of the `_testApiPerfState` projection used by `tests/perf/`.
//
// What this test guards:
//   • `_testApiPerfState` exists on the `extendApp({...})` mixin in
//     `src/app/app-test-api.js`.
//   • It exposes the keys the perf harness polls on (regressing one
//     to a typo would silently break all wait-conditions in
//     `tests/perf/timeline-100k.spec.ts`).
//   • The body never assigns to `this.*` — i.e. it is a pure
//     observer. The perf harness depends on this; a stray write would
//     make perf measurements lie about app state.
//   • `__loupeTest.perfState` is wired in the IIFE that exposes the
//     test-API surface on `window.__loupeTest`.
//
// Static-source assertions only (matches the pattern used by other
// `app-test-api*` checks). The runtime contract is exercised
// transitively by every perf-harness run.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SRC = fs.readFileSync(
  path.join(__dirname, '..', '..', 'src', 'app', 'app-test-api.js'),
  'utf8',
);

test('_testApiPerfState is defined inside extendApp', () => {
  assert.match(SRC, /_testApiPerfState\s*\(\s*\)\s*\{/,
    'expected `_testApiPerfState() { ... }` method declaration');
});

test('_testApiPerfState surfaces every key the perf harness polls on', () => {
  // The keys below are referenced in the predicate strings inside
  // `tests/perf/timeline-100k.spec.ts`. Adding/removing one must be
  // a deliberate edit to both files in lockstep.
  const expectedKeys = [
    'hasCurrentResult',
    'timelineMounted',
    'yaraScanInProgress',
    'timelineLoadInFlight',
    'autoExtractApplying',
    'autoExtractIdleHandlePending',
    'geoipBaseDetectKind',
    'pendingTasksSize',
    'timelineRowCount',
    'baseColCount',
    'extractedColCount',
    'geoipColCount',
    'extractedCols',
    // Sub-phase markers — populated by `_testApiPerfMark` calls
    // emitted via `window.__loupePerfMark` from the load critical
    // path (timeline-router, timeline-view, timeline-view-render-grid).
    'marks',
    // Worker self-reported parse time (`msg.parseMs` from the
    // terminal `done` event). `null` until stamped.
    'parseMs',
  ];
  // Slice to the function body so a mention of one of these keys
  // elsewhere in the file (e.g. a comment) doesn't satisfy the check.
  const fnStart = SRC.indexOf('_testApiPerfState()');
  assert.ok(fnStart >= 0, 'fn declaration not found');
  // Walk braces from the open `{` to find the body span.
  const openBrace = SRC.indexOf('{', fnStart);
  let depth = 1, i = openBrace + 1;
  while (i < SRC.length && depth > 0) {
    const c = SRC[i++];
    if (c === '{') depth++;
    else if (c === '}') depth--;
  }
  const body = SRC.slice(openBrace, i);
  for (const k of expectedKeys) {
    assert.match(body, new RegExp(`\\b${k}\\b`),
      `_testApiPerfState body must reference key '${k}'`);
  }
});

test('_testApiPerfState body contains no `this.X = ...` writes', () => {
  // Read-only contract. The body is allowed to read `this.*` and to
  // assign to local variables, but `this.foo = …` would mutate App
  // state and corrupt perf measurements.
  const fnStart = SRC.indexOf('_testApiPerfState()');
  const openBrace = SRC.indexOf('{', fnStart);
  let depth = 1, i = openBrace + 1;
  while (i < SRC.length && depth > 0) {
    const c = SRC[i++];
    if (c === '{') depth++;
    else if (c === '}') depth--;
  }
  const body = SRC.slice(openBrace, i);
  // Match `this.<name> =` but NOT `this.<name> ===` (comparison) or
  // `this.<name>.<deeper> = …` (would still be a mutation but the
  // simple pattern here catches the common form; deeper writes
  // would be an unusual style and merit a deliberate review).
  // Also exclude `this.X = this.X` no-ops via the requirement that
  // the RHS is followed by content (not =).
  const writes = body.match(/this\.[A-Za-z_][A-Za-z0-9_]*\s*=(?!=)/g);
  assert.equal(writes, null,
    `_testApiPerfState body must not assign to this.*; found ${writes && writes.join(', ')}`);
});

test('window.__loupeTest exposes perfState()', () => {
  // The IIFE at the bottom of app-test-api.js publishes the public
  // surface. Pinning this prevents an accidental drop in the
  // re-export when the surface gets edited (it has happened before
  // for `dumpResult`).
  assert.match(SRC, /perfState\s*\(\s*\)\s*\{[\s\S]*?_testApiPerfState\s*\(/,
    'expected `perfState() { ... _testApiPerfState(...) }` re-export');
});

test('_testApiPerfMark is defined and stamps `_perfMarks[name]`', () => {
  // The marker stamping helper is the writer-side companion of
  // `_testApiPerfState`. Production call sites read
  // `window.__loupePerfMark` (see test below) and short-circuit
  // when undefined; this asserts the test-API method itself
  // exists on the mixin.
  assert.match(SRC, /_testApiPerfMark\s*\(\s*name\s*,\s*value\s*\)\s*\{/,
    'expected `_testApiPerfMark(name, value) { ... }` method');
  // Body must (a) lazy-init `this._perfMarks`, (b) write the
  // timestamp under `name`. Pinning these together so a refactor
  // can't silently drop the lazy-init (which would NPE the global
  // wrapper before the first reset).
  assert.match(SRC, /this\._perfMarks\s*=\s*Object\.create\(null\)/,
    'expected lazy-init `this._perfMarks = Object.create(null)`');
  assert.match(SRC, /this\._perfMarks\[name\]\s*=/,
    'expected `this._perfMarks[name] = …` write');
});

test('_testApiClearPerfMarks is defined and nulls `_perfMarks`', () => {
  // Called from `_testApiResetCrossLoadState` so a back-to-back
  // load doesn't see stale markers.
  assert.match(SRC, /_testApiClearPerfMarks\s*\(\s*\)\s*\{/,
    'expected `_testApiClearPerfMarks() { ... }` method');
  assert.match(SRC, /this\._perfMarks\s*=\s*null/,
    'expected `this._perfMarks = null` reset');
  // Same wide-window rationale as the `_perfWorkerParseMs` assertion
  // below — just pin that the call happens inside the reset body.
  assert.match(SRC,
    /_testApiResetCrossLoadState\s*\(\s*\)\s*\{[\s\S]*?_testApiClearPerfMarks\s*\(/,
    'expected `_testApiResetCrossLoadState` to call `_testApiClearPerfMarks`');
});

test('window.__loupePerfMark global is exposed (test-API IIFE)', () => {
  // Production call sites (timeline-router etc.) read this global
  // and short-circuit when undefined. Release builds (no
  // `--test-api`) MUST NOT publish it. The IIFE at the bottom of
  // app-test-api.js is the only definition site; pinning the
  // assignment + the `window.app._testApiPerfMark` dispatch keeps
  // the path observable.
  assert.match(SRC, /window\.__loupePerfMark\s*=\s*function\s*\(/,
    'expected `window.__loupePerfMark = function (…)` IIFE export');
  assert.match(SRC, /window\.app\._testApiPerfMark\s*\(/,
    'expected the wrapper to dispatch into `window.app._testApiPerfMark(…)`');
});

test('window.__loupeTest re-exports perfMark()', () => {
  // Mirrors the `perfState` re-export pinned above. Lets harness
  // call `await page.evaluate(() => window.__loupeTest.perfMark(…))`
  // for synthetic markers (e.g. file-buffer-ready, set in the
  // harness before the file picker triggers a load).
  assert.match(SRC, /perfMark\s*\([^)]*\)\s*\{[\s\S]*?_testApiPerfMark\s*\(/,
    'expected `perfMark(...) { ... _testApiPerfMark(...) }` re-export');
});

test('_perfWorkerParseMs slot is reset on cross-load state clear', () => {
  // The worker's self-reported `parseMs` is overwritten on each
  // load via `window.__loupePerfWorkerParseMs(ms)` (see
  // `timeline-router.js`). The reset cycle nulls it so a second
  // load that omits the marker doesn't show the previous value.
  // Wide regex window — the doc-comment above
  // `_testApiResetCrossLoadState()` is large; we just need to assert
  // the null-write happens somewhere in the function body. The body
  // closes on the next `}` at column 2 followed by a blank line and
  // a `/**` doc-comment for the next method.
  assert.match(SRC,
    /_testApiResetCrossLoadState\s*\(\s*\)\s*\{[\s\S]*?this\._perfWorkerParseMs\s*=\s*null[\s\S]*?\n\s*\},/,
    'expected `_testApiResetCrossLoadState() { ... this._perfWorkerParseMs = null ... }`');
  // And the perf-state projection reads it.
  assert.match(SRC, /this\._perfWorkerParseMs/,
    'expected `_testApiPerfState` to read `_perfWorkerParseMs`');
});

test('window.__loupePerfWorkerParseMs global is exposed (test-API IIFE)', () => {
  // Worker `done` event handler stamps this. Same release-build
  // contract as `__loupePerfMark` — caller short-circuits when
  // undefined.
  assert.match(SRC, /window\.__loupePerfWorkerParseMs\s*=\s*function\s*\(/,
    'expected `window.__loupePerfWorkerParseMs = function (…)` IIFE export');
});
