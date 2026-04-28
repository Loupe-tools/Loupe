'use strict';
// parser-watchdog.test.js — async timeout guard around parser invocations.
//
// `ParserWatchdog.run(fn, opts)` wraps a sync or async function with a
// configurable deadline; if the function hangs, the returned promise
// rejects after the timeout. The watchdog also passes an `AbortSignal`
// to the wrapped function so signal-aware code can short-circuit early.
//
// These tests cover the contract on the four common shapes: sync return
// (no timer hit), async resolve (no timer hit), async timeout
// (rejection carries `_watchdogTimeout` sentinel + signal aborts), and
// async reject (passes through verbatim).

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// `parser-watchdog.js` references `PARSER_LIMITS.TIMEOUT_MS` for the
// default deadline; load constants.js first.
const ctx = loadModules(['src/constants.js', 'src/parser-watchdog.js']);
const { ParserWatchdog } = ctx;

test('parser-watchdog: sync function resolves with its return value', async () => {
  // The sync code path is the buffer-read shape: `() => file.arrayBuffer()`
  // returns a value; the watchdog must NOT race-trip against the synchronous
  // return.
  const out = await ParserWatchdog.run(() => 'sync-result', { timeout: 1000 });
  assert.equal(out, 'sync-result');
});

test('parser-watchdog: async function resolves with its eventual value', async () => {
  // The async code path is the renderer-dispatch shape: the wrapped
  // function returns a promise the watchdog awaits.
  const out = await ParserWatchdog.run(
    () => new Promise(r => setTimeout(() => r('async-result'), 5)),
    { timeout: 1000 }
  );
  assert.equal(out, 'async-result');
});

test('parser-watchdog: hung function rejects with sentinel-bearing error', async () => {
  // The whole point of the watchdog: a hung promise must reject with
  // an Error carrying the three sentinel fields callers branch on
  // (`_watchdogTimeout`, `_watchdogName`, `_watchdogTimeoutMs`) so
  // they can switch to a fallback renderer instead of bubbling.
  let rejected = null;
  try {
    await ParserWatchdog.run(
      () => new Promise(() => { /* never resolves */ }),
      { timeout: 30, name: 'test-renderer' }
    );
    assert.fail('should have rejected');
  } catch (e) {
    rejected = e;
  }
  assert.ok(rejected instanceof Error, 'rejection must be an Error');
  assert.equal(rejected._watchdogTimeout, true);
  assert.equal(rejected._watchdogName, 'test-renderer');
  assert.equal(rejected._watchdogTimeoutMs, 30);
  assert.match(rejected.message, /timed out/i);
  assert.match(rejected.message, /test-renderer/);
});

test('parser-watchdog: timeout aborts the AbortSignal handed to fn', async () => {
  // Signal-aware renderers poll `signal.aborted` between chunks. The
  // watchdog must `controller.abort()` BEFORE rejecting so a renderer
  // that races the timer sees `signal.aborted === true` and bails
  // cleanly instead of writing into a torn-down DOM.
  let capturedSignal = null;
  try {
    await ParserWatchdog.run(
      ({ signal }) => {
        capturedSignal = signal;
        return new Promise(() => { /* never resolves */ });
      },
      { timeout: 30 }
    );
    assert.fail('should have rejected');
  } catch (_e) { /* expected */ }
  assert.ok(capturedSignal, 'signal must be passed to fn');
  assert.equal(capturedSignal.aborted, true,
    'signal must be aborted before rejection lands');
});

test('parser-watchdog: thrown sync exception passes through verbatim', async () => {
  // A synchronous throw inside `fn` must surface as the rejection
  // value, NOT get wrapped in a watchdog-timeout error. Otherwise the
  // sentinel-branch logic would treat genuine parser errors as
  // timeouts.
  const sentinel = new Error('parser-internal');
  let rejected = null;
  try {
    await ParserWatchdog.run(() => { throw sentinel; }, { timeout: 1000 });
    assert.fail('should have rejected');
  } catch (e) {
    rejected = e;
  }
  assert.equal(rejected, sentinel);
  assert.notEqual(rejected._watchdogTimeout, true);
});

test('parser-watchdog: async rejection passes through verbatim', async () => {
  // Same contract on the async path — a real renderer error must reach
  // the caller as-is so `RenderRoute` can pick the right fallback.
  const sentinel = new Error('async-parser-internal');
  let rejected = null;
  try {
    await ParserWatchdog.run(
      () => Promise.reject(sentinel),
      { timeout: 1000 }
    );
    assert.fail('should have rejected');
  } catch (e) {
    rejected = e;
  }
  assert.equal(rejected, sentinel);
  assert.notEqual(rejected._watchdogTimeout, true);
});

test('parser-watchdog: signal is provided even when fn is sync', async () => {
  // Per the docstring, `fn` is ALWAYS invoked with `{ signal }` so the
  // renderer-side contract is uniform. Verify even the sync path
  // receives the abort signal (it just won't fire because sync returns
  // before the timer).
  let signal = null;
  await ParserWatchdog.run(({ signal: s }) => { signal = s; return 1; }, { timeout: 1000 });
  // Signal may legitimately be null in environments without
  // `AbortController`, but our sandbox provides one.
  assert.ok(signal, 'signal must be passed even on sync path');
  assert.equal(signal.aborted, false);
});
