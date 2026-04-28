'use strict';
// archive-budget.test.js — recursive archive-expansion budget guard.
//
// `ArchiveBudget` aggregates entry / byte counts across every archive
// renderer in the recursion (top-level ZIP → JAR → MSIX → 7z…). A single
// pure class with three counters and two configurable caps lifted from
// `PARSER_LIMITS`. Tests cover the four contract points: fresh budget is
// healthy, `consume` advances counters, exhaustion latches `reason`, and
// `reset()` restores the budget for a subsequent top-level load.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// `archive-budget.js` reads PARSER_LIMITS for the two caps; load
// constants.js first so the module sees the production values rather
// than its own internal fallbacks.
const ctx = loadModules(['src/constants.js', 'src/archive-budget.js']);
const { ArchiveBudget, PARSER_LIMITS } = ctx;

test('archive-budget: fresh budget is unexhausted, zeroed counters', () => {
  // The contract: a brand-new ArchiveBudget reports zero entries / bytes
  // and `exhausted === false`. Renderers gate every push on `consume`,
  // so a stale-state-leak across loads would silently truncate the next
  // archive — guard via the public surface.
  const b = new ArchiveBudget();
  assert.equal(b.exhausted, false);
  assert.equal(b.reason, '');
  assert.equal(b.entries, 0);
  assert.equal(b.bytes, 0);
});

test('archive-budget: consume advances counters and stays healthy', () => {
  // Three small rows under both caps must succeed and accumulate.
  const b = new ArchiveBudget();
  assert.equal(b.consume(1, 1024), true);
  assert.equal(b.consume(1, 2048), true);
  assert.equal(b.consume(2, 4096), true);
  assert.equal(b.entries, 4);
  assert.equal(b.bytes, 7168);
  assert.equal(b.exhausted, false);
});

test('archive-budget: exhausting MAX_AGGREGATE_ENTRIES latches reason', () => {
  // Pump entries past the cap in a single call. Renderers commonly do
  // 1-by-1 consumption inside the for loop, but `consume(N, …)` accepts
  // a batch entry count so a single overflow scenario is enough.
  const b = new ArchiveBudget();
  const cap = PARSER_LIMITS.MAX_AGGREGATE_ENTRIES;
  // First call sits just under the cap; second call pushes us over.
  assert.equal(b.consume(cap, 0), true);
  assert.equal(b.consume(1, 0), false);
  assert.equal(b.exhausted, true);
  // The reason string is the public-facing analyst message.
  assert.match(b.reason, /entry budget exhausted/i);
  assert.match(b.reason, new RegExp(cap.toLocaleString().replace('.', '\\.')));
});

test('archive-budget: exhausting MAX_AGGREGATE_DECOMPRESSED_BYTES latches reason', () => {
  // Same flow, byte cap path.
  const b = new ArchiveBudget();
  const cap = PARSER_LIMITS.MAX_AGGREGATE_DECOMPRESSED_BYTES;
  assert.equal(b.consume(1, cap), true);
  assert.equal(b.consume(1, 1), false);
  assert.equal(b.exhausted, true);
  assert.match(b.reason, /decompressed-bytes budget exhausted/i);
});

test('archive-budget: exhausted budget short-circuits subsequent consume', () => {
  // Once exhausted, `consume` returns false without further work — the
  // counters past the trip point are intentionally allowed to keep
  // climbing for telemetry, but the return value is the gate.
  const b = new ArchiveBudget();
  // Force exhaustion via the entry cap.
  b.consume(PARSER_LIMITS.MAX_AGGREGATE_ENTRIES + 1, 0);
  assert.equal(b.exhausted, true);
  // Subsequent calls must short-circuit (no extra work, false return).
  assert.equal(b.consume(1, 100), false);
  assert.equal(b.consume(0, 0), false);
});

test('archive-budget: reset() clears state for next top-level load', () => {
  // Drill-down loads share a budget intentionally — the renderers must
  // NOT call reset(). But App._handleFiles MUST. Verify reset restores
  // every public-surface property to its initial value.
  const b = new ArchiveBudget();
  b.consume(PARSER_LIMITS.MAX_AGGREGATE_ENTRIES + 1, 0);
  assert.equal(b.exhausted, true);
  b.reset();
  assert.equal(b.exhausted, false);
  assert.equal(b.reason, '');
  assert.equal(b.entries, 0);
  assert.equal(b.bytes, 0);
  // After reset, consumption works again.
  assert.equal(b.consume(1, 1024), true);
});

test('archive-budget: defensive coercion of bogus inputs', () => {
  // Renderers feed `e.uncompressedSize | 0` — but defensive coding in
  // ArchiveBudget should still survive `NaN`, negative values, etc.
  // without throwing. The parser-watchdog / sidebar would cope, but
  // belt-and-braces.
  const b = new ArchiveBudget();
  assert.equal(b.consume(NaN, NaN), true);
  assert.equal(b.consume(-1, -1), true);
  assert.equal(b.entries, 0);
  assert.equal(b.bytes, 0);
});
