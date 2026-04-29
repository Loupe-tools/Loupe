'use strict';
// capabilities.test.js — capa-lite capability tagger.
//
// `Capabilities.detect({imports, dylibs, strings})` walks the static
// rule list in `src/capabilities.js` and returns the named behaviours
// each binary's API + string corpus matches. The PE / ELF / Mach-O
// renderers feed the result into the IOC sidebar (Pattern rows tagged
// `[capability]`) and the riskScore tally.
//
// This file pins the behavioural contract for the noise-reduction work
// landed 2026-04 (split quorum, tightened anti-debug, network-winhttp
// quorum) — failures here usually mean a future contributor relaxed a
// quorum and re-introduced false positives on benign system DLLs.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

function fresh() {
  // capabilities.js is pure — no constants needed for `detect()` itself.
  return loadModules(['src/capabilities.js'], { expose: ['Capabilities'] });
}

function ids(caps) { return caps.map(c => c.id).sort(); }

test('detect: returns empty for empty inputs', () => {
  // `assert.deepEqual` checks prototype-identity across realms, and the
  // returned array is constructed in the vm context — so compare length
  // instead of relying on Array-identity.
  const ctx = fresh();
  assert.equal(ctx.Capabilities.detect({}).length, 0);
  assert.equal(ctx.Capabilities.detect({ imports: [], strings: [], dylibs: [] }).length, 0);
});

test('anti-debug-winapi: requires QUORUM ≥ 2 — single API alone never fires', () => {
  // Pre-2026-04 the rule had `any:true` and lit up on any single
  // anti-debug API, which produced FPs on every CRT-using binary.
  // Now it needs at least 2 imports / strings combined. Verify a
  // single-import sample stays quiet.
  const ctx = fresh();
  const caps = ctx.Capabilities.detect({
    imports: ['isdebuggerpresent'],   // ONE only
    strings: [],
  });
  assert.equal(caps.find(c => c.id === 'anti-debug-winapi'), undefined,
               'single anti-debug import must not fire the cluster');
});

test('anti-debug-winapi: fires when TWO imports co-occur', () => {
  const ctx = fresh();
  const caps = ctx.Capabilities.detect({
    imports: ['isdebuggerpresent', 'checkremotedebuggerpresent'],
    strings: [],
  });
  const c = caps.find(c => c.id === 'anti-debug-winapi');
  assert.ok(c, 'anti-debug cluster should fire on 2 cooperating imports');
  assert.equal(c.severity, 'medium');
  assert.equal(c.mitre, 'T1622');
});

test('anti-debug-winapi: fires when ONE import + ONE PEB-walk string co-occur', () => {
  // Tightened rule combines import and string hits into a single quorum
  // total — a `RtlGetNtGlobalFlags` import + a `BeingDebugged` string
  // reference is the classic PEB-walk pattern even without two distinct
  // anti-debug imports.
  const ctx = fresh();
  const caps = ctx.Capabilities.detect({
    imports: ['rtlgetntglobalflags'],
    strings: ['fs:[30h]+0x68 BeingDebugged'],
  });
  assert.ok(caps.find(c => c.id === 'anti-debug-winapi'),
            'import+string quorum should fire the anti-debug cluster');
});

test('sandbox-sleep-skip: split quorum requires BOTH timing AND stalling primitives', () => {
  // The split-quorum policy means `Sleep` + `SleepEx` (two stalling APIs
  // alone) must NOT fire — that is benign Windows CRT init. A timing
  // primitive (`GetTickCount`) needs to co-occur with the stalling
  // primitive for the sandbox-evasion pattern to be plausible.
  const ctx = fresh();
  const stallingOnly = ctx.Capabilities.detect({
    imports: ['sleep', 'sleepex'],
  });
  assert.equal(stallingOnly.find(c => c.id === 'sandbox-sleep-skip'), undefined,
               'two stalling primitives alone must not fire sandbox-sleep-skip');

  const timingOnly = ctx.Capabilities.detect({
    imports: ['gettickcount', 'queryperformancecounter'],
  });
  assert.equal(timingOnly.find(c => c.id === 'sandbox-sleep-skip'), undefined,
               'two timing primitives alone must not fire sandbox-sleep-skip');

  const bothBuckets = ctx.Capabilities.detect({
    imports: ['gettickcount', 'sleep'],
  });
  assert.ok(bothBuckets.find(c => c.id === 'sandbox-sleep-skip'),
            'one timing + one stalling primitive together must fire');
});

test('network-winhttp: requires QUORUM ≥ 2 — single API alone never fires', () => {
  // The pair we want is "open the request" + "send the request" (or any
  // two of the canonical WinHTTP / InternetOpen / URLDownloadToFile API
  // names). A single InternetOpenA alone is the classic "benign update
  // check" pattern that pre-quorum produced FPs on.
  const ctx = fresh();
  const single = ctx.Capabilities.detect({
    imports: ['winhttpopen'],
  });
  assert.equal(single.find(c => c.id === 'network-winhttp'), undefined);

  const two = ctx.Capabilities.detect({
    imports: ['winhttpopenrequest', 'winhttpsendrequest'],
  });
  assert.ok(two.find(c => c.id === 'network-winhttp'),
            'two WinHTTP APIs together should fire the cluster');
});

test('proc-injection-classic: AND semantics across all 3 imports', () => {
  // The classic CreateRemoteThread cluster has no `any`/`quorum` flag —
  // every listed import must be present. This guards against a relaxed
  // rule firing on a benign sample with just `VirtualAllocEx`.
  const ctx = fresh();
  const partial = ctx.Capabilities.detect({
    imports: ['virtualallocex', 'writeprocessmemory'],
  });
  assert.equal(partial.find(c => c.id === 'proc-injection-classic'), undefined);
  const full = ctx.Capabilities.detect({
    imports: ['virtualallocex', 'writeprocessmemory', 'createremotethread'],
  });
  const cap = full.find(c => c.id === 'proc-injection-classic');
  assert.ok(cap);
  assert.equal(cap.severity, 'high');
  // Spread cap.evidence into a host-realm array before comparing — see
  // the cross-realm note on the empty-inputs test.
  const ev = Array.from(cap.evidence).sort();
  assert.equal(ev.length, 3);
  assert.equal(ev[0], 'createremotethread');
  assert.equal(ev[1], 'virtualallocex');
  assert.equal(ev[2], 'writeprocessmemory');
});

test('detect: returns evidence tokens that actually matched', () => {
  const ctx = fresh();
  const caps = ctx.Capabilities.detect({
    imports: ['isdebuggerpresent', 'checkremotedebuggerpresent'],
  });
  const c = caps.find(c => c.id === 'anti-debug-winapi');
  assert.ok(c);
  for (const tok of c.evidence) {
    assert.ok(['isdebuggerpresent', 'checkremotedebuggerpresent'].includes(tok),
              `unexpected evidence token: ${tok}`);
  }
});

test('detect: never returns the same capability id twice for one call', () => {
  // Rules are written so `id` is unique within `_CAPABILITIES`; this
  // guards against a future refactor that accidentally creates a dupe.
  const ctx = fresh();
  const caps = ctx.Capabilities.detect({
    imports: ['isdebuggerpresent', 'checkremotedebuggerpresent',
              'virtualallocex', 'writeprocessmemory', 'createremotethread'],
  });
  const seen = new Set();
  for (const c of caps) {
    assert.ok(!seen.has(c.id), `duplicate capability id: ${c.id}`);
    seen.add(c.id);
  }
});

test('detect: every result has the documented public shape', () => {
  const ctx = fresh();
  const caps = ctx.Capabilities.detect({
    imports: ['virtualallocex', 'writeprocessmemory', 'createremotethread'],
  });
  assert.ok(caps.length > 0);
  for (const c of caps) {
    assert.equal(typeof c.id, 'string');
    assert.equal(typeof c.name, 'string');
    assert.equal(typeof c.severity, 'string');
    assert.equal(typeof c.mitre, 'string');
    assert.equal(typeof c.description, 'string');
    assert.ok(Array.isArray(c.evidence));
    // MITRE IDs are like `T1055.012` or `T1622`. No bare grouping strings.
    assert.match(c.mitre, /^T\d{4}(?:\.\d{3})?$/, `bad mitre id: ${c.mitre}`);
  }
});

// Sanity: ensure the rule list itself doesn't accidentally re-introduce
// a relaxed `any:true` on the anti-debug-winapi rule. This is the most
// likely regression pattern (a contributor reverts to the simpler form
// because a single test sample stops firing).
test('rule integrity: anti-debug-winapi keeps quorum semantics', () => {
  const ctx = fresh();
  // Run a single-import probe and assert it does NOT fire. If a future
  // refactor flips back to `any:true` this will catch it immediately.
  const caps = ctx.Capabilities.detect({ imports: ['outputdebugstringa'] });
  assert.equal(caps.find(c => c.id === 'anti-debug-winapi'), undefined,
               'anti-debug-winapi must require quorum ≥ 2 — never `any:true`');
});

// The PE / ELF / Mach-O renderers depend on stable `id` strings (they
// build the `capCategory` map keyed off them). Lock down a small set of
// well-known ids so a renaming / id-rotation gets caught here before
// the gating maps drift.
test('rule integrity: stable capability ids the renderers depend on', () => {
  const ctx = fresh();
  const fired = ctx.Capabilities.detect({
    imports: [
      // anti-debug-winapi (quorum ≥ 2)
      'isdebuggerpresent', 'checkremotedebuggerpresent',
      // proc-injection-classic
      'virtualallocex', 'writeprocessmemory', 'createremotethread',
      // network-winhttp (quorum ≥ 2)
      'winhttpopenrequest', 'winhttpsendrequest',
      // sandbox-sleep-skip (split quorum)
      'gettickcount', 'sleep',
    ],
  });
  const got = ids(fired);
  for (const id of [
    'anti-debug-winapi',
    'proc-injection-classic',
    'network-winhttp',
    'sandbox-sleep-skip',
  ]) {
    assert.ok(got.includes(id), `expected capability id "${id}" to fire — got [${got.join(', ')}]`);
  }
});
