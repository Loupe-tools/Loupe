'use strict';
// ioc-extract-trojan-source.test.js — Trojan Source / Unicode bidi flagging.
//
// Three classes:
//   • Bidi controls (CVE-2021-42574) — RLO/LRO/RLI/etc embedded in code or
//     text that flips render order against parser order.
//   • Invisible characters (ZWSP/ZWNJ/ZWJ/WJ/BOM) inside identifiers — used
//     to fork two visually-identical names into distinct symbols.
//   • Mixed-script identifiers — Latin paired with Cyrillic or Greek inside
//     a single word-shaped run. Catches `раypal` (Cyrillic-а), `scаle`, etc.
//
// All three surface as IOC.PATTERN at medium severity. Each class is
// capped at 8 hits per scan to bound sidebar noise on hostile inputs.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/constants.js', 'src/ioc-extract.js']);
const { extractInterestingStringsCore, IOC } = ctx;

function patternsContaining(findings, needle) {
  return host(findings
    .filter(e => e.type === IOC.PATTERN && e.url.includes(needle))
    .map(e => ({ url: e.url, severity: e.severity, note: e.note || null })));
}

test('trojan-source: RLO bidi control flagged with codepoint', () => {
  // Classic Trojan Source one-liner — RLO inside a comment.
  const src = '/* admin\u202E zone secret */ const x = 1;';
  const r = extractInterestingStringsCore(src);
  const hits = patternsContaining(r.findings, 'Trojan Source');
  assert.ok(hits.length >= 1, `expected at least one bidi finding: ${JSON.stringify(hits)}`);
  assert.ok(hits[0].url.includes('U+202E'),
    `expected codepoint U+202E in finding: ${hits[0].url}`);
  assert.equal(hits[0].severity, 'medium');
});

test('trojan-source: PDI/LRI/FSI all caught', () => {
  for (const ch of ['\u202A', '\u202B', '\u202C', '\u202D', '\u2066', '\u2067', '\u2068', '\u2069']) {
    const r = extractInterestingStringsCore(`prefix ${ch} suffix`);
    const hits = patternsContaining(r.findings, 'bidi control');
    assert.ok(hits.length >= 1,
      `bidi control U+${ch.codePointAt(0).toString(16)} must be flagged`);
  }
});

test('trojan-source: ZWSP inside identifier flagged', () => {
  // `pas\u200Bsword` renders identically to `password` but is a different
  // symbol — classic identifier-fork attack.
  const r = extractInterestingStringsCore('let pas\u200Bsword = "secret";');
  const hits = patternsContaining(r.findings, 'Invisible character');
  assert.ok(hits.length >= 1, `expected invisible-char finding: ${JSON.stringify(hits)}`);
  assert.ok(hits[0].url.includes('U+200B'),
    `expected U+200B codepoint, got: ${hits[0].url}`);
});

test('trojan-source: ZWSP between non-word chars NOT flagged', () => {
  // ZWNJ between non-word chars (legitimate use in some scripts) must not
  // false-positive. Identifier rule requires `\w{2,}` either side.
  const r = extractInterestingStringsCore('text. \u200B "more text"');
  const hits = patternsContaining(r.findings, 'Invisible character');
  assert.equal(hits.length, 0,
    `non-identifier ZWSP must not flag: ${JSON.stringify(hits)}`);
});

test('trojan-source: mixed Latin+Cyrillic identifier flagged', () => {
  // `раypal` — first two are Cyrillic 'р' (U+0440) + 'а' (U+0430).
  const r = extractInterestingStringsCore('login at \u0440\u0430ypal-secure.com');
  const hits = patternsContaining(r.findings, 'Mixed-script');
  assert.ok(hits.length >= 1, `expected mixed-script finding: ${JSON.stringify(hits)}`);
  assert.ok(hits[0].url.includes('Latin + Cyrillic'),
    `expected blend label: ${hits[0].url}`);
});

test('trojan-source: mixed Latin+Greek identifier flagged', () => {
  // `scale` with Greek alpha (U+03B1) instead of Latin 'a'.
  const r = extractInterestingStringsCore('use sc\u03B1le() carefully');
  const hits = patternsContaining(r.findings, 'Mixed-script');
  assert.ok(hits.length >= 1, `expected mixed-script finding: ${JSON.stringify(hits)}`);
  assert.ok(hits[0].url.includes('Latin + Greek'),
    `expected blend label: ${hits[0].url}`);
});

test('trojan-source: pure Latin / pure Cyrillic prose NOT flagged', () => {
  // Russian text on its own is not an attack signal.
  const r = extractInterestingStringsCore('\u041F\u0440\u0438\u0432\u0435\u0442 mir');
  // The "mir" run has no Cyrillic so it's fine; the Cyrillic run has no
  // Latin so it's fine. Each identifier is single-script — must not fire.
  const hits = patternsContaining(r.findings, 'Mixed-script');
  assert.equal(hits.length, 0,
    `pure-script runs must not flag: ${JSON.stringify(hits)}`);
});

test('trojan-source: cap at 8 hits per class to bound sidebar noise', () => {
  // 50 RLO-tainted lines should produce ≤ 8 findings.
  const tainted = Array.from({ length: 50 }, (_, i) => `line ${i} \u202E end`).join('\n');
  const r = extractInterestingStringsCore(tainted);
  const hits = patternsContaining(r.findings, 'bidi control');
  assert.ok(hits.length <= 8,
    `expected ≤ 8 capped hits, got ${hits.length}`);
  assert.ok(hits.length >= 1,
    `expected at least one hit before the cap kicks in`);
});

test('trojan-source: ASCII-only input emits nothing', () => {
  const r = extractInterestingStringsCore(
    'Plain ASCII source code. No bidi. No invisibles. password123 is fine.'
  );
  const hits = host(r.findings.filter(e => e.type === IOC.PATTERN
    && (e.url.includes('Trojan') || e.url.includes('Invisible') || e.url.includes('Mixed-script'))));
  assert.equal(hits.length, 0, `ASCII must produce zero hits, got: ${JSON.stringify(hits)}`);
});

test('trojan-source: severity is medium for all three classes', () => {
  const src = 'a\u202Eb pas\u200Bsword \u0440\u0430ypal';
  const r = extractInterestingStringsCore(src);
  const all = host(r.findings.filter(e => e.type === IOC.PATTERN
    && (e.url.includes('Trojan') || e.url.includes('Invisible') || e.url.includes('Mixed-script')))
    .map(e => e.severity));
  assert.ok(all.length >= 3, `expected at least 3 hits, got: ${all.length}`);
  for (const s of all) assert.equal(s, 'medium');
});
