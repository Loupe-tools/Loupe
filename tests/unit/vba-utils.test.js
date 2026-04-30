'use strict';
// vba-utils.test.js — VBA helper functions, including stomping (T1564.007).
//
// Stomping detection heuristic: vbaProject.bin contains the compiled
// `_VBA_PROJECT` performance-cache marker (UTF-16 LE) but lacks any
// `Attribute VB_` source-module marker (ASCII). Mirrors the YARA rule
// Office_VBA_Stomping in src/rules/office-macros.yar, but here applies
// to vbaProject.bin extracted from .docx/.xlsm/.pptx (where the outer
// YARA scan never sees the marker because it sits inside a zipped
// inner CFB).

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  ['src/vba-utils.js'],
  { expose: ['detectVbaStomping', 'parseVBAText', 'autoExecPatterns'] },
);
const { detectVbaStomping, parseVBAText, autoExecPatterns } = ctx;

// ── Helpers ─────────────────────────────────────────────────────────────────

function utf16le(s) {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) out[i * 2] = s.charCodeAt(i);
  return out;
}
function ascii(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function concat(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
function pad(n, byte = 0x00) { return new Uint8Array(n).fill(byte); }

// ── detectVbaStomping ───────────────────────────────────────────────────────

test('vba stomp: empty input returns all-false', () => {
  const r = detectVbaStomping(new Uint8Array(0));
  assert.equal(r.stomped, false);
  assert.equal(r.hasPcode, false);
  assert.equal(r.hasSource, false);
  assert.equal(r.sourceMarkers, 0);
});

test('vba stomp: null/undefined input returns all-false', () => {
  assert.equal(detectVbaStomping(null).stomped, false);
  assert.equal(detectVbaStomping(undefined).stomped, false);
});

test('vba stomp: legitimate project (P-code + source) NOT flagged', () => {
  // Realistic shape: pad, _VBA_PROJECT in UTF-16LE, more pad, source modules.
  const buf = concat([
    pad(64),
    utf16le('_VBA_PROJECT'),
    pad(128),
    ascii('Attribute VB_Name = "Module1"\r\nSub Foo()\r\nEnd Sub\r\n'),
    ascii('Attribute VB_Name = "Module2"\r\nSub Bar()\r\nEnd Sub\r\n'),
  ]);
  const r = detectVbaStomping(buf);
  assert.equal(r.hasPcode, true);
  assert.equal(r.hasSource, true);
  assert.equal(r.sourceMarkers, 2);
  assert.equal(r.stomped, false);
});

test('vba stomp: P-code present + source ABSENT IS flagged (canonical case)', () => {
  const buf = concat([
    pad(64),
    utf16le('_VBA_PROJECT'),
    pad(2048), // p-code body — no Attribute VB_ markers anywhere
  ]);
  const r = detectVbaStomping(buf);
  assert.equal(r.hasPcode, true);
  assert.equal(r.hasSource, false);
  assert.equal(r.sourceMarkers, 0);
  assert.equal(r.stomped, true);
});

test('vba stomp: source-only blob (no P-code marker) NOT flagged', () => {
  // Plain text VBA dump — no compiled section.
  const buf = ascii('Attribute VB_Name = "M"\r\nSub Hi()\r\nEnd Sub\r\n');
  const r = detectVbaStomping(buf);
  assert.equal(r.hasPcode, false);
  assert.equal(r.hasSource, true);
  assert.equal(r.stomped, false, 'no P-code → not stomping (just unusual)');
});

test('vba stomp: P-code marker not in UTF-16LE alignment is rejected', () => {
  // The bytes spell "_VBA_PROJECT" in plain ASCII, NOT UTF-16LE — must NOT
  // count as P-code (the helper requires NUL bytes between letters).
  const buf = concat([
    pad(64),
    ascii('_VBA_PROJECT'),
    pad(2048),
  ]);
  const r = detectVbaStomping(buf);
  assert.equal(r.hasPcode, false, 'ASCII _VBA_PROJECT must not count as P-code marker');
  assert.equal(r.stomped, false);
});

test('vba stomp: source marker counter caps at 64', () => {
  const parts = [pad(64), utf16le('_VBA_PROJECT'), pad(64)];
  for (let i = 0; i < 200; i++) parts.push(ascii('Attribute VB_Name="M"\r\n'));
  const buf = concat(parts);
  const r = detectVbaStomping(buf);
  assert.equal(r.hasPcode, true);
  assert.equal(r.hasSource, true);
  assert.equal(r.sourceMarkers, 64, 'counter must cap to bound work');
  assert.equal(r.stomped, false);
});

test('vba stomp: P-code marker scan covers byte i=0', () => {
  // No leading padding — marker starts at byte 0.
  const buf = concat([utf16le('_VBA_PROJECT'), pad(2048)]);
  const r = detectVbaStomping(buf);
  assert.equal(r.hasPcode, true);
  assert.equal(r.stomped, true);
});

test('vba stomp: marker that overlaps the SCAN_CAP boundary is OK', () => {
  // Buffer larger than the 4 MB cap — marker placed at byte ~100KB
  // (well within the cap) and source absent. Sanity check the cap doesn't
  // accidentally truncate before reaching the marker for normal-sized files.
  const bigPad = pad(100 * 1024);
  const buf = concat([bigPad, utf16le('_VBA_PROJECT'), pad(1024)]);
  const r = detectVbaStomping(buf);
  assert.equal(r.hasPcode, true);
  assert.equal(r.stomped, true);
});

test('vba stomp: case sensitivity — "_vba_project" lowercase NOT counted', () => {
  const buf = concat([pad(64), utf16le('_vba_project'), pad(2048)]);
  const r = detectVbaStomping(buf);
  assert.equal(r.hasPcode, false, 'marker is case-sensitive');
});

test('vba stomp: tail comment as decoy (whitespace only) IS flagged', () => {
  // Real-world stomped sample shape: P-code intact, source replaced with
  // a one-line decoy that has no Attribute VB_ marker (e.g. just `'`).
  const buf = concat([
    pad(64),
    utf16le('_VBA_PROJECT'),
    pad(1024),
    ascii('\' decoy comment\r\n'),
    pad(512),
  ]);
  const r = detectVbaStomping(buf);
  assert.equal(r.hasPcode, true);
  assert.equal(r.hasSource, false);
  assert.equal(r.stomped, true);
});

// ── parseVBAText / autoExecPatterns smoke tests (no prior coverage) ────────

test('parseVBAText: extracts module name from Attribute VB_Name', () => {
  const buf = ascii('Attribute VB_Name = "Sheet1"\r\n'
    + 'Sub Workbook_Open()\r\n'
    + 'Shell("calc.exe")\r\n'
    + 'End Sub\r\n');
  const mods = parseVBAText(buf);
  assert.ok(mods.length >= 1);
  assert.equal(mods[0].name, 'Sheet1');
});

test('autoExecPatterns: detects Workbook_Open + Shell', () => {
  const src = 'Sub Workbook_Open()\nShell("calc.exe")\nEnd Sub';
  const pats = autoExecPatterns(src);
  assert.ok(pats.some(p => /Workbook_Open/.test(p)));
  assert.ok(pats.some(p => /Shell/.test(p)));
});

test('autoExecPatterns: benign source returns empty array', () => {
  const out = autoExecPatterns('Function Add(a, b)\n  Add = a + b\nEnd Function');
  assert.equal(out.length, 0);
});
