'use strict';
// encoding-decoders.test.js — `_decodeCandidate` dispatcher and the
// per-encoding decoders for the secondary encoding family.
//
// `_decodeCandidate(candidate)` is the single switch dispatched by
// `_processCandidate`. Each `case` returns a `Uint8Array` (or `null`)
// that downstream classification / IOC extraction consumes. The
// per-encoding decoders are pure string → bytes round-trips; this
// file tests representatives of each branch.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// `_decodeCandidate` and the per-encoding decoders live in
// encoding-decoders.js; the Base64 / Hex / Base32 cases inside the
// switch delegate back to `_decodeBase64` / `_decodeHex` /
// `_decodeBase32` from base64-hex.js, so we load both.
const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/base64-hex.js',
  'src/decoders/encoding-decoders.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

function bytesToString(bytes) {
  return new TextDecoder().decode(bytes);
}

test('encoding-decoders: dispatches Base64 candidates to _decodeBase64', () => {
  // The dispatcher is a thin switch — verify the wiring lands on the
  // right decoder for each `candidate.type` label.
  const out = d._decodeCandidate({ type: 'Base64', raw: 'SGk=' });
  assert.equal(bytesToString(out), 'Hi');
});

test('encoding-decoders: dispatches Hex / escaped-Hex / PS-byte-array', () => {
  // All three "hex-shape" labels share the same decoder.
  const a = d._decodeCandidate({ type: 'Hex', raw: '4869' });
  const b = d._decodeCandidate({ type: 'Hex (escaped)', raw: '4869' });
  const c = d._decodeCandidate({ type: 'Hex (PS byte array)', raw: '4869' });
  assert.equal(bytesToString(a), 'Hi');
  assert.equal(bytesToString(b), 'Hi');
  assert.equal(bytesToString(c), 'Hi');
});

test('encoding-decoders: _decodeUrlEncoded handles standard %XX', () => {
  // Real-world payloads use percent-encoding for `:` `/` `?` `&`.
  const out = d._decodeCandidate({
    type: 'URL Encoding',
    raw: 'https%3A%2F%2Fevil.example.com%2Fp%3Fa%3D1',
  });
  assert.equal(bytesToString(out), 'https://evil.example.com/p?a=1');
});

test('encoding-decoders: _decodeHtmlEntities decimal subtype', () => {
  // `&#72;` → 'H'. Common JS-eval obfuscation: `eval(String.fromCharCode(…))`
  // pasted as HTML entity sequence in a script body.
  const out = d._decodeCandidate({
    type: 'HTML Entities',
    raw: '&#72;&#101;&#108;&#108;&#111;',
    _subtype: 'decimal',
  });
  assert.equal(bytesToString(out), 'Hello');
});

test('encoding-decoders: _decodeHtmlEntities hex subtype', () => {
  // `&#x48;` → 'H'. The `_subtype: 'hex'` selector toggles the regex.
  const out = d._decodeCandidate({
    type: 'HTML Entities',
    raw: '&#x48;&#x69;',
    _subtype: 'hex',
  });
  assert.equal(bytesToString(out), 'Hi');
});

test('encoding-decoders: _decodeUnicodeEscapes handles \\uXXXX', () => {
  // JS / JSON unicode escape sequence — common in obfuscated JS.
  const out = d._decodeCandidate({
    type: 'Unicode Escape',
    raw: '\\u0048\\u0069',
  });
  assert.equal(bytesToString(out), 'Hi');
});

test('encoding-decoders: _decodeCharArray default subtype splits on commas', () => {
  // The default subtype is the JS `[72, 105]` / fromCharCode array
  // shape — comma-split, parseInt each, reassemble.
  const out = d._decodeCandidate({ type: 'Char Array', raw: '72, 105' });
  assert.equal(bytesToString(out), 'Hi');
});

test('encoding-decoders: _decodeCharArray subtype "ps-char" parses [char]N', () => {
  // PowerShell `[char]72 + [char]105` → "Hi". The regex extracts the
  // numeric arguments.
  const out = d._decodeCandidate({
    type: 'Char Array',
    raw: '[char]72 + [char]105',
    _subtype: 'ps-char',
  });
  assert.equal(bytesToString(out), 'Hi');
});

test('encoding-decoders: _decodeOctalEscapes handles \\NNN', () => {
  // Perl / shell-style octal escapes: `\110` (0o110 = 72) → 'H'.
  const out = d._decodeCandidate({
    type: 'Octal Escape',
    raw: '\\110\\151',
  });
  assert.equal(bytesToString(out), 'Hi');
});

test('encoding-decoders: _decodeRot13 rotates ASCII letters by 13', () => {
  // Classic ROT13: "Uryyb, Jbeyq!" → "Hello, World!"
  const out = d._decodeCandidate({
    type: 'ROT13',
    raw: 'Uryyb, Jbeyq!',
  });
  assert.equal(bytesToString(out), 'Hello, World!');
});

test('encoding-decoders: _decodeRotN supports arbitrary 1..25 shift', () => {
  // ROT-N is the bruteforce-mode generalisation of ROT13 — the shift
  // arrives on the candidate as `_shift`. Caesar shift of 3:
  // "Khoor" → "Hello".
  const out = d._decodeCandidate({
    type: 'ROT-N',
    raw: 'Khoor',
    _shift: 23, // inverse of +3 (26 - 3 = 23)
  });
  assert.equal(bytesToString(out), 'Hello');
});

test('encoding-decoders: _decodeJsHexEscape handles \\xHH pairs', () => {
  // The most common JS string-obfuscation form. Mirror finder is in
  // base64-hex.js (label: "Hex (escaped)") which also decodes here.
  const out = d._decodeCandidate({
    type: 'JS Hex Escape',
    raw: '\\x48\\x65\\x6c\\x6c\\x6f',
  });
  assert.equal(bytesToString(out), 'Hello');
});

test('encoding-decoders: _decodeSplitJoin reassembles a separator-spaced string', () => {
  // JS / PowerShell `'Hello'.split('|').join('')` → drops the `|`
  // separators. The decoder's job is the join step (the finder
  // picks up the candidate already in fully-separated shape).
  const out = d._decodeCandidate({
    type: 'Split-Join',
    raw: 'H|e|l|l|o',
    _separator: '|',
  });
  assert.equal(bytesToString(out), 'Hello');
});

test('encoding-decoders: synthetic XOR candidate returns _xorBytes verbatim', () => {
  // The XOR case is special: the synthetic candidate carries the
  // pre-computed cleartext on `_xorBytes`. The dispatcher just hands
  // it back so the regular classification / IOC / recursion path runs
  // on the post-XOR bytes.
  const fakeBytes = new Uint8Array([72, 105]);
  const out = d._decodeCandidate({ type: 'XOR', _xorBytes: fakeBytes });
  assert.strictEqual(out, fakeBytes);
});

test('encoding-decoders: unknown candidate type returns null', () => {
  // The default branch: any label not in the switch returns null so
  // the caller drops the candidate cleanly.
  assert.equal(d._decodeCandidate({ type: 'Not-A-Real-Type', raw: 'x' }), null);
});
