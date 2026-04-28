'use strict';
// zlib.test.js — embedded compressed-blob detection.
//
// `_findCompressedBlobCandidates(bytes, context)` is a magic-byte scan
// for gzip (1F 8B), zlib (78 01/9C/DA/5E with the RFC 1950 §2.2 header
// checksum gate), and embedded ZIP (PK\x03\x04). This test file
// covers the pure scan path — no vendored library needed. The eager
// decompression path (`_processCompressedCandidate`) requires the
// `Decompressor` global (which in turn needs vendored pako) and is
// covered by the e2e fixture suite.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/zlib.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

/**
 * Build a Uint8Array prefixed with the given bytes followed by zero
 * padding to ensure the scanner has room to inspect.
 */
function buf(prefix, totalLen) {
  const out = new Uint8Array(totalLen);
  for (let i = 0; i < prefix.length; i++) out[i] = prefix[i];
  return out;
}

test('zlib: detects gzip magic at offset 0', () => {
  // Gzip magic is 1F 8B; it has no header-checksum gate so any 1F 8B
  // followed by any byte fires.
  const bytes = buf([0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0], 64);
  const candidates = d._findCompressedBlobCandidates(bytes, {});
  const gz = host(candidates.filter(c => c.format === 'gzip'));
  assert.ok(gz.length >= 1, `expected gzip candidate; got: ${JSON.stringify(host(candidates))}`);
  assert.equal(gz[0].offset, 0);
  assert.equal(gz[0].label, 'Gzip');
});

test('zlib: detects valid zlib header (78 9C, FCHECK passes)', () => {
  // 0x78 0x9C: 0x789C = 30876 = 31 × 996 → divisible by 31. The
  // RFC 1950 §2.2 FCHECK gate accepts.
  const bytes = buf([0x78, 0x9C, 0xAA, 0xBB, 0xCC, 0xDD], 32);
  const candidates = d._findCompressedBlobCandidates(bytes, {});
  const zl = host(candidates.filter(c => c.format === 'zlib'));
  assert.ok(zl.length >= 1, `expected zlib candidate; got: ${JSON.stringify(host(candidates))}`);
  assert.equal(zl[0].offset, 0);
  assert.equal(zl[0].label, 'Zlib (default)');
});

test('zlib: rejects 0x78 0x9D (FCHECK fails) — no false positive', () => {
  // 0x789D = 30877; 30877 / 31 = 995.7… → not divisible by 31, so the
  // FCHECK gate should reject. This is THE thing that stops random
  // 0x78 bytes inside arbitrary binary data from being false-flagged
  // as compressed payloads.
  const bytes = buf([0x78, 0x9D, 0, 0, 0], 32);
  const candidates = d._findCompressedBlobCandidates(bytes, {});
  const zl = host(candidates.filter(c => c.format === 'zlib' && c.offset === 0));
  assert.equal(zl.length, 0, 'invalid zlib FCHECK must not emit a candidate');
});

test('zlib: detects embedded PK\\x03\\x04 ZIP local file header', () => {
  // PK\x03\x04 inside a non-ZIP-container file is a legitimate
  // embedded-archive signal (e.g. a JAR carried inside a binary
  // dropper). The candidate is emitted but NOT decompressed by this
  // function — the eager decompression / JSZip validation lives in
  // `_processCompressedCandidate`.
  const bytes = buf([0x50, 0x4B, 0x03, 0x04, 0, 0], 32);
  const candidates = d._findCompressedBlobCandidates(bytes, {});
  const zip = host(candidates.filter(c => c.format === 'zip'));
  assert.ok(zip.length >= 1);
  assert.equal(zip[0].offset, 0);
  assert.equal(zip[0].label, 'Embedded ZIP');
});

test('zlib: skips scanning inside zip-container fileTypes', () => {
  // ZIP-based container formats (OOXML, ODF, JAR, APK, EPUB, …) have
  // PK\x03\x04 local file headers as STRUCTURE, not embedded payload.
  // The scanner must short-circuit for these fileTypes so we don't
  // flag every internal entry header as an "embedded ZIP".
  const bytes = buf([0x50, 0x4B, 0x03, 0x04, 0, 0], 32);
  // docx, jar, odt, …
  for (const fileType of ['docx', 'jar', 'odt', 'apk', 'epub']) {
    const candidates = d._findCompressedBlobCandidates(bytes, { fileType });
    assert.deepEqual(host(candidates), [], `must skip scan inside ${fileType}`);
  }
});

test('zlib: returns empty for too-short input', () => {
  // The function bails when `bytes.length < 8` — defensive against
  // tiny user-supplied buffers (extracted strings, magic-prefix
  // probes, etc.).
  const candidates = d._findCompressedBlobCandidates(new Uint8Array(4), {});
  assert.deepEqual(host(candidates), []);
});

test('zlib: detects zlib magic at non-zero offset', () => {
  // The scan walks the entire buffer (`for i = 0; i < len-4; i++`),
  // so a zlib blob mid-buffer should still be found.
  const len = 128;
  const bytes = new Uint8Array(len);
  // Fill with arbitrary non-magic bytes.
  for (let i = 0; i < len; i++) bytes[i] = 0x55;
  // Plant zlib magic at offset 32. Use 0x78 0xDA (best-compression).
  // 0x78DA = 30938; 30938 / 31 = 998 → valid FCHECK.
  bytes[32] = 0x78;
  bytes[33] = 0xDA;
  const candidates = d._findCompressedBlobCandidates(bytes, {});
  const zl = host(candidates.filter(c => c.format === 'zlib' && c.offset === 32));
  assert.equal(zl.length, 1);
  assert.equal(zl[0].label, 'Zlib (best)');
});
