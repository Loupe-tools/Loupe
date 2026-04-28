'use strict';
// whitelist.test.js — context-based whitelist predicates for the
// encoded-content detector.
//
// These predicates inspect the ±N-char window around a candidate offset
// to decide whether the match is benign infrastructure (data: URI, PEM
// block, CSS @font-face, MIME body, GUID, hash literal, PowerShell
// -EncodedCommand) and should be skipped before the heavy decode pass.
// All methods are pure / side-effect free.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/whitelist.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

test('whitelist: _isDataURI matches `data:image/png;base64,…` lookback', () => {
  // The Base64 candidate inside a data: URI is the URI's payload itself
  // — the inline image renderer handles it; the encoded-content
  // detector should skip.
  const text = 'src="data:image/png;base64,iVBORw0KGgoAAAA"';
  // The Base64 payload starts after the comma; offset = position of `i`.
  const offset = text.indexOf('iVBORw');
  assert.equal(d._isDataURI(text, offset), true);
});

test('whitelist: _isDataURI rejects when no preceding data: scheme', () => {
  const text = 'A bare token: iVBORw0KGgoAAAA';
  const offset = text.indexOf('iVBORw');
  assert.equal(d._isDataURI(text, offset), false);
});

test('whitelist: _isPEMBlock matches PEM block header', () => {
  // PEM-armoured Base64 (CERTIFICATE / RSA PRIVATE KEY / etc.) is
  // legitimate cryptographic material; the candidate region inside
  // the block is the actual key bytes — skipped by design.
  const text = '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJ...';
  const offset = text.indexOf('MIIDXTCC');
  assert.equal(d._isPEMBlock(text, offset), true);
});

test('whitelist: _isCSSFontData matches `src: url(data:font/…` lookback', () => {
  // Inline base64 fonts in CSS @font-face are huge and noisy. Skip.
  const text = "@font-face { src: url(data:font/woff2;base64,d09GMgABAAAAAAQ";
  const offset = text.indexOf('d09GMgAB');
  assert.equal(d._isCSSFontData(text, offset), true);
});

test('whitelist: _isMIMEBody only fires for fileType=eml', () => {
  // The EML renderer already extracts MIME-encoded attachments; the
  // encoded-content scanner shouldn't double-report. Gate is on
  // `context.fileType === 'eml'` AND a Content-Transfer-Encoding:
  // base64 header within 300 chars before the candidate.
  const header = 'Content-Transfer-Encoding: base64\n\n';
  const text = header + 'iVBORw0KGgoAAAANSUhEUgAA';
  const offset = text.indexOf('iVBORw');
  assert.equal(d._isMIMEBody(text, offset, { fileType: 'eml' }), true);
  // Same buffer, non-EML fileType → never matches.
  assert.equal(d._isMIMEBody(text, offset, { fileType: 'txt' }), false);
});

test('whitelist: _isHashLength flags MD5/SHA-1/SHA-256/SHA-512', () => {
  // Hex strings of the exact canonical hash widths (32, 40, 64, 128
  // hex chars) are dropped — they're overwhelmingly hash literals
  // rather than encoded payloads.
  assert.equal(d._isHashLength('a'.repeat(32)), true);  // MD5
  assert.equal(d._isHashLength('a'.repeat(40)), true);  // SHA-1
  assert.equal(d._isHashLength('a'.repeat(64)), true);  // SHA-256
  assert.equal(d._isHashLength('a'.repeat(128)), true); // SHA-512
  // Non-canonical lengths (48, 56, …) are NOT hashes — keep them.
  assert.equal(d._isHashLength('a'.repeat(48)), false);
  assert.equal(d._isHashLength('a'.repeat(56)), false);
});

test('whitelist: _isGUID matches the canonical 8-4-4-4-12 shape', () => {
  // The match window is 5 chars before to 40 chars after the offset,
  // so the GUID must overlap that span. Anchor the candidate at the
  // GUID start.
  const text = 'GUID = 550e8400-e29b-41d4-a716-446655440000 trailing';
  const offset = text.indexOf('550e8400');
  assert.equal(d._isGUID(text, offset), true);
});

test('whitelist: _isPowerShellEncodedCommand matches -enc / -EncodedCommand', () => {
  // PowerShell `-EncodedCommand <Base64>` is a high-confidence flag —
  // the *opposite* of a whitelist (we want to surface it). But this
  // helper's job is to TELL the caller "you're inside an enc context",
  // and the caller flips the entropy gate / increases confidence.
  // Verify the regex hits the canonical short / long flag forms.
  const longForm = 'powershell -EncodedCommand SGVsbG8=';
  const shortForm = 'powershell -enc SGVsbG8=';
  const aliasForm = 'powershell -ec SGVsbG8=';
  assert.equal(d._isPowerShellEncodedCommand(longForm,  longForm.indexOf('SGVs')),  true);
  assert.equal(d._isPowerShellEncodedCommand(shortForm, shortForm.indexOf('SGVs')), true);
  assert.equal(d._isPowerShellEncodedCommand(aliasForm, aliasForm.indexOf('SGVs')), true);
  // No `-enc` flag → not in encoded-command context.
  const plain = 'powershell  SGVsbG8=';
  assert.equal(d._isPowerShellEncodedCommand(plain, plain.indexOf('SGVs')), false);
});

test('whitelist: _hasBase32Context requires keyword OR quote-context', () => {
  // Base32 has the lowest signal-to-noise of the three encodings the
  // detector knows about; the gate insists on at least one of:
  //   • a keyword in the preceding 100 chars
  //   • the candidate sits immediately after an opening quote
  const withKeyword = 'encoded payload: MZXW6YTBOI';
  assert.equal(d._hasBase32Context(withKeyword, withKeyword.indexOf('MZXW')), true);
  const withQuote = 'token: "MZXW6YTBOI';
  assert.equal(d._hasBase32Context(withQuote, withQuote.indexOf('MZXW')), true);
  // No keyword, no quote — return false so the caller skips.
  const plain = 'just a string MZXW6YTBOI';
  assert.equal(d._hasBase32Context(plain, plain.indexOf('MZXW')), false);
});
