'use strict';
// ════════════════════════════════════════════════════════════════════════════
// url-normalize.test.js — direct unit tests for `UrlNormalizeUtil` in
// src/util/url-normalize.js.
//
// The util is consumed by `src/ioc-extract.js::processUrl` (host + IOC
// worker bundle) and `src/decoders/ioc-extract.js` (decoded-payload pass)
// to surface the canonical URL alongside an obfuscated original.
//
// A regression here would silently lose IOCs for malware that uses any of:
//   • inline `\uXXXX` / `\xHH` escape obfuscation in URL strings
//   • percent-encoded host or path bytes
//   • hex / octal / decimal `inet_aton`-shape IP literals as host
// All three are routine evasion tricks the regex-only IOC pass misses.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { UrlNormalizeUtil } = require(path.resolve(__dirname, '..', '..', 'src/util/url-normalize.js'));

test('normalizeUrl — null/empty input', () => {
  assert.equal(UrlNormalizeUtil.normalizeUrl(null), null);
  assert.equal(UrlNormalizeUtil.normalizeUrl(undefined), null);
  assert.equal(UrlNormalizeUtil.normalizeUrl(''), null);
  assert.equal(UrlNormalizeUtil.normalizeUrl(123), null);
});

test('normalizeUrl — plain URL passes through unchanged', () => {
  const r = UrlNormalizeUtil.normalizeUrl('https://example.com/foo');
  assert.equal(r.changed, false);
  assert.equal(r.normalized, 'https://example.com/foo');
  assert.equal(r.transformations.length, 0);
  assert.equal(r.hostIsIp, false);
});

test('normalizeUrl — strict dotted-quad host is recognised as IP without transform', () => {
  const r = UrlNormalizeUtil.normalizeUrl('http://192.168.1.1/foo');
  assert.equal(r.changed, false);
  assert.equal(r.hostIsIp, true);
  assert.equal(r.normalizedHost, '192.168.1.1');
});

test('normalizeUrl — leaves query string percent-encoding alone', () => {
  // `?q=hello%20world` is legitimate; rewriting it would change semantics.
  const r = UrlNormalizeUtil.normalizeUrl('https://example.com/path?q=hello%20world');
  assert.equal(r.changed, false);
  assert.equal(r.normalized, 'https://example.com/path?q=hello%20world');
});

test('normalizeUrl — decodes inline \\uXXXX escapes', () => {
  // Single-char unicode escape inside the host — too short for the
  // EncodedContentDetector finder threshold, exactly the gap this util
  // exists to close.
  const r = UrlNormalizeUtil.normalizeUrl('https://evil\\u002Ecom/payload');
  assert.equal(r.changed, true);
  assert.equal(r.normalized, 'https://evil.com/payload');
  assert.ok(r.transformations.includes('unicode-escape'));
});

test('normalizeUrl — decodes inline \\xHH escapes', () => {
  const r = UrlNormalizeUtil.normalizeUrl('https://evil\\x2Ecom/p');
  assert.equal(r.changed, true);
  assert.equal(r.normalized, 'https://evil.com/p');
  assert.ok(r.transformations.includes('unicode-escape'));
});

test('normalizeUrl — decodes \\u{HHHH} braced escapes', () => {
  const r = UrlNormalizeUtil.normalizeUrl('https://evil\\u{2E}com/p');
  assert.equal(r.changed, true);
  assert.equal(r.normalized, 'https://evil.com/p');
});

test('normalizeUrl — decodes percent-encoded host', () => {
  const r = UrlNormalizeUtil.normalizeUrl('https://%65%76%69%6c.com/p');
  assert.equal(r.changed, true);
  assert.equal(r.normalized, 'https://evil.com/p');
  assert.ok(r.transformations.includes('percent-encoding'));
});

test('normalizeUrl — decodes percent-encoded path but leaves query alone', () => {
  const r = UrlNormalizeUtil.normalizeUrl('https://example.com/%65%76%69%6c?q=%65');
  assert.equal(r.changed, true);
  // Path decoded; query preserved verbatim.
  assert.ok(r.normalized.startsWith('https://example.com/evil'));
  assert.ok(r.normalized.endsWith('?q=%65'));
});

test('normalizeUrl — integer IP host (inet_aton 1-part form)', () => {
  // 3232235777 == 0xC0A80101 == 192.168.1.1
  const r = UrlNormalizeUtil.normalizeUrl('http://3232235777/payload');
  assert.equal(r.changed, true);
  assert.equal(r.normalized, 'http://192.168.1.1/payload');
  assert.equal(r.hostIsIp, true);
  assert.equal(r.normalizedHost, '192.168.1.1');
  assert.ok(r.transformations.includes('numeric-ip'));
});

test('normalizeUrl — hex integer IP host (0xCAFEBABE shape)', () => {
  // 0xC0A80101 → 192.168.1.1
  const r = UrlNormalizeUtil.normalizeUrl('http://0xC0A80101/p');
  assert.equal(r.changed, true);
  assert.equal(r.normalizedHost, '192.168.1.1');
  assert.equal(r.normalized, 'http://192.168.1.1/p');
});

test('normalizeUrl — dotted hex IP host', () => {
  const r = UrlNormalizeUtil.normalizeUrl('http://0xC0.0xA8.0x01.0x01/p');
  assert.equal(r.changed, true);
  assert.equal(r.normalizedHost, '192.168.1.1');
  assert.equal(r.normalized, 'http://192.168.1.1/p');
});

test('normalizeUrl — dotted octal IP host', () => {
  // 0300.0250.01.01 → 192.168.1.1
  const r = UrlNormalizeUtil.normalizeUrl('http://0300.0250.01.01/p');
  assert.equal(r.changed, true);
  assert.equal(r.normalizedHost, '192.168.1.1');
});

test('normalizeUrl — mixed hex/decimal/octal dotted IP host', () => {
  // 0xC0.168.0x01.01 → 192.168.1.1
  const r = UrlNormalizeUtil.normalizeUrl('http://0xC0.168.0x01.01/p');
  assert.equal(r.changed, true);
  assert.equal(r.normalizedHost, '192.168.1.1');
});

test('normalizeUrl — 2-part inet_aton host (A.B-as-24-bit)', () => {
  // 192.11010305 → 192.168.1.1  (B = (168<<16)|(1<<8)|1 = 0xA80101)
  const r = UrlNormalizeUtil.normalizeUrl('http://192.11010305/p');
  assert.equal(r.changed, true);
  assert.equal(r.normalizedHost, '192.168.1.1');
});

test('normalizeUrl — 3-part inet_aton host (A.B.C-as-16-bit)', () => {
  // 192.168.257 → 192.168.1.1 (low 16 bits = 257 = 0x101)
  const r = UrlNormalizeUtil.normalizeUrl('http://192.168.257/p');
  assert.equal(r.changed, true);
  assert.equal(r.normalizedHost, '192.168.1.1');
});

test('normalizeUrl — full mixed example from feature request', () => {
  // http://0\u0078b5\u00614c9/mh\u0078 — inline unicode escapes wrap a
  // hex integer host. After escape decoding:
  //   \u0078 → x, \u0061 → a, \u0078 → x  ⇒  http://0xb5a4c9/mhx
  // 0xb5a4c9 = 11,904,201 → 0.181.164.201 (a 0.x.y.z "this network"
  // address — plausibly obfuscated, so we surface it).
  // Verifying this end-to-end is the canary for the whole feature.
  const r = UrlNormalizeUtil.normalizeUrl('http://0\\u0078b5\\u00614c9/mh\\u0078');
  assert.equal(r.changed, true);
  assert.equal(r.normalized, 'http://0.181.164.201/mhx');
  assert.equal(r.hostIsIp, true);
  assert.equal(r.normalizedHost, '0.181.164.201');
  assert.ok(r.transformations.includes('unicode-escape'));
  assert.ok(r.transformations.includes('numeric-ip'));
});

test('normalizeUrl — rejects 0.x.x.x results', () => {
  // Integer 0x000000FF would parse to 0.0.0.255 — reserved (this network).
  // Treat as not-an-IP so we don't pollute findings with placeholder values.
  const r = UrlNormalizeUtil.normalizeUrl('http://255/p');
  // The numeric host parses to 0.0.0.255; we reject it, so no transform.
  assert.equal(r.hostIsIp, false);
});

test('normalizeUrl — rejects integer host overflow', () => {
  // 4294967296 = 2^32 — out of range. Should fail to normalise.
  const r = UrlNormalizeUtil.normalizeUrl('http://4294967296/p');
  assert.equal(r.hostIsIp, false);
  assert.equal(r.changed, false);
});

test('normalizeUrl — rejects octet > 255 in 4-part dotted form', () => {
  // 256.1.1.1 — octet out of range. Should NOT be claimed as a valid IP.
  const r = UrlNormalizeUtil.normalizeUrl('http://256.1.1.1/p');
  assert.equal(r.hostIsIp, false);
});

test('normalizeUrl — rejects malformed nested dots', () => {
  const r = UrlNormalizeUtil.normalizeUrl('http://1..2.3/p');
  assert.equal(r.hostIsIp, false);
});

test('normalizeUrl — non-numeric host left alone', () => {
  const r = UrlNormalizeUtil.normalizeUrl('http://example.com/p');
  assert.equal(r.changed, false);
  assert.equal(r.hostIsIp, false);
});

test('normalizeUrl — bracketed IPv6 left alone', () => {
  const r = UrlNormalizeUtil.normalizeUrl('http://[2001:db8::1]/p');
  assert.equal(r.changed, false);
  assert.equal(r.hostIsIp, false);
});

test('normalizeUrl — preserves userinfo / port', () => {
  const r = UrlNormalizeUtil.normalizeUrl('http://user:pass@0xC0A80101:8080/p');
  assert.equal(r.changed, true);
  assert.equal(r.normalized, 'http://user:pass@192.168.1.1:8080/p');
  assert.equal(r.hostIsIp, true);
});

test('normalizeUrl — preserves fragment', () => {
  const r = UrlNormalizeUtil.normalizeUrl('http://0xC0A80101/p#frag');
  assert.equal(r.normalized, 'http://192.168.1.1/p#frag');
});

test('normalizeUrl — caps oversized input', () => {
  const huge = 'http://' + 'a'.repeat(20000) + '.com/';
  const r = UrlNormalizeUtil.normalizeUrl(huge);
  // Returns null per the documented MAX_LEN cap.
  assert.equal(r, null);
});

test('_normalizeNumericHost — returns null for empty / non-string', () => {
  assert.equal(UrlNormalizeUtil._normalizeNumericHost(''), null);
  assert.equal(UrlNormalizeUtil._normalizeNumericHost(null), null);
  assert.equal(UrlNormalizeUtil._normalizeNumericHost(undefined), null);
});

test('_normalizeNumericHost — accepts trailing dot', () => {
  // `192.168.1.1.` is sometimes seen in BSD-style code. Tolerate it.
  const r = UrlNormalizeUtil._normalizeNumericHost('192.168.1.1.');
  assert.equal(r, '192.168.1.1');
});

test('_decodeInlineEscapes — no escapes is a no-op', () => {
  const r = UrlNormalizeUtil._decodeInlineEscapes('https://example.com/');
  assert.equal(r.changed, false);
  assert.equal(r.out, 'https://example.com/');
});

test('_decodeInlineEscapes — handles all three escape shapes in one pass', () => {
  const r = UrlNormalizeUtil._decodeInlineEscapes('a\\u0042c\\x44e\\u{46}g');
  assert.equal(r.changed, true);
  assert.equal(r.out, 'aBcDeFg');
});
