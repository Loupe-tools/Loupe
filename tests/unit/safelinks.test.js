'use strict';
// safelinks.test.js — SafeLink URL unwrapping for Proofpoint URLDefense
// (v1, v2, v3) and Microsoft SafeLinks.
//
// `EncodedContentDetector.unwrapSafeLink(url)` is a static helper (mounted
// directly on the constructor, not on the prototype) — pure string work
// with no `this`-state. Each provider has its own URL shape; this file
// covers the four formats the EML / image / PDF renderers send through.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

// safelinks.js attaches `unwrapSafeLink` onto the EncodedContentDetector
// constructor. Load the class root + the safelinks helper.
const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
]);
const unwrap = ctx.EncodedContentDetector.unwrapSafeLink;

test('safelinks: returns null for non-string / empty input', () => {
  // Defensive contract: callers may pass `null` for "no link extracted"
  // — the helper must NOT throw.
  assert.equal(unwrap(null), null);
  assert.equal(unwrap(undefined), null);
  assert.equal(unwrap(''), null);
  assert.equal(unwrap(42), null);
});

test('safelinks: returns null for a plain non-wrapped URL', () => {
  // Anything that doesn't match a known wrapper format falls through
  // to `return null`. The caller treats null as "not a safelink".
  assert.equal(unwrap('https://example.com/page'), null);
});

test('safelinks: unwraps Microsoft SafeLinks URL', () => {
  // Outlook ATP wraps inbound URLs in
  // https://<tenant>.safelinks.protection.outlook.com/?url=<encoded>&data=...
  // The extractor decodes the `url` param and pulls any email
  // addresses from the `data` param for analyst pivoting.
  const target = 'https://malicious.example.com/payload.exe?id=42';
  const data = '04%7C01%7Cuser%40example.org%7Cabc';
  // Note: the MS regex restricts the tenant subdomain to `[a-z0-9]+`
  // (no hyphens), so `eu-prod.safelinks.…` would NOT match. Use a
  // plain alpha tenant here so the regex hits.
  const wrapped =
    'https://nam04.safelinks.protection.outlook.com/?url=' +
    encodeURIComponent(target) +
    '&data=' + data +
    '&sdata=xxx';
  const r = unwrap(wrapped);
  assert.ok(r, 'must return a result');
  assert.equal(r.originalUrl, target);
  assert.equal(r.provider, 'Microsoft SafeLinks');
  // `user@example.org` was URL-encoded inside `data`; the unwrapper
  // decodes it once before scanning for emails. Cross-realm: project
  // the vm-realm Array into the host realm via host().
  assert.deepEqual(host(r.emails), ['user@example.org']);
});

test('safelinks: unwraps Proofpoint URLDefense v3', () => {
  // v3 format: https://urldefense.com/v3/__<URL>__;!!<token>
  // The extractor unwraps the `__…__` segment and converts `*XX` hex
  // escapes back to characters (Proofpoint's encoding for `?` `&` etc).
  const wrapped =
    'https://urldefense.com/v3/__https://evil.example.com/path*3Fid*3D1__;JSU!!abc-defGHI';
  const r = unwrap(wrapped);
  assert.ok(r);
  assert.equal(r.provider, 'Proofpoint v3');
  // `*3F` → `?`, `*3D` → `=`.
  assert.equal(r.originalUrl, 'https://evil.example.com/path?id=1');
});

test('safelinks: unwraps Proofpoint URLDefense v2', () => {
  // v2 format: https://urldefense.proofpoint.com/v2/url?u=<encoded>&d=...
  // The extractor turns `-` → `%`, `_` → `/`, then URL-decodes once.
  // Encode "https://evil.example.com/p" via Proofpoint's scheme.
  // Easiest path: take a real `encodeURIComponent`-encoded value, then
  // swap `%`→`-` and `/`→`_` to mimic what Proofpoint sends.
  const target = 'https://evil.example.com/p?x=1';
  const ppEnc = encodeURIComponent(target).replace(/%/g, '-').replace(/\//g, '_');
  const wrapped = 'https://urldefense.proofpoint.com/v2/url?u=' + ppEnc + '&d=...';
  const r = unwrap(wrapped);
  assert.ok(r);
  assert.equal(r.provider, 'Proofpoint v2');
  assert.equal(r.originalUrl, target);
});

test('safelinks: unwraps Proofpoint URLDefense v1', () => {
  // v1 format mirrors v2 but uses a different param scheme (`k=` instead
  // of `d=`). Encoding is identical: `-` → `%`, `_` → `/`.
  const target = 'https://evil.example.com/v1';
  const ppEnc = encodeURIComponent(target).replace(/%/g, '-').replace(/\//g, '_');
  const wrapped = 'https://urldefense.proofpoint.com/v1/url?u=' + ppEnc + '&k=...';
  const r = unwrap(wrapped);
  assert.ok(r);
  assert.equal(r.provider, 'Proofpoint v1');
  assert.equal(r.originalUrl, target);
});

test('safelinks: malformed wrapper falls through to null', () => {
  // A URL whose host-level shape matches the wrapper regex but whose
  // `url` / `u` param is missing (or unparseable) returns null —
  // callers treat null as "couldn't extract", not as a malformed
  // safelink finding.
  assert.equal(
    unwrap('https://nam04.safelinks.protection.outlook.com/?data=foo'),
    null
  );
  // urldefense.proofpoint.com without `u=` parameter
  assert.equal(
    unwrap('https://urldefense.proofpoint.com/v2/url?d=just-data'),
    null
  );
});
