'use strict';
// ════════════════════════════════════════════════════════════════════════════
// x509-private-key-only.test.js — regression coverage for the X509Renderer's
// "private-key-only PEM" early-return path.
//
// Background — the bug this test pins down
// ----------------------------------------
// Inside `X509Renderer.analyzeForSecurity`, the PEM-decode branch walked
// every BEGIN/END block and pushed a high-severity `Private Key Detected`
// detection (+40 risk score) whenever it hit a `*PRIVATE KEY*` block. The
// post-loop code that mirrored every `findings.detections[]` entry into
// `findings.externalRefs` as `IOC.PATTERN` only ran AFTER the per-cert
// analysis loop. When the file contained a private key but no parseable
// certificate (the `examples/crypto/private-example.key` shape — a PGP
// private-key block, but the same PEM grammar), the function returned
// early at `if (certs.length === 0)` BEFORE the mirror step.
//
// The user-visible failure: "Private Key Detected" appeared in the
// renderer's local detections list but produced ZERO `IOC.PATTERN`
// rows in Summary / Share / STIX / MISP / sidebar exports — surfaces
// that all read from `findings.externalRefs`, not `findings.detections`.
//
// Fix (src/renderers/x509-renderer.js, in the `certs.length === 0`
// branch): mirror detections into externalRefs, stamp metadata from
// formatSpecific, derive riskLevel from accumulated riskScore, and call
// escalateRisk — all the same ceremony the post-loop block performs.
//
// What this test asserts
// ----------------------
//  1. A private-key-only PEM produces a non-empty `findings.externalRefs`.
//  2. That array contains an `IOC.PATTERN` entry whose `url` mentions
//     "Private Key Detected" — the canonical detection name.
//  3. `findings.riskScore >= 40` (one detection × +40 score).
//  4. `findings.riskLevel === 'high'` (40 falls in the >=30 bucket per
//     the renderer's risk-bucket logic).
//  5. `findings.summary` reflects that this was a key-only file, not a
//     truly-empty parse failure.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// X509Renderer depends on constants.js (IOC, escalateRisk, pushIOC,
// mirrorMetadataIOCs, stripDerTail). No other src files needed —
// `analyzeForSecurity` operates entirely on the raw bytes and never
// touches the DOM or any host-only globals.
const ctx = loadModules(
  ['src/constants.js', 'src/renderers/x509-renderer.js'],
  { expose: ['X509Renderer', 'IOC', 'escalateRisk'] },
);
const { X509Renderer, IOC } = ctx;

// Build a minimal valid PEM that exercises the X.509 PEM decode path.
// The project's PGP fixture (`examples/crypto/private-example.key`)
// can't be used directly because PGP armor blocks carry plaintext
// `Version:` / `Comment:` headers that break X509Renderer._decodePEM's
// strict atob() of the body — a pre-existing PGP/X.509 boundary issue
// out of scope for this fix. A hand-rolled PKCS#8-shaped block exercises
// the actual code path the fix addresses (block.label.includes('PRIVATE
// KEY') → detections.push → certs.length === 0 → early return).
const SAMPLE_PRIVATE_KEY_PEM = [
  '-----BEGIN PRIVATE KEY-----',
  'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMG6kJv9I3pT5MZL',
  'wQ7HXCxHZkkzyYP3wOdUSQwxJj0wYexJ4xJh1QGqGzL5uRPOsOaQ3pQzJkxqvN0a',
  '-----END PRIVATE KEY-----',
  '',
].join('\n');

test('x509-renderer: private-key-only PEM mirrors detection into externalRefs', () => {
  const bytes = new TextEncoder().encode(SAMPLE_PRIVATE_KEY_PEM);

  const renderer = new X509Renderer();
  const findings = renderer.analyzeForSecurity(bytes.buffer, 'private.key');

  // Sanity: the early-return path was taken (no certificates parsed).
  // x509Certs is only set in the post-loop block; a private-key-only
  // PEM must NOT have it.
  assert.equal(findings.x509Certs, undefined,
    'should hit the certs.length === 0 early-return branch');

  // The detection itself must still be present in the local list.
  assert.ok(Array.isArray(findings.detections), 'detections must be an array');
  const privKeyDetection = findings.detections.find(d => d.name === 'Private Key Detected');
  assert.ok(privKeyDetection, 'Private Key Detected must be in findings.detections');
  assert.equal(privKeyDetection.severity, 'high');

  // The fix: detections must be mirrored into externalRefs as IOC.PATTERN.
  assert.ok(Array.isArray(findings.externalRefs),
    'externalRefs must be an array (was undefined before the fix)');
  assert.ok(findings.externalRefs.length >= 1,
    'externalRefs must contain at least the Private Key Detected mirror');

  const mirror = findings.externalRefs.find(r =>
    typeof r.url === 'string' && r.url.includes('Private Key Detected'));
  assert.ok(mirror, 'externalRefs must include a Private Key Detected mirror');
  assert.equal(mirror.type, IOC.PATTERN, 'mirror type must be IOC.PATTERN');
  assert.equal(mirror.severity, 'high', 'mirror severity must carry through');

  // Risk: the renderer adds +40 per Private Key block.
  assert.ok(findings.riskScore >= 40,
    `riskScore must reflect the +40 detection (got ${findings.riskScore})`);
  // riskLevel maps from riskScore (>=30 → 'high', >=50 → 'critical').
  assert.ok(['high', 'critical'].includes(findings.riskLevel),
    `riskLevel must be high or critical (got ${findings.riskLevel})`);

  // Summary text should distinguish "private key only" from a truly
  // unparseable file so the analyst doesn't think the parser failed.
  assert.match(findings.summary, /private key/i,
    `summary should mention private key (got: ${findings.summary})`);
});

test('x509-renderer: empty PEM (no blocks at all) keeps the prior summary', () => {
  // Belt-and-braces: ensure the early-return branch still produces the
  // canonical "No certificates could be parsed" summary when no
  // detections were accumulated. Guards against a regression where
  // the fix's `hasPrivateKey` ternary defaults the wrong way.
  const bytes = new TextEncoder().encode('not a PEM file at all\n');
  const renderer = new X509Renderer();
  const findings = renderer.analyzeForSecurity(bytes.buffer, 'random.key');
  assert.equal(findings.x509Certs, undefined);
  // No PRIVATE KEY block was seen, so detections stays empty and the
  // mirror produces an empty externalRefs array.
  assert.ok(Array.isArray(findings.externalRefs));
  assert.equal(findings.externalRefs.length, 0);
  assert.match(findings.summary, /no certificates/i);
});
