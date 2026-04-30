'use strict';
// ioc-extract-secrets.test.js — vendor-specific secret leak detection.
//
// Eight credential families emit IOC.SECRET, capped at 8 hits per family
// per scan:
//   • AWS access key IDs       AKIA/ASIA/AGPA/AROA/AIDA + 16 base32
//   • GitHub tokens            ghp_/gho_/ghu_/ghs_/ghr_ + 36 base62
//   • GitHub fine-grained PAT  github_pat_ + 82 base62/_
//   • Slack tokens             xox[abprs]- + 3 numeric segments + secret
//   • Stripe live API keys     sk_live_/rk_live_ + 24+ base62
//   • Google API keys          AIza + 35 base64url
//   • PEM private key armour   -----BEGIN … PRIVATE KEY----- (8 variants)
//   • JWT                      eyJ.eyJ.<sig> (medium severity, not high)
//
// Canonical severity floor is 'high' (live credentials); JWT explicitly
// downgrades to 'medium' because OIDC id_tokens are routinely logged and
// aren't a credential per se.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/constants.js', 'src/ioc-extract.js']);
const { extractInterestingStringsCore, IOC } = ctx;

function secretsOf(findings) {
  return host(findings.filter(e => e.type === IOC.SECRET)
    .map(e => ({ value: e.url, note: e.note, severity: e.severity })));
}

test('secrets: AWS AKIA long-term IAM access key', () => {
  // Canonical AWS docs example — well-known fixture, not a live key.
  const r = extractInterestingStringsCore(
    'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_REGION=us-east-1'
  );
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === 'AKIAIOSFODNN7EXAMPLE'),
    `expected AKIA hit, got: ${JSON.stringify(hits)}`);
  const h = hits.find(x => x.value === 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(h.severity, 'high');
  assert.equal(h.note, 'AWS access key ID');
});

test('secrets: AWS STS temporary credential (ASIA prefix)', () => {
  const r = extractInterestingStringsCore('Token: ASIA1234567890ABCDEF');
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === 'ASIA1234567890ABCDEF'));
});

test('secrets: AWS rejects 19-char and 21-char malformed', () => {
  // Length is exactly 4+16. Other lengths must not match.
  const r = extractInterestingStringsCore('short AKIAIOSFODNN7EXAMPL too long AKIAIOSFODNN7EXAMPLES');
  const hits = secretsOf(r.findings);
  assert.equal(hits.filter(h => h.note === 'AWS access key ID').length, 0,
    `wrong-length AWS keys must not match: ${JSON.stringify(hits)}`);
});

test('secrets: GitHub classic PAT (ghp_)', () => {
  const ghp = 'ghp_' + 'a'.repeat(36);
  const r = extractInterestingStringsCore(`token: ${ghp} (used in CI)`);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === ghp),
    `expected ghp_, got: ${JSON.stringify(hits)}`);
  const h = hits.find(x => x.value === ghp);
  assert.equal(h.severity, 'high');
  assert.equal(h.note, 'GitHub token');
});

test('secrets: GitHub OAuth + server-server tokens', () => {
  const gho = 'gho_' + 'b'.repeat(36);
  const ghs = 'ghs_' + 'c'.repeat(36);
  const r = extractInterestingStringsCore(`oauth=${gho} server=${ghs}`);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === gho));
  assert.ok(hits.some(h => h.value === ghs));
});

test('secrets: GitHub fine-grained PAT', () => {
  // 82 char body — base62 + underscores.
  const pat = 'github_pat_' + 'A'.repeat(22) + '_' + 'B'.repeat(59);
  const r = extractInterestingStringsCore(`new_token=${pat} expires=2026-01-01`);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === pat),
    `expected github_pat_, got: ${JSON.stringify(hits)}`);
  const h = hits.find(x => x.value === pat);
  assert.equal(h.note, 'GitHub fine-grained PAT');
});

test('secrets: Slack bot token', () => {
  // Real-shaped bot token (base62 secret tail).
  const slack = 'xoxb-1234567890-9876543210-1122334455-' + 'A'.repeat(40);
  const r = extractInterestingStringsCore(`SLACK_BOT_TOKEN=${slack}`);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === slack),
    `expected slack token, got: ${JSON.stringify(hits)}`);
  assert.equal(hits.find(x => x.value === slack).note, 'Slack token');
});

test('secrets: Stripe live secret key', () => {
  const stripe = 'sk_live_' + 'A'.repeat(30);
  const r = extractInterestingStringsCore(`STRIPE_SECRET=${stripe};`);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === stripe));
  assert.equal(hits.find(x => x.value === stripe).note, 'Stripe live API key');
});

test('secrets: Stripe pk_live_ (publishable) is NOT a secret', () => {
  const pk = 'pk_live_' + 'B'.repeat(30);
  const r = extractInterestingStringsCore(`STRIPE_PUB=${pk};`);
  const hits = secretsOf(r.findings);
  assert.equal(hits.filter(h => h.value === pk).length, 0,
    `pk_live_ must not match: ${JSON.stringify(hits)}`);
});

test('secrets: Stripe restricted key (rk_live_)', () => {
  const rk = 'rk_live_' + 'C'.repeat(30);
  const r = extractInterestingStringsCore(`STRIPE_RESTRICTED=${rk};`);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === rk));
});

test('secrets: Google API key', () => {
  const goog = 'AIza' + 'a'.repeat(35);
  const r = extractInterestingStringsCore(`<meta name="google-api-key" content="${goog}">`);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === goog),
    `expected Google key, got: ${JSON.stringify(hits)}`);
  assert.equal(hits.find(x => x.value === goog).note, 'Google API key');
});

test('secrets: PEM RSA private key armour', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYw…';
  const r = extractInterestingStringsCore(pem);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === '-----BEGIN RSA PRIVATE KEY-----'),
    `expected PEM armour hit, got: ${JSON.stringify(hits)}`);
});

test('secrets: PEM OPENSSH private key armour', () => {
  const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk…';
  const r = extractInterestingStringsCore(pem);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === '-----BEGIN OPENSSH PRIVATE KEY-----'));
});

test('secrets: PEM ENCRYPTED PRIVATE KEY', () => {
  const pem = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFD…';
  const r = extractInterestingStringsCore(pem);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === '-----BEGIN ENCRYPTED PRIVATE KEY-----'));
});

test('secrets: PEM PUBLIC KEY is NOT flagged', () => {
  const pem = '-----BEGIN PUBLIC KEY-----\nMIIBI…';
  const r = extractInterestingStringsCore(pem);
  const hits = secretsOf(r.findings);
  assert.equal(hits.filter(h => /PUBLIC KEY/.test(h.value)).length, 0,
    `public key must not flag: ${JSON.stringify(hits)}`);
});

test('secrets: JWT (medium severity)', () => {
  // Realistic-shape JWT: header.payload.signature, all base64url.
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    + '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0'
    + '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const r = extractInterestingStringsCore(`Authorization: Bearer ${jwt}`);
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.value === jwt),
    `expected JWT, got: ${JSON.stringify(hits)}`);
  const h = hits.find(x => x.value === jwt);
  assert.equal(h.severity, 'medium', 'JWT should be medium, not high');
  assert.equal(h.note, 'JWT');
});

test('secrets: per-family cap of 8', () => {
  // Build 12 distinct AKIA keys; cap should stop at 8.
  const lines = [];
  for (let i = 0; i < 12; i++) {
    // 16-char base32 body; vary one position so each is unique.
    const body = 'IOSFODNN7EXAMP' + String.fromCharCode(65 + (i % 26)) + 'X';
    lines.push(`AKIA${body}`);
  }
  const r = extractInterestingStringsCore(lines.join('\n'));
  const hits = secretsOf(r.findings);
  const aws = hits.filter(h => h.note === 'AWS access key ID');
  assert.equal(aws.length, 8, `expected exactly 8 capped AWS hits, got ${aws.length}`);
});

test('secrets: caps are per-family (AWS cap does not block GitHub)', () => {
  const lines = [];
  for (let i = 0; i < 12; i++) {
    const body = 'IOSFODNN7EXAMP' + String.fromCharCode(65 + i) + 'X';
    lines.push(`AKIA${body}`);
  }
  // Add one GitHub token after — it must still be emitted.
  lines.push('ghp_' + 'z'.repeat(36));
  const r = extractInterestingStringsCore(lines.join('\n'));
  const hits = secretsOf(r.findings);
  assert.ok(hits.some(h => h.note === 'GitHub token'),
    `GitHub family must not be blocked by AWS cap: ${JSON.stringify(hits.map(x => x.note))}`);
});

test('secrets: severity is high for live credentials', () => {
  const text = [
    'AKIAIOSFODNN7EXAMPLE',
    'ghp_' + 'a'.repeat(36),
    'sk_live_' + 'A'.repeat(30),
    'AIza' + 'b'.repeat(35),
  ].join(' ');
  const r = extractInterestingStringsCore(text);
  const hits = secretsOf(r.findings);
  assert.ok(hits.length >= 4);
  for (const h of hits) {
    if (h.note === 'JWT') continue; // medium by design
    assert.equal(h.severity, 'high', `${h.note} should be high severity`);
  }
});

test('secrets: all hits use IOC.SECRET constant', () => {
  // Bare strings would silently break the sidebar filter, STIX/MISP
  // exports, and the nicelist (per CONTRIBUTING § IOC Push Checklist).
  const r = extractInterestingStringsCore(
    'AKIAIOSFODNN7EXAMPLE ghp_' + 'a'.repeat(36) + ' AIza' + 'b'.repeat(35)
  );
  const secretHits = r.findings.filter(e => e.type === IOC.SECRET);
  assert.ok(secretHits.length >= 3);
  for (const e of secretHits) assert.equal(e.type, IOC.SECRET);
});

test('secrets: arbitrary base64 32-char string does NOT match', () => {
  // The whole point of vendor-prefix anchoring is that random base64-ish
  // strings (PE digest tables, JSON signatures, etc.) don't fire.
  const r = extractInterestingStringsCore(
    'sha256: dGVzdEhhc2hOb3RBQ3JlZGVudGlhbDEyMzQ1Njc4OTAxMjM='
  );
  const hits = secretsOf(r.findings);
  assert.equal(hits.length, 0, `bare base64 must not match: ${JSON.stringify(hits)}`);
});
