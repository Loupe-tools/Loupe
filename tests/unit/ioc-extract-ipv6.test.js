'use strict';
// ioc-extract-ipv6.test.js — IPv6 IOC extraction parity with IPv4.
//
// Locks down the canonical accept-set:
//
//   • compressed form         2001:db8::1                    documentation→ DROP
//                             2606:4700:4700::1111           public DNS    → ACCEPT
//   • bracketed-in-URL form   [2606:4700:4700::1111]:443     C2 endpoint   → ACCEPT
//                             with port surfacing as `[addr]:port`
//   • fully-spelled form      2606:4700:0000:0000:0000:0000:0000:1111
//                                                            8 hextets     → ACCEPT
//
// And the canonical reject-set:
//
//   • loopback ::1, unspecified ::                         → DROP (not pivots)
//   • link-local fe80::/10                                 → DROP (private)
//   • unique-local fc00::/7                                → DROP (private)
//   • multicast ff00::/8                                   → DROP (no pivot value)
//   • documentation 2001:db8::/32                          → DROP (RFC 3849)
//   • IPv4-mapped ::ffff:a.b.c.d                           → DROP (IPv4 pipeline)
//   • version-string-shaped 1:2:3:4:5:6:7:8                → DROP (every group ≤1)
//   • preceded by `version`/`build`                        → DROP (anti-version)

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/constants.js', 'src/ioc-extract.js']);
const { extractInterestingStringsCore, IOC } = ctx;

function ips(findings) {
  return host(findings.filter(e => e.type === IOC.IP).map(e => e.url).sort());
}

test('ipv6: extracts compressed routable address', () => {
  const r = extractInterestingStringsCore('Beacon to 2606:4700:4700::1111 observed.');
  assert.ok(ips(r.findings).includes('2606:4700:4700::1111'),
    `expected IPv6 in findings, got: ${JSON.stringify(ips(r.findings))}`);
});

test('ipv6: extracts bracketed form with port and surfaces as [addr]:port', () => {
  const r = extractInterestingStringsCore('Connect to [2606:4700:4700::1111]:443 next.');
  // The bracketed form lives inside the URL extractor's character class, but
  // there's no scheme — so it must surface independently as IPv6.
  assert.ok(ips(r.findings).includes('[2606:4700:4700::1111]:443'),
    `expected bracketed IPv6+port, got: ${JSON.stringify(ips(r.findings))}`);
});

test('ipv6: extracts fully-spelled 8-hextet form', () => {
  const r = extractInterestingStringsCore(
    'Endpoint 2606:4700:0000:0000:0000:0000:0000:1111 in capture.'
  );
  // Note the full form is preserved verbatim — not canonicalised — so the
  // analyst sees what was actually in the file.
  assert.ok(ips(r.findings).some(v => v.includes('2606:4700:0000:0000:0000:0000:0000:1111')),
    `expected full IPv6, got: ${JSON.stringify(ips(r.findings))}`);
});

test('ipv6: rejects loopback ::1 and unspecified ::', () => {
  const r = extractInterestingStringsCore('Local: ::1 and unspecified :: should not pivot.');
  for (const v of ips(r.findings)) {
    assert.notEqual(v, '::1');
    assert.notEqual(v, '::');
  }
});

test('ipv6: rejects link-local fe80::', () => {
  const r = extractInterestingStringsCore('Interface addr fe80::1 should not pivot.');
  for (const v of ips(r.findings)) {
    assert.ok(!v.startsWith('fe80'), `link-local leaked: ${v}`);
  }
});

test('ipv6: rejects unique-local fc00::/7', () => {
  const r = extractInterestingStringsCore('ULA fd00::1 and fc12:3456::beef should not pivot.');
  for (const v of ips(r.findings)) {
    assert.ok(!/^fc|^fd/i.test(v), `unique-local leaked: ${v}`);
  }
});

test('ipv6: rejects multicast ff00::/8', () => {
  const r = extractInterestingStringsCore('All nodes ff02::1 should not pivot.');
  for (const v of ips(r.findings)) {
    assert.ok(!v.startsWith('ff'), `multicast leaked: ${v}`);
  }
});

test('ipv6: rejects documentation 2001:db8::/32', () => {
  const r = extractInterestingStringsCore('Doc range 2001:db8::1 must not pivot.');
  for (const v of ips(r.findings)) {
    assert.ok(!v.toLowerCase().startsWith('2001:db8'), `doc range leaked: ${v}`);
  }
});

test('ipv6: rejects IPv4-mapped ::ffff:1.2.3.4', () => {
  const r = extractInterestingStringsCore('Mapped ::ffff:198.51.100.7 should be IPv4-only.');
  // The IPv4 scanner pivots 198.51.100.7 (TEST-NET-2 — also dropped). Either
  // way, no IPv6-shaped value should leak.
  for (const v of ips(r.findings)) {
    assert.ok(!/::ffff:/i.test(v), `IPv4-mapped leaked: ${v}`);
  }
});

test('ipv6: rejects version-string-shaped 1:2:3:4:5:6:7:8', () => {
  const r = extractInterestingStringsCore('Schema 1:2:3:4:5:6:7:8 is not an address.');
  for (const v of ips(r.findings)) {
    assert.ok(!/^1:2:3:4:5/.test(v), `version-shape leaked: ${v}`);
  }
});

test('ipv6: rejects when preceded by version/build context', () => {
  // Same anti-version lookbehind as the IPv4 scanner.
  const r = extractInterestingStringsCore('build 2606:4700:4700::1111 was deployed.');
  // The "build " prefix immediately before triggers the anti-version drop.
  for (const v of ips(r.findings)) {
    assert.ok(!v.includes('2606:4700:4700::1111'), `version-context leaked: ${v}`);
  }
});

test('ipv6: dedupe against existingValues honoured', () => {
  const text = 'Note: 2606:4700:4700::1111 only.';
  const dup = extractInterestingStringsCore(text);
  assert.ok(ips(dup.findings).includes('2606:4700:4700::1111'));
  const dedup = extractInterestingStringsCore(text, {
    existingValues: ['2606:4700:4700::1111'],
  });
  assert.equal(ips(dedup.findings).length, 0);
});

test('ipv6: severity tier — info baseline, medium with port', () => {
  const r = extractInterestingStringsCore(
    'Bare 2606:4700:4700::1111 vs portful [2606:4700:4700::1111]:8443.'
  );
  const findings = host(r.findings.filter(e => e.type === IOC.IP)
    .map(e => ({ url: e.url, severity: e.severity })));
  const bare = findings.find(f => f.url === '2606:4700:4700::1111');
  const portful = findings.find(f => f.url === '[2606:4700:4700::1111]:8443');
  assert.ok(bare, `bare not found: ${JSON.stringify(findings)}`);
  assert.ok(portful, `portful not found: ${JSON.stringify(findings)}`);
  assert.equal(bare.severity, 'info');
  assert.equal(portful.severity, 'medium');
});

test('ipv6: type is the IOC.IP constant, not a bare string', () => {
  // Mirrors the IPv4 invariant in ioc-extract.test.js — the sidebar filter
  // and STIX/MISP exports key off the constant.
  const r = extractInterestingStringsCore('2606:4700:4700::1111');
  for (const e of r.findings.filter(x => /[A-Fa-f0-9]:/.test(x.url))) {
    assert.equal(e.type, IOC.IP);
  }
});
