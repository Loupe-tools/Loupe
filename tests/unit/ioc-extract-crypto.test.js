'use strict';
// ioc-extract-crypto.test.js — crypto / dark-web / IPFS address pivots.
//
// Six variants emit IOC.CRYPTO_ADDRESS at MEDIUM severity:
//   • BTC legacy P2PKH/P2SH    1Boatzz…/3FZbgi…       (base58, 26-35 chars)
//   • BTC bech32 / taproot     bc1q… (42) / bc1p… (62)
//   • ETH (or EVM-chain)       0x + 40 hex
//   • XMR / XMR integrated     4… (95 or 106 base58 chars)
//   • Tor onion v3             56-char base32 + `.onion`
//   • IPFS CIDv0 / CIDv1       Qm + 44 base58 / bafy + 55 base32
//
// All seven validators are SHAPE-ONLY by design — checksum verification
// would require keccak256 / base58check, which costs more in bundle size
// than the false-positive reduction is worth. The tight character classes
// + length anchors keep noise acceptable.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/constants.js', 'src/ioc-extract.js']);
const { extractInterestingStringsCore, IOC } = ctx;

function cryptoOf(findings) {
  return host(findings.filter(e => e.type === IOC.CRYPTO_ADDRESS)
    .map(e => ({ value: e.url, note: e.note, severity: e.severity })));
}

test('crypto: BTC legacy P2PKH (Satoshi genesis address)', () => {
  // The Genesis-block coinbase-recipient address — well-known, used as a
  // canonical fixture in many parser test suites.
  const r = extractInterestingStringsCore(
    'Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa for the donation.'
  );
  const hits = cryptoOf(r.findings);
  assert.ok(hits.some(h => h.value === '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'),
    `expected BTC genesis address, got: ${JSON.stringify(hits)}`);
  const hit = hits.find(h => h.value === '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
  assert.ok(hit.note.includes('BTC'));
  assert.equal(hit.severity, 'medium');
});

test('crypto: BTC P2SH 3-prefixed address', () => {
  const r = extractInterestingStringsCore('Pay to 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy and confirm.');
  const hits = cryptoOf(r.findings);
  assert.ok(hits.some(h => h.value === '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'),
    `expected P2SH, got: ${JSON.stringify(hits)}`);
});

test('crypto: BTC bech32 P2WPKH (42 chars)', () => {
  const r = extractInterestingStringsCore('Wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq for testing.');
  const hits = cryptoOf(r.findings);
  assert.ok(hits.some(h => h.note.includes('bech32')),
    `expected bech32 address, got: ${JSON.stringify(hits)}`);
});

test('crypto: BTC bech32 wrong length rejected', () => {
  // 50-char body — neither 42 nor 62, must be rejected.
  const r = extractInterestingStringsCore('Garbage bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa here.');
  const hits = cryptoOf(r.findings);
  assert.equal(hits.filter(h => h.note.includes('bech32')).length, 0,
    `wrong-length bech32 must not match: ${JSON.stringify(hits)}`);
});

test('crypto: ETH-style 0x-prefixed 40-hex address', () => {
  // Vitalik's well-known address.
  const r = extractInterestingStringsCore(
    'Refund to 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 immediately.'
  );
  const hits = cryptoOf(r.findings);
  assert.ok(hits.some(h => h.value === '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'),
    `expected ETH address, got: ${JSON.stringify(hits)}`);
});

test('crypto: ETH burn address dropped', () => {
  const r = extractInterestingStringsCore(
    'Sent to 0x0000000000000000000000000000000000000000 (burn).'
  );
  const hits = cryptoOf(r.findings);
  assert.equal(hits.filter(h => /^0x0+$/.test(h.value)).length, 0,
    `burn address must not pivot: ${JSON.stringify(hits)}`);
});

test('crypto: SHA-256 hex (64 chars) does NOT match ETH', () => {
  // 64-hex strings are sha256 hashes — must not be misclassified as ETH.
  // The lookahead `(?![0-9a-fA-F])` in the ETH regex is what enforces this.
  const r = extractInterestingStringsCore(
    'sha256: 0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
  );
  const hits = cryptoOf(r.findings);
  assert.equal(hits.filter(h => h.note.includes('ETH')).length, 0,
    `64-hex must not match ETH: ${JSON.stringify(hits)}`);
});

test('crypto: XMR standard 95-char address', () => {
  // Real-shaped XMR donation address (length-correct, leading-`4` mainnet).
  const xmr = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';
  const r = extractInterestingStringsCore(`Donate ${xmr} thanks.`);
  const hits = cryptoOf(r.findings);
  assert.ok(hits.some(h => h.value === xmr),
    `expected XMR address, got: ${JSON.stringify(hits)}`);
  const h = hits.find(x => x.value === xmr);
  assert.equal(h.note, 'XMR');
});

test('crypto: XMR integrated 106-char address', () => {
  // 106-char shape — standard 95 + 11-char payment ID. Leading 4 + base58.
  // 95 standard + 11 base58 payment ID. base58 alphabet excludes 0/O/I/l.
  const xmrInt = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A123456789ab';
  const r = extractInterestingStringsCore(`Pay ${xmrInt} now.`);
  const hits = cryptoOf(r.findings);
  const h = hits.find(x => x.value === xmrInt);
  assert.ok(h, `expected integrated XMR, got: ${JSON.stringify(hits)}`);
  assert.equal(h.note, 'XMR (integrated)');
});

test('crypto: Tor onion v3 with .onion suffix', () => {
  // 56 lowercase base32 chars + `.onion`. Real DuckDuckGo onion shape.
  const onion = 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion';
  const r = extractInterestingStringsCore(`Visit ${onion} privately.`);
  const hits = cryptoOf(r.findings);
  assert.ok(hits.some(h => h.value === onion),
    `expected onion address, got: ${JSON.stringify(hits)}`);
  const h = hits.find(x => x.value === onion);
  assert.equal(h.note, 'Tor onion v3');
});

test('crypto: random 56-char base32 without .onion does NOT match', () => {
  const r = extractInterestingStringsCore(
    'Token abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx is not an address.'
  );
  const hits = cryptoOf(r.findings);
  assert.equal(hits.filter(h => h.note.includes('onion')).length, 0,
    `bare 56-char base32 must not match onion: ${JSON.stringify(hits)}`);
});

test('crypto: IPFS CIDv0 (Qm + 44 base58)', () => {
  const cid = 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG';
  const r = extractInterestingStringsCore(`Resource ${cid} pinned.`);
  const hits = cryptoOf(r.findings);
  assert.ok(hits.some(h => h.value === cid),
    `expected IPFS CIDv0, got: ${JSON.stringify(hits)}`);
});

test('crypto: IPFS CIDv1 (bafy + 55 base32)', () => {
  // Canonical 59-char CIDv1 starting with `bafy` (dag-pb).
  const cid = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';
  const r = extractInterestingStringsCore(`CID ${cid} resolved.`);
  const hits = cryptoOf(r.findings);
  assert.ok(hits.some(h => h.value === cid),
    `expected IPFS CIDv1, got: ${JSON.stringify(hits)}`);
});

test('crypto: cap at 32 hits per scan', () => {
  // Build 60 valid-shaped legacy BTC addresses. Cap should hold at 32.
  const lines = [];
  for (let i = 0; i < 60; i++) {
    // Pad with random base58 chars (drop 0/O/I/l). Keep length 34.
    const tail = '23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
    let body = '';
    for (let j = 0; j < 33; j++) body += tail[(i * 7 + j) % tail.length];
    lines.push(`addr 1${body}`);
  }
  const r = extractInterestingStringsCore(lines.join('\n'));
  const hits = cryptoOf(r.findings);
  assert.ok(hits.length <= 32, `expected ≤ 32 capped hits, got ${hits.length}`);
  assert.ok(hits.length >= 1, `expected at least one hit before cap`);
});

test('crypto: severity is medium for every variant', () => {
  const text = [
    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
    '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
    'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion',
    'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG',
    'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
  ].join(' ');
  const r = extractInterestingStringsCore(text);
  const hits = cryptoOf(r.findings);
  assert.ok(hits.length >= 5, `expected at least 5 variants, got ${hits.length}`);
  for (const h of hits) assert.equal(h.severity, 'medium');
});

test('crypto: all hits use IOC.CRYPTO_ADDRESS constant', () => {
  // Same invariant as ipv6 / trojan-source — bare strings break the
  // sidebar filter and STIX/MISP exports.
  const r = extractInterestingStringsCore(
    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'
  );
  const cryptoHits = r.findings.filter(e => e.type === IOC.CRYPTO_ADDRESS);
  assert.ok(cryptoHits.length >= 2);
  for (const e of cryptoHits) assert.equal(e.type, IOC.CRYPTO_ADDRESS);
});
