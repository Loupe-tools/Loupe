'use strict';
// nicelist.test.js — known-good global infrastructure whitelist.
//
// `isNicelisted(value, type)` is the public entry-point consulted by the
// sidebar to demote a passive IOC's row when it's recognised as benign
// global infrastructure (cloud APIs, package registries, CAs, schema
// URIs, …). The function is pure (modulo a single `safeStorage.get` for
// the kill-switch), and the matching contract is narrow: only URL /
// Domain / Hostname / Email types are ever considered, and matching is
// host-or-trailing-label exact (no regex, no wildcards) to keep
// homoglyph attacks (`malicious-amazonaws.com`) out of the demotion path.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// nicelist.js consults `safeStorage.get('loupe_nicelist_builtin_enabled')`
// at every call to honour the Settings → Nicelists kill-switch. Load
// `storage.js` first so `safeStorage` is the real shim (backed by the
// in-memory localStorage in `load-bundle.js`).
const ctx = loadModules([
  'src/constants.js',
  'src/storage.js',
  'src/nicelist.js',
]);
const { isNicelisted, NICELIST } = ctx;

test('nicelist: NICELIST is a frozen, non-empty array', () => {
  // The list is hand-curated and intentionally narrow — but it must be
  // populated and frozen so user code can't mutate the canonical list
  // at runtime. Renderers downstream rely on this immutability.
  assert.ok(Array.isArray(NICELIST), 'NICELIST must be an array');
  assert.ok(NICELIST.length > 0, 'NICELIST must not be empty');
  assert.equal(Object.isFrozen(NICELIST), true);
});

test('nicelist: matches exact domain entry for type=Domain', () => {
  // Cloud-provider apex matches its own bare hostname.
  assert.equal(isNicelisted('amazonaws.com', 'Domain'), true);
  assert.equal(isNicelisted('w3.org', 'Domain'), true);
});

test('nicelist: matches subdomain via trailing-label suffix', () => {
  // `amazonaws.com` should cover `s3.amazonaws.com` (label-boundary
  // match), per the comment in nicelist.js. Hostnames take the same
  // path as domains.
  assert.equal(isNicelisted('s3.amazonaws.com', 'Hostname'), true);
  assert.equal(
    isNicelisted('cognito-identity-fips.us-east-1.amazonaws.com', 'Domain'),
    true
  );
});

test('nicelist: rejects homoglyph / suffix-spoof domains', () => {
  // The whole reason for label-boundary matching: `malicious-amazonaws.com`
  // is a different registrable domain and must NOT be treated as a
  // subdomain of `amazonaws.com`. This is a security-sensitive guard;
  // never weaken it.
  assert.equal(isNicelisted('malicious-amazonaws.com', 'Domain'), false);
  assert.equal(isNicelisted('notamazonaws.com', 'Hostname'), false);
});

test('nicelist: matches URL via host extraction', () => {
  // URL inputs go through `_nicelistHostFromUrl` to strip scheme / port /
  // userinfo before the host check.
  assert.equal(
    isNicelisted('https://registry.npmjs.org/foo', 'URL'),
    true
  );
  assert.equal(
    isNicelisted('http://user:pass@s3.amazonaws.com:8080/bucket?x=1', 'URL'),
    true
  );
});

test('nicelist: refuses to match non-pivot IOC types', () => {
  // The IOC types that CAN be nicelisted are a closed set: URL, Domain,
  // Hostname, Email. Hashes, paths, registry keys, command lines, etc.
  // must NEVER be silently demoted regardless of value (a hash is a
  // hash — there's no benign infrastructure interpretation).
  assert.equal(isNicelisted('amazonaws.com', 'SHA-256'), false);
  assert.equal(isNicelisted('amazonaws.com', 'File Path'), false);
  assert.equal(isNicelisted('amazonaws.com', 'Pattern'), false);
  // Empty / falsy inputs return false rather than throw.
  assert.equal(isNicelisted('', 'URL'), false);
  assert.equal(isNicelisted(null, 'URL'), false);
  assert.equal(isNicelisted('amazonaws.com', null), false);
});

test('nicelist: extracts email host before matching', () => {
  // Email IOCs are unwrapped from `Display Name <addr@host>` form before
  // the host-suffix match runs. iCloud is in the list (intentional —
  // see the comment in nicelist.js).
  assert.equal(isNicelisted('engineer@apple.com', 'Email'), true);
  assert.equal(
    isNicelisted('Bob Smith <bob.smith@apple.com>', 'Email'),
    true
  );
  // Free-webmail is explicitly OUT of scope per the file's non-goals
  // — gmail.com etc. should NOT match. This guards against the most
  // common "let's just nicelist everything" PR.
  assert.equal(isNicelisted('attacker@gmail.com', 'Email'), false);
  assert.equal(isNicelisted('phish@outlook.com', 'Email'), false);
});

test('nicelist: kill-switch via safeStorage disables matching', () => {
  // Settings → Nicelists writes `loupe_nicelist_builtin_enabled = "0"`
  // to disable the built-in list. With the kill-switch on, every value
  // returns false even for canonical entries — analyst override.
  const { safeStorage } = ctx;
  // Sanity baseline before flipping the switch.
  assert.equal(isNicelisted('amazonaws.com', 'Domain'), true);
  safeStorage.set('loupe_nicelist_builtin_enabled', '0');
  assert.equal(isNicelisted('amazonaws.com', 'Domain'), false);
  // Restore the default state for downstream tests in the same file.
  safeStorage.remove('loupe_nicelist_builtin_enabled');
  assert.equal(isNicelisted('amazonaws.com', 'Domain'), true);
});

test('nicelist: path-qualified entries match URL prefix', () => {
  // `microsoft.com/pkiops` is a path-qualified entry — bare
  // `microsoft.com` is deliberately NOT on the list (homoglyph target),
  // but the narrow PKI sub-surface IS. The matcher must observe the
  // path scope.
  assert.equal(
    isNicelisted('https://www.microsoft.com/pkiops/certs/MicCodSig.crt', 'URL'),
    true
  );
  // Bare microsoft.com domain (without the path) must not match since
  // the entry requires the path. The Domain branch only consults
  // host-only entries.
  assert.equal(isNicelisted('microsoft.com', 'Domain'), false);
});
