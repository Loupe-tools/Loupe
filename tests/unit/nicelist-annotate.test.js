'use strict';
// nicelist-annotate.test.js — single canonical IOC tagger.
//
// `annotateNicelist(findings)` walks `findings.externalRefs` +
// `findings.interestingStrings` and stamps `_nicelisted` /
// `_nicelistSource` on each entry. It is the single source of truth
// consumed by the sidebar IOC table, the Copy Analysis Summary builder,
// and the STIX / MISP / CSV exporters in `app-ui.js`.
//
// Things this file MUST guard:
//   • Default Nicelist hits are tagged with `'Default Nicelist'` (not
//     a user-list name, even if a user list also matches — built-in
//     wins by load order).
//   • User-list hits surface their list display name on
//     `_nicelistSource`.
//   • Detection-class refs (YARA / Pattern / Info) are NEVER tagged
//     (they are rule hits, not user-suppressible IOCs).
//   • Calling the helper twice is idempotent — the export pipeline
//     calls it both at end-of-`_loadFile` and after the IOC worker
//     fallback path.
//   • Refs with no `url` or no `type` are tolerated (set `_nicelisted:
//     false`) — earlier code paths sometimes push partial entries
//     before the renderer fills them in.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

function fresh() {
  // The annotator only needs constants + storage + nicelist + nicelist-user
  // + the helper itself. Everything is pure (modulo the safeStorage
  // kill-switch which defaults to "on" with no key set).
  return loadModules([
    'src/constants.js',
    'src/storage.js',
    'src/nicelist.js',
    'src/nicelist-user.js',
    'src/nicelist-annotate.js',
  ], {
    expose: [
      'IOC', 'isNicelisted', 'safeStorage',
      '_NicelistUser', 'annotateNicelist',
    ],
  });
}

test('annotate: tags Default Nicelist hits with the built-in label', () => {
  const ctx = fresh();
  const findings = {
    externalRefs: [
      { type: ctx.IOC.URL, url: 'https://s3.amazonaws.com/foo' },
      { type: ctx.IOC.HOSTNAME, url: 'evil.example.com' },
    ],
  };
  ctx.annotateNicelist(findings);
  assert.equal(findings.externalRefs[0]._nicelisted, true);
  assert.equal(findings.externalRefs[0]._nicelistSource, 'Default Nicelist');
  assert.equal(findings.externalRefs[1]._nicelisted, false);
  assert.equal(findings.externalRefs[1]._nicelistSource, null);
});

test('annotate: walks both externalRefs AND interestingStrings', () => {
  // The two arrays together are exactly what `_collectIocs` unions.
  const ctx = fresh();
  const findings = {
    externalRefs: [{ type: ctx.IOC.DOMAIN, url: 'amazonaws.com' }],
    interestingStrings: [{ type: ctx.IOC.HOSTNAME, url: 'attacker.test' }],
  };
  ctx.annotateNicelist(findings);
  assert.equal(findings.externalRefs[0]._nicelisted, true);
  assert.equal(findings.interestingStrings[0]._nicelisted, false);
});

test('annotate: skips detection-class refs (YARA / Pattern / Info)', () => {
  // These are rule hits / rendering hints, never user-suppressible IOCs.
  // The helper still SETS the fields (to false / null) so downstream
  // code can rely on the property existing — but they must not match
  // any nicelist regardless of value.
  const ctx = fresh();
  const findings = {
    externalRefs: [
      { type: ctx.IOC.YARA,    url: 'amazonaws.com', ruleName: 'YARA_Hit' },
      { type: ctx.IOC.PATTERN, url: 'amazonaws.com', description: 'pattern' },
      { type: ctx.IOC.INFO,    url: 'amazonaws.com', description: 'info' },
    ],
  };
  ctx.annotateNicelist(findings);
  for (const r of findings.externalRefs) {
    assert.equal(r._nicelisted, false, `expected ${r.type} not nicelisted`);
    assert.equal(r._nicelistSource, null);
  }
});

test('annotate: idempotent — second call leaves tags identical', () => {
  // The deferred IOC-worker patcher path in `app-load.js` calls the
  // helper a second time after merging fresh IOCs. Tag values must not
  // flip between calls when the underlying ref is unchanged.
  const ctx = fresh();
  const findings = {
    externalRefs: [
      { type: ctx.IOC.URL, url: 'https://s3.amazonaws.com/foo' },
      { type: ctx.IOC.HOSTNAME, url: 'evil.example.com' },
    ],
  };
  ctx.annotateNicelist(findings);
  const snap = findings.externalRefs.map(r => ({
    n: r._nicelisted, s: r._nicelistSource,
  }));
  ctx.annotateNicelist(findings);
  for (let i = 0; i < findings.externalRefs.length; i++) {
    assert.equal(findings.externalRefs[i]._nicelisted, snap[i].n);
    assert.equal(findings.externalRefs[i]._nicelistSource, snap[i].s);
  }
});

test('annotate: tolerates partial refs (missing url or type)', () => {
  // ioc-extract.js + the recursive-decode pipeline can transiently
  // push entries that have either no `url` (placeholder) or no `type`
  // (pre-classification). Annotator must not throw on those — set
  // `_nicelisted: false` and move on.
  const ctx = fresh();
  const findings = {
    externalRefs: [
      { type: ctx.IOC.URL },                           // no url
      { url: 'amazonaws.com' },                        // no type
      null,                                            // hostile
      { type: ctx.IOC.URL, url: 'https://s3.amazonaws.com/' },
    ],
  };
  // Must not throw.
  ctx.annotateNicelist(findings);
  assert.equal(findings.externalRefs[0]._nicelisted, false);
  assert.equal(findings.externalRefs[1]._nicelisted, false);
  // null entry left alone — annotator must skip rather than crash.
  assert.equal(findings.externalRefs[2], null);
  assert.equal(findings.externalRefs[3]._nicelisted, true);
});

test('annotate: tolerates findings without externalRefs / interestingStrings', () => {
  // `_collectIocs` is sometimes invoked on a synthetic findings shape
  // (test harness, future "report from saved JSON" path). The helper
  // must short-circuit cleanly in that case.
  const ctx = fresh();
  ctx.annotateNicelist({});                            // no arrays at all
  ctx.annotateNicelist({ externalRefs: null });        // null array
  ctx.annotateNicelist(null);                          // null findings
  // No assertions — we just need this not to throw.
});

test('annotate: built-in wins over user-list when both match', () => {
  // Load order for `nicelist-annotate.js` is: nicelist.js (built-in
  // first) → nicelist-user.js (custom). The annotator checks built-in
  // first, then falls through to the user list. Verify the priority.
  const ctx = fresh();
  // Inject a user list whose entries collide with the built-in
  // 'amazonaws.com' apex. Built-in must still win the source label.
  const list = ctx._NicelistUser.createList('My CDN list');
  ctx._NicelistUser.addEntry(list.id, 'amazonaws.com');
  const findings = {
    externalRefs: [{ type: ctx.IOC.HOSTNAME, url: 's3.amazonaws.com' }],
  };
  ctx.annotateNicelist(findings);
  assert.equal(findings.externalRefs[0]._nicelisted, true);
  assert.equal(findings.externalRefs[0]._nicelistSource, 'Default Nicelist');
});
