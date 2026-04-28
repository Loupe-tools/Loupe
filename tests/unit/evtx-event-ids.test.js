'use strict';
// evtx-event-ids.test.js — Windows Event-ID → human label + MITRE registry.
//
// `EvtxEventIds.lookup(id, channel)` is the Timeline-Mode helper that
// turns a numeric event ID + Windows channel into a `{name, summary,
// channel, category, noisy, techniques[]}` record. The lookup is two-
// step (`<channel>:<id>` then bare `<id>`) and hydrates MITRE technique
// IDs through the global `window.MITRE` registry. The class is pure
// over a frozen lookup table — no DOM, no I/O.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// evtx-event-ids.js depends on `window.MITRE` for technique hydration;
// load mitre.js first so the registry is populated before the EvtxEventIds
// IIFE runs.
const ctx = loadModules(['src/mitre.js', 'src/evtx-event-ids.js']);
const { EvtxEventIds } = ctx;

test('evtx-event-ids: exposes the canonical four-method API', () => {
  assert.equal(typeof EvtxEventIds.lookup, 'function');
  assert.equal(typeof EvtxEventIds.formatTooltip, 'function');
  assert.equal(typeof EvtxEventIds.normChannel, 'function');
  assert.equal(typeof EvtxEventIds.EVENTS, 'object');
});

test('evtx-event-ids: lookup of 4624 returns Successful logon', () => {
  // 4624 (Security) is the canonical "successful logon" event — every
  // SOC analyst knows it by number. The bare-id fallback path means
  // we don't need to pass a channel for it to resolve.
  const r = EvtxEventIds.lookup(4624);
  assert.ok(r, '4624 must resolve');
  assert.equal(r.id, '4624');
  assert.match(r.name, /successfully logged on/i);
  assert.equal(r.category, 'Logon');
  assert.equal(r.noisy, true);
});

test('evtx-event-ids: lookup of 4625 returns Failed logon', () => {
  // 4625 is the failed-logon counterpart, not noisy by default.
  const r = EvtxEventIds.lookup(4625);
  assert.ok(r);
  assert.equal(r.id, '4625');
  assert.match(r.name, /failed to log on/i);
  assert.equal(r.category, 'Logon');
});

test('evtx-event-ids: lookup hydrates MITRE techniques with names + URLs', () => {
  // The whole point of cross-loading mitre.js: every technique ID in
  // the EVTX entry's `mitre` array resolves to `{id, name, tactic, url}`.
  // 4624 references T1078 (Valid Accounts) and T1021 (Remote Services).
  const r = EvtxEventIds.lookup(4624);
  assert.ok(Array.isArray(r.techniques));
  const t1078 = r.techniques.find(t => t.id === 'T1078');
  assert.ok(t1078, 'T1078 must be in the technique list');
  assert.equal(t1078.name, 'Valid Accounts');
  assert.match(t1078.url, /attack\.mitre\.org/);
});

test('evtx-event-ids: channel-keyed lookup beats bare-id lookup', () => {
  // Same numeric ID can have different meanings on different channels
  // (e.g. Sysmon 1 = ProcessCreate vs Security 4688). The lookup tries
  // the channel-keyed entry first.
  const sysmon1 = EvtxEventIds.lookup(1, 'Microsoft-Windows-Sysmon/Operational');
  assert.ok(sysmon1, 'sysmon:1 must resolve via channel-key path');
  // Sysmon 1 is the "Process Creation" event — should NOT be the
  // fallback bare "1" entry (if that even exists).
  assert.match(
    sysmon1.name + ' ' + sysmon1.summary,
    /process|creation/i
  );
});

test('evtx-event-ids: lookup of unknown ID returns null', () => {
  // Out-of-table IDs return null so renderers can drop the annotation
  // pill — we never want a hallucinated event description.
  assert.equal(EvtxEventIds.lookup(99999), null);
  assert.equal(EvtxEventIds.lookup(null), null);
  assert.equal(EvtxEventIds.lookup(''), null);
});

test('evtx-event-ids: normChannel maps Microsoft-Windows-* prefixes', () => {
  // The channel-normalisation table is documented at the top of
  // evtx-event-ids.js. Verify every common Microsoft-Windows-* prefix
  // collapses to the short tag the lookup uses.
  assert.equal(
    EvtxEventIds.normChannel('Microsoft-Windows-Sysmon/Operational'),
    'sysmon'
  );
  assert.equal(
    EvtxEventIds.normChannel('Microsoft-Windows-PowerShell/Operational'),
    'powershell'
  );
  assert.equal(
    EvtxEventIds.normChannel('Microsoft-Windows-TaskScheduler/Operational'),
    'taskscheduler'
  );
  assert.equal(EvtxEventIds.normChannel('Security'), 'security');
  assert.equal(EvtxEventIds.normChannel(''), '');
});

test('evtx-event-ids: formatTooltip emits a multi-line analyst tooltip', () => {
  // The tooltip is what the timeline drawer pill shows on hover. Format:
  //   "<id> — <name>"
  //   "Channel: <ch> · <category>"
  //   ""
  //   "MITRE ATT&CK:"
  //   "  T1078  Valid Accounts"
  //   …
  const r = EvtxEventIds.lookup(4624);
  const tip = EvtxEventIds.formatTooltip(r);
  assert.match(tip, /^4624 — /);
  assert.match(tip, /Channel: Security · Logon/);
  assert.match(tip, /MITRE ATT&CK:/);
  assert.match(tip, /T1078/);
});
