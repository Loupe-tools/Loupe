'use strict';
// mitre.test.js — MITRE ATT&CK technique registry.
//
// `mitre.js` publishes its surface onto `window.MITRE` (the bundle is one
// inline <script>; module-as-IIFE pattern). The test harness aliases
// `window` to the sandbox itself, so `window.MITRE = …` lands as
// `globalThis.MITRE` — accessible as `ctx.MITRE` after evaluation.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// mitre.js is dependency-free — no constants needed.
const ctx = loadModules(['src/mitre.js']);
const { MITRE } = ctx;

test('mitre: exposes the canonical four-method API on window.MITRE', () => {
  // Renderers and the EVTX subsystem call these by name; freezing the
  // surface here catches accidental rename / removal.
  assert.equal(typeof MITRE.lookup, 'function');
  assert.equal(typeof MITRE.primaryTactic, 'function');
  assert.equal(typeof MITRE.urlFor, 'function');
  assert.equal(typeof MITRE.tacticMeta, 'function');
  assert.equal(typeof MITRE.rollupByTactic, 'function');
  assert.equal(typeof MITRE.TECHNIQUES, 'object');
  assert.equal(typeof MITRE.TACTICS, 'object');
});

test('mitre: lookup of T1059 returns Command and Scripting Interpreter', () => {
  // T1059 is the classic Execution-tactic technique covering every
  // shell / interpreter abuse path (PowerShell, cmd, bash, …).
  // Renderers reference it from the binary-capability strip; if the
  // canonical name drifted, the strip would render confusing labels.
  const t = MITRE.lookup('T1059');
  assert.ok(t, 'T1059 must resolve');
  assert.equal(t.id, 'T1059');
  assert.equal(t.name, 'Command and Scripting Interpreter');
  assert.equal(t.tactic, 'execution');
  assert.equal(t.url, 'https://attack.mitre.org/techniques/T1059/');
});

test('mitre: lookup of sub-technique T1059.001 hydrates parent + URL', () => {
  // Sub-techniques carry `parent: 'T1059'` so the rollup can group them
  // back under the parent in the sidebar. URL format uses `/T1059/001/`
  // for the canonical attack.mitre.org link.
  const t = MITRE.lookup('T1059.001');
  assert.equal(t.id, 'T1059.001');
  assert.equal(t.name, 'PowerShell');
  assert.equal(t.parent, 'T1059');
  assert.equal(t.url, 'https://attack.mitre.org/techniques/T1059/001/');
});

test('mitre: lookup of unknown ID returns a best-effort fallback', () => {
  // The contract documented in mitre.js: an unknown ID returns
  // `{ id, name: id, tactic: '', url: <urlFor result> }` so the caller
  // never has to null-check. Critical because EVTX hydrates IDs from
  // its own table and an out-of-sync entry must NOT crash the lookup.
  const t = MITRE.lookup('T9999');
  assert.equal(t.id, 'T9999');
  assert.equal(t.name, 'T9999');
  assert.equal(t.tactic, '');
  assert.equal(t.url, 'https://attack.mitre.org/techniques/T9999/');
});

test('mitre: primaryTactic strips a comma-joined tactic list', () => {
  // T1078 is genuinely both privilege-escalation AND defense-evasion.
  // The first listed tactic is the canonical grouping per the file
  // comment.
  assert.equal(MITRE.primaryTactic('T1078'), 'privilege-escalation');
  // Single-tactic technique returns that tactic verbatim.
  assert.equal(MITRE.primaryTactic('T1059'), 'execution');
});

test('mitre: urlFor refuses non-technique IDs', () => {
  // The regex gate on `urlFor` is what stops bogus / user-supplied
  // strings from being turned into attack.mitre.org links downstream.
  assert.equal(MITRE.urlFor('not-a-technique'), '');
  assert.equal(MITRE.urlFor(''), '');
  assert.equal(MITRE.urlFor(null), '');
  // Valid forms.
  assert.equal(MITRE.urlFor('T1059'), 'https://attack.mitre.org/techniques/T1059/');
  assert.equal(MITRE.urlFor('T1055.012'), 'https://attack.mitre.org/techniques/T1055/012/');
});

test('mitre: tacticMeta returns label + icon + ATT&CK kill-chain order', () => {
  const ex = MITRE.tacticMeta('execution');
  assert.equal(ex.label, 'Execution');
  assert.equal(ex.order, 1);
  // Unknown tactic falls through to a neutral placeholder.
  const unk = MITRE.tacticMeta('not-a-tactic');
  assert.equal(unk.order, 99);
});

test('mitre: rollupByTactic groups + sorts techniques per tactic', () => {
  // Mix two execution-tactic items, one persistence-tactic item, plus
  // a duplicate id. Output groups by tactic, sorts groups by ATT&CK
  // kill-chain order (execution=1 before persistence=2), and dedupes
  // within a tactic keeping highest severity.
  const out = MITRE.rollupByTactic([
    { id: 'T1059',     severity: 'medium' },
    { id: 'T1059.001', severity: 'high' },
    { id: 'T1053',     severity: 'low' },
    { id: 'T1059',     severity: 'critical' }, // dedup: keep critical
  ]);
  assert.equal(out.length, 2);
  assert.equal(out[0].tactic, 'execution');
  assert.equal(out[1].tactic, 'persistence');
  // Within execution, dedup must have kept the critical-severity T1059
  // entry (the rollup picks highest-severity duplicate).
  const t1059 = out[0].techniques.find(t => t.id === 'T1059');
  assert.equal(t1059.severity, 'critical');
});
