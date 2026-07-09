'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

function loadHelpers() {
  return loadModules(['src/renderer-helpers.js'], {
    shims: {
      pushIOC(findings, opts) {
        const bucket = opts.bucket || 'externalRefs';
        if (!findings[bucket]) findings[bucket] = [];
        findings[bucket].push(opts);
      },
      escalateRisk(findings, tier) {
        const order = { low: 0, medium: 1, high: 2, critical: 3 };
        const cur = findings.risk || 'low';
        if (order[tier] > order[cur]) findings.risk = tier;
      },
      IOC: { PATTERN: 'pattern' },
    },
    expose: [
      'calibrateRiskFromEvidence',
      'mirrorDetectionsToExternalRefs',
      'pushExternalRef',
      'riskLevelFromScore',
      'finalizeScoreBasedRisk',
      'IOC',
    ],
  });
}

test('calibrateRiskFromEvidence escalates from externalRefs severity counts', () => {
  const { calibrateRiskFromEvidence } = loadHelpers();
  const findings = {
    risk: 'low',
    externalRefs: [
      { severity: 'medium' },
      { severity: 'high' },
      { severity: 'high' },
    ],
  };
  calibrateRiskFromEvidence(findings);
  assert.equal(findings.risk, 'high');
});

test('calibrateRiskFromEvidence respects monotonic escalateRisk (no downgrade)', () => {
  const { calibrateRiskFromEvidence } = loadHelpers();
  const findings = {
    risk: 'critical',
    externalRefs: [{ severity: 'low' }],
  };
  calibrateRiskFromEvidence(findings);
  assert.equal(findings.risk, 'critical');
});

test('riskLevelFromScore boundary pins', () => {
  const { riskLevelFromScore } = loadHelpers();
  assert.equal(riskLevelFromScore(9), 'low');
  assert.equal(riskLevelFromScore(10), 'medium');
  assert.equal(riskLevelFromScore(29), 'medium');
  assert.equal(riskLevelFromScore(30), 'high');
  assert.equal(riskLevelFromScore(49), 'high');
  assert.equal(riskLevelFromScore(50), 'critical');
  assert.equal(riskLevelFromScore(Number.NaN), 'low');
});

test('finalizeScoreBasedRisk mirrors score tier then lifts from evidence', () => {
  const { finalizeScoreBasedRisk } = loadHelpers();
  const findings = {
    riskScore: 40,
    detections: [{ name: 'Private Key Detected', description: 'test', severity: 'high' }],
    externalRefs: [],
  };
  finalizeScoreBasedRisk(findings);
  assert.equal(findings.riskLevel, 'high');
  assert.equal(findings.risk, 'high');
  assert.equal(findings.externalRefs.length, 1);
});

test('finalizeScoreBasedRisk does not downgrade score tier via evidence calibration', () => {
  const { finalizeScoreBasedRisk } = loadHelpers();
  const findings = {
    riskScore: 40,
    detections: [{ name: 'Private Key Detected', description: 'test', severity: 'high' }],
    externalRefs: [],
  };
  finalizeScoreBasedRisk(findings);
  // One high ref → evidence-only path would be medium; score floor stays high.
  assert.equal(findings.risk, 'high');
});

test('finalizeScoreBasedRisk lifts when critical evidence exceeds score tier', () => {
  const { finalizeScoreBasedRisk } = loadHelpers();
  const findings = {
    riskScore: 15,
    detections: [{
      name: 'Unprotected PGP Private Key',
      description: 'test',
      severity: 'critical',
    }],
    externalRefs: [],
  };
  finalizeScoreBasedRisk(findings);
  assert.equal(findings.riskLevel, 'medium');
  assert.equal(findings.risk, 'critical');
});

test('finalizeScoreBasedRisk: critical evidence lifts a low score floor', () => {
  const { finalizeScoreBasedRisk, IOC } = loadHelpers();
  const findings = {
    detections: [{ name: 'SyntheticHigh', description: 'misaligned', severity: 'critical' }],
    riskScore: 0,   // score floor → 'low'
    externalRefs: [],
  };
  finalizeScoreBasedRisk(findings);
  assert.equal(findings.riskLevel, 'low');      // score floor preserved
  assert.equal(findings.risk, 'critical');      // but evidence lifts to critical
  // And mirror produced an externalRefs PATTERN row
  assert.ok(findings.externalRefs.some(r => r.type === IOC.PATTERN && r.severity === 'critical'));
});

test('finalizeScoreBasedRisk: score-tier-critical + low evidence stays critical', () => {
  const { finalizeScoreBasedRisk } = loadHelpers();
  const findings = { detections: [], riskScore: 100, externalRefs: [] };
  finalizeScoreBasedRisk(findings);
  assert.equal(findings.riskLevel, 'critical');
  assert.equal(findings.risk, 'critical');      // no downgrade from low evidence
});