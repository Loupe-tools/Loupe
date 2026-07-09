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
    expose: ['calibrateRiskFromEvidence', 'mirrorDetectionsToExternalRefs', 'pushExternalRef'],
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