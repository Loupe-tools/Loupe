'use strict';

const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  [
    'src/constants.js',
    'src/renderer-helpers.js',
    'src/renderers/x509-renderer.js',
    'src/renderers/pgp-renderer.js',
  ],
  { expose: ['X509Renderer', 'PgpRenderer'] },
);

const { X509Renderer, PgpRenderer } = ctx;

function analyzeFixture(Renderer, rel) {
  const abs = path.join(process.cwd(), rel);
  const buf = fs.readFileSync(abs);
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  return new Renderer().analyzeForSecurity(ab, path.basename(rel));
}

const PINS = [
  {
    renderer: 'x509',
    path: 'examples/crypto/example-expired.crt',
    risk: 'medium',
    riskLevel: 'medium',
    riskScoreMin: 10,
  },
  {
    renderer: 'x509',
    path: 'examples/crypto/example-selfsigned.pem',
    risk: 'medium',
    riskLevel: 'medium',
    riskScoreMin: 10,
  },
  {
    renderer: 'x509',
    path: 'examples/crypto/example-with-key.pem',
    risk: 'critical',
    riskLevel: 'critical',
    riskScoreMin: 50,
  },
  {
    renderer: 'x509',
    path: 'examples/crypto/google-chain.pem',
    risk: 'medium',
    riskLevel: 'medium',
    riskScoreMin: 10,
  },
  {
    renderer: 'pgp',
    path: 'examples/crypto/private-example.key',
    risk: 'critical',
    riskLevel: 'critical',
    riskScoreMin: 50,
  },
];

for (const pin of PINS) {
  const label = `${pin.renderer}: ${pin.path}`;
  test(`crypto risk tier pin — ${label}`, () => {
    const Renderer = pin.renderer === 'x509' ? X509Renderer : PgpRenderer;
    const findings = analyzeFixture(Renderer, pin.path);
    assert.equal(findings.risk, pin.risk, `${label} risk`);
    assert.equal(findings.riskLevel, pin.riskLevel, `${label} riskLevel`);
    assert.ok(
      findings.riskScore >= pin.riskScoreMin,
      `${label} riskScore >= ${pin.riskScoreMin} (got ${findings.riskScore})`,
    );
    assert.ok(Array.isArray(findings.externalRefs) && findings.externalRefs.length >= 1,
      `${label} must mirror detections into externalRefs`);
  });
}