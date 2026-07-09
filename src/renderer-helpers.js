'use strict';
// ════════════════════════════════════════════════════════════════════════════
// renderer-helpers.js — shared renderer/dispatch primitives
//
// Canonical chokepoints for IOC emission and risk calibration that every
// format handler should route through instead of hand-rolling local
// `refs.push` arrays or bespoke `findings.externalRefs = …` assignments.
// Loaded immediately after constants.js (pushIOC / escalateRisk / IOC.*).
// ════════════════════════════════════════════════════════════════════════════

/**
 * Push a prebuilt IOC row into `findings.externalRefs` via `pushIOC()`.
 * @param {object} findings
 * @param {object} ref  Prebuilt entry (`type`, `url`, `severity`, …).
 */
function pushExternalRef(findings, ref) {
  pushIOC(findings, Object.assign({ bucket: 'externalRefs' }, ref));
}

/**
 * Mirror `findings.detections[]` into `externalRefs` as `IOC.PATTERN` rows.
 * Appends — does not overwrite existing externalRefs.
 * @param {object} findings
 */
function mirrorDetectionsToExternalRefs(findings) {
  if (!findings || !Array.isArray(findings.detections)) return;
  for (const d of findings.detections) {
    if (!d || !d.name) continue;
    pushExternalRef(findings, {
      type: IOC.PATTERN,
      url: `${d.name} — ${d.description || ''}`,
      severity: d.severity || 'medium',
    });
  }
}

/**
 * Evidence-derived risk calibration from `externalRefs` severity counts.
 * See CONTRIBUTING.md → Risk Tier Calibration.
 * @param {object} findings
 */
function calibrateRiskFromEvidence(findings) {
  if (!findings) return;
  const refs = findings.externalRefs || [];
  const highs = refs.filter(r => r && r.severity === 'high').length;
  const hasCrit = refs.some(r => r && r.severity === 'critical');
  const hasMed = refs.some(r => r && r.severity === 'medium');
  if (hasCrit) escalateRisk(findings, 'critical');
  else if (highs >= 2) escalateRisk(findings, 'high');
  else if (highs >= 1) escalateRisk(findings, 'medium');
  else if (hasMed) escalateRisk(findings, 'low');
}