'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-export-parity.test.js — pin the B2f4 split.
//
// B2f4 hoists the pivot-table builder + every CSV / PNG export
// path out of `timeline-view.js` into `timeline-view-export.js`.
// The mixin attaches via `Object.assign(TimelineView.prototype,
// {...})`.
//
// Pins:
//   • each method's `methodName(args) {` definition is GONE from
//     `timeline-view.js`
//   • each method appears EXACTLY once in
//     `timeline-view-export.js`
//   • build order: export mixin loads after `timeline-view.js`
//   • the forensic-filename naming convention survives byte-
//     identical (analyst-visible UX contract)
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const VIEW = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view.js'),
  'utf8',
);
const MIXIN = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-export.js'),
  'utf8',
);
const BUILD = fs.readFileSync(
  path.join(REPO_ROOT, 'scripts/build.py'),
  'utf8',
);

const MOVED_METHODS = [
  // Pivot
  '_autoPivotFromColumn',
  '_buildPivot',
  // Section actions
  '_onSectionAction',
  // Forensic filename helpers
  '_forensicFilename',
  '_forensicSourceStem',
  '_forensicCompactUtc',
  '_forensicCompactNum',
  '_forensicRangeSegment',
  // Exporters
  '_exportChartPng',
  '_exportChartCsv',
  '_exportGridCsv',
  '_exportColumnsCsv',
  '_exportPivotCsv',
];

// ── Removal asserts ────────────────────────────────────────────────────────

test('timeline-view.js no longer defines any pivot/export method', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      VIEW,
      re,
      `${name} must be moved to timeline-view-export.js`,
    );
  }
});

// ── Presence asserts ───────────────────────────────────────────────────────

test('timeline-view-export.js attaches via Object.assign(TimelineView.prototype, ...)', () => {
  assert.match(
    MIXIN,
    /Object\.assign\(\s*TimelineView\.prototype\s*,\s*\{/,
  );
});

test('timeline-view-export.js defines every pivot/export method exactly once', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'gm');
    const matches = MIXIN.match(re) || [];
    assert.equal(
      matches.length,
      1,
      `${name} must appear exactly once in timeline-view-export.js (got ${matches.length})`,
    );
  }
});

// ── Body anchors ───────────────────────────────────────────────────────────

test('Every exporter routes through window.FileDownload', () => {
  // The CSP forbids `URL.createObjectURL` outside the
  // `FileDownload` helper; pin that the exporters keep using it
  // rather than rolling their own download path. A regression
  // here would silently violate the CSP contract documented in
  // SECURITY.md.
  assert.match(
    MIXIN,
    /window\.FileDownload\.downloadText/,
    'exporters must route through window.FileDownload.downloadText',
  );
  assert.match(
    MIXIN,
    /window\.FileDownload\.downloadBlob/,
    '_exportChartPng must route through window.FileDownload.downloadBlob',
  );
});

test('_forensicFilename anchors the analyst-visible naming convention', () => {
  // Pattern: `<source-stem>__<section>__<UTC>.<ext>`.  Pin the
  // double-underscore separators — investigators sort outputs from
  // multiple loupe runs against the same source by the embedded UTC
  // timestamp, so a refactor that reformatted the filename would
  // silently break their workflow.
  assert.match(
    MIXIN,
    /__/,
    '_forensicFilename must keep the `__` separator',
  );
});

test('_buildPivot consumes _filteredIdx (not the full data range)', () => {
  // The pivot honours the active query — pin the source-of-rows so
  // a refactor that re-based on the full dataset (`store.rowCount`)
  // is caught. Regressions here would silently produce pivot
  // tables that don't match what's visible in the grid.
  assert.match(
    MIXIN,
    /this\._filteredIdx/,
    '_buildPivot must read this._filteredIdx',
  );
});

test('_exportChartPng goes through canvas.toBlob (PNG export path)', () => {
  // The PNG exporter is the only canvas-to-Blob path; pin
  // `toBlob` so a refactor that fell back to `toDataURL` (which
  // is much slower for big charts) is caught.
  assert.match(
    MIXIN,
    /\.toBlob\(/,
    '_exportChartPng must use canvas.toBlob',
  );
});

// ── Build order ────────────────────────────────────────────────────────────

test('scripts/build.py registers timeline-view-export.js after timeline-view.js', () => {
  const viewIdx = BUILD.indexOf("'src/app/timeline/timeline-view.js'");
  const expIdx = BUILD.indexOf("'src/app/timeline/timeline-view-export.js'");
  assert.notEqual(viewIdx, -1);
  assert.notEqual(expIdx, -1);
  assert.ok(expIdx > viewIdx, 'export mixin must load AFTER timeline-view.js');
});

// ── TimelineDataset invariant ──────────────────────────────────────────────

test('moved pivot/export bodies do not introduce a bare this._evtxEvents reference', () => {
  const stripped = MIXIN
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
    .replace(/`[\s\S]*?`/g, '``')
    .replace(/"[^"\n]*"/g, '""')
    .replace(/'[^'\n]*'/g, "''");
  assert.doesNotMatch(
    stripped,
    /this\._evtxEvents\b/,
    'timeline-view-export.js must not read this._evtxEvents — use the dataset / store',
  );
});
