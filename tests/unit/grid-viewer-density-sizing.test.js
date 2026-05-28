'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grid-viewer-density-sizing.test.js — pin opt-in Timeline grid density /
// sizing affordances without changing shared GridViewer defaults.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const GV = fs.readFileSync(
  path.join(REPO_ROOT, 'src/renderers/grid-viewer.js'),
  'utf8',
);
const TIMELINE_GRID = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-render-grid.js'),
  'utf8',
);
const TIMELINE_FILTER = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-filter.js'),
  'utf8',
);
const VIEWERS_CSS = fs.readFileSync(
  path.join(REPO_ROOT, 'src/styles/viewers.css'),
  'utf8',
);

test('GridViewer supports opt-in compact density without changing default row constants', () => {
  assert.match(
    GV,
    /this\._density\s*=\s*opts\.density\s*===\s*['"]compact['"]\s*\?\s*['"]compact['"]\s*:\s*['"]default['"]/,
    'constructor must capture an opt-in compact density preset',
  );
  assert.match(
    GV,
    /this\.ROW_HEIGHT\s*=\s*this\._density\s*===\s*['"]compact['"]\s*\?\s*24\s*:\s*28\s*;/,
    'compact density must use 24px rows while default remains 28px',
  );
  assert.match(
    GV,
    /this\.HEADER_H\s*=\s*this\._density\s*===\s*['"]compact['"]\s*\?\s*28\s*:\s*32\s*;/,
    'compact density must use a 28px header while default remains 32px',
  );
  assert.match(
    GV,
    /grid-density-compact/,
    'GridViewer root must carry a compact-density class when the preset is active',
  );
});

test('compact density has matching CSS row and header heights', () => {
  assert.match(
    VIEWERS_CSS,
    /\.grid-view\.grid-density-compact\s+\.grid-header\s*\{[\s\S]{0,80}?height:\s*28px;/,
    'compact CSS header height must match GridViewer.HEADER_H',
  );
  assert.match(
    VIEWERS_CSS,
    /\.grid-view\.grid-density-compact\s+\.grid-row\s*\{[\s\S]{0,80}?height:\s*24px;/,
    'compact CSS row height must match GridViewer.ROW_HEIGHT',
  );
  assert.match(
    VIEWERS_CSS,
    /\.grid-view\.grid-density-compact\s+\.grid-cell\s*\{[\s\S]{0,80}?padding:\s*2px\s+8px;/,
    'compact CSS must reduce body-cell padding for higher information density',
  );
});

test('GridViewer exposes per-instance column sizing knobs', () => {
  assert.match(
    GV,
    /opts\.columnSizing\s*&&\s*typeof\s+opts\.columnSizing\s*===\s*['"]object['"]/,
    'constructor must accept an optional columnSizing object',
  );
  assert.match(
    GV,
    /this\.MAX_COL_W\s*=\s*optNum\(\s*['"]maxTextColW['"]\s*,\s*320/,
    'text-column width cap must be overrideable without changing the default',
  );
  assert.match(
    GV,
    /this\._growShortColumns\s*=\s*sizing\.growShortColumns\s*!==\s*false\s*;/,
    'short-column slack growth must be opt-out per grid instance',
  );
  assert.match(
    GV,
    /this\._fixedColExtraPx\s*=\s*optNum\(\s*['"]fixedExtraPx['"]\s*,\s*8/,
    'fixed-shape column breathing room must be overrideable per grid instance',
  );
  assert.match(
    GV,
    /this\._identityMaxColW\s*=\s*optNum\(\s*['"]maxIdentityColW['"]/,
    'identity/email column cap must be overrideable per grid instance',
  );
  assert.match(
    GV,
    /!this\._growShortColumns\s*&&\s*k\s*===\s*['"]short['"]/,
    '_applyColumnTemplate must honor the growShortColumns opt-out',
  );
});

test('Timeline grid opts into compact density, tuned widths, and file-scoped width persistence', () => {
  assert.match(
    TIMELINE_GRID,
    /gridKey\s*:\s*['"]tl-grid-inner_['"]\s*\+\s*this\._fileKey/,
    'Timeline GridViewer widths must be scoped by file key, not only by generic class name',
  );
  assert.match(
    TIMELINE_GRID,
    /density\s*:\s*['"]compact['"]/,
    'Timeline main grid must opt into compact density',
  );
  assert.match(
    TIMELINE_GRID,
    /columnSizing\s*:\s*\{[\s\S]{0,220}?maxTextColW\s*:\s*420[\s\S]{0,220}?maxIdentityColW\s*:\s*480[\s\S]{0,220}?fixedExtraPx\s*:\s*0[\s\S]{0,220}?growShortColumns\s*:\s*false/,
    'Timeline main grid must opt into tuned text, identity, fixed-column, and short-column sizing',
  );
  assert.match(
    TIMELINE_GRID,
    /widthHints\s*:\s*this\._gridWidthHintsFromStats\(\)/,
    'Timeline main grid must seed GridViewer with full-column width hints when stats already exist',
  );
});

test('Timeline column stats expose maxLen for GridViewer width hints', () => {
  assert.match(
    TIMELINE_FILTER,
    /const\s+maxLens\s*=\s*new\s+Array\(span\)\.fill\(0\)/,
    'Timeline column-stat passes must track per-column maxLen',
  );
  assert.match(
    TIMELINE_FILTER,
    /maxLen:\s*maxLens\[c\]/,
    'Timeline column-stat output must expose maxLen on every stats slot',
  );
  assert.match(
    TIMELINE_GRID,
    /^ {2}_gridWidthHintsFromStats\s*\(/m,
    'timeline grid mixin must expose _gridWidthHintsFromStats()',
  );
  assert.match(
    TIMELINE_GRID,
    /maxLen:\s*Math\.max\(0,\s*Number\(s\.maxLen\)\)/,
    'timeline grid width hints must be derived from per-column stats maxLen',
  );
  assert.match(
    TIMELINE_GRID,
    /this\._grid\._setColumnWidthHints\(hints\)/,
    'timeline grid must push width hints into the live GridViewer after stats compute',
  );
});

test('GridViewer consumes maxLen hints for fixed and identity column sizing', () => {
  assert.match(
    GV,
    /^ {2}_setColumnWidthHints\s*\(/m,
    'GridViewer must expose _setColumnWidthHints(hints)',
  );
  assert.match(
    GV,
    /const\s+maxObservedLen\s*=\s*hintMaxLen\s*==\s*null\s*\?\s*p100\s*:\s*Math\.max\(p100,\s*hintMaxLen\)/,
    'width math must combine sampled p100 with full-stat maxLen hints',
  );
  assert.match(
    GV,
    /const\s+identity\s*=\s*roles\[c\]\s*===\s*['"]identity['"]/,
    'GridViewer must track semantic identity/email columns separately from generic text',
  );
  assert.match(
    GV,
    /Math\.ceil\(maxObservedLen\s*\*\s*chW\)\s*\+\s*this\.CELL_PAD_PX\s*\+\s*TIGHT_PAD/,
    'fixed-shape columns must size from maxObservedLen, not percentile length',
  );
  assert.match(
    GV,
    /this\._identityMaxColW[\s\S]{0,120}?Math\.ceil\(maxObservedLen\s*\*\s*chW\)\s*\+\s*this\.CELL_PAD_PX/,
    'identity/email columns must size from maxObservedLen up to their cap',
  );
});

test('character-width probe uses the rendered grid-row monospace font', () => {
  const m = GV.match(/^ {2}_measureCharWidth\s*\(\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_measureCharWidth body not found');
  const body = m[1];
  assert.match(
    body,
    /document\.createElement\(\s*['"]span['"]\s*\)/,
    'character-width probe should be inline text-shaped, not a block grid cell',
  );
  assert.match(
    body,
    /probe\.style\.fontFamily\s*=\s*['"][\s\S]{0,80}?Fira Code/,
    'character-width probe must set the same monospace family used by grid rows',
  );
  assert.match(
    body,
    /probe\.style\.fontSize\s*=\s*['"]12px['"]/,
    'character-width probe must set the same font size used by grid rows',
  );
});

test('column header menu exposes reset-width escape hatches', () => {
  assert.match(
    GV,
    /Reset column width/,
    'column menu must expose a discoverable reset for the active column width',
  );
  assert.match(
    GV,
    /Reset all column widths/,
    'column menu must expose a reset-all action when multiple manual widths exist',
  );
  assert.match(
    GV,
    /^ {2}_resetAllColumnWidths\s*\(/m,
    'GridViewer must define _resetAllColumnWidths()',
  );
});
