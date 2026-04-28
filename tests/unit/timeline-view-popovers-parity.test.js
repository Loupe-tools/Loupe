'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-popovers-parity.test.js — pin the B2d split.
//
// B2d hoists the popover / menu / dialog methods out of
// `timeline-view.js` into `timeline-view-popovers.js`. The mixin
// attaches them via `Object.assign(TimelineView.prototype, {...})`.
//
// Pins:
//   • each method's `methodName(args) {` definition is GONE from
//     `timeline-view.js`
//   • each method appears EXACTLY once in
//     `timeline-view-popovers.js`
//   • the tiny utilities `_ellipsis`, `_copyToClipboard`,
//     `_positionFloating` STAY in `timeline-view.js` (shared by chart
//     and grid mixins — moving them would invert the dep direction)
//   • build order: popovers mixin loads after timeline-view.js
//   • user-visible affordances pinned by string anchor (the bulk-add
//     copy in Add-Sus, the Auto/JSON/Regex tab labels in the
//     Extraction dialog) — regressions in those would silently break
//     features no other test currently covers
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
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-popovers.js'),
  'utf8',
);
const BUILD = fs.readFileSync(
  path.join(REPO_ROOT, 'scripts/build.py'),
  'utf8',
);

const MOVED_METHODS = [
  '_openAddSusPopover',
  '_openRowContextMenu',
  '_closePopover',
  '_openColumnMenu',
  '_closeDialog',
  '_openExtractionDialog',
];

// Shared helpers that MUST stay in timeline-view.js (chart + grid call
// them; centralising them in the popovers mixin would invert the
// dependency direction).
const KEPT_IN_CORE = ['_ellipsis', '_copyToClipboard', '_positionFloating'];

// ── Removal asserts ────────────────────────────────────────────────────────

test('timeline-view.js no longer defines any popover/menu/dialog method', () => {
  for (const name of MOVED_METHODS) {
    // `  methodName(` at start of line, indented EXACTLY two spaces — the
    // original definition shape inside `class TimelineView`. Call sites
    // (`this.methodName(`) are indented further.
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      VIEW,
      re,
      `${name} must be moved to timeline-view-popovers.js (no class-method definition left in timeline-view.js)`,
    );
  }
});

test('timeline-view.js KEEPS the shared popover utilities (_ellipsis, _copyToClipboard, _positionFloating)', () => {
  for (const name of KEPT_IN_CORE) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.match(
      VIEW,
      re,
      `${name} must remain in timeline-view.js — chart and grid mixins call it`,
    );
  }
});

// ── Presence asserts ───────────────────────────────────────────────────────

test('timeline-view-popovers.js attaches via Object.assign(TimelineView.prototype, ...)', () => {
  assert.match(
    MIXIN,
    /Object\.assign\(\s*TimelineView\.prototype\s*,\s*\{/,
    'mixin must use `Object.assign(TimelineView.prototype, {...})`',
  );
});

test('timeline-view-popovers.js defines every popover method exactly once', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'gm');
    const matches = MIXIN.match(re) || [];
    assert.equal(
      matches.length,
      1,
      `${name} must appear exactly once in timeline-view-popovers.js (got ${matches.length})`,
    );
  }
});

test('timeline-view-popovers.js does NOT redefine the kept utilities', () => {
  for (const name of KEPT_IN_CORE) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      MIXIN,
      re,
      `${name} must NOT be moved to popovers mixin — it stays in core timeline-view.js`,
    );
  }
});

// ── Body / string anchors — user-visible affordances survive byte-identical ─

test('Add-Sus popover user-visible copy survives', () => {
  // Pin the on-screen affordances: the "Mark suspicious" submit-button
  // label, the multi-line / comma-separated paste hint, and the
  // `is:sus` query-bar reference. Regressions in any of these would
  // silently strip user-facing wording that no other test covers.
  assert.match(
    MIXIN,
    /Mark suspicious/,
    'Add-Sus popover submit-button label is missing',
  );
  assert.match(
    MIXIN,
    /one per line, or comma-separated/,
    'Add-Sus popover bulk-paste hint is missing',
  );
  assert.match(
    MIXIN,
    /is:sus/,
    'Add-Sus popover query-bar cross-reference is missing',
  );
});

test('Extraction dialog Auto/JSON/Regex tab labels survive', () => {
  // The 3-tab modal layout is a load-bearing UX contract; pin each tab
  // label so a careless reorder doesn't silently rename them.
  assert.match(MIXIN, /\bAuto\b/, 'Extraction dialog Auto tab label missing');
  assert.match(MIXIN, /\bJSON\b/, 'Extraction dialog JSON tab label missing');
  assert.match(MIXIN, /\bRegex\b/, 'Extraction dialog Regex tab label missing');
});

test('_openRowContextMenu Include/Exclude submenu survives', () => {
  // The Include / Exclude / Pin / Sus / Copy submenu is the primary
  // way users build query AST chips from grid cells — pin its label
  // string so a careless rewrite doesn't silently remove it.
  assert.match(
    MIXIN,
    /Include "/,
    '_openRowContextMenu Include label is missing',
  );
});

test('_openColumnMenu single-slot toggle survives', () => {
  // The toggle-on-second-click pattern keeps the same column header
  // from spawning duplicate menus. Pin the dataset-driven gate.
  assert.match(
    MIXIN,
    /this\._openPopover\.dataset\.colIdx === String\(colIdx\)/,
    '_openColumnMenu re-click toggle is missing or its dataset key changed',
  );
});

test('_closeDialog teardown nulls the single _openDialog slot', () => {
  // Pin the symmetric tear-down so a future refactor that introduces a
  // second slot has to update the parity test deliberately.
  assert.match(
    MIXIN,
    /this\._openDialog = null/,
    '_closeDialog must clear this._openDialog',
  );
});

// ── Build order ────────────────────────────────────────────────────────────

test('scripts/build.py registers timeline-view-popovers.js after timeline-view.js', () => {
  const viewIdx = BUILD.indexOf("'src/app/timeline/timeline-view.js'");
  const popIdx = BUILD.indexOf("'src/app/timeline/timeline-view-popovers.js'");
  assert.notEqual(viewIdx, -1);
  assert.notEqual(popIdx, -1);
  assert.ok(popIdx > viewIdx, 'popovers mixin must load AFTER timeline-view.js');
});

// ── TimelineDataset invariant — moved bodies still respect dataset ─────────

test('moved popover bodies do not introduce a bare this._evtxEvents reference', () => {
  // The B1 invariant: moved code reads parallel arrays via `this._timeMs`
  // / `this.store` — never directly via `this._evtxEvents`. Strip
  // comments + strings before scanning so this test's own explanation
  // doesn't trip the assertion.
  const stripped = MIXIN
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
    .replace(/`[\s\S]*?`/g, '``')
    .replace(/"[^"\n]*"/g, '""')
    .replace(/'[^'\n]*'/g, "''");
  assert.doesNotMatch(
    stripped,
    /this\._evtxEvents\b/,
    'timeline-view-popovers.js must not read this._evtxEvents — use the dataset / store',
  );
});
