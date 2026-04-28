'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-query-chips-parity.test.js — pin the B2f3 split.
//
// B2f3 hoists the query-AST manipulation surface + chips renderer
// out of `timeline-view.js` into `timeline-view-query-chips.js`.
// The mixin attaches via `Object.assign(TimelineView.prototype,
// {...})`.
//
// Pins:
//   • each method's `methodName(args) {` definition is GONE from
//     `timeline-view.js`
//   • each method appears EXACTLY once in
//     `timeline-view-query-chips.js`
//   • build order: query-chips mixin loads after `timeline-view.js`
//   • the contradictions-drop pass (eq A × ne A → drop) survives
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
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-query-chips.js'),
  'utf8',
);
const BUILD = fs.readFileSync(
  path.join(REPO_ROOT, 'scripts/build.py'),
  'utf8',
);

const MOVED_METHODS = [
  // Chips strip render
  '_renderChips',
  // AST read / commit primitives
  '_queryCurrentAst',
  '_queryTopLevelClauses',
  '_queryClausesToAst',
  '_queryCommitClauses',
  '_clauseTargetsCol',
  // AST edit helpers
  '_queryAddClause',
  '_queryDropContradictions',
  '_queryToggleEqClause',
  '_queryToggleNeClause',
  '_queryReplaceContainsForCol',
  '_queryReplaceEqForCol',
  '_queryReplaceNotInForCol',
  '_queryReplaceAllForCol',
  '_queryRemoveClausesForCols',
  // Chip operations
  '_addOrToggleChip',
  '_addContainsChipsReplace',
  '_replaceEqChipsForCol',
  // Ctrl+Click multi-select
  '_accumulateCtrlSelect',
  '_commitCtrlSelect',
  '_clearCtrlSelect',
  '_togglePinCol',
];

// ── Removal asserts ────────────────────────────────────────────────────────

test('timeline-view.js no longer defines any query-AST / chips method', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      VIEW,
      re,
      `${name} must be moved to timeline-view-query-chips.js`,
    );
  }
});

// ── Presence asserts ───────────────────────────────────────────────────────

test('timeline-view-query-chips.js attaches via Object.assign(TimelineView.prototype, ...)', () => {
  assert.match(
    MIXIN,
    /Object\.assign\(\s*TimelineView\.prototype\s*,\s*\{/,
  );
});

test('timeline-view-query-chips.js defines every query/chips method exactly once', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'gm');
    const matches = MIXIN.match(re) || [];
    assert.equal(
      matches.length,
      1,
      `${name} must appear exactly once in timeline-view-query-chips.js (got ${matches.length})`,
    );
  }
});

// ── Body anchors ───────────────────────────────────────────────────────────

test('_queryDropContradictions exists with eq/ne semantics', () => {
  // The contradictions-drop pass strips `eq A` if `ne A` is being
  // added (and vice versa) so click-pivots can't build
  // self-contradicting queries. Pin the function exists and that it
  // mentions both ops by name in its body — a refactor that lost
  // either branch would silently let users build dead queries.
  assert.match(
    MIXIN,
    /_queryDropContradictions[\s\S]{0,800}['"]eq['"]/,
    '_queryDropContradictions must reference the "eq" op',
  );
  assert.match(
    MIXIN,
    /_queryDropContradictions[\s\S]{0,800}['"]ne['"]/,
    '_queryDropContradictions must reference the "ne" op',
  );
});

test('_queryCommitClauses bridges into the filter mixin via _applyQueryString', () => {
  // The commit path serialises the AST and calls
  // `this._applyQueryString(s)` (in the B2c filter mixin), which in
  // turn persists via `TimelineView._saveQueryFor` (in the B2b
  // persist mixin). Pin the bridge call here — a regression that
  // bypassed it would skip both the persistence AND the recompute.
  assert.match(
    MIXIN,
    /this\._applyQueryString\(/,
    '_queryCommitClauses must bridge into _applyQueryString',
  );
});

test('_addOrToggleChip dispatches by op (eq / ne / contains / in / nin)', () => {
  // Pin each op string so a refactor that collapsed or renamed
  // an op breaks visibly.
  for (const op of ['eq', 'ne', 'contains']) {
    assert.match(
      MIXIN,
      new RegExp(`['"]${op}['"]`),
      `_addOrToggleChip must reference the '${op}' op`,
    );
  }
});

// ── Build order ────────────────────────────────────────────────────────────

test('scripts/build.py registers timeline-view-query-chips.js after timeline-view.js', () => {
  const viewIdx = BUILD.indexOf("'src/app/timeline/timeline-view.js'");
  const qcIdx = BUILD.indexOf("'src/app/timeline/timeline-view-query-chips.js'");
  assert.notEqual(viewIdx, -1);
  assert.notEqual(qcIdx, -1);
  assert.ok(qcIdx > viewIdx, 'query-chips mixin must load AFTER timeline-view.js');
});

// ── TimelineDataset invariant ──────────────────────────────────────────────

test('moved query-chips bodies do not introduce a bare this._evtxEvents reference', () => {
  const stripped = MIXIN
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
    .replace(/`[\s\S]*?`/g, '``')
    .replace(/"[^"\n]*"/g, '""')
    .replace(/'[^'\n]*'/g, "''");
  assert.doesNotMatch(
    stripped,
    /this\._evtxEvents\b/,
    'timeline-view-query-chips.js must not read this._evtxEvents — use the dataset / store',
  );
});
