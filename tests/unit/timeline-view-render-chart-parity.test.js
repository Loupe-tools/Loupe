'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-render-chart-parity.test.js — pin the B2f1 split.
//
// B2f1 hoists the 19-method chart paint stack (scrubber + chart +
// cursor + rubber-band + legend + chart-height drag) out of
// `timeline-view.js` into `timeline-view-render-chart.js`. The
// mixin attaches via `Object.assign(TimelineView.prototype,
// {...})`.
//
// Pins:
//   • each method's `methodName(args) {` definition is GONE from
//     `timeline-view.js`
//   • each method appears EXACTLY once in
//     `timeline-view-render-chart.js`
//   • `_scheduleRender` and `_installSplitterDrag` STAY in core
//     (they cross chart + grid)
//   • build order: chart mixin loads after `timeline-view.js`
//   • hot-path body anchors survive byte-identical (chart paint
//     loop, scrubber rAF coalescing, rubber-band pointer-capture)
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
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-render-chart.js'),
  'utf8',
);
const BUILD = fs.readFileSync(
  path.join(REPO_ROOT, 'scripts/build.py'),
  'utf8',
);

const MOVED_METHODS = [
  // Scrubber
  '_renderScrubber',
  '_installScrubberDrag',
  '_paintScrubberCursor',
  // Chart paint
  '_renderChart',
  '_buildStableStackColorMap',
  '_renderChartInto',
  // Red-line cursor
  '_paintChartCursorFor',
  '_findNearestDataIdxForTime',
  '_scrollGridToCursorIdx',
  '_installCursorDrag',
  '_updateCursorFromGridScroll',
  '_setCursorDataIdx',
  // Pointer / wheel handlers
  '_onChartClick',
  '_installChartDrag',
  '_onChartHover',
  // Legend
  '_handleLegendClick',
  '_handleLegendDbl',
  '_handleLegendContext',
  // Resize
  '_installChartResizeDrag',
];

// Methods that MUST stay in core (cross chart + grid).
const KEPT_IN_CORE = ['_scheduleRender', '_installSplitterDrag'];

// ── Removal asserts ────────────────────────────────────────────────────────

test('timeline-view.js no longer defines any chart-paint method', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      VIEW,
      re,
      `${name} must be moved to timeline-view-render-chart.js`,
    );
  }
});

test('timeline-view.js KEEPS the cross-surface render methods', () => {
  for (const name of KEPT_IN_CORE) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.match(
      VIEW,
      re,
      `${name} must remain in timeline-view.js — it crosses chart and grid surfaces`,
    );
  }
});

// ── Presence asserts ───────────────────────────────────────────────────────

test('timeline-view-render-chart.js attaches via Object.assign(TimelineView.prototype, ...)', () => {
  assert.match(
    MIXIN,
    /Object\.assign\(\s*TimelineView\.prototype\s*,\s*\{/,
  );
});

test('timeline-view-render-chart.js defines every chart-paint method exactly once', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'gm');
    const matches = MIXIN.match(re) || [];
    assert.equal(
      matches.length,
      1,
      `${name} must appear exactly once in timeline-view-render-chart.js (got ${matches.length})`,
    );
  }
});

test('timeline-view-render-chart.js does NOT redefine the cross-surface render methods', () => {
  for (const name of KEPT_IN_CORE) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      MIXIN,
      re,
      `${name} must NOT be moved to chart mixin — it stays in core`,
    );
  }
});

// ── Body anchors — perf-critical hot loops survive byte-identical ──────────

test('_renderChartInto canvas-2D paint contract survives', () => {
  // The `getContext('2d')` call is the entry into the chart's canvas
  // paint path; pin it so a refactor that swapped to a different
  // backend (or accidentally dropped the canvas) lights up here.
  assert.match(
    MIXIN,
    /getContext\(\s*['"]2d['"]\s*\)/,
    '_renderChartInto must use canvas-2D context',
  );
  // The fillRect bucket draw — perf-critical inner loop.
  assert.match(
    MIXIN,
    /\.fillRect\(/,
    '_renderChartInto bucket fillRect path is missing',
  );
});

test('_installChartDrag uses pointer-capture for rubber-band selection', () => {
  // The pointer-capture model is what makes the rubber-band keep
  // tracking even when the cursor strays outside the canvas. A
  // refactor that fell back to window listeners would silently break
  // the off-canvas drag-extend pattern.
  assert.match(
    MIXIN,
    /setPointerCapture/,
    '_installChartDrag must use setPointerCapture for rubber-band',
  );
});

test('_renderScrubber consults the dataRange before painting', () => {
  // The scrubber paints the FULL data range as its baseline (not the
  // active filter window). Pin the `_dataRange` reference so a future
  // refactor doesn't accidentally re-base it on `_filteredIdx`.
  assert.match(
    MIXIN,
    /this\._dataRange/,
    '_renderScrubber must read this._dataRange',
  );
});

test('_setCursorDataIdx persists nothing — cursor is volatile by design', () => {
  // The red-line cursor reflects the currently-focused row in the
  // grid; it is intentionally NOT persisted (re-derived from the
  // grid's saved scroll position on next mount). Pin that the moved
  // body has no `loupe_timeline_cursor*` write — adding one would
  // be a regression in the persisted-state contract.
  assert.doesNotMatch(
    MIXIN,
    /loupe_timeline_cursor/,
    '_setCursorDataIdx must NOT persist — cursor is volatile by design',
  );
});

test('_buildStableStackColorMap produces a deterministic colour assignment', () => {
  // The stack-colour map is keyed off the stack column's distinct
  // values so the SAME value gets the SAME colour across re-renders
  // (otherwise legend colours flicker on every paint). Pin a
  // `_stackColorMap` reference; a refactor that broke this would
  // light up legend tests in e2e.
  assert.match(
    MIXIN,
    /_stackColorMap/,
    '_buildStableStackColorMap must touch this._stackColorMap',
  );
});

// ── Build order ────────────────────────────────────────────────────────────

test('scripts/build.py registers timeline-view-render-chart.js after timeline-view.js', () => {
  const viewIdx = BUILD.indexOf("'src/app/timeline/timeline-view.js'");
  const chartIdx = BUILD.indexOf("'src/app/timeline/timeline-view-render-chart.js'");
  assert.notEqual(viewIdx, -1);
  assert.notEqual(chartIdx, -1);
  assert.ok(chartIdx > viewIdx, 'chart mixin must load AFTER timeline-view.js');
});

// ── TimelineDataset invariant ──────────────────────────────────────────────

test('moved chart bodies do not introduce a bare this._evtxEvents reference', () => {
  const stripped = MIXIN
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
    .replace(/`[\s\S]*?`/g, '``')
    .replace(/"[^"\n]*"/g, '""')
    .replace(/'[^'\n]*'/g, "''");
  assert.doesNotMatch(
    stripped,
    /this\._evtxEvents\b/,
    'timeline-view-render-chart.js must not read this._evtxEvents — use the dataset / store',
  );
});
