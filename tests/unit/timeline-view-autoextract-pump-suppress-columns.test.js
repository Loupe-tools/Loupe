'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract-pump-suppress-columns.test.js — pin the
// performance fix that suppresses the per-proposal `'columns'` render
// task during the auto-extract apply pump.
//
// CONTEXT — the regression this test exists to prevent:
//   `_autoExtractBestEffort` applies eligible proposals one per idle
//   tick. Each apply calls `_rebuildExtractedStateAndRender` which —
//   pre-fix — scheduled `['chart', 'scrubber', 'chips', 'columns']` on
//   every tick. The `'columns'` task triggers `_computeColumnStatsAsync`,
//   an O(rows × cols) sweep over the filtered index. With N proposals
//   on a 100k-row file the sweeps superseded each other continuously
//   (the cancel API correctly noticed but each in-flight sweep still
//   ran a full 50 000-row chunk before yielding), burning ~28 s of
//   main-thread CPU on work the apply pump itself was about to
//   invalidate.
//
//   The fix:
//     1. `TimelineView` declares `this._autoExtractApplying = false`
//        in its constructor and clears it in `destroy()`.
//     2. `_autoExtractBestEffort` sets the flag to `true` immediately
//        before scheduling the FIRST `applyStep` tick (after the
//        `if (!eligible.length) return;` early-exit) and clears it in
//        the terminating `idx >= ranked.length` branch BEFORE the
//        existing GeoIP retry block, then schedules `['columns']`
//        exactly once so the Top Values strip populates from the
//        final column set.
//     3. `_rebuildExtractedStateAndRender` consults the flag and omits
//        `'columns'` from the per-proposal `_scheduleRender(...)` call
//        in BOTH the fast-path branch (in-place `_grid._updateColumns`)
//        AND the cold-path branch (destroy + rebuild) AND the
//        in-place-failure fallback branch.
//
// What this test pins (static-text only — the runtime behaviour is
// covered by `timeline-view-autoextract-real-fixture.test.js` and the
// e2e CSV-load smoke):
//
//   • `_autoExtractApplying` is initialised to `false` in
//     `timeline-view.js` and cleared in `destroy()`.
//   • The flag is set to `true` exactly ONCE in
//     `timeline-view-autoextract.js`, immediately before the FIRST
//     `schedule(applyStep)` call.
//   • The flag is cleared in the apply-pump terminus (the
//     `idx >= ranked.length` branch) BEFORE any toast / GeoIP-retry
//     work and that branch schedules `['columns']` exactly once.
//   • `_rebuildExtractedStateAndRender` reads the flag and dispatches
//     a tasks list WITHOUT `'columns'` while the pump is running.
//
// These are static-source assertions, mirroring the pattern in
// `timeline-view-autoextract-uncapped.test.js`. Runtime / vm-based
// integration would require stubbing the entire grid + dataset stack;
// the static checks catch the regression class we care about (a
// future "let's just put 'columns' back in the per-proposal schedule"
// edit) without that machinery.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const VIEW_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view.js'), 'utf8');
const AUTOEXTRACT_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-autoextract.js'), 'utf8');
const DRAWER_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'), 'utf8');

// ── Constructor + destroy invariants (timeline-view.js) ────────────────────

test('TimelineView constructor initialises _autoExtractApplying = false', () => {
  // The flag MUST be defined as a primitive `false` on every fresh
  // view so `_rebuildExtractedStateAndRender` can read it
  // unconditionally without a `typeof` guard. Pin the literal
  // assignment.
  assert.ok(
    /this\._autoExtractApplying\s*=\s*false\s*;/.test(VIEW_SRC),
    'expected `this._autoExtractApplying = false;` in TimelineView constructor'
  );
});

test('TimelineView.destroy() clears _autoExtractApplying', () => {
  // Belt-and-braces — defensively clear the flag on destroy so a
  // recycled prototype slot or a leaked reference never carries a
  // stale `true` into a future view's `_rebuildExtractedStateAndRender`.
  // Two assignments are expected (constructor + destroy), so use a
  // global match count and assert >= 2.
  const matches = VIEW_SRC.match(/this\._autoExtractApplying\s*=\s*false\s*;/g);
  assert.ok(matches && matches.length >= 2,
    `expected >= 2 \`this._autoExtractApplying = false;\` lines in ` +
    `timeline-view.js (constructor + destroy), got ${matches ? matches.length : 0}`);
});

// ── Apply-pump bracketing (timeline-view-autoextract.js) ───────────────────

test('_autoExtractBestEffort sets _autoExtractApplying = true exactly once', () => {
  // Set on the apply-pump entry; cleared by the terminus + by destroy.
  // If a refactor accidentally moves the set higher (above the
  // `if (!eligible.length) return;` early-exit) the flag would stick
  // for files with no eligible proposals — guard against that by
  // pinning the count.
  const setMatches = AUTOEXTRACT_SRC.match(/this\._autoExtractApplying\s*=\s*true\s*;/g);
  assert.ok(setMatches && setMatches.length === 1,
    `expected exactly 1 \`this._autoExtractApplying = true;\` in ` +
    `timeline-view-autoextract.js, got ${setMatches ? setMatches.length : 0}`);
});

test('the `true` set sits immediately before the first schedule(applyStep) call', () => {
  // Ordering matters: the set must come AFTER the
  // `if (!eligible.length) return;` early-exit (so a no-eligible-
  // proposals file doesn't leave the flag stuck `true`) but BEFORE
  // the first `applyStep` schedule (so the very first idle tick sees
  // the flag set when it lands in `_rebuildExtractedStateAndRender`).
  // Pin the relative order with an in-line regex.
  const re = /this\._autoExtractApplying\s*=\s*true\s*;\s*\n\s*this\._autoExtractIdleHandle\s*=\s*schedule\(applyStep\)\s*;/;
  assert.ok(re.test(AUTOEXTRACT_SRC),
    'expected `this._autoExtractApplying = true;` to immediately precede ' +
    'the first `this._autoExtractIdleHandle = schedule(applyStep);` in ' +
    'timeline-view-autoextract.js');
});

test('apply-pump terminus clears the flag and schedules [\'columns\'] once', () => {
  // The terminating branch (`idx >= ranked.length`) must:
  //   (a) clear `_autoExtractApplying` so subsequent
  //       `_rebuildExtractedStateAndRender` calls (e.g. from the GeoIP
  //       retry below, or from any future user action) re-include
  //       `'columns'` in their schedule;
  //   (b) schedule `['columns']` exactly once so the Top Values strip
  //       populates from the final column set.
  // Both lines must appear inside the terminus branch — assert their
  // co-location with a multi-line regex.
  const re = /this\._autoExtractApplying\s*=\s*false\s*;\s*\n\s*this\._scheduleRender\(\[\s*'columns'\s*\]\)\s*;/;
  assert.ok(re.test(AUTOEXTRACT_SRC),
    'expected `this._autoExtractApplying = false;` followed by ' +
    '`this._scheduleRender([\'columns\']);` in the apply-pump terminus ' +
    'branch of timeline-view-autoextract.js');
});

// ── Per-proposal schedule suppression (timeline-drawer.js) ─────────────────

test('_rebuildExtractedStateAndRender omits \'columns\' while pump is running', () => {
  // The fast-path branch (in-place `_grid._updateColumns`) must build
  // its tasks list conditionally on `_autoExtractApplying`. We pin the
  // ternary literal — a direct `_scheduleRender(['chart', 'scrubber',
  // 'chips', 'columns'])` (the pre-fix line) would slip through this
  // assertion and trigger N supersession-cancelled column-stats sweeps.
  assert.ok(
    /this\._autoExtractApplying[\s\S]{0,80}\['chart',\s*'scrubber',\s*'chips'\]/.test(DRAWER_SRC),
    'expected fast-path tasks list to OMIT \'columns\' when ' +
    '`_autoExtractApplying` is true (look for a `[\'chart\', \'scrubber\', ' +
    '\'chips\']` literal under a `_autoExtractApplying ? ...` ternary)'
  );
});

test('_rebuildExtractedStateAndRender cold-path branch suppresses \'columns\' too', () => {
  // The cold path (no live grid) and the in-place-failure fallback
  // both rebuild via `_scheduleRender([..., 'grid', ...])`. They must
  // also drop `'columns'` while the pump runs — otherwise a GridViewer
  // crash mid-pump would re-enable the supersession churn.
  // Two cold/fallback branches expected; both must drop 'columns' under
  // the flag.
  const matches = DRAWER_SRC.match(
    /this\._autoExtractApplying[\s\S]{0,140}\['chart',\s*'scrubber',\s*'chips',\s*'grid'\]/g);
  assert.ok(matches && matches.length >= 2,
    `expected >= 2 cold/fallback branches that omit 'columns' under ` +
    `\`_autoExtractApplying\`, got ${matches ? matches.length : 0}. ` +
    `One protects the destroy/rebuild cold path; one protects the ` +
    `in-place-update failure fallback.`);
});

test('post-fix drawer no longer emits a per-proposal columns schedule unconditionally', () => {
  // Pre-fix the file contained the literal
  //   this._scheduleRender(['chart', 'scrubber', 'chips', 'columns']);
  // exactly once (the in-place success branch). Post-fix that line is
  // gone — replaced by the conditional ternary. Pin its absence so a
  // future "simplify" PR doesn't re-introduce the supersession churn.
  // (The cold path's pre-fix line `['chart', 'scrubber', 'chips',
  // 'grid', 'columns']` is also covered by being absent below.)
  assert.ok(
    !/_scheduleRender\(\[\s*'chart'\s*,\s*'scrubber'\s*,\s*'chips'\s*,\s*'columns'\s*\]\)/.test(DRAWER_SRC),
    'expected the unconditional `_scheduleRender([\'chart\', \'scrubber\', ' +
    '\'chips\', \'columns\'])` line to be GONE from timeline-drawer.js — ' +
    'replaced by an `_autoExtractApplying ? ...` ternary');
  assert.ok(
    !/_scheduleRender\(\[\s*'chart'\s*,\s*'scrubber'\s*,\s*'chips'\s*,\s*'grid'\s*,\s*'columns'\s*\]\)/.test(DRAWER_SRC),
    'expected the unconditional `_scheduleRender([\'chart\', \'scrubber\', ' +
    '\'chips\', \'grid\', \'columns\'])` lines (cold path + fallback) to ' +
    'be GONE — replaced by `_autoExtractApplying ? ...` ternaries'
  );
});
