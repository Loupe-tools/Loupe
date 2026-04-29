'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract-replay-rerun.test.js — pin the structural
// contract that lets auto-extract run on every reopen without the
// extract-persistence asymmetry causing silent column loss.
//
// CONTEXT — the bug class this test exists to prevent regressing:
//   `_persistRegexExtracts` (timeline-drawer.js) historically wrote
//   entries whose `kind` was `'regex'` OR `'auto'`. The auto-extract
//   scanner emits a mix of regex-shaped (`kind:'auto'` with a
//   `pattern`) and JSON-path-shaped (`kind:'json'`-via-`autoKind`,
//   no pattern) outputs. Persisting the regex half meant that on
//   reopen, only the regex-shaped auto-extracted columns replayed
//   while the JSON ones vanished — a JSON-heavy CSV like
//   `examples/forensics/json-example.csv` lost 10 of its 12 columns
//   on every reopen.
//
//   The fix:
//     • Auto-extract runs on every file open, unconditionally.
//     • `_persistRegexExtracts` ONLY writes `kind:'regex'` (manual
//       Regex-tab) — not `kind:'auto'`. Auto extracts are ephemeral.
//     • The done-marker (`loupe_timeline_autoextract_done`) was
//       renamed to `loupe_timeline_autoextract_toast_shown` and now
//       gates only the post-apply toast, not the extraction.
//     • Dedup inside `_addJsonExtractedColNoRender` /
//       `_addRegexExtractNoRender` handles overlap when a manual
//       Regex-tab extract collides with an auto proposal — the
//       manual one wins.
//
// What this test pins (static-text only — the end-to-end reopen flow
// is pinned by `timeline-view-autoextract-reopen-path.test.js`):
//
//   • `_persistRegexExtracts.filter(...)` includes `'regex'` and
//     specifically EXCLUDES `'auto'` and `'json'`. A regression that
//     re-adds either re-introduces the silent-drop bug.
//
//   • `_autoExtractBestEffort` does NOT call
//     `_loadAutoExtractToastShownFor` as an early-return guard. It's
//     allowed to consult the marker, but only at the toast call site
//     near the bottom of the apply loop.
//
//   • The constants + methods are renamed correctly:
//     `AUTOEXTRACT_TOAST_SHOWN` is the new key constant;
//     `_loadAutoExtractToastShownFor` / `_saveAutoExtractToastShownFor`
//     are the new methods. The legacy `AUTOEXTRACT_DONE_LEGACY`
//     constant exists ONLY to drive the one-shot localStorage cleanup.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const AUTOEXTRACT_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-autoextract.js'),
  'utf8');
const DRAWER_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'),
  'utf8');
const HELPERS_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-helpers.js'),
  'utf8');
const PERSIST_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-persist.js'),
  'utf8');

test('_persistRegexExtracts filter is `kind === regex` ONLY (no auto, no json)', () => {
  // The HEART of the fix: auto and json extracts must NOT persist.
  // Re-adding either re-introduces the silent-drop bug for JSON-shaped
  // CSVs (where only the regex-shaped half of the auto-extract output
  // would survive across reopens).
  const fnStart = DRAWER_SRC.indexOf('_persistRegexExtracts() {');
  assert.ok(fnStart >= 0,
    '_persistRegexExtracts() { … } method definition must exist');
  const slice = DRAWER_SRC.slice(fnStart, fnStart + 1500);
  // The function contains TWO `.filter(...)` calls in sequence:
  //   .filter(e => e.kind === 'regex')   ← the kind filter (pin THIS)
  //   …
  //   .filter(e => e.pattern)            ← drops empty patterns
  // Match the first one explicitly by anchoring on `kind`.
  const kindFilterMatch = slice.match(/\.filter\(\s*[a-z]\s*=>\s*[^)]*\.kind[^)]*\)/);
  assert.ok(kindFilterMatch,
    `_persistRegexExtracts must contain a .filter(...) on .kind. ` +
    `Slice: ${slice.slice(0, 500)}`);
  assert.ok(kindFilterMatch[0].includes("'regex'"),
    `_persistRegexExtracts kind-filter must include 'regex'. ` +
    `Got: ${kindFilterMatch[0]}`);
  assert.ok(!kindFilterMatch[0].includes("'auto'"),
    `_persistRegexExtracts kind-filter must NOT include 'auto'. ` +
    `Auto extracts are ephemeral — they're re-derived by the silent ` +
    `auto-extract pass on every file open. Persisting them would ` +
    `re-introduce the silent-drop bug for JSON-shaped CSVs (where ` +
    `the json-leaf half of the auto-extract output isn't persistable ` +
    `as a regex anyway). Got: ${kindFilterMatch[0]}`);
  assert.ok(!kindFilterMatch[0].includes("'json'"),
    `_persistRegexExtracts kind-filter must NOT include 'json'. ` +
    `JSON extracts have no \`pattern\` field; persisting them would ` +
    `mean writing a half-shaped record. Got: ${kindFilterMatch[0]}`);
});

test('_autoExtractBestEffort does NOT use the toast-shown marker as an early-return guard', () => {
  // The pre-fix code short-circuited the entire extraction when the
  // marker was set. The new design reads the marker only to gate the
  // toast call — extraction runs unconditionally, dedup inside the
  // apply helpers handles overlap with replayed manual regex extracts.
  //
  // This test catches a regression that re-adds an `if (… marker …)
  // return;` line near the top of the function.
  const fnStart = AUTOEXTRACT_SRC.indexOf('_autoExtractBestEffort()');
  assert.ok(fnStart >= 0,
    '_autoExtractBestEffort() method definition must exist');
  // The function body runs ~140 lines (long inline doc + scheduler
  // setup + scanStep + applyStep). Look at the FIRST 30 lines after
  // the method header — that's where the early-return guards live.
  // The toast-shown marker read should appear there, but NOT followed
  // by `return`.
  const slice = AUTOEXTRACT_SRC.slice(fnStart, fnStart + 4000);
  // Find the first 30 lines or so of the method body (everything
  // up to the start of the idle-scheduler setup, marked by
  // `const useIdle =`).
  const earlyEnd = slice.indexOf('const useIdle =');
  assert.ok(earlyEnd > 0,
    '_autoExtractBestEffort must contain the idle scheduler setup');
  const earlyBody = slice.slice(0, earlyEnd);
  // Negative pin: no `if (… ToastShown …) return`-style early-return.
  assert.ok(!/_loadAutoExtractToastShownFor\([^)]*\)\s*\)\s*return/.test(earlyBody),
    `_autoExtractBestEffort must not bail on the toast-shown marker. ` +
    `That would re-introduce the silent-drop bug — extraction must ` +
    `run on every open, the marker only suppresses the toast. ` +
    `Found offending early-return in body:\n${earlyBody}`);
  // Negative pin: no `_loadAutoExtractDoneFor` (the legacy method) —
  // catches a mistaken revert of the rename.
  assert.ok(!/_loadAutoExtractDoneFor\(/.test(earlyBody),
    `_autoExtractBestEffort must use _loadAutoExtractToastShownFor, ` +
    `not the legacy _loadAutoExtractDoneFor. The rename matters: ` +
    `the legacy method gated extraction; the new one only gates the ` +
    `toast.`);
  // Positive pin: the toast marker IS read in the early body (we
  // capture it at the top so the closure reads a stable value, not
  // a value that might race with another file's mark).
  assert.ok(/_loadAutoExtractToastShownFor\(/.test(earlyBody),
    `_autoExtractBestEffort must call _loadAutoExtractToastShownFor ` +
    `near the top to capture the toast-suppression flag for use at ` +
    `the toast call site later.`);
});

test('TIMELINE_KEYS exposes AUTOEXTRACT_TOAST_SHOWN with the renamed value', () => {
  // The constant rename must be consistent across the codebase. The
  // legacy alias (AUTOEXTRACT_DONE_LEGACY) must STILL exist for the
  // migration path inside _loadAutoExtractToastShownFor.
  assert.ok(/AUTOEXTRACT_TOAST_SHOWN:\s*'loupe_timeline_autoextract_toast_shown'/.test(HELPERS_SRC),
    `TIMELINE_KEYS.AUTOEXTRACT_TOAST_SHOWN must be the canonical key, ` +
    `with value 'loupe_timeline_autoextract_toast_shown'.`);
  assert.ok(/AUTOEXTRACT_DONE_LEGACY:\s*'loupe_timeline_autoextract_done'/.test(HELPERS_SRC),
    `TIMELINE_KEYS.AUTOEXTRACT_DONE_LEGACY must exist with the ` +
    `pre-rename value 'loupe_timeline_autoextract_done' so the ` +
    `migration inside _loadAutoExtractToastShownFor can locate and ` +
    `delete stale entries.`);
  // Negative: the old `AUTOEXTRACT_DONE` constant (without the
  // _LEGACY suffix) must NOT exist — it would be ambiguous and
  // would invite accidental writes to the dead key.
  assert.ok(!/^\s*AUTOEXTRACT_DONE:/m.test(HELPERS_SRC),
    `TIMELINE_KEYS.AUTOEXTRACT_DONE (unsuffixed) must not exist — ` +
    `it was renamed to AUTOEXTRACT_TOAST_SHOWN. The legacy value ` +
    `lives under AUTOEXTRACT_DONE_LEGACY for the migration only.`);
});

test('_loadAutoExtractToastShownFor performs one-shot legacy-key cleanup', () => {
  // The migration is intentionally located inside the load function
  // (not a module-level IIFE) so it runs lazily on the first file
  // open after upgrade and is idempotent thereafter
  // (safeStorage.remove on a missing key is a no-op).
  const fnStart = PERSIST_SRC.indexOf('_loadAutoExtractToastShownFor(');
  assert.ok(fnStart >= 0,
    '_loadAutoExtractToastShownFor(…) method definition must exist');
  const slice = PERSIST_SRC.slice(fnStart, fnStart + 800);
  assert.ok(/safeStorage\.remove\([^)]*AUTOEXTRACT_DONE_LEGACY/.test(slice),
    `_loadAutoExtractToastShownFor must call safeStorage.remove(` +
    `TIMELINE_KEYS.AUTOEXTRACT_DONE_LEGACY) so existing browser ` +
    `profiles with the pre-rename key get cleaned up on first open ` +
    `after the upgrade.`);
});

test('text-host detection in _autoExtractScan uses anchored TL_HOSTNAME_RE', () => {
  // Issue 2 fix from commit 237eb7d (kept): the unanchored
  // `TL_HOSTNAME_INLINE_RE` matched the millisecond fragment `21.271Z`
  // inside ISO-8601 timestamps and flagged Timestamp as a hostname
  // column. Detection switched to anchored
  // `TL_HOSTNAME_RE.test(s.v.trim())`. The EXTRACTION regex is
  // separately unanchored — that's intentional, see the source comment.
  const detectionAnchor = AUTOEXTRACT_SRC.indexOf(
    'Plain-text column: test URL + hostname patterns directly.');
  assert.ok(detectionAnchor >= 0,
    'plain-text detection block anchor comment must exist');
  const slice = AUTOEXTRACT_SRC.slice(detectionAnchor, detectionAnchor + 1500);
  assert.ok(/TL_HOSTNAME_RE\.test\(/.test(slice),
    `text-host detection must call \`TL_HOSTNAME_RE.test(...)\` ` +
    `(anchored) instead of \`TL_HOSTNAME_INLINE_RE.exec(...)\` ` +
    `(unanchored). The unanchored variant matches hostname-shaped ` +
    `fragments inside structured cells (notably the millisecond ` +
    `fragment of ISO-8601 timestamps).`);
  const detectionLoopMatch = slice.match(
    /for\s*\(\s*const\s+s\s+of\s+samples\s*\)\s*\{[\s\S]*?\}/);
  assert.ok(detectionLoopMatch,
    'detection for-loop over samples must exist in plain-text branch');
  assert.ok(!detectionLoopMatch[0].includes('TL_HOSTNAME_INLINE_RE'),
    `detection for-loop must NOT reference TL_HOSTNAME_INLINE_RE — ` +
    `that's the unanchored variant that caused Timestamp false ` +
    `positives. Got: ${detectionLoopMatch[0]}`);
});
