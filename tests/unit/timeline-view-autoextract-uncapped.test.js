'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract-uncapped.test.js — pin the size-conditional
// cap on the auto-extract apply loop.
//
// CONTEXT — the analyst-facing change this test exists to lock in:
//   The auto-extract pass historically clipped to the top 12 ranked
//   eligible proposals, regardless of file size. For JSON-heavy logs
//   with 20+ extractable nested keys, the analyst saw 12 columns and
//   reasonably concluded "this is what the file has." The fix lifts
//   the cap below `RENDER_LIMITS.LARGE_FILE_THRESHOLD` (200 MB) so
//   every eligible proposal applies; above that the historical 12-cap
//   still kicks in to bound the O(rows × proposals) apply cost.
//
//   `LARGE_FILE_THRESHOLD` is the same byte boundary the codebase
//   already uses to switch `timeline-router.js` from "fall back to
//   sync main-thread parse" to "refuse — worker only" (router.js:463).
//   Reusing it keeps the auto-extract decision aligned with the rest
//   of the load-pipeline's "this file is in the danger zone" boundary.
//
// What this test pins (static-text only — the integration is pinned
// by `timeline-view-autoextract-reopen-path.test.js`):
//
//   • The literal `MAX = 12` hard-cap line is gone. A file-size guard
//     reads `_app._fileMeta.size` and consults
//     `RENDER_LIMITS.LARGE_FILE_THRESHOLD`.
//
//   • The huge-file fallback uses the SAME 12 value (`HUGE_FILE_CAP`)
//     so a regression that drifts to 50 / 100 / etc surfaces here.
//
//   • The cap is conditional, NOT a flat slice — i.e. there's no
//     `eligible.slice(0, 12)` written without a size predicate
//     surrounding it.
//
//   • The doc comment still mentions the JSON_LEAF_CAP / KV_FIELD_CAP
//     scanner-internal soft caps so the contract stays visible: the
//     scanner bounds proposals per source column even when the apply
//     loop is uncapped.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const AUTOEXTRACT_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-autoextract.js'),
  'utf8');
const CONSTANTS_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/constants.js'),
  'utf8');

// ── Source-text invariants ─────────────────────────────────────────────────

test('hard-coded `MAX = 12` slice is GONE from _autoExtractBestEffort', () => {
  // The old (pre-uncap) code was literally:
  //   const MAX = 12;
  //   const ranked = eligible.slice(0, MAX);
  // Pin its absence so a "let's just put the cap back" regression
  // surfaces here. We allow `HUGE_FILE_CAP = 12` and `eligible.slice(0,
  // HUGE_FILE_CAP)` because that's the new, gated-on-file-size form.
  assert.doesNotMatch(
    AUTOEXTRACT_SRC,
    /\bconst\s+MAX\s*=\s*12\b/,
    '_autoExtractBestEffort still defines the old `const MAX = 12` ' +
    'hard cap. The cap is now `HUGE_FILE_CAP` and only applies above ' +
    '200 MB.');
});

test('huge-file fallback names a HUGE_FILE_CAP constant set to 12', () => {
  assert.match(
    AUTOEXTRACT_SRC,
    /\bconst\s+HUGE_FILE_CAP\s*=\s*12\b/,
    '_autoExtractBestEffort must define `const HUGE_FILE_CAP = 12` ' +
    'as the named constant for the huge-file fallback. The fallback ' +
    'value of 12 matches the historical cap so files ≥ 200 MB get ' +
    'identical behaviour to before the uncap change.');
});

test('apply-loop slice is conditional on RENDER_LIMITS.LARGE_FILE_THRESHOLD', () => {
  // Two invariants:
  //   1. RENDER_LIMITS.LARGE_FILE_THRESHOLD is referenced inside
  //      _autoExtractBestEffort (the cap-decision site).
  //   2. There is NO bare `eligible.slice(0, <number>)` without a
  //      surrounding size guard. Allowed forms are:
  //        eligible.slice(0, HUGE_FILE_CAP)  — gated above
  //   We approximate (2) by checking the slice goes through
  //   HUGE_FILE_CAP rather than a numeric literal.
  assert.match(
    AUTOEXTRACT_SRC,
    /RENDER_LIMITS\.LARGE_FILE_THRESHOLD/,
    '_autoExtractBestEffort must reference ' +
    'RENDER_LIMITS.LARGE_FILE_THRESHOLD to decide whether to cap.');

  // Disallow `eligible.slice(0, <number-literal>)` — must go through
  // a named constant.
  assert.doesNotMatch(
    AUTOEXTRACT_SRC,
    /eligible\.slice\(\s*0\s*,\s*\d+\s*\)/,
    '_autoExtractBestEffort must not slice eligible by a numeric ' +
    'literal — use HUGE_FILE_CAP so the cap value is named and ' +
    'searchable.');

  assert.match(
    AUTOEXTRACT_SRC,
    /eligible\.slice\(\s*0\s*,\s*HUGE_FILE_CAP\s*\)/,
    '_autoExtractBestEffort must slice via HUGE_FILE_CAP in the ' +
    'huge-file branch.');
});

test('size guard reads _app._fileMeta.size, not file.size', () => {
  // The timeline view doesn't own a `this.file` — file-size signal
  // comes via the app from `_fileMeta.size` (set by timeline-router
  // at load). Pin the path so a refactor that uses `this.file.size`
  // (which would be undefined inside the view) surfaces here.
  assert.match(
    AUTOEXTRACT_SRC,
    /_app[\s\S]{0,80}?_fileMeta[\s\S]{0,40}?\.size/,
    '_autoExtractBestEffort must read file size from ' +
    '`this._app._fileMeta.size` to gate the cap. ' +
    '`this.file.size` does not exist on the timeline view.');
});

test('size-guard tolerates missing _fileMeta', () => {
  // Defensive: when `_app._fileMeta` is null/undefined (early
  // synchronous-factory path before the router stamps it), the cap
  // decision must default to the uncapped branch (file-size = 0,
  // which is < LARGE_FILE_THRESHOLD). Pin a `Number.isFinite` or
  // similar guard so a regression that does `view._app._fileMeta.size`
  // unguarded (and throws on null) surfaces here.
  assert.match(
    AUTOEXTRACT_SRC,
    /(Number\.isFinite|typeof\s+[^)]*\bsize\b\s*===|_fileMeta\s*\?|_fileMeta\s*&&)/,
    '_autoExtractBestEffort must guard against missing _fileMeta ' +
    'when reading file size — auto-extract runs in the constructor ' +
    'tick before the router has finished wiring _app.');
});

test('LARGE_FILE_THRESHOLD constant is 200 MB in src/constants.js', () => {
  // Cross-file pin: the threshold value is fixed at 200 MB. If a
  // future commit moves the threshold (raising or lowering it), this
  // test surfaces the change so the cap-decision site can be re-
  // examined. 209715200 bytes = 200 * 1024 * 1024.
  assert.match(
    CONSTANTS_SRC,
    /LARGE_FILE_THRESHOLD\s*:\s*200\s*\*\s*1024\s*\*\s*1024/,
    'RENDER_LIMITS.LARGE_FILE_THRESHOLD must remain 200 MB. ' +
    'The auto-extract uncap path reuses this threshold; if it ' +
    'changes, audit the auto-extract test fixtures and behaviour.');
});

test('doc comment explains the uncap + 200 MB fallback', () => {
  // The block comment above `_autoExtractBestEffort` is where future
  // contributors learn the contract. Pin the keywords so a comment
  // refactor that drops the rationale (and silently leaves an
  // unjustified cap-shaped slice) surfaces here.
  const commentBlockStart = AUTOEXTRACT_SRC.indexOf('Ranking + cap');
  assert.ok(commentBlockStart >= 0,
    'Doc-comment block "Ranking + cap" must exist above ' +
    '_autoExtractBestEffort');
  // Take a generous window for the doc-block; we only assert it
  // mentions the key signal-words.
  const commentSlice = AUTOEXTRACT_SRC.slice(commentBlockStart,
    commentBlockStart + 1200);
  assert.match(commentSlice, /200\s*MB/i,
    'Doc-comment must mention the 200 MB threshold to explain when ' +
    'the cap kicks in');
  assert.match(commentSlice, /(uncapped|every eligible|all eligible)/i,
    'Doc-comment must explain that below the threshold ALL eligible ' +
    'proposals apply (no cap)');
  assert.match(commentSlice, /JSON_LEAF_CAP/,
    'Doc-comment must mention JSON_LEAF_CAP so the scanner-internal ' +
    'soft-cap contract stays visible');
});
