'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-geoip-extracted-detect.test.js — pin the second-chance
// IP detection path that scans extracted columns.
//
// CONTEXT — what this test exists to lock in:
//   The original `_detectIpColumns` only ever saw BASE columns. Files
//   whose IPv4 addresses lived inside a JSON blob, an EVTX kv-field,
//   or any regex-extracted column were silently skipped — the analyst
//   would see auto-extracted columns appear, expect a `.geo` sibling,
//   and find nothing. The fix is `_detectIpColumnsExtracted`, a sister
//   scan over the extracted-column plane fired post-settle by the
//   auto-extract terminal hook when the natural-detect pass came up
//   empty.
//
// What this test pins:
//
//   • Static-text invariants on `_detectIpColumnsExtracted`:
//       - exists exactly once in the geoip mixin
//       - skips `geoip` / `geoip-asn` cols (self-reference guard)
//       - returns indices in the unified column plane (baseLen + i)
//
//   • The retry call site in autoextract:
//       - calls _runGeoipEnrichment with `{ retryExtractedCols: true }`
//       - is gated on `_geoipBaseDetectResult.length === 0`
//       - clears the gate after firing
//
//   • The result-cache wiring:
//       - `_runGeoipEnrichment` populates `_geoipBaseDetectResult`
//         after `_detectIpColumns()` on the natural-detect path
//       - the cache is initialised on the view (constructor-side null)
//
// Behavioural coverage of the full reopen flow lives in the e2e spec.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const GEOIP_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-geoip.js'),
  'utf8');
const AUTOEXTRACT_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-autoextract.js'),
  'utf8');
const VIEW_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view.js'),
  'utf8');

// ── _detectIpColumnsExtracted source-text invariants ───────────────────────

test('_detectIpColumnsExtracted is defined exactly once in geoip mixin', () => {
  const re = /^\s+_detectIpColumnsExtracted\s*\(/gm;
  const matches = GEOIP_SRC.match(re) || [];
  assert.equal(matches.length, 1,
    `_detectIpColumnsExtracted must appear exactly once in the ` +
    `geoip mixin (got ${matches.length})`);
});

// Helper — locate the body of `_detectIpColumnsExtracted` by anchoring
// on the method definition (leading whitespace + `(` after the name)
// rather than just the bare identifier (which also appears at the
// call site inside `_runGeoipEnrichment`).
function locateDetectIpColumnsExtractedBody() {
  const re = /^[ \t]+_detectIpColumnsExtracted\s*\(\s*\)\s*\{/m;
  const m = re.exec(GEOIP_SRC);
  assert.ok(m, '_detectIpColumnsExtracted method definition not found ' +
    '(must be a top-level mixin method, indented 4 spaces, taking no args)');
  return GEOIP_SRC.slice(m.index, m.index + 1500);
}

test('_detectIpColumnsExtracted skips geoip and geoip-asn kinds', () => {
  // Self-reference guard: an enriched `.geo` column whose formatted
  // string happened to look like an IPv4 (extremely unlikely, but
  // possible if a future formatRow change emits raw IPs) would
  // otherwise trigger another enrichment pass on its own output.
  const slice = locateDetectIpColumnsExtractedBody();
  assert.match(slice,
    /kind\s*===\s*['"]geoip['"]\s*\|\|\s*[^=]*kind\s*===\s*['"]geoip-asn['"]/,
    '_detectIpColumnsExtracted must skip cols with ' +
    `kind === 'geoip' || kind === 'geoip-asn' to prevent ` +
    `self-reference loops`);
});

test('_detectIpColumnsExtracted returns unified-plane indices (baseLen + i)', () => {
  const slice = locateDetectIpColumnsExtractedBody();
  // Pin that the index pushed into `out` is computed from baseLen + i,
  // not just `i` (which would collide with base-col indices).
  assert.match(slice, /baseLen\s*\+\s*i/,
    '_detectIpColumnsExtracted must return baseLen + i as the column ' +
    'index so it slots into the unified column plane consumed by ' +
    '_enrichSingleIpCol via _cellAt');
});

test('_detectIpColumnsExtracted uses _cellAt (extracted-aware reader)', () => {
  // The base detector uses `this.store.getCell` which only sees base
  // cols. The extracted detector MUST use `this._cellAt` so it reads
  // the in-memory `_extractedCols[i].values[r]` array.
  const slice = locateDetectIpColumnsExtractedBody();
  assert.match(slice, /this\._cellAt\(/,
    '_detectIpColumnsExtracted must use this._cellAt(...) to read ' +
    'extracted-column values');
});

test('_detectIpColumnsExtracted reuses isStrictIPv4 + the same threshold', () => {
  // The detection threshold (≥80% hit rate when nonEmpty >= 8, or
  // 100% when sparse) is shared with the base detector — pin it so
  // the two paths can't drift.
  const slice = locateDetectIpColumnsExtractedBody();
  assert.match(slice, /isStrictIPv4\(/,
    '_detectIpColumnsExtracted must call isStrictIPv4 to share the ' +
    'IPv4 validator with _detectIpColumns');
  assert.match(slice, /nonEmpty\s*>=\s*8/,
    '_detectIpColumnsExtracted must use the same nonEmpty>=8 ' +
    'threshold as _detectIpColumns');
  assert.match(slice, /0\.8\b/,
    '_detectIpColumnsExtracted must use the same 0.8 (80%) hit-rate ' +
    'threshold as _detectIpColumns');
});

// ── retryExtractedCols wiring in _runGeoipEnrichment ───────────────────────

test('_runGeoipEnrichment accepts opts.retryExtractedCols', () => {
  // Pin the opt name so a rename surfaces here.
  assert.match(GEOIP_SRC, /opts\s*&&\s*opts\.retryExtractedCols/,
    '_runGeoipEnrichment must read opts.retryExtractedCols (used by ' +
    'the auto-extract settle hook)');
  assert.match(GEOIP_SRC, /retryExtractedCols\s*=\s*!!\(/,
    '_runGeoipEnrichment must coerce opts.retryExtractedCols to a ' +
    'boolean (defensive against non-boolean callers)');
});

test('_runGeoipEnrichment dispatches to _detectIpColumnsExtracted on retry', () => {
  // Pin the routing: when retryExtractedCols is true, targetCols
  // comes from the extracted detector; otherwise from the base
  // detector (or forceCol).
  assert.match(GEOIP_SRC,
    /retryExtractedCols[\s\S]{0,200}?this\._detectIpColumnsExtracted\(\)/,
    '_runGeoipEnrichment must call this._detectIpColumnsExtracted() ' +
    'when opts.retryExtractedCols is true');
});

test('_runGeoipEnrichment caches base-detect result on _geoipBaseDetectResult', () => {
  // The auto-extract settle hook reads `_geoipBaseDetectResult` to
  // decide whether to fire the retry. Pin that the natural-detect
  // path stamps it.
  assert.match(GEOIP_SRC,
    /this\._geoipBaseDetectResult\s*=\s*targetCols\.slice\(\)/,
    '_runGeoipEnrichment must cache the base-detect result on ' +
    'this._geoipBaseDetectResult so the auto-extract settle hook ' +
    'can read it without re-scanning');
});

test('TimelineView constructor initialises _geoipBaseDetectResult to null', () => {
  // Without a constructor-side null init, the autoextract settle
  // hook's `Array.isArray(this._geoipBaseDetectResult)` guard would
  // depend on JS hoisting + later property assignment — fragile.
  // Pin the explicit `= null;` init.
  assert.match(VIEW_SRC,
    /this\._geoipBaseDetectResult\s*=\s*null;/,
    'TimelineView constructor must initialise _geoipBaseDetectResult ' +
    'to null so the autoextract settle hook never reads undefined');
});

// ── autoextract settle-hook call site ──────────────────────────────────────

test('autoextract settle hook calls _runGeoipEnrichment with retryExtractedCols', () => {
  assert.match(AUTOEXTRACT_SRC,
    /_runGeoipEnrichment\(\s*\{\s*retryExtractedCols\s*:\s*true\s*\}\s*\)/,
    '_autoExtractBestEffort terminal branch must call ' +
    '_runGeoipEnrichment({ retryExtractedCols: true }) — that is the ' +
    'opt name pinned by the geoip side');
});

test('settle hook is gated on _geoipBaseDetectResult.length === 0', () => {
  // The retry only fires when the initial natural-detect run found
  // ZERO IP-shaped base cols. Pin the gate so a regression that fires
  // the retry unconditionally (creating duplicate enrichment work)
  // surfaces here.
  const idx = AUTOEXTRACT_SRC.indexOf('retryExtractedCols');
  assert.ok(idx >= 0,
    'autoextract.js must contain the retryExtractedCols call site');
  // Take a window around the call site.
  const windowStart = Math.max(0, idx - 800);
  const windowEnd = Math.min(AUTOEXTRACT_SRC.length, idx + 200);
  const slice = AUTOEXTRACT_SRC.slice(windowStart, windowEnd);
  assert.match(slice,
    /_geoipBaseDetectResult[\s\S]{0,80}?\.length\s*===\s*0/,
    'autoextract settle hook must gate on ' +
    '`_geoipBaseDetectResult.length === 0` to skip the retry when ' +
    'natural-detect already found IP cols. Window:\n' + slice);
});

test('settle hook clears _geoipBaseDetectResult after firing the retry', () => {
  // Stale-snapshot defence: subsequent triggers (MMDB hydrate, user
  // upload, right-click) should re-evaluate against a fresh natural
  // detect, not the snapshot from this run.
  const idx = AUTOEXTRACT_SRC.indexOf('retryExtractedCols');
  const slice = AUTOEXTRACT_SRC.slice(idx, idx + 600);
  assert.match(slice,
    /this\._geoipBaseDetectResult\s*=\s*null/,
    'autoextract settle hook must clear _geoipBaseDetectResult to ' +
    'null after firing the retry, so future GeoIP triggers re-scan');
});

test('settle hook is also gated on _extractedCols.length > 0', () => {
  // No new extracted cols → nothing to retry against. Pin the
  // emptiness check so a regression that fires the retry against
  // an empty extracted-col list (wasted work, possibly crashes)
  // surfaces here.
  const idx = AUTOEXTRACT_SRC.indexOf('retryExtractedCols');
  const windowStart = Math.max(0, idx - 800);
  const windowEnd = Math.min(AUTOEXTRACT_SRC.length, idx + 200);
  const slice = AUTOEXTRACT_SRC.slice(windowStart, windowEnd);
  assert.match(slice, /this\._extractedCols[\s\S]{0,40}?\.length/,
    'autoextract settle hook must check ' +
    '`this._extractedCols.length` before firing the retry');
});

// ── Skip-heuristic bypass on retry path ────────────────────────────────────

test('_runGeoipEnrichment bypasses neighbour-skip heuristic on retry', () => {
  // Extracted IP cols have no inherent base-col neighbours, so the
  // ±3 base-col walk in `_classifyColumnNeighbourhood` is meaningless
  // (and could give garbage results reading off the end of
  // `_baseColumns`). Pin that retryExtractedCols joins forceCol in
  // bypassing the heuristic.
  assert.match(GEOIP_SRC,
    /(forceCol\s*>=\s*0\s*\|\|\s*retryExtractedCols|retryExtractedCols\s*\|\|\s*forceCol\s*>=\s*0)/,
    '_runGeoipEnrichment must bypass the neighbour-skip heuristic ' +
    'when retryExtractedCols is true (mirroring the forceCol ' +
    'bypass already in place)');
});
