// timeline-view-autoextract-srcvalues-cache.test.js
//
// B1 — group apply-pump proposals by `sourceCol` and reuse a single
// pre-decoded copy of the source column across every proposal in the
// group.
//
// Background: each proposal's helper (`_addJsonExtractedColNoRender` /
// `_addRegexExtractNoRender`) loops `rowCount` times and calls
// `this._cellAt(i, sourceCol)`, which goes through `RowStore.getCell` /
// `_decodeAsciiSlice`. On a 100k-row CSV with several proposals on the
// same JSON column (the json-leaf cascade), this is the dominant cost
// — `_decodeAsciiSlice` is the second-largest sample bucket in the tab
// profile.
//
// The fix is two-part:
//   (1) The helpers grow an optional `srcValues` parameter that, when
//       supplied as a length-rowCount string array, replaces the
//       per-row `_cellAt` call.
//   (2) `applyStep` groups `ranked` by `sourceCol`, materialises the
//       column once on first proposal of each group, threads it through
//       `_applyAutoProposal(p, srcValues)`, and drops the reference at
//       the group boundary so peak memory stays bounded.
//
// All assertions are static-text — pattern matches the
// `timeline-view-autoextract-uncapped.test.js` style and avoids
// stubbing the entire dataset/render pipeline.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const DRAWER = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-drawer.js'),
  'utf8'
);
const AUTO = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-autoextract.js'),
  'utf8'
);

// ── Drawer side: helpers accept and use srcValues ──────────────────────────

test('_addJsonExtractedColNoRender opts.srcValues is validated as length-rowCount array', () => {
  // The validation gate has to refuse anything that isn't an array of
  // exactly `store.rowCount` strings — otherwise a stale or mis-sized
  // cache from an earlier load would silently corrupt the extracted
  // column.
  const re = /Array\.isArray\(opts\.srcValues\)\s*&&\s*opts\.srcValues\.length === this\.store\.rowCount/;
  assert.match(DRAWER, re,
    'expected `Array.isArray(opts.srcValues) && opts.srcValues.length === this.store.rowCount` gate');
});

test('_addJsonExtractedColNoRender main loop reads srcValues[i] OR falls back to _cellAt', () => {
  // The hot loop has to choose between the cached buffer and the
  // legacy decode call. The ternary `srcValues ? srcValues[i] :
  // this._cellAt(i, colIdx)` is the contract — anything else (e.g.
  // separate code paths, prebuilt buffer rebuild) is a refactor risk.
  assert.match(DRAWER,
    /const raw = srcValues \? srcValues\[i\] : this\._cellAt\(i, colIdx\);/,
    'expected JSON helper main loop to read `srcValues[i]` with `_cellAt` fallback');
});

test('_addRegexExtractNoRender spec.srcValues validation mirrors the JSON helper', () => {
  // Same length+array gate, just on `spec.srcValues` (the regex helper
  // takes a single options bag rather than positional args). Keeping
  // both gates structurally identical makes the next refactor easier.
  const re = /Array\.isArray\(spec\.srcValues\)\s*&&\s*spec\.srcValues\.length === this\.store\.rowCount/;
  assert.match(DRAWER, re,
    'expected `Array.isArray(spec.srcValues) && spec.srcValues.length === this.store.rowCount` gate');
});

test('_addRegexExtractNoRender main loop uses srcValues with _cellAt fallback', () => {
  assert.match(DRAWER,
    /const v = srcValues \? srcValues\[i\] : this\._cellAt\(i, col\);/,
    'expected regex helper main loop to read `srcValues[i]` with `_cellAt` fallback');
});

// ── Auto-extract side: pump groups by sourceCol and threads cache ──────────

test('_applyAutoProposal accepts srcValues as a 2nd positional arg', () => {
  // The arity bump is the public surface of the optimisation — every
  // future caller gets the same opt-in. Manual / dialog callers that
  // omit the arg keep working because the helpers fall back to
  // `_cellAt`.
  assert.match(AUTO, /_applyAutoProposal\(p, srcValues\) \{/,
    'expected `_applyAutoProposal(p, srcValues)` signature');
});

test('_applyAutoProposal threads srcValues into BOTH json and regex helpers', () => {
  // Every dispatch branch has to forward the cache, otherwise
  // proposals of certain kinds would silently bypass the optimisation.
  // Count occurrences — the four kinds (json-*, text-*, kv-field, url-
  // part) collapse into two helpers, so `srcValues` should appear in
  // each helper's call site at least once.
  assert.match(AUTO,
    /_addJsonExtractedColNoRender\(p\.sourceCol, p\.path, p\.proposedName, \{ autoKind: p\.kind, srcValues \}\);/,
    'expected JSON helper call to forward srcValues');

  // Regex helper gets a bag — `srcValues` should be a property of
  // each call's options literal. Match the trailing `srcValues,` line
  // that closes each branch.
  const regexCalls = AUTO.match(/_addRegexExtractNoRender\(\{[\s\S]*?srcValues,\s*\}\);/g) || [];
  assert.ok(regexCalls.length >= 3,
    `expected each regex-helper branch (text-*, kv-field, url-part) to forward srcValues; got ${regexCalls.length}`);
});

test('apply pump groups capped proposals by sourceCol via Map', () => {
  // The grouping step is what makes the cache useful — without it,
  // a json-leaf proposal followed by a text-host proposal on a
  // different column would invalidate the cache every step. The
  // contract is "stable insertion-order Map keyed on sourceCol".
  assert.match(AUTO, /const bySource = new Map\(\);/,
    'expected `bySource = new Map()` to hold the per-source-col groups');

  // Verify the bucket-fill loop reads `p.sourceCol` and pushes onto
  // the bucket (preserves rank within group).
  assert.match(AUTO,
    /for \(const p of capped\) \{[\s\S]*?bySource\.get\(p\.sourceCol\)/,
    'expected the bucket-fill loop to key on `p.sourceCol`');
});

test('apply pump preserves rank order within each source-col group', () => {
  // Insertion-ordered iteration is the JS spec guarantee for `Map`,
  // and the rebuilt `ranked` is constructed by iterating
  // `bySource.values()`. This is the test that the strongest proposal
  // globally still appears first in the cascade — the user-visible
  // ordering survives the regrouping.
  assert.match(AUTO,
    /for \(const bucket of bySource\.values\(\)\) \{\s*for \(const p of bucket\) ranked\.push\(p\);/,
    'expected the rebuilt `ranked` to flatten `bySource.values()` in insertion order');
});

test('apply pump materialises source column lazily, on first proposal of each group', () => {
  // The cache fill is gated on `cachedSrcCol !== p.sourceCol` —
  // anything else (eager pre-decode of every group up front) would
  // defeat the memory-bound contract.
  assert.match(AUTO,
    /if \(cachedSrcCol !== p\.sourceCol\) \{\s*cachedSrcCol = p\.sourceCol;[\s\S]*?for \(let i = 0; i < n; i\+\+\) buf\[i\] = this\._cellAt\(i, p\.sourceCol\);/,
    'expected lazy fill of cache when `cachedSrcCol !== p.sourceCol`');
});

test('apply pump drops cache at group boundary (peak memory stays at one column)', () => {
  // Lookahead at `ranked[idx]` after `idx` has already advanced. When
  // the next proposal targets a different column (or there is no
  // next), `cachedSrcValues` is nulled out so the GC can reclaim the
  // string array. Without this the cache would grow to all 30 columns
  // by pump end on a wide grid.
  assert.match(AUTO,
    /const next = ranked\[idx\];\s*if \(!next \|\| next\.sourceCol !== cachedSrcCol\) \{\s*cachedSrcValues = null;\s*cachedSrcCol = -1;\s*\}/,
    'expected the cache-drop gate to release the buffer at group boundaries');
});

test('apply pump passes cachedSrcValues into _applyAutoProposal', () => {
  // The whole point of building the cache is that it gets threaded
  // through. A caller that forgets the second arg silently regresses
  // every helper to the `_cellAt` path.
  assert.match(AUTO,
    /this\._applyAutoProposal\(p, cachedSrcValues\);/,
    'expected `_applyAutoProposal(p, cachedSrcValues)` invocation');
});
