'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-geoip-marker-isolation.test.js — pin the split between the
// auto-extract done-marker and the GeoIP done-marker.
//
// HISTORY: GeoIP enrichment briefly shared `loupe_timeline_autoextract_done`
// with `_autoExtractBestEffort()`. On the no-IP-columns path, GeoIP would
// stamp the marker even though it added zero columns, which poisoned
// auto-extract's idempotence guard so JSON / URL / host extraction
// silently never ran on files like `examples/forensics/json-example.csv`.
//
// FIX: split into a distinct `loupe_timeline_geoip_done` key, owned
// exclusively by `_runGeoipEnrichment`. `_autoExtractBestEffort` retains
// sole ownership of `loupe_timeline_autoextract_done`.
//
// Pins (static-text invariants — NOT a behavioural test):
//   • TIMELINE_KEYS defines BOTH `AUTOEXTRACT_DONE` and `GEOIP_DONE`,
//     with distinct string values.
//   • `timeline-view-geoip.js` references ONLY the GeoIP-specific
//     load/save methods (never the auto-extract pair).
//   • `timeline-view-autoextract.js` references ONLY the auto-extract
//     load/save methods (never the GeoIP pair).
//   • `timeline-view-persist.js` defines all four methods.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const HELPERS = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-helpers.js'),
  'utf8',
);
const PERSIST = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-persist.js'),
  'utf8',
);
const GEOIP = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-geoip.js'),
  'utf8',
);
const AUTOEXTRACT = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-autoextract.js'),
  'utf8',
);

// ── Key definitions ────────────────────────────────────────────────────────

test('TIMELINE_KEYS defines AUTOEXTRACT_DONE with the canonical key string', () => {
  assert.match(
    HELPERS,
    /AUTOEXTRACT_DONE:\s*'loupe_timeline_autoextract_done'/,
    'TIMELINE_KEYS.AUTOEXTRACT_DONE must be loupe_timeline_autoextract_done',
  );
});

test('TIMELINE_KEYS defines GEOIP_DONE with a distinct key string', () => {
  assert.match(
    HELPERS,
    /GEOIP_DONE:\s*'loupe_timeline_geoip_done'/,
    'TIMELINE_KEYS.GEOIP_DONE must be loupe_timeline_geoip_done — sharing the auto-extract key would resurrect the bug where GeoIP no-op silently disables JSON / URL / host extraction',
  );
});

test('the two keys are distinct strings', () => {
  // Defence in depth — even if someone redefines the constants, the
  // string values themselves must differ.
  const auto = HELPERS.match(/AUTOEXTRACT_DONE:\s*'([^']+)'/);
  const geo = HELPERS.match(/GEOIP_DONE:\s*'([^']+)'/);
  assert.ok(auto, 'AUTOEXTRACT_DONE constant not found');
  assert.ok(geo, 'GEOIP_DONE constant not found');
  assert.notEqual(
    auto[1], geo[1],
    'AUTOEXTRACT_DONE and GEOIP_DONE must be distinct localStorage keys',
  );
});

// ── Persist mixin owns all four methods ────────────────────────────────────

test('timeline-view-persist.js defines _loadAutoExtractDoneFor + _saveAutoExtractDoneFor', () => {
  assert.match(PERSIST, /_loadAutoExtractDoneFor\s*\(/);
  assert.match(PERSIST, /_saveAutoExtractDoneFor\s*\(/);
});

test('timeline-view-persist.js defines _loadGeoipDoneFor + _saveGeoipDoneFor', () => {
  assert.match(PERSIST, /_loadGeoipDoneFor\s*\(/);
  assert.match(PERSIST, /_saveGeoipDoneFor\s*\(/);
});

// ── Subsystem ownership ────────────────────────────────────────────────────

test('timeline-view-geoip.js does NOT reference auto-extract marker methods', () => {
  // The whole point of the split is that GeoIP can no longer poison the
  // auto-extract guard. Re-introducing a call to either method here
  // would re-introduce the regression we just fixed.
  assert.doesNotMatch(
    GEOIP,
    /_loadAutoExtractDoneFor/,
    'timeline-view-geoip.js must not read the auto-extract marker — it has its own (_loadGeoipDoneFor)',
  );
  assert.doesNotMatch(
    GEOIP,
    /_saveAutoExtractDoneFor/,
    'timeline-view-geoip.js must not write the auto-extract marker — that was the bug. Use _saveGeoipDoneFor.',
  );
});

test('timeline-view-geoip.js DOES reference GeoIP-specific marker methods', () => {
  // Sanity: confirm the GeoIP idempotence path is wired up. If the
  // mixin stops persisting its own marker entirely, an analyst who
  // deletes a geo / asn column will see it return on every reopen.
  assert.match(
    GEOIP,
    /_loadGeoipDoneFor/,
    'timeline-view-geoip.js lost its GeoIP marker read — geo / asn deletions will resurface on reopen',
  );
  assert.match(
    GEOIP,
    /_saveGeoipDoneFor/,
    'timeline-view-geoip.js lost its GeoIP marker write — file will be re-scanned for IP cols on every reopen',
  );
});

test('timeline-view-autoextract.js does NOT reference GeoIP marker methods', () => {
  // The reverse split — auto-extract should never read or write GeoIP
  // state. Doing so would imply a circular ownership of the markers.
  assert.doesNotMatch(
    AUTOEXTRACT,
    /_loadGeoipDoneFor/,
    'timeline-view-autoextract.js must not read the GeoIP marker',
  );
  assert.doesNotMatch(
    AUTOEXTRACT,
    /_saveGeoipDoneFor/,
    'timeline-view-autoextract.js must not write the GeoIP marker',
  );
});

test('timeline-view-autoextract.js DOES reference auto-extract marker methods', () => {
  assert.match(AUTOEXTRACT, /_loadAutoExtractDoneFor/);
  assert.match(AUTOEXTRACT, /_saveAutoExtractDoneFor/);
});
