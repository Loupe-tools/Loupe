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
// sole ownership of its own marker — which has since been renamed from
// `AUTOEXTRACT_DONE` (`loupe_timeline_autoextract_done`) to
// `AUTOEXTRACT_TOAST_SHOWN` (`loupe_timeline_autoextract_toast_shown`)
// when its semantics changed: it no longer gates the EXTRACTION (which
// runs every open) but only the post-apply TOAST.
//
// Pins (static-text invariants — NOT a behavioural test):
//   • TIMELINE_KEYS defines BOTH `AUTOEXTRACT_TOAST_SHOWN` and
//     `GEOIP_DONE`, with distinct string values. The legacy
//     `AUTOEXTRACT_DONE_LEGACY` constant exists ONLY for the
//     migration cleanup inside `_loadAutoExtractToastShownFor`.
//   • `timeline-view-geoip.js` references ONLY the GeoIP-specific
//     load/save methods (never the auto-extract pair).
//   • `timeline-view-autoextract.js` references ONLY the
//     auto-extract toast-shown load/save methods (never the GeoIP
//     pair).
//   • `timeline-view-persist.js` defines all four current methods.
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

test('TIMELINE_KEYS defines AUTOEXTRACT_TOAST_SHOWN with the canonical key string', () => {
  assert.match(
    HELPERS,
    /AUTOEXTRACT_TOAST_SHOWN:\s*'loupe_timeline_autoextract_toast_shown'/,
    'TIMELINE_KEYS.AUTOEXTRACT_TOAST_SHOWN must be loupe_timeline_autoextract_toast_shown',
  );
});

test('TIMELINE_KEYS defines AUTOEXTRACT_DONE_LEGACY for migration only', () => {
  // The legacy alias must be present so `_loadAutoExtractToastShownFor`
  // can locate and delete stale entries from existing browser profiles.
  assert.match(
    HELPERS,
    /AUTOEXTRACT_DONE_LEGACY:\s*'loupe_timeline_autoextract_done'/,
    'TIMELINE_KEYS.AUTOEXTRACT_DONE_LEGACY must keep the pre-rename ' +
    'value loupe_timeline_autoextract_done so the migration cleanup ' +
    'in _loadAutoExtractToastShownFor can target it.',
  );
});

test('TIMELINE_KEYS defines GEOIP_DONE with a distinct key string', () => {
  assert.match(
    HELPERS,
    /GEOIP_DONE:\s*'loupe_timeline_geoip_done'/,
    'TIMELINE_KEYS.GEOIP_DONE must be loupe_timeline_geoip_done — sharing the auto-extract key would resurrect the bug where GeoIP no-op silently disables JSON / URL / host extraction',
  );
});

test('the toast-shown and GeoIP keys are distinct strings', () => {
  // Defence in depth — even if someone redefines the constants, the
  // string values themselves must differ.
  const auto = HELPERS.match(/AUTOEXTRACT_TOAST_SHOWN:\s*'([^']+)'/);
  const geo = HELPERS.match(/GEOIP_DONE:\s*'([^']+)'/);
  assert.ok(auto, 'AUTOEXTRACT_TOAST_SHOWN constant not found');
  assert.ok(geo, 'GEOIP_DONE constant not found');
  assert.notEqual(
    auto[1], geo[1],
    'AUTOEXTRACT_TOAST_SHOWN and GEOIP_DONE must be distinct localStorage keys',
  );
});

// ── Persist mixin owns all four methods ────────────────────────────────────

test('timeline-view-persist.js defines _loadAutoExtractToastShownFor + _saveAutoExtractToastShownFor', () => {
  assert.match(PERSIST, /_loadAutoExtractToastShownFor\s*\(/);
  assert.match(PERSIST, /_saveAutoExtractToastShownFor\s*\(/);
});

test('timeline-view-persist.js does NOT define the legacy auto-extract methods', () => {
  // The pre-rename method names (`_loadAutoExtractDoneFor` /
  // `_saveAutoExtractDoneFor`) must not coexist with the new ones —
  // having both invites confusion about which gates extraction vs
  // toast.
  assert.doesNotMatch(
    PERSIST,
    /_loadAutoExtractDoneFor\s*\(/,
    'timeline-view-persist.js must not define the pre-rename method ' +
    '_loadAutoExtractDoneFor — it was renamed to _loadAutoExtractToastShownFor.',
  );
  assert.doesNotMatch(
    PERSIST,
    /_saveAutoExtractDoneFor\s*\(/,
    'timeline-view-persist.js must not define the pre-rename method ' +
    '_saveAutoExtractDoneFor — it was renamed to _saveAutoExtractToastShownFor.',
  );
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
    /_loadAutoExtractToastShownFor/,
    'timeline-view-geoip.js must not read the auto-extract toast-shown ' +
    'marker — it has its own (_loadGeoipDoneFor)',
  );
  assert.doesNotMatch(
    GEOIP,
    /_saveAutoExtractToastShownFor/,
    'timeline-view-geoip.js must not write the auto-extract toast-shown ' +
    'marker — that was the bug class. Use _saveGeoipDoneFor.',
  );
  // Also block any reference to the pre-rename methods (defensive — if
  // someone reverts the rename in geoip but the rest of the codebase
  // moved on, this fires first).
  assert.doesNotMatch(GEOIP, /_loadAutoExtractDoneFor|_saveAutoExtractDoneFor/,
    'timeline-view-geoip.js must not reference the legacy ' +
    '_loadAutoExtractDoneFor / _saveAutoExtractDoneFor methods.');
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

test('timeline-view-autoextract.js DOES reference toast-shown marker methods', () => {
  assert.match(AUTOEXTRACT, /_loadAutoExtractToastShownFor/);
  assert.match(AUTOEXTRACT, /_saveAutoExtractToastShownFor/);
});

test('timeline-view-autoextract.js does NOT reference the legacy marker methods', () => {
  // Once the rename's complete, no caller should reference the old names.
  assert.doesNotMatch(AUTOEXTRACT, /_loadAutoExtractDoneFor/,
    'timeline-view-autoextract.js must not reference the legacy ' +
    '_loadAutoExtractDoneFor method — it was renamed to ' +
    '_loadAutoExtractToastShownFor.');
  assert.doesNotMatch(AUTOEXTRACT, /_saveAutoExtractDoneFor/,
    'timeline-view-autoextract.js must not reference the legacy ' +
    '_saveAutoExtractDoneFor method — it was renamed to ' +
    '_saveAutoExtractToastShownFor.');
});
