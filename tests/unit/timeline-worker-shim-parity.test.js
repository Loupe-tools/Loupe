'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-worker-shim-parity.test.js — assert that the small subset of
// `RENDER_LIMITS`, `EVTX_COLUMN_ORDER`, and `TIMELINE_MAX_ROWS` that the
// Timeline parse-only worker shim re-declares matches the canonical
// values in `src/constants.js`.
//
// Why this exists (independent of the existing `scripts/check_shim_parity.py`)
// ─────────────────────────────────────────────────────────────────────────
// The Python `check_shim_parity.py` covers byte-equivalent constants and
// functions (`safeRegex`, `looksRedosProne`, `_REDOS_*` patterns, etc.)
// that are inlined verbatim into worker shims. It does NOT cover the
// `RENDER_LIMITS` / `EVTX_COLUMN_ORDER` / `TIMELINE_MAX_ROWS` block at the
// top of `timeline-worker-shim.js` because those mirror a SUBSET of a
// frozen object — there is no byte-equivalent body to diff. A drift on
// `MAX_TIMELINE_ROWS` (e.g. main thread bumps to 2 M, worker stays at
// 1 M) would silently truncate every multi-million-row CSV / EVTX in
// the worker without any user-visible toast or build error.
//
// This test loads `src/constants.js` via the bundle harness and reads
// the actual evaluated values, then parses the same names out of the
// shim source and asserts equality. Numeric, string-array, and scalar
// shapes are all handled.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SHIM_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/workers/timeline-worker-shim.js'),
  'utf8',
);

// ── Canonical values from src/constants.js ──────────────────────────────────
const ctx = loadModules(['src/constants.js'], {
  expose: ['RENDER_LIMITS', 'EVTX_COLUMN_ORDER'],
});
const { RENDER_LIMITS, EVTX_COLUMN_ORDER } = ctx;

// ── Helpers — extract values from the shim source ──────────────────────────

// Extract the body of `const RENDER_LIMITS = Object.freeze({ ... });` from
// the shim and return a `{ key: number }` map.
function extractShimRenderLimits(src) {
  const m = src.match(/const\s+RENDER_LIMITS\s*=\s*Object\.freeze\(\{([\s\S]*?)\}\);/);
  if (!m) throw new Error('RENDER_LIMITS not found in shim source');
  const body = m[1];
  const out = {};
  // Match `KEY: <numeric expression>,` where the expression may include
  // numeric literals with `_` separators and `*` arithmetic
  // (e.g. `16 * 1024 * 1024`).
  const lineRe = /^\s*([A-Z_][A-Z0-9_]*)\s*:\s*([0-9_*. ]+?)\s*,/gm;
  let lm;
  while ((lm = lineRe.exec(body))) {
    const key = lm[1];
    // Strip underscores; evaluate the arithmetic in JS — the regex above
    // restricts the match to digits, dots, underscores, asterisks, and
    // spaces, so `eval` here is safe input from the file system.
    const expr = lm[2].replace(/_/g, '');
    // eslint-disable-next-line no-eval
    out[key] = eval(expr);
  }
  return out;
}

// Extract `const EVTX_COLUMN_ORDER = ['a', 'b', ...];` from the shim and
// return the array. The shim writes it as a plain literal (not the
// frozen `EVTX_COLUMNS.X` references the canonical file uses) so a
// simple JSON-ish parse is enough.
function extractShimEvtxOrder(src) {
  const m = src.match(/const\s+EVTX_COLUMN_ORDER\s*=\s*\[([\s\S]*?)\]\s*;/);
  if (!m) throw new Error('EVTX_COLUMN_ORDER not found in shim source');
  return m[1]
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => {
      const sm = s.match(/^['"](.*)['"]$/);
      if (!sm) throw new Error('EVTX_COLUMN_ORDER entry not a string literal: ' + s);
      return sm[1];
    });
}

function extractShimScalar(src, name) {
  const m = src.match(new RegExp('const\\s+' + name + '\\s*=\\s*([0-9_*. ]+?)\\s*;'));
  if (!m) throw new Error(name + ' not found in shim source');
  // eslint-disable-next-line no-eval
  return eval(m[1].replace(/_/g, ''));
}

// ── Tests ──────────────────────────────────────────────────────────────────

test('shim RENDER_LIMITS subset matches canonical values', () => {
  const shimLimits = extractShimRenderLimits(SHIM_SRC);
  // The shim only mirrors values the worker parse path actually reads —
  // the canonical RENDER_LIMITS table is much larger. Iterate over the
  // shim's keys and confirm every one is present + equal in canonical.
  const keys = Object.keys(shimLimits);
  assert.ok(keys.length > 0, 'shim must mirror at least one RENDER_LIMITS key');
  for (const key of keys) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(RENDER_LIMITS, key),
      'shim mirrors RENDER_LIMITS.' + key + ' but the canonical table has no such key',
    );
    assert.equal(
      shimLimits[key],
      RENDER_LIMITS[key],
      'shim RENDER_LIMITS.' + key + ' (' + shimLimits[key] +
        ') does not match canonical (' + RENDER_LIMITS[key] + ')',
    );
  }
});

test('shim EVTX_COLUMN_ORDER matches canonical array exactly', () => {
  const shimOrder = extractShimEvtxOrder(SHIM_SRC);
  // Length and per-index equality. Use deepEqual for clearer diff output
  // when a single column name drifts.
  assert.deepEqual(shimOrder, Array.from(EVTX_COLUMN_ORDER));
});

test('shim TIMELINE_MAX_ROWS matches canonical RENDER_LIMITS.MAX_TIMELINE_ROWS', () => {
  const shimVal = extractShimScalar(SHIM_SRC, 'TIMELINE_MAX_ROWS');
  assert.equal(shimVal, RENDER_LIMITS.MAX_TIMELINE_ROWS);
});

test('shim SAFE_REGEX_MAX_PATTERN_LEN matches canonical', () => {
  // Sanity check — this constant IS already covered by the Python parity
  // gate (`scripts/check_shim_parity.py`), but we re-assert it here to
  // catch any future split where the JS test runs without the Python
  // gate (e.g. someone running `node --test tests/unit/` locally).
  const shimVal = extractShimScalar(SHIM_SRC, 'SAFE_REGEX_MAX_PATTERN_LEN');
  // SAFE_REGEX_MAX_PATTERN_LEN is a top-level scalar in constants.js;
  // re-load it via a fresh sandbox so we read the canonical declaration.
  const ctx2 = loadModules(['src/constants.js'], {
    expose: ['SAFE_REGEX_MAX_PATTERN_LEN'],
  });
  assert.equal(shimVal, ctx2.SAFE_REGEX_MAX_PATTERN_LEN);
});
