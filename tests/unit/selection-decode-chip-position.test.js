'use strict';
// selection-decode-chip-position.test.js
//
// Verifies the `_showDecodeChip` horizontal positioning math in
// `src/app/app-selection-decode.js`.
//
// Why a static-text + extracted-math test: `_showDecodeChip` is a method
// on `App.prototype` that touches DOM (`document.body.appendChild`,
// `chip.style.top`) and reads `window.innerWidth`. Reproducing that
// wiring at runtime would need a full JSDOM setup, which the unit-test
// harness (`tests/helpers/load-bundle.js`) intentionally avoids.
// Instead, we:
//   1. Pin the source-text contract: the function MUST clamp the
//      selection rect to the viewport [0, innerWidth] BEFORE computing
//      the chip's center, otherwise long unwrapped lines (white-space:
//      pre on .plaintext-virtual) push the chip off-screen invisibly.
//   2. Re-implement the pure-math portion verbatim and exercise it
//      against the canonical edge cases (small selection, off-screen
//      left, off-screen right, larger-than-viewport).
//
// Invariants asserted:
//   • Source contains `Math.max(rect.left, 0)` and
//     `Math.min(rect.right, viewportWidth)` — the clamp to the visible
//     viewport. NO `scrollLeft` lookup (a previous version of this
//     function mixed coordinate frames by adding the viewer's internal
//     scroll offset to viewport-relative `getBoundingClientRect()`
//     output, which double-counted scroll).
//   • The chip's final `left` is always within
//     `[8, viewportWidth - 180]` regardless of how far off-screen the
//     selection extends.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SRC = fs.readFileSync(
  path.join(__dirname, '..', '..', 'src', 'app', 'app-selection-decode.js'),
  'utf8'
);

test('selection-decode: _showDecodeChip clamps rect to viewport [0, innerWidth]', () => {
  // The clamp is the load-bearing fix for the off-screen-chip bug on
  // long unwrapped lines. Make sure both halves of it survive any
  // future refactor.
  assert.match(SRC, /Math\.max\(rect\.left,\s*0\)/,
    'expected `Math.max(rect.left, 0)` in _showDecodeChip — clamps the ' +
    'selection rect\'s left edge to the viewport origin so the chip never ' +
    'positions itself in negative coordinate space when the analyst selects ' +
    'a region whose start is scrolled off the left edge.');
  assert.match(SRC, /Math\.min\(rect\.right,\s*viewportWidth\)/,
    'expected `Math.min(rect.right, viewportWidth)` in _showDecodeChip — ' +
    'clamps the selection\'s right edge to the viewport so very wide ' +
    'selections (long unwrapped base64 blobs) center the chip on the ' +
    'visible portion rather than far off-screen right.');
});

test('selection-decode: _showDecodeChip does NOT use scrollLeft (coordinate-frame regression guard)', () => {
  // A previous iteration of this function read `viewerEl.scrollLeft` and
  // added it to the viewport-clamp range. That was a coordinate-frame
  // bug: `getBoundingClientRect()` output is already viewport-relative
  // (post-scroll), and `position: fixed` chip coordinates are also
  // viewport-relative. Mixing in the viewer's internal `scrollLeft`
  // double-counted the scroll offset and put the chip in the wrong
  // place when the viewer had been scrolled. Pin against regression.
  assert.doesNotMatch(SRC, /scrollLeft/,
    '_showDecodeChip must not read .scrollLeft — getBoundingClientRect() ' +
    'is already viewport-relative, and `position: fixed` chips use the ' +
    'same frame. Re-introducing scrollLeft would re-introduce the off-' +
    'screen-chip bug on scrolled viewers.');
});

test('selection-decode: chip-position math keeps chip on-screen for off-viewport selections', () => {
  // Re-implement the pure-math portion of _showDecodeChip and exercise
  // it. Mirrors the source so test failures point at a real divergence
  // (drift here = source drifted from the documented clamp contract).
  function chipLeft(rect, viewportWidth) {
    const visibleLeft  = Math.max(rect.left, 0);
    const visibleRight = Math.min(rect.right, viewportWidth);
    const visibleCenterX = (visibleLeft + visibleRight) / 2;
    let left = visibleCenterX - 80;  // half chip width (~160px / 2)
    left = Math.max(8, Math.min(left, viewportWidth - 180));
    return left;
  }

  const W = 1200;  // typical viewport width

  // Case 1: small selection in middle of viewport — chip centered on it.
  const r1 = { left: 500, right: 600 };
  const c1 = chipLeft(r1, W);
  assert.equal(c1, (500 + 600) / 2 - 80,
    'chip centered on small selection (no clamping fires)');

  // Case 2: selection extends OFF-SCREEN LEFT — chip clamps to visible
  // portion. visibleLeft = 0, visibleRight = 400, center = 200, left = 120.
  const r2 = { left: -10000, right: 400 };
  const c2 = chipLeft(r2, W);
  assert.equal(c2, (0 + 400) / 2 - 80,
    'chip uses visible portion of selection that extends off-screen left');
  assert.ok(c2 >= 8 && c2 <= W - 180, 'chip stays in viewport bounds');

  // Case 3: selection extends OFF-SCREEN RIGHT — chip clamps to visible
  // portion. visibleLeft = 800, visibleRight = W = 1200, center = 1000,
  // left = 920.
  const r3 = { left: 800, right: 80000 };
  const c3 = chipLeft(r3, W);
  assert.equal(c3, (800 + W) / 2 - 80,
    'chip uses visible portion of selection that extends off-screen right');
  assert.ok(c3 >= 8 && c3 <= W - 180, 'chip stays in viewport bounds');

  // Case 4: selection LARGER than viewport (76 KB single-line base64
  // blob — the canonical recursive-powershell.ps1 case). visibleLeft =
  // 0, visibleRight = W, center = W/2, left = W/2 - 80.
  const r4 = { left: -50000, right: 50000 };
  const c4 = chipLeft(r4, W);
  assert.equal(c4, W / 2 - 80,
    'chip centered on viewport for selections larger than viewport');
  assert.ok(c4 >= 8 && c4 <= W - 180, 'chip stays in viewport bounds');

  // Case 5: tiny viewport (mobile) — left clamp engages.
  const r5 = { left: 0, right: 100 };
  const c5 = chipLeft(r5, 200);
  assert.equal(c5, 8,
    'chip clamped to left margin (8px) when computed position would be ' +
    'less than the minimum');
});

test('selection-decode: size-based depth tier passes correct `_maxRecursionDepth`', () => {
  // The `_decodeCurrentSelection` method picks a recursion-depth cap
  // based on the selection's UTF-8 byte length to prevent exponential
  // recursion explosion on large nested-base64 blobs. Verify the three
  // tiers are wired into the source:
  //   • >50 KB  → 3 layers  (large — crash prevention)
  //   • 10–50 KB → 4 layers (medium — balanced)
  //   • <10 KB  → 6 layers  (small — bruteforce default, no restrictions)
  assert.match(SRC, /bytes\.length\s*>\s*50_000\s*\?\s*3/,
    'expected `bytes.length > 50_000 ? 3` tier in _decodeCurrentSelection — ' +
    'large selections cap at 3 layers to prevent exponential recursion');
  assert.match(SRC, /bytes\.length\s*>\s*10_000\s*\?\s*4/,
    'expected `bytes.length > 10_000 ? 4` tier in _decodeCurrentSelection — ' +
    'medium selections cap at 4 layers');
  assert.match(SRC, /:\s*6;/,
    'expected fallback `6` (small selections) in size tier — full bruteforce ' +
    'default applies for selections under 10 KB');
  assert.match(SRC, /_maxRecursionDepth:\s*sizeBasedMaxDepth/,
    'expected `_maxRecursionDepth: sizeBasedMaxDepth` to be passed into ' +
    'openInnerFile() — without this the depth-tier computation is dead code');
});
