// timeline-view-popovers-extract-layout.test.js
//
// Extract Values dialog UX shake-up — sticky footer + always-visible
// header CTA. Pins the contract so a future markup refactor can't
// silently regress the "primary action stays in view" property that
// motivated the redesign.
//
// Background: pre-redesign the dialog had `<footer>` (with the
// "Extract selected" button) nested inside the same scroll container
// as the proposal list. On a long auto-scan the analyst saw the list
// fill the viewport and had to scroll all the way down to extract.
// The fix:
//
//   1. Add `.tl-dialog-head-cta` — a duplicate primary button in the
//      dialog header that mirrors the footer button's disabled state
//      and selection count, and forwards click → footer.
//   2. CSS: scope `overflow:auto` to `.tl-auto-body` only, give the
//      pane a flex column with `min-height: 0`, and pin toolbar /
//      preview / footer with `flex: 0 0 auto`.
//   3. Reset `autoBody.scrollTop = 0` after each `renderList()` so a
//      fresh open / rescan / facet/search/sort change always reveals
//      the first proposal.
//
// All three legs are asserted via static text on the source files —
// same convention as the sibling `…-extract-selected-srcvalues` test.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const POPOVERS = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-popovers.js'),
  'utf8'
);
const CSS = readFileSync(
  join(__dirname, '..', '..', 'src', 'styles', 'viewers.css'),
  'utf8'
);

// ── Markup contract ────────────────────────────────────────────────────────

test('dialog header includes the primary Extract CTA', () => {
  // The header CTA is the user-visible payoff of the redesign — it
  // must be a `<button>` with the data-act marker so the JS wiring
  // can find it, and must carry the count `<span>` so updateCount()
  // has somewhere to write.
  assert.match(POPOVERS,
    /class="tl-tb-btn tl-tb-btn-primary tl-dialog-head-cta"[^>]*data-act="auto-extract-head"/,
    'expected `.tl-dialog-head-cta` button with data-act="auto-extract-head" in header');
  assert.match(POPOVERS, /<span class="tl-dialog-head-cta-count">/,
    'expected the head CTA to contain a `.tl-dialog-head-cta-count` count span');
});

test('head CTA is hidden on the Manual tab', () => {
  // The Manual tab has its own ƒx Extract button at the bottom of a
  // short pane — duplicating the header CTA there would be confusing.
  // _showTab toggles `headCta.style.display`.
  assert.match(POPOVERS,
    /headCta\.style\.display = \(which === 'auto'\) \? '' : 'none'/,
    'expected _showTab to hide headCta when switching away from the auto tab');
});

test('head CTA click forwards to the footer Extract button', () => {
  // One apply path. The forwarder must be a plain `.click()` so that
  // the disabled-state guard on the footer button (and any future
  // decoration) is honoured automatically.
  assert.match(POPOVERS,
    /headCta\.addEventListener\('click', \(\) => \{ autoExtractBtn\.click\(\); \}\)/,
    'expected headCta click → autoExtractBtn.click() forwarder');
});

test('updateCount mirrors selection size and disabled state into head CTA', () => {
  // The head CTA must reflect the same N-selected / disabled story as
  // the footer button, otherwise the user sees stale state.
  assert.match(POPOVERS, /headCta\.disabled = selN === 0/,
    'expected updateCount to mirror disabled state into headCta');
  assert.match(POPOVERS,
    /headCta\.querySelector\('\.tl-dialog-head-cta-count'\)/,
    'expected updateCount to update headCta count span');
});

test('renderList resets scroll-to-top after each render', () => {
  // Avoids the "dialog opens already-scrolled" jarring effect on a
  // long auto-scan.
  assert.match(POPOVERS, /autoBody\.scrollTop = 0/,
    'expected `autoBody.scrollTop = 0` reset inside renderList');
});

// ── CSS contract — sticky toolbar/footer + dedicated scroll region ────────

test('CSS: only .tl-auto-body scrolls inside the auto pane', () => {
  // Pane is flex column with `overflow:hidden` on the body so the
  // primary action stays in view; the proposal list is the sole
  // overflow:auto child.
  assert.match(CSS,
    /\.tl-dialog-extract \.tl-dialog-body \{[^}]*overflow:\s*hidden/,
    'expected `.tl-dialog-extract .tl-dialog-body { overflow: hidden }`');
  assert.match(CSS,
    /\.tl-auto-body \{[^}]*overflow:\s*auto/,
    'expected `.tl-auto-body { overflow: auto }` as the dedicated scroll region');
});

test('CSS: auto pane is a flex column with min-height:0', () => {
  // Without `min-height: 0` on a flex column the child's overflow
  // does nothing — the pane just grows to fit the list.
  assert.match(CSS,
    /\.tl-dialog-extract \.tl-dialog-pane-auto[\s\S]{0,200}min-height:\s*0/,
    'expected `min-height: 0` on the auto pane (flex scroll fix)');
});

test('CSS: head CTA has primary-button styling hooks', () => {
  assert.match(CSS, /\.tl-dialog-head-cta \{/,
    'expected `.tl-dialog-head-cta` rule');
  assert.match(CSS, /\.tl-dialog-head-cta:disabled \{[^}]*opacity/,
    'expected disabled-state rule for `.tl-dialog-head-cta`');
});
