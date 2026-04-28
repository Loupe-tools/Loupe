'use strict';
// numbering-resolver.test.js — DOCX list-numbering / bullet resolver.
//
// `NumberingResolver` is the lookup helper that turns a `<w:numId>` /
// `<w:ilvl>` pair from a Word paragraph into a resolved list marker
// ("1.", "a.", "•", "ii.", …). The XML parser path requires a real
// DOM and is exercised by the e2e DOCX fixtures; this unit test
// targets the *resolution / counter* logic by constructing an
// instance with no doc and seeding `this.abstract` / `this.nums`
// directly. That's exactly how the renderer consumes the class — it
// builds the tables once at parse, then calls `nextCount` /
// `formatMarker` per paragraph.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

// numbering-resolver.js references `W` (the WordprocessingML namespace
// constant) and `wa` / `wfirst` / `toRoman` helpers from constants.js.
// We never trigger the DOM path here, so the only real dependency is
// `toRoman` — but constants.js is the canonical loader for everything
// numbered, so we just load it.
const ctx = loadModules(['src/constants.js', 'src/numbering-resolver.js']);
const { NumberingResolver } = ctx;

/**
 * Build a NumberingResolver with no doc, then seed its in-memory tables
 * directly. Mirrors the post-parse shape produced by `_parse()` against
 * a real DOCX.
 */
function makeSeeded(abstract, nums) {
  const r = new NumberingResolver(null);
  r.abstract = abstract;
  r.nums = nums;
  return r;
}

test('numbering-resolver: constructor with null doc does not throw', () => {
  // The DOCX renderer constructs a fresh resolver per document; if the
  // numbering part is missing we still want a usable empty resolver
  // rather than a crash.
  const r = new NumberingResolver(null);
  // Cross-realm identity: host() round-trip projects vm-realm Object
  // into the host realm so `deepStrictEqual` prototype-identity check
  // passes against a plain `{}`.
  assert.deepEqual(host(r.abstract), {});
  assert.deepEqual(host(r.nums), {});
  assert.deepEqual(host(r.counters), {});
});

test('numbering-resolver: getLvl resolves abstractNumId chain', () => {
  // The lookup chain is numId → abstractNumId → ilvl. Verify every
  // hop with a synthetic two-level list.
  const r = makeSeeded(
    {
      'A1': {
        0: { numFmt: 'decimal', lvlText: '%1.', start: 1, indent: null },
        1: { numFmt: 'lowerLetter', lvlText: '%2.', start: 1, indent: null },
      },
    },
    { '1': { abstractId: 'A1', overrides: {} } }
  );
  const lvl0 = r.getLvl('1', 0);
  assert.equal(lvl0.numFmt, 'decimal');
  assert.equal(lvl0.start, 1);
  const lvl1 = r.getLvl('1', 1);
  assert.equal(lvl1.numFmt, 'lowerLetter');
});

test('numbering-resolver: getLvl returns null on missing numId', () => {
  // Defensive: a paragraph that references a numId not in the document
  // (mid-edit corruption, broken pasted XML) must not throw.
  const r = makeSeeded({}, {});
  assert.equal(r.getLvl('999', 0), null);
});

test('numbering-resolver: nextCount increments per (numId, ilvl)', () => {
  // The counter table is the live state the renderer relies on for
  // sequential 1, 2, 3 numbering on the same level.
  const r = makeSeeded(
    { 'A1': { 0: { numFmt: 'decimal', lvlText: '%1.', start: 1, indent: null } } },
    { '1': { abstractId: 'A1', overrides: {} } }
  );
  assert.equal(r.nextCount('1', 0), 1);
  assert.equal(r.nextCount('1', 0), 2);
  assert.equal(r.nextCount('1', 0), 3);
});

test('numbering-resolver: nextCount honours start override', () => {
  // `lvlOverride/startOverride` remaps the starting number — used in
  // continued lists where the second list resumes at e.g. 5.
  const r = makeSeeded(
    { 'A1': { 0: { numFmt: 'decimal', lvlText: '%1.', start: 1, indent: null } } },
    { '1': { abstractId: 'A1', overrides: { 0: 5 } } }
  );
  assert.equal(r.nextCount('1', 0), 5);
  assert.equal(r.nextCount('1', 0), 6);
});

test('numbering-resolver: deeper level resets when re-entering shallower', () => {
  // The contract documented in `nextCount`: starting a new shallower-
  // level item resets every deeper level, so a nested numbered list
  // restarts at "a." each time the outer item advances.
  const r = makeSeeded(
    {
      'A1': {
        0: { numFmt: 'decimal', lvlText: '%1.', start: 1, indent: null },
        1: { numFmt: 'lowerLetter', lvlText: '%2.', start: 1, indent: null },
      },
    },
    { '1': { abstractId: 'A1', overrides: {} } }
  );
  assert.equal(r.nextCount('1', 0), 1);
  assert.equal(r.nextCount('1', 1), 1); // a.
  assert.equal(r.nextCount('1', 1), 2); // b.
  // Re-entering level 0 must clear level 1's counter.
  assert.equal(r.nextCount('1', 0), 2);
  assert.equal(r.nextCount('1', 1), 1); // a. again, fresh.
});

test('numbering-resolver: isOrdered is false for bullet / none', () => {
  // Bullets and "none" formats never get an ordered marker — the renderer
  // uses this to decide whether to bump the counter.
  const r = makeSeeded(
    {
      'A1': {
        0: { numFmt: 'bullet', lvlText: '\u2022', start: 1, indent: null },
        1: { numFmt: 'none', lvlText: '', start: 1, indent: null },
        2: { numFmt: 'decimal', lvlText: '%1.', start: 1, indent: null },
      },
    },
    { '1': { abstractId: 'A1', overrides: {} } }
  );
  assert.equal(r.isOrdered('1', 0), false);
  assert.equal(r.isOrdered('1', 1), false);
  assert.equal(r.isOrdered('1', 2), true);
});

test('numbering-resolver: formatMarker maps bullet glyphs', () => {
  // Word stores lvlText="•" (or "\uF0B7" / Symbol-font private-use) for
  // bullet-style lists. The MAP table normalises a few common variants
  // back to the canonical "•" character.
  const r = makeSeeded(
    { 'A1': { 0: { numFmt: 'bullet', lvlText: '\uF0B7', start: 1, indent: null } } },
    { '1': { abstractId: 'A1', overrides: {} } }
  );
  assert.equal(r.formatMarker('1', 0, 1), '\u2022');
});

test('numbering-resolver: formatMarker emits decimal / letter / Roman', () => {
  // The four numFmts the renderer cares about: decimal, lowerLetter,
  // upperLetter, lowerRoman / upperRoman. Spot-check each.
  const r = makeSeeded(
    {
      'A1': {
        0: { numFmt: 'decimal',     lvlText: '%1.', start: 1, indent: null },
        1: { numFmt: 'lowerLetter', lvlText: '%1.', start: 1, indent: null },
        2: { numFmt: 'upperLetter', lvlText: '%1.', start: 1, indent: null },
        3: { numFmt: 'lowerRoman',  lvlText: '%1.', start: 1, indent: null },
        4: { numFmt: 'upperRoman',  lvlText: '%1.', start: 1, indent: null },
      },
    },
    { '1': { abstractId: 'A1', overrides: {} } }
  );
  assert.equal(r.formatMarker('1', 0, 3), '3.');
  assert.equal(r.formatMarker('1', 1, 2), 'b.');
  assert.equal(r.formatMarker('1', 2, 3), 'C.');
  assert.equal(r.formatMarker('1', 3, 4), 'iv.');
  assert.equal(r.formatMarker('1', 4, 9), 'IX.');
});

test('numbering-resolver: reset() clears live counters', () => {
  // Renderers that re-render a document (re-flow on settings change)
  // must be able to restart numbering from scratch without rebuilding
  // the abstract/nums tables.
  const r = makeSeeded(
    { 'A1': { 0: { numFmt: 'decimal', lvlText: '%1.', start: 1, indent: null } } },
    { '1': { abstractId: 'A1', overrides: {} } }
  );
  r.nextCount('1', 0);
  r.nextCount('1', 0);
  assert.equal(Object.keys(r.counters).length, 1);
  r.reset();
  assert.deepEqual(host(r.counters), {});
  assert.equal(r.nextCount('1', 0), 1);
});
