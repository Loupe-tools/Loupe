'use strict';
// timeline-csv-escape.test.js — pins the CSV formula-injection
// neutralisation in `_tlCsvCell` (timeline audit H4).
//
// Loupe's timeline corpus is untrusted forensic data. A cell whose text
// begins with `= + - @` (or a leading TAB / CR) is interpreted as a
// formula by Excel / LibreOffice / Sheets on open. `_tlCsvCell` must
// defang such cells with a leading apostrophe while still applying the
// normal RFC-4180 quoting.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-helpers.js',
], { expose: ['_tlCsvCell', '_tlCsvRow'] });
const { _tlCsvCell, _tlCsvRow } = ctx;

test('H4: formula-leading cells are prefixed with an apostrophe', () => {
  // The defanged value also contains no comma/quote/newline, so it is
  // NOT additionally RFC-quoted — the apostrophe alone neutralises it.
  assert.strictEqual(_tlCsvCell('=1+1'), "'=1+1");
  assert.strictEqual(_tlCsvCell('+cmd'), "'+cmd");
  assert.strictEqual(_tlCsvCell('-2+3'), "'-2+3");
  assert.strictEqual(_tlCsvCell('@SUM(A1)'), "'@SUM(A1)");
});

test('H4: leading TAB / CR (spreadsheet strip tricks) are also defanged', () => {
  // A leading TAB is defanged with the apostrophe but needs no RFC
  // quoting. A leading CR is both defanged AND RFC-quoted (CR is a
  // quote-trigger char).
  assert.strictEqual(_tlCsvCell('\t=evil'), "'\t=evil");
  assert.strictEqual(_tlCsvCell('\r=evil'), '"\'\r=evil"');
});

test('H4: a dangerous cell that ALSO needs RFC quoting gets both', () => {
  // `=cmd|'/c calc'!A1` starts with `=` (defang) and contains a comma →
  // must be apostrophe-prefixed AND wrapped in quotes.
  const out = _tlCsvCell('=HYPERLINK("http://x", "a,b")');
  assert.ok(out.startsWith('"\'='), 'quoted and apostrophe-defanged: ' + out);
  assert.ok(out.includes('""'), 'inner double-quotes are doubled');
});

test('H4: benign values are untouched (no spurious apostrophe)', () => {
  assert.strictEqual(_tlCsvCell('hello'), 'hello');
  assert.strictEqual(_tlCsvCell('4624'), '4624');
  assert.strictEqual(_tlCsvCell('192.168.1.1'), '192.168.1.1');
  assert.strictEqual(_tlCsvCell('user@example.com'), 'user@example.com'); // `@` not leading
  assert.strictEqual(_tlCsvCell(''), '');
  assert.strictEqual(_tlCsvCell(null), '');
});

test('H4: a benign value containing a comma is still RFC-quoted', () => {
  assert.strictEqual(_tlCsvCell('a,b'), '"a,b"');
});

test('H4: _tlCsvRow applies the escaping to every cell', () => {
  assert.strictEqual(_tlCsvRow(['ok', '=evil', 'a,b']), 'ok,\'=evil,"a,b"');
});
