'use strict';
// ics-renderer.test.js — iCalendar (.ics) invite analyser.
//
// Verifies structured parsing, URL IOC extraction, risk calibration, and
// encoding helpers for calendar-invite phishing triage (T1566.002).

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  ['src/constants.js', 'src/renderers/ics-renderer.js'],
  { expose: ['IcsRenderer', 'IOC', 'escalateRisk'] },
);
const { IcsRenderer, IOC } = ctx;

function bufFor(text) {
  return new TextEncoder().encode(text).buffer;
}

const ICS_HEAD = 'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Loupe Test//EN\r\n';
const ICS_TAIL = 'END:VCALENDAR\r\n';

test('ics: format banner is always emitted', () => {
  const ics = ICS_HEAD + 'BEGIN:VEVENT\r\nSUMMARY:Team sync\r\nEND:VEVENT\r\n' + ICS_TAIL;
  const r = new IcsRenderer();
  const f = r.analyzeForSecurity(bufFor(ics), 'invite.ics');
  const banner = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /iCalendar/.test(x.url));
  assert.ok(banner, `expected format banner, got: ${JSON.stringify(f.externalRefs)}`);
  assert.equal(banner.severity, 'info');
});

test('ics: URL in description escalates risk to medium via externalRefs', () => {
  const ics = ICS_HEAD
    + 'BEGIN:VEVENT\r\n'
    + 'SUMMARY:Urgent meeting\r\n'
    + 'DESCRIPTION:Please join https://evil.example/phish/login\r\n'
    + 'END:VEVENT\r\n'
    + ICS_TAIL;
  const r = new IcsRenderer();
  const f = r.analyzeForSecurity(bufFor(ics), 'phish.ics');
  assert.equal(f.risk, 'medium');
  const url = f.externalRefs.find(x =>
    x.type === IOC.URL && x.url === 'https://evil.example/phish/login');
  assert.ok(url, `expected URL IOC in externalRefs, got: ${JSON.stringify(f.externalRefs)}`);
  assert.equal(url.severity, 'medium');
});

test('ics: _parseIcs unfolds folded lines', () => {
  const ics = ICS_HEAD
    + 'BEGIN:VEVENT\r\n'
    + 'DESCRIPTION:This is a long description\r\n'
    + ' that continues on the next line\r\n'
    + 'END:VEVENT\r\n'
    + ICS_TAIL;
  const parsed = IcsRenderer._parseIcs(ics);
  assert.equal(parsed.events.length, 1);
  // RFC 5545 removes the CRLF + single folding whitespace; the leading
  // space on the continuation line is the fold marker, not content.
  assert.equal(parsed.events[0].description, 'This is a long descriptionthat continues on the next line');
});

test('ics: METHOD is available on events and calendar scope', () => {
  const ics = ICS_HEAD
    + 'METHOD:REQUEST\r\n'
    + 'BEGIN:VEVENT\r\n'
    + 'SUMMARY:Invite\r\n'
    + 'END:VEVENT\r\n'
    + ICS_TAIL;
  const parsed = IcsRenderer._parseIcs(ics);
  assert.equal(parsed.method, 'REQUEST');
  assert.equal(parsed.events[0].method, 'REQUEST');
});

test('ics: ATTENDEE and URL properties are parsed', () => {
  const ics = ICS_HEAD
    + 'BEGIN:VEVENT\r\n'
    + 'SUMMARY:Review\r\n'
    + 'ORGANIZER:mailto:boss@example.com\r\n'
    + 'ATTENDEE:mailto:alice@example.com\r\n'
    + 'URL:https://meet.example/room\r\n'
    + 'END:VEVENT\r\n'
    + ICS_TAIL;
  const parsed = IcsRenderer._parseIcs(ics);
  assert.equal(parsed.events[0].organizer, 'boss@example.com');
  assert.equal(parsed.events[0].attendees.length, 1);
  assert.equal(parsed.events[0].attendees[0], 'alice@example.com');
  assert.equal(parsed.events[0].links.length, 1);
  assert.equal(parsed.events[0].links[0], 'https://meet.example/room');
});

test('ics: quoted-printable DESCRIPTION is decoded', () => {
  const ics = ICS_HEAD
    + 'BEGIN:VEVENT\r\n'
    + 'DESCRIPTION;ENCODING=QUOTED-PRINTABLE:Join=20now=0Ahttps://evil.example/p\r\n'
    + 'END:VEVENT\r\n'
    + ICS_TAIL;
  const parsed = IcsRenderer._parseIcs(ics);
  assert.equal(parsed.events[0].description, 'Join now\nhttps://evil.example/p');
  assert.equal(parsed.unsupportedEncoding, false);
});

test('ics: benign invite without URLs stays low risk', () => {
  const ics = ICS_HEAD
    + 'BEGIN:VEVENT\r\n'
    + 'SUMMARY:Standup\r\n'
    + 'DESCRIPTION:Daily team standup in room 3\r\n'
    + 'END:VEVENT\r\n'
    + ICS_TAIL;
  const r = new IcsRenderer();
  const f = r.analyzeForSecurity(bufFor(ics), 'standup.ics');
  assert.equal(f.risk, 'low');
  const urls = f.externalRefs.filter(x => x.type === IOC.URL);
  assert.equal(urls.length, 0);
});