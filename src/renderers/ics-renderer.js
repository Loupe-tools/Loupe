'use strict';
// ════════════════════════════════════════════════════════════════════════════
// ics-renderer.js — iCalendar (.ics) invite / calendar event viewer
//
// .ics files (RFC 5545) are used for calendar invitations (T1566.002).
// Phishing actors abuse them to deliver links that auto-open in the
// victim's calendar app (live click risk) or to socially-engineer
// targets via meeting lures containing credential-harvesting URLs.
//
// Loupe provides a safe, offline, structured view + extracts URLs as
// IOCs so the analyst can triage without a live calendar client.
//
// YARA already has dedicated rules (Info_ICS_Calendar_Invite,
// Info_ICS_Calendar_With_URL) — this renderer improves human
// readability and surfaces the same signals via the sidebar.
//
// Detection: text-sniff on "BEGIN:VCALENDAR" (case-insensitive) +
// .ics extension. Falls back gracefully.
//
// Depends on: constants.js (IOC, escalateRisk, lfNormalize,
//             pushIOC, RENDER_LIMITS)
// ════════════════════════════════════════════════════════════════════════════
class IcsRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const wrap = document.createElement('div');
    wrap.className = 'ics-view';

    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const strong = document.createElement('strong');
    strong.textContent = 'Calendar Invite (.ics)';
    banner.appendChild(strong);
    banner.appendChild(document.createTextNode(
      ' — iCalendar file. Opening in a real calendar app may follow embedded URLs or ATTACHments. Triage the event details and any links here instead.'
    ));
    wrap.appendChild(banner);

    const parsed = IcsRenderer._parseIcs(text);
    const evCount = parsed.events.length;
    const info = document.createElement('div');
    info.className = 'plaintext-info';
    info.textContent = `${evCount} event${evCount !== 1 ? 's' : ''} · ${parsed.version || '2.0'} · ${this._fmtBytes(bytes.length)}`;
    wrap.appendChild(info);

    if (parsed.prodId) {
      const pid = document.createElement('div');
      pid.className = 'ics-prodid';
      pid.textContent = `ProdID: ${parsed.prodId}`;
      wrap.appendChild(pid);
    }

    // Render events as cards
    if (evCount) {
      const eventsWrap = document.createElement('div');
      eventsWrap.className = 'ics-events';
      for (const ev of parsed.events) {
        const card = document.createElement('div');
        card.className = 'ics-event';

        const title = document.createElement('div');
        title.className = 'ics-event-title';
        title.textContent = ev.summary || '(no summary)';
        card.appendChild(title);

        const meta = document.createElement('div');
        meta.className = 'ics-meta';
        const rows = [];
        if (ev.dtstart) rows.push(['Start', ev.dtstart]);
        if (ev.dtend) rows.push(['End', ev.dtend]);
        if (ev.organizer) rows.push(['Organizer', ev.organizer]);
        if (ev.location) rows.push(['Location', ev.location]);
        if (ev.status) rows.push(['Status', ev.status]);
        if (ev.method) rows.push(['Method', ev.method]);
        for (const [k, v] of rows) {
          const r = document.createElement('div');
          r.className = 'ics-meta-row';
          const lbl = document.createElement('span'); lbl.className = 'ics-lbl'; lbl.textContent = k + ':';
          const val = document.createElement('span'); val.className = 'ics-val'; val.textContent = v;
          r.appendChild(lbl); r.appendChild(val);
          meta.appendChild(r);
        }
        card.appendChild(meta);

        if (ev.attendees && ev.attendees.length) {
          const attH = document.createElement('div');
          attH.className = 'ics-att-h'; attH.textContent = `Attendees (${ev.attendees.length})`;
          card.appendChild(attH);
          const ul = document.createElement('ul'); ul.className = 'ics-att-list';
          for (const a of ev.attendees.slice(0, 20)) {
            const li = document.createElement('li'); li.textContent = a;
            ul.appendChild(li);
          }
          if (ev.attendees.length > 20) {
            const more = document.createElement('li'); more.textContent = `… +${ev.attendees.length - 20} more`;
            ul.appendChild(more);
          }
          card.appendChild(ul);
        }

        if (ev.description) {
          const descH = document.createElement('div');
          descH.className = 'ics-desc-h'; descH.textContent = 'Description';
          card.appendChild(descH);
          const desc = document.createElement('div');
          desc.className = 'ics-desc';
          // Show description; URLs are surfaced as IOCs + raw-view highlights.
          // Keep simple text (no live links).
          desc.textContent = ev.description.length > 2000 ? ev.description.slice(0, 2000) + '…' : ev.description;
          card.appendChild(desc);
        }

        // Any ATTACH or URL values discovered during parse (non-URL props may still carry links)
        if (ev.links && ev.links.length) {
          const linkH = document.createElement('div');
          linkH.className = 'ics-link-h'; linkH.textContent = 'Links / Attachments';
          card.appendChild(linkH);
          const linksDiv = document.createElement('div'); linksDiv.className = 'ics-links';
          for (const l of ev.links.slice(0, 10)) {
            const b = document.createElement('span');
            b.className = 'ics-link';
            b.textContent = l.length > 80 ? l.slice(0, 80) + '…' : l;
            linksDiv.appendChild(b);
          }
          card.appendChild(linksDiv);
        }

        eventsWrap.appendChild(card);
      }
      wrap.appendChild(eventsWrap);
    } else {
      const empty = document.createElement('div');
      empty.className = 'ics-empty';
      empty.textContent = 'No VEVENT entries found (may still contain other iCalendar components).';
      wrap.appendChild(empty);
    }

    this._addRawView(wrap, text, bytes.length);
    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const normalized = lfNormalize(text);

    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: [],
      _rawText: normalized,
    };

    // Format marker — visible even for benign invites
    pushIOC(f, {
      type: IOC.PATTERN,
      value: 'iCalendar (.ics) invite — check embedded URLs / ATTACH for phishing (T1566.002)',
      severity: 'info',
      bucket: 'externalRefs',
    });

    const parsed = IcsRenderer._parseIcs(text);

    // Push any URLs discovered in URL, ATTACH, DESCRIPTION, etc.
    // We intentionally omit sourceOffset/highlightText for these per-field
    // extractions to avoid incorrect click-to-focus positions (the values are
    // substrings). The final raw-body scan below provides the same IOCs with
    // correct global offsets against _rawText.
    const urlRe = /https?:\/\/[^\s<>"'()\[\]{}]+/gi;
    const seen = new Set();

    function pushUrl(val, note) {
      urlRe.lastIndex = 0;
      let u;
      while ((u = urlRe.exec(val)) !== null) {
        const url = u[0];
        if (seen.has(url)) continue;
        seen.add(url);
        pushIOC(f, {
          type: IOC.URL,
          value: url,
          severity: 'medium',
          note: note || 'ICS',
        });
      }
    }

    if (parsed.calendarUrls) for (const u of parsed.calendarUrls) pushUrl(u, 'ICS calendar');
    for (const ev of parsed.events) {
      if (ev.organizer) pushUrl(ev.organizer, 'ICS organizer');
      if (ev.location) pushUrl(ev.location, 'ICS location');
      if (ev.description) pushUrl(ev.description, 'ICS description');
      if (ev.links) for (const l of ev.links) pushUrl(l, 'ICS link/attach');
      if (ev.attendees) for (const a of ev.attendees) pushUrl(a, 'ICS attendee');
    }

    // Also scan the raw body for any obvious http(s) not captured above (defense in depth)
    let m;
    const bodyUrlRe = /https?:\/\/[^\s<>"'()\[\]{}]+/gi;
    while ((m = bodyUrlRe.exec(normalized)) !== null) {
      const url = m[0];
      if (!seen.has(url)) {
        seen.add(url);
        pushIOC(f, {
          type: IOC.URL,
          value: url,
          severity: 'medium',
          note: 'ICS (raw)',
          highlightText: url,
          sourceOffset: m.index,
          sourceLength: url.length,
        });
      }
    }

    // Evidence-based risk
    const refs = f.externalRefs;
    const highs = refs.filter(r => r.severity === 'high').length;
    const hasCrit = refs.some(r => r.severity === 'critical');
    const hasMed = refs.some(r => r.severity === 'medium');
    if (hasCrit) escalateRisk(f, 'critical');
    else if (highs >= 1) escalateRisk(f, 'high');
    else if (hasMed) escalateRisk(f, 'medium');
    return f;
  }

  // ── Parser (static, exported for tests) ──────────────────────────────────
  // RFC 5545-ish: unfold folded lines, split on first ':', handle common
  // properties. Sufficient for SOC triage (summary, times, attendees, URLs).
  static _parseIcs(text) {
    const normalized = lfNormalize(text);
    const lines = normalized.split('\n');

    // Unfold: lines that start with space or tab continue the previous
    const unfolded = [];
    for (let raw of lines) {
      if ((raw.startsWith(' ') || raw.startsWith('\t')) && unfolded.length) {
        unfolded[unfolded.length - 1] += raw.slice(1);
      } else {
        unfolded.push(raw);
      }
    }

    const out = {
      version: null,
      prodId: null,
      method: null,
      calendarUrls: [],
      events: [],
    };

    let current = null;
    for (let line of unfolded) {
      line = line.trim();
      if (!line) continue;
      const colon = line.indexOf(':');
      if (colon < 0) continue;
      let keyPart = line.slice(0, colon);
      let val = line.slice(colon + 1).trim();

      // Strip params (e.g. DTSTART;TZID=... )
      const semi = keyPart.indexOf(';');
      const key = (semi >= 0 ? keyPart.slice(0, semi) : keyPart).toUpperCase();

      if (key === 'BEGIN' && val.toUpperCase() === 'VCALENDAR') {
        current = null;
        continue;
      }
      if (key === 'BEGIN' && val.toUpperCase() === 'VEVENT') {
        current = { attendees: [], links: [] };
        out.events.push(current);
        continue;
      }
      if (key === 'END' && val.toUpperCase() === 'VEVENT') {
        current = null;
        continue;
      }

      if (key === 'VERSION') { out.version = val; continue; }
      if (key === 'PRODID') { out.prodId = val; continue; }
      if (key === 'METHOD') { out.method = val; continue; }

      if (key === 'URL' || key === 'ATTACH') {
        if (current) current.links.push(val);
        else out.calendarUrls.push(val);
        continue;
      }

      if (!current) {
        if (key === 'X-WR-CALNAME' || key === 'NAME') { /* ignore for now */ }
        continue;
      }

      if (key === 'SUMMARY') current.summary = val;
      else if (key === 'DTSTART') current.dtstart = val;
      else if (key === 'DTEND') current.dtend = val;
      else if (key === 'ORGANIZER') current.organizer = val.replace(/^mailto:/i, '');
      else if (key === 'LOCATION') current.location = val;
      else if (key === 'STATUS') current.status = val;
      else if (key === 'DESCRIPTION') current.description = val;
      else if (key === 'ATTENDEE') {
        const clean = val.replace(/^mailto:/i, '');
        if (clean && !current.attendees.includes(clean)) current.attendees.push(clean);
      }
    }

    return out;
  }

  // ── Render helpers (modeled on scf/url/library-ms) ───────────────────────
  _addRawView(wrap, text, byteLen) {
    const normalizedText = lfNormalize(text);
    const lines = normalizedText.split('\n');

    const sourcePane = document.createElement('div');
    sourcePane.className = 'ics-source plaintext-scroll';

    const table = document.createElement('table');
    table.className = 'plaintext-table';
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
    const count = Math.min(lines.length, maxLines);
    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && normalizedText.length <= 200000) {
      try {
        const result = hljs.highlight(normalizedText, { language: 'ini', ignoreIllegals: true });
        highlightedLines = result.value.split('\n');
      } catch (_) { /* plain */ }
    }
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td');
      tdNum.className = 'plaintext-ln';
      tdNum.textContent = i + 1;
      const tdCode = document.createElement('td');
      tdCode.className = 'plaintext-code';
      if (highlightedLines && highlightedLines[i] !== undefined) {
        tdCode.innerHTML = highlightedLines[i] || '';
      } else {
        tdCode.textContent = lines[i];
      }
      tr.appendChild(tdNum); tr.appendChild(tdCode);
      table.appendChild(tr);
    }
    sourcePane.appendChild(table);
    wrap.appendChild(sourcePane);

    wrap._rawText = lfNormalize(text);
    wrap._showSourcePane = () => {
      sourcePane.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
