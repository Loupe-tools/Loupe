'use strict';
// ════════════════════════════════════════════════════════════════════════════
// iqy-slk-renderer.js — IQY (Internet Query) and SLK (Symbolic Link) analysis
// Both are text-based formats weaponised to execute macros or fetch payloads.
// Depends on: constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class IqySlkRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const wrap = document.createElement('div'); wrap.className = 'iqy-view';

    if (ext === 'iqy') {
      return this._renderIqy(wrap, text, bytes);
    } else {
      return this._renderSlk(wrap, text, bytes);
    }
  }

  analyzeForSecurity(buffer, fileName) {
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const f = {
      risk: 'high', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);

    if (ext === 'iqy') {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'Internet Query (.iqy) file — tells Excel to fetch data from a remote URL',
        severity: 'high'
      });

      // Extract the URL from IQY
      const lines = text.split(/\r?\n/).filter(l => l.trim());
      for (const line of lines) {
        if (/^https?:\/\//i.test(line.trim())) {
          f.externalRefs.push({ type: IOC.URL, url: line.trim(), severity: 'high' });
        }
      }
    } else {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'Symbolic Link (.slk) file — text-based spreadsheet that can execute macros',
        severity: 'high'
      });

      // Check for macro execution in SLK
      if (/\bEXEC\b/i.test(text) || /\bCALL\b/i.test(text)) {
        f.externalRefs.push({ type: IOC.PATTERN, url: 'SLK contains EXEC/CALL — macro execution', severity: 'high' });
      }
      if (/\bRUN\b/i.test(text)) {
        f.externalRefs.push({ type: IOC.PATTERN, url: 'SLK contains RUN — macro auto-execution', severity: 'high' });
      }

      // Extract URLs
      for (const m of text.matchAll(/https?:\/\/[^\s"';]+/g)) {
        f.externalRefs.push({ type: IOC.URL, url: m[0], severity: 'high' });
      }
    }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  // ── IQY renderer ──────────────────────────────────────────────────────────

  _renderIqy(wrap, text, bytes) {
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    const bannerStrong = document.createElement('strong'); bannerStrong.textContent = '⚠ Internet Query File (.iqy)';
    banner.appendChild(bannerStrong);
    banner.appendChild(document.createTextNode(' — This file instructs Excel to fetch data from a remote URL. IQY files are commonly weaponised in phishing to download and execute malicious payloads.'));
    wrap.appendChild(banner);

    const lines = text.split(/\r?\n/);
    const parsed = this._parseIqy(lines);

    // URL card
    const card = document.createElement('div'); card.className = 'url-card';

    if (parsed.url) {
      const urlDiv = document.createElement('div'); urlDiv.className = 'url-target';
      const lbl = document.createElement('span'); lbl.className = 'url-label'; lbl.textContent = 'Fetch URL: ';
      const val = document.createElement('span'); val.className = 'url-value'; val.textContent = parsed.url;
      urlDiv.appendChild(lbl); urlDiv.appendChild(val);
      card.appendChild(urlDiv);

      const warn = document.createElement('div'); warn.className = 'url-risk url-risk-high';
      warn.textContent = '⚠ Opening this file in Excel will attempt to fetch data from this URL';
      card.appendChild(warn);
    }

    if (parsed.queryType) {
      const row = document.createElement('div'); row.className = 'url-field';
      const lbl = document.createElement('span'); lbl.className = 'url-label'; lbl.textContent = 'Query Type:';
      const val = document.createElement('span'); val.className = 'url-value'; val.textContent = parsed.queryType;
      row.appendChild(lbl); row.appendChild(document.createTextNode(' ')); row.appendChild(val);
      card.appendChild(row);
    }

    if (parsed.postParams) {
      const row = document.createElement('div'); row.className = 'url-field';
      const lbl = document.createElement('span'); lbl.className = 'url-label'; lbl.textContent = 'POST Parameters:';
      const val = document.createElement('span'); val.className = 'url-value'; val.textContent = parsed.postParams;
      row.appendChild(lbl); row.appendChild(document.createTextNode(' ')); row.appendChild(val);
      card.appendChild(row);
    }

    wrap.appendChild(card);

    // Raw content
    this._addRawView(wrap, text, lines.length, bytes.length, 'IQY');
    return wrap;
  }

  _parseIqy(lines) {
    const result = {};
    // Standard IQY format:
    // Line 1: Query type (usually "WEB")
    // Line 2: Version (usually "1")
    // Line 3: URL
    // Line 4+: POST parameters (optional)
    const nonEmpty = lines.filter(l => l.trim());
    if (nonEmpty.length >= 1) result.queryType = nonEmpty[0].trim();
    for (const line of nonEmpty) {
      if (/^https?:\/\//i.test(line.trim())) {
        result.url = line.trim();
        break;
      }
    }
    // POST params
    const urlIdx = nonEmpty.findIndex(l => /^https?:\/\//i.test(l.trim()));
    if (urlIdx >= 0 && urlIdx + 1 < nonEmpty.length) {
      const params = nonEmpty.slice(urlIdx + 1).join('&');
      if (params.trim()) result.postParams = params.trim();
    }
    return result;
  }

  // ── SLK renderer ──────────────────────────────────────────────────────────

  _renderSlk(wrap, text, bytes) {
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    const bannerStrong = document.createElement('strong'); bannerStrong.textContent = '⚠ Symbolic Link File (.slk)';
    banner.appendChild(bannerStrong);
    banner.appendChild(document.createTextNode(' — SLK is a text-based spreadsheet format that can contain executable macros (EXEC, CALL, RUN). These bypass many security controls.'));
    wrap.appendChild(banner);

    // Analyze for dangerous content
    const dangers = [];
    if (/\bEXEC\b/i.test(text)) dangers.push('EXEC — executes a system command');
    if (/\bCALL\b/i.test(text)) dangers.push('CALL — calls a DLL function');
    if (/\bRUN\b/i.test(text)) dangers.push('RUN — runs a macro');
    if (/\bREGISTER\b/i.test(text)) dangers.push('REGISTER — registers a DLL function');

    if (dangers.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      for (const d of dangers) {
        const w = document.createElement('div'); w.className = 'zip-warning zip-warning-high';
        w.textContent = `⚠ ${d}`; warnDiv.appendChild(w);
      }
      wrap.appendChild(warnDiv);
    }

    // Extract cell data for preview
    const cells = this._parseSlkCells(text);
    if (cells.length) {
      const tbl = document.createElement('table'); tbl.className = 'xlsx-table';
      tbl.style.cssText += 'margin:8px;';
      for (const row of cells) {
        const tr = document.createElement('tr');
        for (const cell of row) {
          const td = document.createElement('td'); td.className = 'xlsx-cell';
          td.textContent = cell; tr.appendChild(td);
        }
        tbl.appendChild(tr);
      }
      wrap.appendChild(tbl);
    }

    // Raw content
    const lines = text.split('\n');
    this._addRawView(wrap, text, lines.length, bytes.length, 'SLK');
    return wrap;
  }

  _parseSlkCells(text) {
    const grid = {};
    let maxR = 0, maxC = 0, curR = 0, curC = 0;

    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      const parts = line.split(';');
      const type = parts[0];

      for (const p of parts.slice(1)) {
        if (p.startsWith('X')) curC = parseInt(p.slice(1)) || curC;
        if (p.startsWith('Y')) curR = parseInt(p.slice(1)) || curR;
        if (p.startsWith('K')) {
          const val = p.slice(1).replace(/^"/, '').replace(/"$/, '');
          if (!grid[curR]) grid[curR] = {};
          grid[curR][curC] = val;
          maxR = Math.max(maxR, curR);
          maxC = Math.max(maxC, curC);
        }
      }
    }

    // Convert to 2D array (cap at 50 rows, 20 cols for display)
    const rows = [];
    for (let r = 1; r <= Math.min(maxR, 50); r++) {
      const row = [];
      for (let c = 1; c <= Math.min(maxC, 20); c++) {
        row.push(grid[r]?.[c] || '');
      }
      rows.push(row);
    }
    return rows;
  }

  // ── Shared helpers ────────────────────────────────────────────────────────

  _addRawView(wrap, text, lineCount, byteLen, format) {
    const info = document.createElement('div'); info.className = 'plaintext-info';
    info.textContent = `${lineCount} line${lineCount !== 1 ? 's' : ''}  ·  ${this._fmtBytes(byteLen)}  ·  ${format} file`;
    wrap.appendChild(info);

    const scr = document.createElement('div'); scr.className = 'plaintext-scroll';
    const table = document.createElement('table'); table.className = 'plaintext-table';
    const lines = text.split('\n');
    const maxLines = 5000;
    const count = Math.min(lines.length, maxLines);
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td'); tdNum.className = 'plaintext-ln'; tdNum.textContent = i + 1;
      const tdCode = document.createElement('td'); tdCode.className = 'plaintext-code'; tdCode.textContent = lines[i];
      tr.appendChild(tdNum); tr.appendChild(tdCode); table.appendChild(tr);
    }
    scr.appendChild(table); wrap.appendChild(scr);
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
