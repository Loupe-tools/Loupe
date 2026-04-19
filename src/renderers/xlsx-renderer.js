'use strict';
// ════════════════════════════════════════════════════════════════════════════
// xlsx-renderer.js — Renders .xlsx / .xlsm / .xls / .ods via SheetJS
// Depends on: vba-utils.js, XLSX (vendor / SheetJS), JSZip (vendor)
// ════════════════════════════════════════════════════════════════════════════
class XlsxRenderer {
  render(buffer, fileName) {
    const wrap = document.createElement('div'); wrap.className = 'xlsx-view';
    let wb;
    try { wb = XLSX.read(new Uint8Array(buffer), { type: 'array', cellStyles: true, cellDates: true, sheetRows: 10001 }); }
    catch (e) { return this._err(wrap, 'Failed to parse spreadsheet', e.message); }
    if (!wb.SheetNames.length) { wrap.textContent = 'No sheets found.'; return wrap; }
    const tabBar = document.createElement('div'); tabBar.className = 'sheet-tab-bar'; wrap.appendChild(tabBar);
    const area = document.createElement('div'); area.className = 'sheet-content-area'; wrap.appendChild(area);
    const panes = wb.SheetNames.map((name, i) => {
      const tab = document.createElement('button'); tab.className = 'sheet-tab'; tab.textContent = name; tabBar.appendChild(tab);
      const pane = document.createElement('div'); pane.className = 'sheet-content'; pane.style.display = 'none'; area.appendChild(pane);
      const p = { tab, pane, done: false };
      tab.addEventListener('click', () => {
        panes.forEach(x => { x.tab.classList.remove('active'); x.pane.style.display = 'none'; });
        tab.classList.add('active'); pane.style.display = 'block';
        if (!p.done) { this._renderSheet(wb.Sheets[name], pane); p.done = true; }
      });
      return p;
    });
    panes[0].tab.click();
    return wrap;
  }

  _renderSheet(ws, container) {
    if (!ws || !ws['!ref']) {
      const p = document.createElement('p'); p.style.cssText = 'color:#888;padding:20px';
      p.textContent = 'Empty sheet'; container.appendChild(p); return;
    }
    const rng = XLSX.utils.decode_range(ws['!ref']), maxR = Math.min(rng.e.r, rng.s.r + 9999);
    const merges = ws['!merges'] || [], cols = ws['!cols'] || [];
    const mStart = new Map(), mSkip = new Set();
    for (const m of merges) {
      mStart.set(`${m.s.r},${m.s.c}`, { cs: m.e.c - m.s.c + 1, rs: m.e.r - m.s.r + 1 });
      for (let r = m.s.r; r <= m.e.r; r++) for (let c = m.s.c; c <= m.e.c; c++) if (r !== m.s.r || c !== m.s.c) mSkip.add(`${r},${c}`);
    }
    const scr = document.createElement('div'); scr.style.cssText = 'overflow:auto;max-height:calc(100vh - 160px)';
    const tbl = document.createElement('table'); tbl.className = 'xlsx-table';
    const thead = document.createElement('thead'), hRow = document.createElement('tr');
    const corner = document.createElement('th'); corner.className = 'xlsx-corner'; hRow.appendChild(corner);
    for (let c = rng.s.c; c <= rng.e.c; c++) {
      const th = document.createElement('th'); th.className = 'xlsx-col-header'; th.textContent = XLSX.utils.encode_col(c);
      const w = cols[c]; if (w && w.wch) th.style.minWidth = Math.max(40, Math.round(w.wch * 7)) + 'px';
      hRow.appendChild(th);
    }
    thead.appendChild(hRow); tbl.appendChild(thead);
    const tbody = document.createElement('tbody');
    for (let r = rng.s.r; r <= maxR; r++) {
      const tr = document.createElement('tr');
      const rh = document.createElement('th'); rh.className = 'xlsx-row-header'; rh.textContent = r + 1; tr.appendChild(rh);
      for (let c = rng.s.c; c <= rng.e.c; c++) {
        const key = `${r},${c}`; if (mSkip.has(key)) continue;
        const td = document.createElement('td'); td.className = 'xlsx-cell';
        const m = mStart.get(key); if (m) { if (m.cs > 1) td.colSpan = m.cs; if (m.rs > 1) td.rowSpan = m.rs; }
        const cell = ws[XLSX.utils.encode_cell({ r, c })];
        if (cell) {
          td.textContent = cell.w !== undefined ? cell.w : (cell.t === 'b' ? (cell.v ? 'TRUE' : 'FALSE') : (cell.t === 'e' ? '#ERR' : String(cell.v ?? '')));
          if (cell.t === 'n') td.style.textAlign = 'right';
        }
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    if (maxR < rng.e.r) {
      const tr = document.createElement('tr'); const td = document.createElement('td');
      td.colSpan = rng.e.c - rng.s.c + 2; td.style.cssText = 'text-align:center;color:#888;padding:8px;font-style:italic';
      td.textContent = `… ${rng.e.r - maxR} more rows`; tr.appendChild(td); tbody.appendChild(tr);
    }
    tbl.appendChild(tbody); scr.appendChild(tbl); container.appendChild(scr);
  }

  async analyzeForSecurity(buffer, fileName) {
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const f = { risk: 'low', hasMacros: false, macroSize: 0, autoExec: [], modules: [], externalRefs: [], metadata: {} };
    try {
      const wb = XLSX.read(new Uint8Array(buffer), { type: 'array', bookVBA: true });
      if (wb.Props) {
        f.metadata = {
          title: wb.Props.Title || '',
          subject: wb.Props.Subject || '',
          creator: wb.Props.Author || '',
          lastModifiedBy: wb.Props.LastAuthor || '',
          created: wb.Props.CreatedDate ? new Date(wb.Props.CreatedDate).toLocaleString() : '',
          modified: wb.Props.ModifiedDate ? new Date(wb.Props.ModifiedDate).toLocaleString() : '',
        };
      }
      if (wb.vbaraw || ['xlsm', 'xltm', 'xlam'].includes(ext)) {
        f.hasMacros = true; f.risk = 'medium';
        if (wb.vbaraw) f.macroSize = wb.vbaraw.byteLength || wb.vbaraw.length || 0;
        try {
          const zip = await JSZip.loadAsync(buffer);
          const vbaEntry = zip.file('xl/vbaProject.bin') || zip.file('xl/vbaProject.bin'.replace('xl/', ''));
          if (vbaEntry) {
            const vbaData = await vbaEntry.async('uint8array');
            if (!f.macroSize) f.macroSize = vbaData.length;
            f.rawBin = vbaData;
            f.modules = parseVBAText(vbaData);
            for (const m of f.modules) {
              if (!m.source) continue;
              const pats = autoExecPatterns(m.source);
              if (pats.length) { f.autoExec.push({ module: m.name, patterns: pats }); f.risk = 'high'; }
            }
          }
          if (!f.rawBin && wb.vbaraw)
            f.rawBin = wb.vbaraw instanceof Uint8Array ? wb.vbaraw : new Uint8Array(wb.vbaraw);
        } catch (e) {
          if (!f.rawBin && wb.vbaraw) {
            try { f.rawBin = wb.vbaraw instanceof Uint8Array ? wb.vbaraw : new Uint8Array(wb.vbaraw); } catch (_) { }
          }
        }
      }
      // Deep scan _rels/*.rels for every .xlsx-family package (runs even
      // without macros — catches attachedTemplate, DDE/oleObject links,
      // externalLink, and UNC paths used for NTLM credential theft).
      if (['xlsx', 'xlsm', 'xltx', 'xltm', 'xlam', 'xlsb'].includes(ext)) {
        try {
          const zip = await JSZip.loadAsync(buffer);
          const relRefs = await OoxmlRelScanner.scan(zip);
          for (const r of relRefs) {
            f.externalRefs.push(r);
            if (r.severity === 'high') f.risk = 'high';
            else if (r.severity === 'medium' && f.risk === 'low') f.risk = 'medium';
          }
        } catch (e) { /* ignore */ }
      }

      // ─── Sheet-level surface scanning ──────────────────────────────────
      // Three passes that run on every workbook (not just macro-bearing
      // files) because the risky constructs all live in the plain sheet
      // XML and don't require VBA to fire:
      //   1. Very-hidden sheets (Hidden===2) — state only settable from
      //      the VBA editor; a legitimate user who "hides" a sheet from
      //      the UI sets Hidden===1. Very-hidden is a malware-docs staple.
      //   2. Defined Names (workbook.Workbook.Names) — historic
      //      `Auto_Open` / `Auto_Close` / `Workbook_Open` names fire
      //      macros on document open; external-link formulas in a Name
      //      pull from `\\attacker\share\a.xlsx!A1`.
      //   3. Per-cell formulas — `HYPERLINK(url, …)` is the most common
      //      phishing vehicle in xlsx; `WEBSERVICE` / `IMPORTDATA` exfil
      //      cell data; `CALL` / `REGISTER` / `EXEC` load DLLs directly
      //      (Excel-4.0 macro territory but works in modern .xlsm).
      const HIGH_RISK_FNS = new Set(['WEBSERVICE', 'IMPORTDATA', 'CALL', 'REGISTER', 'REGISTER.ID', 'EXEC', 'FORMULA', 'FWRITELN', 'FWRITE']);
      const MEDIUM_RISK_FNS = new Set(['HYPERLINK', 'RTD', 'DDEINIT', 'DDE']);
      const formulaHits = [];
      const urlHits = [];
      try {
        for (const name of (wb.SheetNames || [])) {
          const ws = wb.Sheets[name];
          if (!ws) continue;
          // (1) Hidden-state pivot: SheetJS hoists the `Hidden` attribute
          //     onto each sheet object via bookSheets metadata; when it
          //     isn't present fall back to `wb.Workbook.Sheets[i].Hidden`.
          let hidden = ws.Hidden;
          if (hidden === undefined && wb.Workbook && Array.isArray(wb.Workbook.Sheets)) {
            const idx = wb.SheetNames.indexOf(name);
            if (idx >= 0 && wb.Workbook.Sheets[idx]) hidden = wb.Workbook.Sheets[idx].Hidden;
          }
          if (hidden === 2) {
            pushIOC(f, {
              type: IOC.PATTERN,
              value: `Very hidden sheet: "${name}"`,
              severity: 'medium',
              note: 'visibility state settable only from VBA editor',
              bucket: 'externalRefs',
            });
            if (f.risk === 'low') f.risk = 'medium';
          }
          // (3) Per-cell formula scan. Bound by `!ref` so empty sheets and
          //     pathological A1:XFD1048576 ranges don't churn the loop.
          if (!ws['!ref']) continue;
          const rng = XLSX.utils.decode_range(ws['!ref']);
          // Hard cap: 200k cells per sheet — survives 1000×200 grids but
          // bails out on sheet-wide fill-down formulas that would
          // otherwise dominate analysis time on worst-case inputs.
          const CELL_BUDGET = 200_000;
          let scanned = 0;
          outer:
          for (let r = rng.s.r; r <= rng.e.r; r++) {
            for (let c = rng.s.c; c <= rng.e.c; c++) {
              if (++scanned > CELL_BUDGET) break outer;
              const cell = ws[XLSX.utils.encode_cell({ r, c })];
              if (!cell || !cell.f) continue;
              const fml = String(cell.f);
              // Classify every top-level function name in the formula.
              // The regex is deliberately permissive (bare identifiers,
              // `_xlfn.`-prefixed, and `_xlws.`-prefixed) so SheetJS's
              // canonicalisation doesn't hide any of the risky names.
              const fnMatches = fml.match(/(?:_xl(?:fn|ws)\.)?[A-Z][A-Z0-9_.]*(?=\s*\()/gi) || [];
              for (const raw of fnMatches) {
                const fn = raw.replace(/^_xl(?:fn|ws)\./i, '').toUpperCase();
                if (HIGH_RISK_FNS.has(fn)) {
                  formulaHits.push({ sheet: name, addr: XLSX.utils.encode_cell({ r, c }), fn, formula: fml, sev: 'high' });
                } else if (MEDIUM_RISK_FNS.has(fn)) {
                  formulaHits.push({ sheet: name, addr: XLSX.utils.encode_cell({ r, c }), fn, formula: fml, sev: 'medium' });
                }
              }
              // Every formula-embedded URL is surfaced, even when the
              // wrapping function isn't on the risk list — a hand-typed
              // `="Click "&"http://…"` can exfil without HYPERLINK().
              const urls = extractUrls(fml, 8);
              for (const u of urls) urlHits.push({ sheet: name, addr: XLSX.utils.encode_cell({ r, c }), url: u });
            }
          }
        }
      } catch (_) { /* never let formula scan poison the rest of analysis */ }

      // (2) Defined Names — two failure modes surface here:
      //      • name matches Auto_Open / Auto_Close / Workbook_Open
      //        (legacy XLM auto-exec hooks).
      //      • value contains an external-link reference (`[path]` /
      //        `\\server\share\`) or a raw URL.
      try {
        const names = (wb.Workbook && wb.Workbook.Names) || [];
        for (const n of names) {
          if (!n || !n.Name) continue;
          const nm = String(n.Name);
          const ref = String(n.Ref || '');
          if (/^Auto_Open$|^Auto_Close$|^Workbook_Open$|^Auto_Activate$|^Auto_Deactivate$/i.test(nm)) {
            pushIOC(f, {
              type: IOC.PATTERN,
              value: `Defined Name "${nm}" → ${ref || '(empty)'}`,
              severity: 'high',
              note: 'XLM/Excel-4.0 auto-exec name',
              bucket: 'externalRefs',
            });
            f.risk = 'high';
          }
          if (ref && /^\s*[\[\\]/.test(ref)) {
            pushIOC(f, {
              type: IOC.PATTERN,
              value: `Defined Name "${nm}" references external: ${ref}`,
              severity: 'medium',
              note: 'external-workbook or UNC-path link in defined name',
              bucket: 'externalRefs',
            });
            if (f.risk === 'low') f.risk = 'medium';
          }
          for (const u of extractUrls(ref, 4)) {
            pushIOC(f, { type: IOC.URL, value: u, severity: 'medium', note: `defined name "${nm}"`, bucket: 'externalRefs' });
          }
        }
      } catch (_) { /* ignore */ }

      // Roll formula hits back onto findings. Cap each bucket at 50 so a
      // worksheet with 10k =HYPERLINK() rows doesn't drown the sidebar;
      // the count is surfaced as an INFO note when truncated.
      const FORMULA_CAP = 50;
      const shownFormulas = formulaHits.slice(0, FORMULA_CAP);
      for (const h of shownFormulas) {
        pushIOC(f, {
          type: IOC.PATTERN,
          value: `${h.fn}() in ${h.sheet}!${h.addr}`,
          severity: h.sev,
          highlightText: h.formula.length > 200 ? h.formula.slice(0, 200) + '…' : h.formula,
          note: h.sev === 'high' ? 'high-risk spreadsheet function' : 'network/hyperlink formula',
          bucket: 'externalRefs',
        });
        if (h.sev === 'high') f.risk = 'high';
        else if (h.sev === 'medium' && f.risk === 'low') f.risk = 'medium';
      }
      if (formulaHits.length > FORMULA_CAP) {
        pushIOC(f, {
          type: IOC.INFO,
          value: `+${formulaHits.length - FORMULA_CAP} more risky formulas truncated`,
          severity: 'info',
          bucket: 'externalRefs',
        });
      }
      const URL_CAP = 100;
      const seenUrl = new Set();
      let urlCount = 0;
      for (const u of urlHits) {
        if (seenUrl.has(u.url)) continue;
        seenUrl.add(u.url);
        if (++urlCount > URL_CAP) break;
        pushIOC(f, {
          type: IOC.URL,
          value: u.url,
          severity: 'medium',
          note: `formula in ${u.sheet}!${u.addr}`,
          bucket: 'externalRefs',
        });
        if (f.risk === 'low') f.risk = 'medium';
      }
    } catch (e) { }
    return f;
  }



  _err(wrap, title, msg) {
    const b = document.createElement('div'); b.className = 'error-box';
    const h = document.createElement('h3'); h.textContent = title; b.appendChild(h);
    const p = document.createElement('p'); p.textContent = msg; b.appendChild(p);
    wrap.appendChild(b); return wrap;
  }
}
