'use strict';
// ════════════════════════════════════════════════════════════════════════════
// csv-renderer.js — Renders .csv and .tsv files as styled tables
// No external dependencies beyond the browser DOM.
// ════════════════════════════════════════════════════════════════════════════
class CsvRenderer {
  render(text, fileName) {
    const wrap = document.createElement('div'); wrap.className = 'csv-view';
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const delim = ext === 'tsv' ? '\t' : this._delim(text);
    const rows = this._parse(text, delim);
    if (!rows.length) { wrap.textContent = 'Empty file.'; return wrap; }

    // ── Info bar ─────────────────────────────────────────────────────────
    const info = document.createElement('div'); info.className = 'csv-info';
    const dn = delim === '\t' ? 'Tab' : delim === ',' ? 'Comma' : delim === ';' ? 'Semicolon' : 'Pipe';
    info.textContent = `${rows.length} rows × ${rows[0].length} columns · delimiter: ${dn}`;
    wrap.appendChild(info);

    // ── Filter bar ───────────────────────────────────────────────────────
    const filterBar = document.createElement('div');
    filterBar.className = 'csv-filter-bar';

    const filterInput = document.createElement('input');
    filterInput.type = 'text';
    filterInput.placeholder = 'Filter rows…';
    filterInput.className = 'csv-filter-input';

    const clearBtn = document.createElement('button');
    clearBtn.className = 'tb-btn csv-clear-btn';
    clearBtn.textContent = '✕ Clear';
    clearBtn.title = 'Clear filter and show all rows';
    clearBtn.style.display = 'none';

    const filterStatus = document.createElement('span');
    filterStatus.className = 'csv-filter-status';

    filterBar.appendChild(filterInput);
    filterBar.appendChild(clearBtn);
    filterBar.appendChild(filterStatus);
    wrap.appendChild(filterBar);

    // ── Table ────────────────────────────────────────────────────────────
    const scr = document.createElement('div');
    scr.className = 'csv-scroll';
    scr.style.cssText = 'overflow:auto;max-height:calc(100vh - 200px)';

    const tbl = document.createElement('table'); tbl.className = 'xlsx-table csv-table';

    // Track data rows for filtering
    const dataRows = [];

    rows.forEach((row, ri) => {
      if (ri > 10000) return;
      const tr = document.createElement('tr');
      const rh = document.createElement(ri === 0 ? 'th' : 'td');
      rh.className = 'xlsx-row-header';
      rh.textContent = ri === 0 ? '#' : ri;
      tr.appendChild(rh);

      const rowText = [];
      row.forEach(cell => {
        const td = document.createElement(ri === 0 ? 'th' : 'td');
        td.className = ri === 0 ? 'xlsx-col-header csv-header' : 'xlsx-cell';
        td.textContent = cell;
        if (ri > 0 && cell.trim() && !isNaN(parseFloat(cell))) td.style.textAlign = 'right';
        tr.appendChild(td);
        rowText.push(cell.toLowerCase());
      });
      tbl.appendChild(tr);

      // Store reference for filtering (skip header row)
      if (ri > 0) {
        dataRows.push({
          tr: tr,
          searchText: rowText.join(' ')
        });
      }
    });

    scr.appendChild(tbl);
    wrap.appendChild(scr);

    // ── Filter logic ─────────────────────────────────────────────────────
    const applyFilter = () => {
      const query = filterInput.value.toLowerCase().trim();
      let visibleCount = 0;

      if (!query) {
        // Show all rows
        for (const r of dataRows) {
          r.tr.style.display = '';
          r.tr.classList.remove('csv-row-highlight');
        }
        clearBtn.style.display = 'none';
        filterStatus.textContent = '';
        return;
      }

      // Filter rows
      for (const r of dataRows) {
        const matches = r.searchText.includes(query);
        r.tr.style.display = matches ? '' : 'none';
        if (matches) visibleCount++;
      }

      clearBtn.style.display = '';
      filterStatus.textContent = `${visibleCount} of ${dataRows.length} rows`;
    };

    const clearFilter = () => {
      filterInput.value = '';
      applyFilter();
    };

    // Scroll to first match and highlight it
    const scrollToFirstMatch = () => {
      for (const r of dataRows) {
        if (r.tr.style.display !== 'none') {
          r.tr.scrollIntoView({ behavior: 'smooth', block: 'center' });
          r.tr.classList.add('csv-row-highlight');
          setTimeout(() => r.tr.classList.remove('csv-row-highlight'), 2000);
          break;
        }
      }
    };

    filterInput.addEventListener('input', applyFilter);
    filterInput.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        filterInput.blur();
      }
    });
    clearBtn.addEventListener('click', clearFilter);

    // Expose filter controls for external access (IOC navigation)
    wrap._csvFilters = {
      filterInput,
      applyFilter,
      clearFilter,
      scrollToFirstMatch,
      scrollContainer: scr,
      dataRows
    };

    // Store raw CSV text for proper IOC extraction (avoids cell concatenation issues)
    wrap._rawText = text;

    return wrap;
  }

  /** Auto-detect delimiter by counting occurrences in the first line. */
  _delim(text) { const line = (text.split('\n')[0] || ''); const c = { ',': 0, ';': 0, '\t': 0, '|': 0 }; let inQ = false; for (const ch of line) { if (ch === '"') { inQ = !inQ; } else if (!inQ && c[ch] !== undefined) c[ch]++; } return Object.entries(c).sort((a, b) => b[1] - a[1])[0][0]; }

  _parse(text, delim) { const rows = []; for (const line of text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')) { if (!line.trim()) continue; rows.push(this._split(line, delim)); } return rows; }

  _split(line, delim) { const cells = []; let cur = '', inQ = false; for (let i = 0; i < line.length; i++) { const ch = line[i]; if (ch === '"') { if (inQ && line[i + 1] === '"') { cur += '"'; i++; } else inQ = !inQ; } else if (ch === delim && !inQ) { cells.push(cur); cur = ''; } else cur += ch; } cells.push(cur); return cells; }

  analyzeForSecurity(text) {
    const f = { risk: 'low', hasMacros: false, macroSize: 0, macroHash: '', autoExec: [], modules: [], externalRefs: [], metadata: {} };
    if (text.split('\n').slice(0, 1000).some(l => l.trim() && /^["']?[=+\-@]/.test(l.trim()))) {
      f.risk = 'medium';
      f.externalRefs.push({ type: IOC.PATTERN, url: 'Formula injection risk — cells beginning with =, +, -, or @ detected', severity: 'medium' });
    }
    return f;
  }
}
