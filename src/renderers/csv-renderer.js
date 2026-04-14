'use strict';
// ════════════════════════════════════════════════════════════════════════════
// csv-renderer.js — Renders .csv and .tsv files as styled tables
// Features: auto-detect column widths, click-to-expand detail panes (EVTX-style)
// No external dependencies beyond the browser DOM.
// ════════════════════════════════════════════════════════════════════════════
class CsvRenderer {
  render(text, fileName) {
    const wrap = document.createElement('div'); wrap.className = 'csv-view';
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const delim = ext === 'tsv' ? '\t' : this._delim(text);
    const { rows, rowOffsets } = this._parse(text, delim);
    if (!rows.length) { wrap.textContent = 'Empty file.'; return wrap; }

    // Header row (first row)
    const headerRow = rows[0] || [];
    const dataRowsRaw = rows.slice(1);
    // Data row offsets (skip header row offset)
    const dataRowOffsets = rowOffsets.slice(1);

    // Calculate reasonable column widths based on content
    const colWidths = this._calcColumnWidths(rows);

    // ── Info bar ─────────────────────────────────────────────────────────
    const info = document.createElement('div'); info.className = 'csv-info';
    const dn = delim === '\t' ? 'Tab' : delim === ',' ? 'Comma' : delim === ';' ? 'Semicolon' : 'Pipe';
    info.textContent = `${rows.length} rows × ${headerRow.length} columns · delimiter: ${dn}`;
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

    // Expand All / Collapse All toggle button
    const expandToggle = document.createElement('button');
    expandToggle.className = 'tb-btn csv-export-btn csv-expand-toggle';
    expandToggle.textContent = '↕️ Expand All';
    expandToggle.title = 'Expand all visible rows';

    filterBar.appendChild(filterInput);
    filterBar.appendChild(clearBtn);
    filterBar.appendChild(filterStatus);
    filterBar.appendChild(expandToggle);
    wrap.appendChild(filterBar);

    // ── Table ────────────────────────────────────────────────────────────
    const scr = document.createElement('div');
    scr.className = 'csv-scroll';
    scr.style.cssText = 'overflow:auto;max-height:calc(100vh - 200px)';

    const tbl = document.createElement('table'); tbl.className = 'xlsx-table csv-table';

    // ── Header row ───────────────────────────────────────────────────────
    const thead = document.createElement('thead');
    const headerTr = document.createElement('tr');

    // Row number header
    const thNum = document.createElement('th');
    thNum.className = 'xlsx-row-header';
    thNum.textContent = '#';
    headerTr.appendChild(thNum);

    // Column headers with calculated widths
    headerRow.forEach((cell, ci) => {
      const th = document.createElement('th');
      th.className = 'xlsx-col-header csv-header';
      th.textContent = cell;
      th.title = cell;
      if (colWidths[ci]) {
        th.style.maxWidth = colWidths[ci] + 'px';
        th.style.overflow = 'hidden';
        th.style.textOverflow = 'ellipsis';
        th.style.whiteSpace = 'nowrap';
      }
      headerTr.appendChild(th);
    });
    thead.appendChild(headerTr);
    tbl.appendChild(thead);

    // ── Data rows ────────────────────────────────────────────────────────
    const tbody = document.createElement('tbody');
    const dataRows = []; // Track { tr, detailTr, detailTd, rowData, visible }
    let allExpanded = false;
    const limit = Math.min(dataRowsRaw.length, 10000);

    for (let ri = 0; ri < limit; ri++) {
      const row = dataRowsRaw[ri];
      const tr = document.createElement('tr');
      tr.dataset.idx = ri;

      // Row number with expand icon
      const tdNum = document.createElement('td');
      tdNum.className = 'xlsx-row-header';
      tdNum.innerHTML = `<span class="csv-expand-icon">▶</span> ${ri + 1}`;
      tr.appendChild(tdNum);

      // Build search text for filtering
      const rowText = [];

      // Data cells with truncation
      row.forEach((cell, ci) => {
        const td = document.createElement('td');
        td.className = 'xlsx-cell csv-cell-truncate';

        // Apply calculated column width
        if (colWidths[ci]) {
          td.style.setProperty('--csv-col-width', colWidths[ci] + 'px');
        }

        // Truncate display text for very long cells (show first 80 chars)
        const displayText = cell.length > 80 ? cell.substring(0, 80) + '…' : cell;
        td.textContent = displayText;
        td.title = cell.length > 80 ? 'Click row to see full content' : cell;

        // Right-align numeric values
        if (cell.trim() && !isNaN(parseFloat(cell))) {
          td.style.textAlign = 'right';
        }

        tr.appendChild(td);
        rowText.push(cell.toLowerCase());
      });

      tbody.appendChild(tr);

      // ── Detail row (hidden by default) ─────────────────────────────────
      const detailTr = document.createElement('tr');
      detailTr.className = 'csv-detail-row';
      detailTr.style.display = 'none';
      const detailTd = document.createElement('td');
      detailTd.colSpan = headerRow.length + 1; // +1 for row number column
      detailTr.appendChild(detailTd);
      tbody.appendChild(detailTr);

      // Store row reference for filtering, expansion, and YARA match highlighting
      const rowObj = {
        tr,
        detailTr,
        detailTd,
        rowData: row,
        searchText: rowText.join(' '),
        visible: true,
        // Store offset range for YARA match lookup (offset into raw text)
        offsetStart: dataRowOffsets[ri] ? dataRowOffsets[ri].start : 0,
        offsetEnd: dataRowOffsets[ri] ? dataRowOffsets[ri].end : 0
      };
      dataRows.push(rowObj);

      // ── Click handler to expand/collapse ───────────────────────────────
      tr.addEventListener('click', () => {
        const isOpen = detailTr.style.display !== 'none';
        if (isOpen) {
          detailTr.style.display = 'none';
          tr.classList.remove('csv-row-selected');
        } else {
          // Build detail pane lazily on first open
          if (!detailTd.hasChildNodes()) {
            this._buildDetailPane(detailTd, headerRow, row);
          }
          detailTr.style.display = '';
          tr.classList.add('csv-row-selected');
        }
      });
    }

    tbl.appendChild(tbody);
    scr.appendChild(tbl);
    wrap.appendChild(scr);

    if (dataRowsRaw.length > limit) {
      const note = document.createElement('div');
      note.className = 'csv-info';
      note.textContent = `⚠ Showing first ${limit.toLocaleString()} of ${dataRowsRaw.length.toLocaleString()} rows`;
      wrap.appendChild(note);
    }

    // ── Filter logic ─────────────────────────────────────────────────────
    const applyFilter = () => {
      const query = filterInput.value.toLowerCase().trim();
      let visibleCount = 0;

      if (!query) {
        // Show all rows, respect current expand/collapse state
        for (const r of dataRows) {
          r.tr.style.display = '';
          r.visible = true;
          // Respect allExpanded state
          if (allExpanded) {
            if (!r.detailTd.hasChildNodes()) {
              this._buildDetailPane(r.detailTd, headerRow, r.rowData);
            }
            r.detailTr.style.display = '';
            r.tr.classList.add('csv-row-selected');
          } else {
            r.detailTr.style.display = 'none';
            r.tr.classList.remove('csv-row-selected');
          }
          visibleCount++;
        }
        clearBtn.style.display = 'none';
        filterStatus.textContent = '';
        return;
      }

      // Filter rows
      for (const r of dataRows) {
        const matches = r.searchText.includes(query);
        r.tr.style.display = matches ? '' : 'none';
        r.visible = matches;
        if (matches) {
          visibleCount++;
          // Respect allExpanded state for visible rows
          if (allExpanded) {
            if (!r.detailTd.hasChildNodes()) {
              this._buildDetailPane(r.detailTd, headerRow, r.rowData);
            }
            r.detailTr.style.display = '';
            r.tr.classList.add('csv-row-selected');
          } else {
            r.detailTr.style.display = 'none';
            r.tr.classList.remove('csv-row-selected');
          }
        } else {
          r.detailTr.style.display = 'none';
          r.tr.classList.remove('csv-row-selected');
        }
      }

      clearBtn.style.display = '';
      filterStatus.textContent = `${visibleCount} of ${dataRows.length} rows`;
    };

    const clearFilter = () => {
      filterInput.value = '';
      applyFilter();
    };

    // ── Expand / Collapse All ────────────────────────────────────────────
    const expandAllVisible = () => {
      allExpanded = true;
      for (const r of dataRows) {
        if (!r.visible) continue;
        if (!r.detailTd.hasChildNodes()) {
          this._buildDetailPane(r.detailTd, headerRow, r.rowData);
        }
        r.detailTr.style.display = '';
        r.tr.classList.add('csv-row-selected');
      }
      expandToggle.textContent = '↔️ Collapse All';
      expandToggle.title = 'Collapse all expanded rows';
    };

    const collapseAllVisible = () => {
      allExpanded = false;
      for (const r of dataRows) {
        r.detailTr.style.display = 'none';
        r.tr.classList.remove('csv-row-selected');
      }
      expandToggle.textContent = '↕️ Expand All';
      expandToggle.title = 'Expand all visible rows';
    };

    expandToggle.addEventListener('click', () => {
      if (allExpanded) {
        collapseAllVisible();
      } else {
        expandAllVisible();
      }
    });

    // ── Scroll to first match and highlight it ───────────────────────────
    const scrollToFirstMatch = () => {
      for (const r of dataRows) {
        if (r.visible && r.tr.style.display !== 'none') {
          r.tr.scrollIntoView({ behavior: 'smooth', block: 'center' });
          r.tr.classList.add('csv-row-highlight');
          setTimeout(() => r.tr.classList.remove('csv-row-highlight'), 2000);
          break;
        }
      }
    };

    // ── Expand a specific row (for IOC navigation) ───────────────────────
    const expandRow = (rowObj) => {
      if (!rowObj.detailTd.hasChildNodes()) {
        this._buildDetailPane(rowObj.detailTd, headerRow, rowObj.rowData);
      }
      rowObj.detailTr.style.display = '';
      rowObj.tr.classList.add('csv-row-selected');
    };

    filterInput.addEventListener('input', applyFilter);
    filterInput.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        filterInput.blur();
      }
    });
    clearBtn.addEventListener('click', clearFilter);

    // Expose filter controls for external access (IOC navigation, YARA highlighting)
    wrap._csvFilters = {
      filterInput,
      applyFilter,
      clearFilter,
      scrollToFirstMatch,
      scrollContainer: scr,
      dataRows,
      expandRow,
      expandAll: expandAllVisible,
      collapseAll: collapseAllVisible,
      headerRow,
      buildDetailPane: (td, row) => this._buildDetailPane(td, headerRow, row)
    };

    // Store raw CSV text for proper IOC extraction (avoids cell concatenation issues)
    wrap._rawText = text;

    return wrap;
  }

  // ── Calculate reasonable column widths ─────────────────────────────────
  _calcColumnWidths(rows, maxSampleRows = 100) {
    if (!rows.length) return [];
    const colCount = rows[0].length;
    const widths = [];

    for (let col = 0; col < colCount; col++) {
      const samples = [];

      // Sample header + up to maxSampleRows data rows
      for (let row = 0; row < Math.min(rows.length, maxSampleRows + 1); row++) {
        const cell = rows[row]?.[col] || '';
        samples.push(cell.length);
      }

      // Sort and use 85th percentile length (avoids outlier-driven widths)
      samples.sort((a, b) => a - b);
      const p85Idx = Math.floor(samples.length * 0.85);
      const typicalLen = samples[p85Idx] || samples[samples.length - 1] || 10;

      // Convert to pixels: ~7.5px per char in monospace
      // Min 60px (very short columns), max 300px (prevents super-wide columns)
      const width = Math.min(300, Math.max(60, Math.ceil(typicalLen * 7.5)));
      widths.push(width);
    }

    return widths;
  }

  // ── Build detail pane for expanded row ─────────────────────────────────
  _buildDetailPane(container, headerRow, rowData) {
    const pane = document.createElement('div');
    pane.className = 'csv-detail-pane';

    const heading = document.createElement('h4');
    heading.textContent = 'Row Details';
    pane.appendChild(heading);

    const grid = document.createElement('div');
    grid.className = 'csv-detail-grid';

    // Display each column as key-value pair
    for (let i = 0; i < headerRow.length; i++) {
      const key = headerRow[i] || `Column ${i + 1}`;
      const val = rowData[i] || '';

      const keyEl = document.createElement('div');
      keyEl.className = 'csv-detail-key';
      keyEl.textContent = key;
      keyEl.title = key;
      grid.appendChild(keyEl);

      const valEl = document.createElement('div');
      valEl.className = 'csv-detail-val';
      valEl.textContent = val;
      grid.appendChild(valEl);
    }

    pane.appendChild(grid);
    container.appendChild(pane);
  }

  /** Auto-detect delimiter by counting occurrences in the first line. */
  _delim(text) {
    const line = (text.split('\n')[0] || '');
    const c = { ',': 0, ';': 0, '\t': 0, '|': 0 };
    let inQ = false;
    for (const ch of line) {
      if (ch === '"') {
        inQ = !inQ;
      } else if (!inQ && c[ch] !== undefined) {
        c[ch]++;
      }
    }
    return Object.entries(c).sort((a, b) => b[1] - a[1])[0][0];
  }

  /**
   * Parse CSV text into rows. Also tracks row offset ranges for YARA match highlighting.
   * Offsets are relative to the original text (before line ending normalization).
   * @param {string} text - Raw CSV text
   * @param {string} delim - Delimiter character
   * @returns {{ rows: string[][], rowOffsets: {start: number, end: number}[] }}
   */
  _parse(text, delim) {
    const rows = [];
    const rowOffsets = [];
    // Track offsets in original text by scanning for line endings manually
    let offset = 0;
    let lineStart = 0;
    
    while (offset <= text.length) {
      // Find the next line ending (CR, LF, or CRLF)
      let lineEnd = offset;
      while (lineEnd < text.length && text[lineEnd] !== '\r' && text[lineEnd] !== '\n') {
        lineEnd++;
      }
      
      // Extract the line content
      const line = text.substring(lineStart, lineEnd);
      
      if (line.trim()) {
        rows.push(this._split(line, delim));
        rowOffsets.push({ start: lineStart, end: lineEnd });
      }
      
      // Skip past the line ending
      if (lineEnd < text.length) {
        if (text[lineEnd] === '\r' && text[lineEnd + 1] === '\n') {
          // CRLF
          offset = lineEnd + 2;
        } else {
          // CR or LF
          offset = lineEnd + 1;
        }
        lineStart = offset;
      } else {
        break;
      }
    }
    
    return { rows, rowOffsets };
  }

  _split(line, delim) {
    const cells = [];
    let cur = '';
    let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQ && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQ = !inQ;
        }
      } else if (ch === delim && !inQ) {
        cells.push(cur);
        cur = '';
      } else {
        cur += ch;
      }
    }
    cells.push(cur);
    return cells;
  }

  analyzeForSecurity(text) {
    const f = { risk: 'low', hasMacros: false, macroSize: 0, macroHash: '', autoExec: [], modules: [], externalRefs: [], metadata: {} };
    if (text.split('\n').slice(0, 1000).some(l => l.trim() && /^["']?[=+\-@]/.test(l.trim()))) {
      f.risk = 'medium';
      f.externalRefs.push({ type: IOC.PATTERN, url: 'Formula injection risk — cells beginning with =, +, -, or @ detected', severity: 'medium' });
    }
    return f;
  }
}
