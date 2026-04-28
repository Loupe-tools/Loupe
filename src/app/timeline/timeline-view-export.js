'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-export.js — TimelineView prototype mixin (B2f4).
//
// Hosts the pivot table builder + every CSV / PNG export path.
// These two surfaces are bundled into one mixin because every
// export the timeline emits goes through `FileDownload.downloadText`
// (or `downloadBlob`) and shares the forensic-filename naming
// helpers (`_forensicFilename`, `_forensicCompactUtc`, …).
//
// Methods (~13 instance, ~380 lines):
//
//   Pivot:
//     _autoPivotFromColumn — heuristic that picks Rows / Cols /
//       Aggregate from a user-clicked column + the current stack
//       column, expands the pivot section, writes the choices into
//       the select widgets, and calls `_buildPivot()`.
//     _buildPivot — assembles the pivot table from `_filteredIdx`
//       and renders into the pivot card (count / sum / mean / min
//       / max aggregates, drill-down via cell-click → AST chip).
//
//   Section actions (the per-section "⋯" / export menu dispatcher):
//     _onSectionAction
//
//   Forensic-filename helpers (shared by every export):
//     _forensicFilename, _forensicSourceStem,
//     _forensicCompactUtc, _forensicCompactNum,
//     _forensicRangeSegment
//
//   CSV / PNG exporters:
//     _exportChartPng — toBlob → FileDownload.downloadBlob
//     _exportChartCsv — buckets → CSV → FileDownload.downloadText
//     _exportGridCsv  — visible rows → CSV → downloadText
//     _exportColumnsCsv — column-stats → CSV → downloadText
//     _exportPivotCsv — current pivot → CSV → downloadText
//
// Bodies are moved byte-identically. The forensic-filename
// convention (`<source-stem>__<section>__<UTC>.<ext>`) is a
// load-bearing analyst contract — it lets investigators
// chronologically sort outputs from multiple loupe runs against
// the same source. Pinned by parity test below.
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`).
// ════════════════════════════════════════════════════════════════════════════

Object.assign(TimelineView.prototype, {

  // ── Pivot ────────────────────────────────────────────────────────────────
  // Auto-pivot heuristic — pick sensible Rows / Cols / Aggregate selections
  // from a user-clicked column and (optionally) the current stack column,
  // expand the pivot section (it starts collapsed), write the choices into
  // the select widgets, and call `_buildPivot()`. Scrolls the result into
  // view with a brief flash so the user can see where it went.
  //
  // Heuristic (simple on purpose — pivot is ultimately interactive):
  //   - Rows     = clicked column (always).
  //   - Cols     = opts.colsCol if provided; else the current stack column
  //                if it differs from Rows and has 2..60 distinct values;
  //                else the first OTHER column with 2..60 distinct values,
  //                skipping the timestamp column and Rows.
  //   - Agg      = 'count' (the only aggregate that always makes sense for
  //                categorical x categorical).
  _autoPivotFromColumn(rowsCol, opts) {
    opts = opts || {};
    if (!Number.isInteger(rowsCol) || rowsCol < 0 || rowsCol >= this.columns.length) return;

    // Ensure column stats are fresh so the heuristic can read distinct counts.
    if (!this._colStats) {
      this._colStats = this._computeColumnStats(this._filteredIdx || new Uint32Array(0));
    }
    const stats = this._colStats;

    const MIN = 2, MAX = 60;
    const good = (ci) => {
      if (ci === rowsCol) return false;
      if (ci === this._timeCol) return false;
      const s = stats[ci]; if (!s) return false;
      return s.distinct >= MIN && s.distinct <= MAX;
    };

    let colsCol = Number.isInteger(opts.colsCol) ? opts.colsCol : null;
    if (colsCol == null && this._stackCol != null && good(this._stackCol)) {
      colsCol = this._stackCol;
    }
    if (colsCol == null) {
      // Pick the column with the most "interesting" cardinality — prefer
      // mid-range distinct counts (10..30 is ideal for a readable pivot).
      let bestCol = -1, bestScore = -Infinity;
      for (let c = 0; c < this.columns.length; c++) {
        if (!good(c)) continue;
        const d = stats[c].distinct;
        // Score = closeness to 15 (peak), capped. Prefer 5..30.
        const score = -Math.abs(d - 15);
        if (score > bestScore) { bestScore = score; bestCol = c; }
      }
      if (bestCol >= 0) colsCol = bestCol;
    }

    if (colsCol == null) {
      if (this._app) this._app._toast('No suitable pivot column found (need a column with 2–60 distinct values).', 'error');
      return;
    }

    // Wire up the pivot UI.
    const els = this._els;
    els.pvRows.value = String(rowsCol);
    els.pvCols.value = String(colsCol);
    els.pvAgg.value = 'count';
    els.pvAggCol.value = '-1';
    els.pvAggColWrap.style.display = 'none';

    // Uncollapse the pivot section (it defaults to collapsed).
    const pivotSec = this._root.querySelector('.tl-section-pivot');
    if (pivotSec && pivotSec.classList.contains('collapsed')) {
      pivotSec.classList.remove('collapsed');
      this._sections.pivot = false;
      TimelineView._saveSections(this._sections);
    }

    this._buildPivot();

    // Scroll into view + brief flash highlight.
    if (pivotSec && pivotSec.scrollIntoView) {
      pivotSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
      pivotSec.classList.add('tl-section-flash');
      setTimeout(() => pivotSec.classList.remove('tl-section-flash'), 1200);
    }
  },

  _buildPivot() {
    const rowsCol = parseInt(this._els.pvRows.value, 10);
    const colsCol = parseInt(this._els.pvCols.value, 10);
    const aggOp = this._els.pvAgg.value;
    const aggCol = parseInt(this._els.pvAggCol.value, 10);
    if (rowsCol < 0 || colsCol < 0) {
      this._els.pvResultBody.innerHTML = '<div class="tl-pivot-empty">Pick Rows and Columns to build a pivot.</div>';
      return;
    }
    this._pivotSpec = { rows: rowsCol, cols: colsCol, aggOp, aggCol };
    TimelineView._savePivotSpec(this._pivotSpec);

    const idx = this._filteredIdx;
    const rowKeys = new Map(); // rowVal → index
    const colKeys = new Map(); // colVal → index
    const rowList = [];
    const colList = [];
    const rowKeyOf = new Array(idx.length);
    const colKeyOf = new Array(idx.length);

    for (let i = 0; i < idx.length; i++) {
      const rv = this._cellAt(idx[i], rowsCol);
      const cv = this._cellAt(idx[i], colsCol);
      if (!rowKeys.has(rv)) { rowKeys.set(rv, rowList.length); rowList.push(rv); }
      if (!colKeys.has(cv)) { colKeys.set(cv, colList.length); colList.push(cv); }
      rowKeyOf[i] = rowKeys.get(rv);
      colKeyOf[i] = colKeys.get(cv);
    }
    // Sort col keys by total, row keys by total, then cap to 50×50.
    const rowTotals = new Int32Array(rowList.length);
    const colTotals = new Int32Array(colList.length);
    for (let i = 0; i < idx.length; i++) {
      rowTotals[rowKeyOf[i]]++;
      colTotals[colKeyOf[i]]++;
    }
    const rowOrder = Array.from(rowList.keys()).sort((a, b) => rowTotals[b] - rowTotals[a]);
    const colOrder = Array.from(colList.keys()).sort((a, b) => colTotals[b] - colTotals[a]);
    const MAX = 50;
    const visibleRows = rowOrder.slice(0, MAX);
    const visibleCols = colOrder.slice(0, MAX);
    const rowMap = new Map(visibleRows.map((v, i) => [v, i]));
    const colMap = new Map(visibleCols.map((v, i) => [v, i]));

    // Build the aggregate matrix.
    const nR = visibleRows.length, nC = visibleCols.length;
    // For 'count' and 'sum' → Float64Array.
    // For 'distinct' → Array of Set<string> per cell.
    let mat;
    if (aggOp === 'distinct') {
      mat = new Array(nR * nC);
      for (let k = 0; k < mat.length; k++) mat[k] = null;
    } else {
      mat = new Float64Array(nR * nC);
    }

    // `rowMap` / `colMap` are keyed by INDEX into rowList/colList (not by the
    // raw cell value) — `rowKeyOf[i]` / `colKeyOf[i]` are already those
    // indices, so pass them straight through. Passing the resolved value
    // here silently missed on every row (empty pivot table, integer
    // headers) — see CONTRIBUTING for the history of this fix.
    for (let i = 0; i < idx.length; i++) {
      const rk = rowMap.get(rowKeyOf[i]);
      const ck = colMap.get(colKeyOf[i]);
      if (rk == null || ck == null) continue;  // in 'Other' bucket — skip for v1
      const cellIdx = rk * nC + ck;
      if (aggOp === 'count') mat[cellIdx]++;
      else if (aggOp === 'distinct' && aggCol >= 0) {
        let s = mat[cellIdx]; if (!s) { s = new Set(); mat[cellIdx] = s; }
        s.add(this._cellAt(idx[i], aggCol));
      } else if (aggOp === 'sum' && aggCol >= 0) {
        const n = parseFloat(this._cellAt(idx[i], aggCol));
        if (Number.isFinite(n)) mat[cellIdx] += n;
      }
    }

    // Render table.
    const cellVal = (rk, ck) => {
      const x = mat[rk * nC + ck];
      if (aggOp === 'distinct') return x ? x.size : 0;
      return x || 0;
    };
    let maxV = 0;
    for (let r = 0; r < nR; r++) for (let c = 0; c < nC; c++) {
      const v = cellVal(r, c); if (v > maxV) maxV = v;
    }
    const heat = (v) => {
      if (!maxV || v <= 0) return '';
      const pct = Math.min(1, v / maxV);
      return `background: rgb(var(--accent-rgb) / ${(0.05 + pct * 0.45).toFixed(3)});`;
    };

    // Resolve the visible-*-index arrays to their actual cell values for
    // display / drill-down / export. `visibleRows` / `visibleCols` are
    // arrays of indices into `rowList` / `colList`, NOT values.
    const visibleRowVals = visibleRows.map(i => rowList[i]);
    const visibleColVals = visibleCols.map(i => colList[i]);

    const tbl = document.createElement('table');
    tbl.className = 'tl-pivot-table';
    let html = '<thead><tr><th class="tl-pivot-corner"></th>';
    for (const cv of visibleColVals) html += `<th title="${_tlEsc(cv)}">${_tlEsc(cv === '' ? '(empty)' : this._ellipsis(cv, 30))}</th>`;
    if (colOrder.length > MAX) html += `<th class="tl-pivot-other" title="${colOrder.length - MAX} more columns not shown">…+${colOrder.length - MAX}</th>`;
    html += '</tr></thead><tbody>';
    for (let r = 0; r < nR; r++) {
      const rv = visibleRowVals[r];
      html += `<tr><th title="${_tlEsc(rv)}">${_tlEsc(rv === '' ? '(empty)' : this._ellipsis(rv, 30))}</th>`;
      for (let c = 0; c < nC; c++) {
        const v = cellVal(r, c);
        html += `<td data-r="${r}" data-c="${c}" style="${heat(v)}">${v ? v.toLocaleString() : ''}</td>`;
      }
      if (colOrder.length > MAX) html += '<td class="tl-pivot-other"></td>';
      html += '</tr>';
    }
    if (rowOrder.length > MAX) html += `<tr><th class="tl-pivot-other">…+${rowOrder.length - MAX} more rows</th><td colspan="${nC + (colOrder.length > MAX ? 1 : 0)}"></td></tr>`;
    html += '</tbody>';
    tbl.innerHTML = html;

    // Double-click a cell = filter-drill-down. Each add-clause commit
    // triggers a full re-parse + render cycle, but that's fine for a
    // user-initiated drill-down — we get the same render either way.
    tbl.addEventListener('dblclick', (e) => {
      const td = e.target.closest('td[data-r]');
      if (!td) return;
      const r = +td.dataset.r, c = +td.dataset.c;
      const rv = visibleRowVals[r]; const cv = visibleColVals[c];
      this._queryAddClause({ k: 'pred', colIdx: rowsCol, op: 'eq', val: String(rv) }, { dedupe: true });
      this._queryAddClause({ k: 'pred', colIdx: colsCol, op: 'eq', val: String(cv) }, { dedupe: true });
    });

    const summary = document.createElement('div');
    summary.className = 'tl-pivot-summary';
    summary.textContent = `${rowOrder.length.toLocaleString()} × ${colOrder.length.toLocaleString()} → showing ${nR} × ${nC}. Double-click a cell to drill down.`;

    this._els.pvResultBody.innerHTML = '';
    this._els.pvResultBody.appendChild(summary);
    const scroll = document.createElement('div');
    scroll.className = 'tl-pivot-scroll';
    scroll.appendChild(tbl);
    this._els.pvResultBody.appendChild(scroll);

    // Stash for CSV export. Expose the RESOLVED values (not the opaque
    // into-rowList indices) so `_exportPivotCsv` produces a human-readable
    // sheet.
    this._lastPivot = { rowsCol, colsCol, aggOp, aggCol, visibleRowVals, visibleColVals, nR, nC, cellVal };
  },

  // ── Exports / section actions ────────────────────────────────────────────
  _onSectionAction(act) {
    switch (act) {
      case 'chart-png': this._exportChartPng(this._els.chartCanvas, this._forensicFilename('chart', 'png')); break;
      case 'chart-csv': this._exportChartCsv(this._lastChartData, this._forensicFilename('buckets', 'csv')); break;
      case 'grid-csv': this._exportGridCsv(this._filteredIdx, this._forensicFilename('rows', 'csv')); break;
      case 'columns-csv': this._exportColumnsCsv(this._colStats, this._forensicFilename('top-values', 'csv')); break;
      case 'pivot-csv': this._exportPivotCsv(this._forensicFilename('pivot', 'csv')); break;
    }
  },

  // Build a forensic-flavoured filename for a timeline export. Shape:
  //
  //   {sourceStem}__{section}__{fromCompact}_to_{toCompact}.{ext}
  //
  // Where `fromCompact` / `toCompact` are compact UTC timestamps
  // (`YYYYMMDDTHHMMZ` — no seconds, no punctuation, trailing Z) covering
  // the data actually in the export: the current `_window` if the analyst
  // has narrowed the scrubber, else the full `_dataRange`. For numeric-axis
  // columns (ids / periods / years) the compact range falls back to
  // `num_{lo}_to_num_{hi}` with locale-free integer strings, so a file of
  // year-numbered rows doesn't emit misleading 1970 dates.
  //
  // If no timestamp column is chosen, or zero rows parsed, the range
  // segment is omitted — `{sourceStem}__{section}.{ext}`.
  //
  // The source stem is sanitised: non-filename-safe characters become `_`,
  // length capped at 80 chars so the full name stays well under the ~255-
  // byte OS limit.
  _forensicFilename(section, ext) {
    const stem = this._forensicSourceStem();
    const range = this._forensicRangeSegment();
    const parts = [stem, section];
    if (range) parts.push(range);
    return parts.join('__') + '.' + ext;
  },

  _forensicSourceStem() {
    const raw = (this.file && this.file.name) ? String(this.file.name) : '';
    let stem = raw;
    const dot = stem.lastIndexOf('.');
    if (dot > 0) stem = stem.slice(0, dot);
    // Replace filename-unsafe characters (Windows + POSIX reserved) + controls.
    stem = stem.replace(/[\\/:*?"<>|\x00-\x1f]+/g, '_').trim();
    if (!stem) stem = 'timeline';
    if (stem.length > 80) stem = stem.slice(0, 80);
    return stem;
  },

  // Compact UTC formatter — `YYYYMMDDTHHMMZ`. Minute-level precision
  // deliberately (seconds are rarely meaningful on a range spanning
  // hours / days and make filenames noisier to skim).
  _forensicCompactUtc(ms) {
    if (!Number.isFinite(ms)) return '';
    const d = new Date(ms);
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}`
      + `T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}Z`;
  },

  // Compact numeric formatter — strips punctuation so filenames stay
  // shell-safe across platforms. Large magnitudes pass through as plain
  // integers (no thousand-separators), fractional values round to 4 dp.
  _forensicCompactNum(v) {
    if (!Number.isFinite(v)) return '';
    if (Number.isInteger(v)) return String(v);
    return String(Math.round(v * 10000) / 10000);
  },

  _forensicRangeSegment() {
    const dr = this._dataRange; if (!dr) return '';
    const lo = this._window ? this._window.min : dr.min;
    const hi = this._window ? this._window.max : dr.max;
    if (!Number.isFinite(lo) || !Number.isFinite(hi)) return '';
    if (this._timeIsNumeric) {
      const a = this._forensicCompactNum(lo);
      const b = this._forensicCompactNum(hi);
      if (!a || !b) return '';
      return `num_${a}_to_num_${b}`;
    }
    const a = this._forensicCompactUtc(lo);
    const b = this._forensicCompactUtc(hi);
    if (!a || !b) return '';
    return `${a}_to_${b}`;
  },


  _exportChartPng(canvas, filename) {
    if (!canvas) return;
    canvas.toBlob((blob) => {
      if (!blob) return;
      if (window.FileDownload && typeof window.FileDownload.downloadBlob === 'function') {
        window.FileDownload.downloadBlob(blob, filename, 'image/png');
      }
    }, 'image/png');
  },

  _exportChartCsv(data, filename) {
    if (!data) return;
    const { buckets, bucketCount, stackKeys, viewLo, bucketMs } = data;
    const k = stackKeys ? stackKeys.length : 1;
    const header = ['Bucket start (UTC)', 'Bucket end (UTC)'];
    if (stackKeys && stackKeys.length) for (const s of stackKeys) header.push(s);
    else header.push('Count');
    const lines = [_tlCsvRow(header)];
    for (let b = 0; b < bucketCount; b++) {
      const lo = viewLo + b * bucketMs;
      const hi = lo + bucketMs;
      const row = [_tlFormatFullUtc(lo, this._timeIsNumeric), _tlFormatFullUtc(hi, this._timeIsNumeric)];
      for (let j = 0; j < k; j++) row.push(String(buckets[b * k + j]));
      lines.push(_tlCsvRow(row));
    }
    if (window.FileDownload) window.FileDownload.downloadText(lines.join('\r\n'), filename, 'text/csv');
  },

  _exportGridCsv(idx, filename) {
    if (!idx || !idx.length) return;
    const cols = this.columns;
    const lines = [_tlCsvRow(cols)];
    for (let i = 0; i < idx.length; i++) {
      const di = idx[i];
      const row = new Array(cols.length);
      for (let c = 0; c < cols.length; c++) row[c] = this._cellAt(di, c);
      lines.push(_tlCsvRow(row));
    }
    if (window.FileDownload) window.FileDownload.downloadText(lines.join('\r\n'), filename, 'text/csv');
  },

  _exportColumnsCsv(stats, filename) {
    if (!stats) return;
    const lines = [_tlCsvRow(['Column', 'Value', 'Count'])];
    for (let c = 0; c < this.columns.length; c++) {
      const s = stats[c]; if (!s) continue;
      for (const [val, cnt] of s.values) {
        lines.push(_tlCsvRow([this.columns[c] || '', val, String(cnt)]));
      }
    }
    if (window.FileDownload) window.FileDownload.downloadText(lines.join('\r\n'), filename, 'text/csv');
  },

  _exportPivotCsv(filename) {
    const p = this._lastPivot; if (!p) return;
    const header = [''];
    for (const cv of p.visibleColVals) header.push(cv);
    const lines = [_tlCsvRow(header)];
    for (let r = 0; r < p.nR; r++) {
      const row = [p.visibleRowVals[r]];
      for (let c = 0; c < p.nC; c++) row.push(String(p.cellVal(r, c)));
      lines.push(_tlCsvRow(row));
    }
    if (window.FileDownload) window.FileDownload.downloadText(lines.join('\r\n'), filename, 'text/csv');
  },

});
