'use strict';
// ════════════════════════════════════════════════════════════════════════════
// virtual-text-view.js — virtual-scroll line-numbered text viewer.
//
// Used by `PlainTextRenderer` for files where the legacy
// "every line is a live <tr>" approach blows up:
//
//   • 53 k-line minified-JS file → 53 k <tr>s × `pre-wrap` + `break-all`
//     means every sidebar-resize pixel forces the browser to re-layout
//     every row, dropping the page to ~0.1 FPS while the drag is live.
//   • Editor-style scroll-through-the-whole-file performance is gated by
//     the size of the live DOM, not the file.
//
// VirtualTextView mirrors `GridViewer`'s invariants so the same proof of
// correctness applies:
//
//   1. FIXED ROW HEIGHT.  Total scrollable height = `rowCount * ROW_HEIGHT`.
//   2. ABSOLUTE-POSITIONED ROWS inside a `position:relative` sizer.
//      Visible-range math is trivial division.
//   3. ROW DECORATIONS LIVE IN JS STATE.  Every paint reads state and
//      decorates fresh DOM — there is no "scroll-away loses the highlight"
//      bug because decorations aren't anchored to a node, they're anchored
//      to a (rowIdx, charPos) tuple.
//   4. SCROLL IS rAF-DRIVEN. `_render` runs at most once per frame.
//   5. destroy() IS MANDATORY AND COMPLETE.
//
// Backward compatibility — the root element exposes the same fields the
// sidebar click-to-focus engine reads off the legacy `<table.plaintext-table>`:
//
//     root._isVirtual       = true
//     root._lineToFirstRow  = Array<rowIdxOfFirstChunkPerLogicalLine>
//     root._chunkSize       = soft-wrap chunk size in chars (0 if not wrapped)
//     root._hasLongLine     = bool — soft-wrap path active
//     root._rawText         = LF-normalised source text
//     root._virtualView     = ref back to this instance (for app-sidebar-focus)
//     root._lineCount       = logical line count (mirror)
//     root._detectedLang    = hljs language label or null
//
// Highlighting API consumed by `app-sidebar-focus.js`:
//
//     view.setMatchHighlights({ matchesByRow, kind, focusRow,
//                               focusMatchIdx, scroll })   → Promise<rowEl>
//     view.clearMatchHighlights()
//     view.setEncodedHighlight({ startRow, endRow, slicesByRow, flash,
//                                scroll, flashClearMs })   → Promise<void>
//     view.clearEncodedHighlight()
//     view.scrollToRow(rowIdx, charPos?)                   → Promise<rowEl>
//
// Out of scope for this implementation:
//   • Cross-viewport text selection (browser selection only spans rows
//     that are currently in the live DOM). The toolbar's 📋 Copy raw /
//     💾 Save raw still operate on the full file.
//   • Dynamic re-chunking on viewport-width change. Soft-wrap chunk size
//     is fixed at construction so `_lineToFirstRow` stays stable across
//     the session — the highlight engine relies on those indices.
// ════════════════════════════════════════════════════════════════════════════
class VirtualTextView {

  // 13 px font * 1.5 line-height = 19.5 px logical row. Round to 21 for a
  // little vertical breathing room — matches the visual density of the
  // legacy `<tr>` table (which had its own row-padding via `.plaintext-ln`
  // padding plus the line-height).
  static ROW_HEIGHT = 21;
  static BUFFER_ROWS = 12;

  /**
   * @param {{
   *   lines:            string[],
   *   highlightedLines: (string[]|null),       // hljs-rendered HTML per line, or null
   *   chunkSize:        number,                // 0 if not soft-wrapping
   *   hasLongLine:      boolean,
   *   maxLineCount:     number,                // hard cap — usually RENDER_LIMITS.MAX_TEXT_LINES
   *   detectedLang:     (string|null),
   *   lineCount:        number,
   *   truncationMessage:(string|undefined),
   *   gutterDigits:     number,
   *   rawText:          string,
   * }} opts
   */
  constructor(opts) {
    this.lines            = opts.lines || [];
    this.highlightedLines = opts.highlightedLines || null;
    this.chunkSize        = opts.chunkSize || 0;
    this.hasLongLine      = !!opts.hasLongLine;
    this.maxLineCount     = opts.maxLineCount || this.lines.length;
    this.detectedLang     = opts.detectedLang || null;
    this.lineCount        = (typeof opts.lineCount === 'number') ? opts.lineCount : this.lines.length;
    this.truncationMessage = opts.truncationMessage || '';
    this.gutterDigits     = opts.gutterDigits || String(Math.max(1, this.lineCount)).length;
    this.rawText          = opts.rawText || '';
    // Wrap mode: when true, render every row into normal flow with
    // `white-space: pre-wrap` and skip virtualisation entirely. The
    // outer `PlainTextRenderer` gates this on file size + line count
    // (see `WRAP_MAX_TEXT_BYTES` / `WRAP_MAX_LINES`).
    this.wrap             = !!opts.wrap;

    // Flat virtual-row table — indexes into `this.lines` plus an optional
    // chunk index for the soft-wrap path. We never store row text here:
    // rows are reconstituted on demand from `this.lines` so memory stays
    // O(rowCount) for a small descriptor instead of O(rowCount * avgLineLen).
    this.rows = [];
    this.lineToFirstRow = new Array(Math.min(this.lines.length, this.maxLineCount));
    this._buildRowMap();

    // Decoration state — single source of truth, applied on every paint.
    this._matchHighlight = null;
    this._encHighlight   = null;

    this._destroyed     = false;
    this._renderRAF     = null;
    this._renderedRange = { start: -1, end: -1 };
    this._resizeObs     = null;
    this._boundScroll   = null;

    this._buildDOM();
    this._wireEvents();
    this._scheduleRender();
  }

  // ── Row-map construction ────────────────────────────────────────────────
  _buildRowMap() {
    const lines = this.lines;
    const cap   = Math.min(lines.length, this.maxLineCount);
    const ltfr  = this.lineToFirstRow;
    const rows  = this.rows;
    const cs    = this.chunkSize;
    let maxRowChars = 0;
    if (this.wrap) {
      // Wrap mode: one row per logical line, no soft-wrap chunking.
      // Resetting chunkSize / hasLongLine steers the highlight engine
      // (`app-sidebar-focus.js`) into the simple 1-row-per-line path
      // already used by the legacy `<table.plaintext-table>` renderers.
      this.chunkSize  = 0;
      this.hasLongLine = false;
      for (let i = 0; i < cap; i++) {
        ltfr[i] = rows.length;
        rows.push({ logicalLine: i, chunkIdx: 0, isContinuation: false });
        const len = lines[i].length;
        if (len > maxRowChars) maxRowChars = len;
      }
    } else if (this.hasLongLine && cs > 0) {
      for (let i = 0; i < cap; i++) {
        ltfr[i] = rows.length;
        const len = lines[i].length;
        if (len > cs) {
          const chunks = Math.ceil(len / cs);
          for (let c = 0; c < chunks; c++) {
            rows.push({ logicalLine: i, chunkIdx: c, isContinuation: c > 0 });
          }
          if (cs > maxRowChars) maxRowChars = cs;
        } else {
          rows.push({ logicalLine: i, chunkIdx: 0, isContinuation: false });
          if (len > maxRowChars) maxRowChars = len;
        }
      }
    } else {
      for (let i = 0; i < cap; i++) {
        ltfr[i] = rows.length;
        rows.push({ logicalLine: i, chunkIdx: 0, isContinuation: false });
        const len = lines[i].length;
        if (len > maxRowChars) maxRowChars = len;
      }
    }
    this.rowCount = rows.length;
    // Cap absurdly long rows so the horizontal scrollbar track stays
    // sane. With hasLongLine soft-wrap kicking in at 5000 chars this
    // ceiling shouldn't normally engage, but guard against pathological
    // inputs (eg. someone disabling the soft-wrap threshold downstream).
    this.maxRowChars = Math.min(maxRowChars, 50_000);
  }

  // ── DOM construction ────────────────────────────────────────────────────
  _buildDOM() {
    // Root is the scroll container. Tagged with both `.plaintext-scroll`
    // (so the existing flex layout / selection-decode hooks /
    // app-ui copy-as features keep working transparently) and
    // `.plaintext-virtual` (selector the new CSS keys off).
    const root = document.createElement('div');
    root.className = 'plaintext-scroll plaintext-virtual';
    if (this.wrap) root.classList.add('is-wrapping');
    root.tabIndex  = 0;
    root._isVirtual      = true;
    root._lineToFirstRow = this.lineToFirstRow;
    root._chunkSize      = this.chunkSize;
    root._hasLongLine    = this.hasLongLine;
    root._rawText        = lfNormalize(this.rawText);
    root._virtualView    = this;
    root._lineCount      = this.lineCount;
    root._detectedLang   = this.detectedLang;
    root.style.setProperty('--ptv-row-h',     VirtualTextView.ROW_HEIGHT + 'px');
    root.style.setProperty('--ptv-gutter-w',  `calc(${this.gutterDigits}ch + 23px)`);

    const sizer = document.createElement('div');
    sizer.className = 'plaintext-virtual-sizer';
    if (!this.wrap) {
      sizer.style.height = (this.rowCount * VirtualTextView.ROW_HEIGHT) + 'px';
      // Sizer width = widest row × 1ch + gutter + cell padding (14 left +
      // 14 right). `min-width: 100%` (in CSS) keeps row tints covering the
      // viewport when content is narrower; this inline width gives the
      // scroll container the horizontal extent it needs to actually
      // scroll long rows. `ch` is monospace-correct here (Fira Code /
      // Consolas / Monaco are all the same width per glyph).
      if (this.maxRowChars > 0) {
        sizer.style.width = `calc(${this.maxRowChars}ch + var(--ptv-gutter-w) + 28px)`;
      }
    }
    // In wrap mode the sizer flows in normal layout: height comes from
    // the rendered rows, width is `100%` via the new CSS rule keyed off
    // `.plaintext-virtual.is-wrapping`.
    root.appendChild(sizer);

    if (this.truncationMessage) {
      const note = document.createElement('div');
      note.className = 'plaintext-truncated';
      note.textContent = this.truncationMessage;
      root.appendChild(note);
    }

    this._root  = root;
    this._sizer = sizer;
  }

  /** Root DOM element to insert into the page. */
  get rootEl() { return this._root; }

  // ── Event wiring ────────────────────────────────────────────────────────
  _wireEvents() {
    // Wrap mode renders every row up front into normal flow: there is
    // no virtualised window to recompute on scroll/resize, so no
    // listeners are attached. `_render` does a single full paint via
    // the constructor's `_scheduleRender` and is then idle.
    if (this.wrap) return;
    this._boundScroll = () => {
      if (this._destroyed || this._renderRAF) return;
      this._renderRAF = requestAnimationFrame(() => {
        this._renderRAF = null;
        this._render();
      });
    };
    this._root.addEventListener('scroll', this._boundScroll, { passive: true });

    // ResizeObserver — viewport-height changes (sidebar resize, window
    // resize) change the visible row range; row width is invariant
    // because rows use `white-space: pre`, so we don't have to remeasure
    // anything else. This is the structural reason the 0.1 FPS sidebar
    // drag bug goes away.
    if (typeof ResizeObserver !== 'undefined') {
      this._resizeObs = new ResizeObserver(() => this._scheduleRender());
      this._resizeObs.observe(this._root);
    }
  }

  // ── Render loop ─────────────────────────────────────────────────────────
  _scheduleRender() {
    if (this._destroyed || this._renderRAF) return;
    this._renderRAF = requestAnimationFrame(() => {
      this._renderRAF = null;
      this._render();
    });
  }

  _forceFullRender() {
    this._renderedRange = { start: -1, end: -1 };
    this._scheduleRender();
  }

  _render() {
    if (this._destroyed) return;
    const rh    = VirtualTextView.ROW_HEIGHT;
    const total = this.rowCount;
    if (total === 0) {
      this._sizer.replaceChildren();
      this._renderedRange = { start: 0, end: 0 };
      return;
    }
    if (this.wrap) {
      // Wrap mode: build every row once and replace children. The
      // rendered range covers the full row table so `_forceFullRender`
      // calls (triggered by highlight changes) still rebuild everything.
      const fragAll = document.createDocumentFragment();
      for (let i = 0; i < total; i++) fragAll.appendChild(this._buildRow(i));
      this._sizer.replaceChildren(fragAll);
      this._renderedRange = { start: 0, end: total };
      return;
    }
    const scrollTop = this._root.scrollTop;
    const viewportH = this._root.clientHeight || 400;
    const firstIdx  = Math.max(0, Math.floor(scrollTop / rh) - VirtualTextView.BUFFER_ROWS);
    const lastIdx   = Math.min(total, Math.ceil((scrollTop + viewportH) / rh) + VirtualTextView.BUFFER_ROWS);
    if (firstIdx === this._renderedRange.start && lastIdx === this._renderedRange.end) return;

    const frag = document.createDocumentFragment();
    for (let i = firstIdx; i < lastIdx; i++) frag.appendChild(this._buildRow(i));
    this._sizer.replaceChildren(frag);
    this._renderedRange = { start: firstIdx, end: lastIdx };
  }

  _buildRow(rowIdx) {
    const meta = this.rows[rowIdx];
    const tr = document.createElement('div');
    tr.className = 'plaintext-row';
    tr.dataset.rowIdx  = rowIdx;
    tr.dataset.lineIdx = meta.logicalLine;
    if (!this.wrap) {
      tr.style.top = (rowIdx * VirtualTextView.ROW_HEIGHT) + 'px';
    }

    const tdNum = document.createElement('div');
    tdNum.className   = 'plaintext-ln';
    tdNum.textContent = meta.isContinuation ? '↳' : String(meta.logicalLine + 1);
    tr.appendChild(tdNum);

    const tdCode = document.createElement('div');
    tdCode.className = 'plaintext-code';

    const lineText = this.lines[meta.logicalLine] || '';
    let cellText, useHtml = false, html = '';
    if (this.hasLongLine && this.chunkSize > 0 && lineText.length > this.chunkSize) {
      // Soft-wrapped chunk — slice the original text. hljs HTML can't be
      // sliced safely (would orphan tag opens/closes), so the soft-wrap
      // path always falls through to plain text. This matches the legacy
      // renderer's behaviour at `src/renderers/plaintext-renderer.js:599-614`.
      cellText = lineText.substr(meta.chunkIdx * this.chunkSize, this.chunkSize);
    } else if (this.highlightedLines && this.highlightedLines[meta.logicalLine] !== undefined) {
      html     = this.highlightedLines[meta.logicalLine] || '';
      useHtml  = true;
      cellText = lineText;
    } else {
      cellText = lineText;
    }

    // Match marks from sidebar-focus + encoded-content highlights are
    // computed afresh on every paint. When a row carries any mark we
    // render plain text + <mark> spans; the syntax-highlighting span tree
    // for that row is sacrificed for correctness (the legacy
    // _highlightInHtmlNode TreeWalker path is too fragile against the
    // virtualizer's row recycling — and the syntax HTML for any row is
    // bounded in size anyway since hljs is gated to ≤ 100 KB total).
    const decorMarks = this._collectMarksForRow(rowIdx);
    if (decorMarks.length) {
      tdCode.innerHTML = this._buildMarkedHtml(cellText, decorMarks);
    } else if (useHtml) {
      tdCode.innerHTML = html;
    } else {
      tdCode.textContent = cellText;
    }
    tr.appendChild(tdCode);

    // Row-level classes (line-band tints).
    const mh = this._matchHighlight;
    if (mh && mh.matchesByRow.has(rowIdx)) {
      tr.classList.add(mh.lineClass);
    }
    const eh = this._encHighlight;
    if (eh && rowIdx >= eh.startRow && rowIdx <= eh.endRow) {
      tr.classList.add('enc-highlight-line');
      if (eh.flash) tr.classList.add('enc-highlight-flash');
    }
    return tr;
  }

  _collectMarksForRow(rowIdx) {
    const marks = [];
    const mh = this._matchHighlight;
    if (mh) {
      const arr = mh.matchesByRow.get(rowIdx);
      if (arr) {
        for (const lm of arr) {
          marks.push({
            charPos:    lm.charPos,
            length:     lm.length,
            markClass:  mh.markClass,
            flashClass: mh.flashClass,
            dataAttr:   mh.dataAttr,
            matchIdx:   lm.matchIdx,
          });
        }
      }
    }
    const eh = this._encHighlight;
    if (eh && eh.slicesByRow) {
      const arr = eh.slicesByRow.get(rowIdx);
      if (arr) {
        for (const sl of arr) {
          marks.push({
            charPos:    sl.charPos,
            length:     sl.length,
            markClass:  'enc-highlight',
            flashClass: eh.flash ? 'enc-highlight-pulse' : null,
            dataAttr:   null,
            matchIdx:   0,
          });
        }
      }
    }
    return marks;
  }

  _buildMarkedHtml(text, marks) {
    // Sort earliest-start-first, drop overlaps (keep first).
    marks.sort((a, b) => a.charPos - b.charPos);
    const keep = [];
    let cursor = -1;
    for (const m of marks) {
      if (m.charPos >= cursor) {
        keep.push(m);
        cursor = m.charPos + m.length;
      }
    }
    let out = '';
    let pos = 0;
    for (const m of keep) {
      const start = Math.min(m.charPos, text.length);
      const end   = Math.min(start + m.length, text.length);
      if (end <= start) continue;
      if (start > pos) out += _ptvEsc(text.substring(pos, start));
      const cls       = m.markClass + (m.flashClass ? ' ' + m.flashClass : '');
      const dataAttr  = m.dataAttr ? ` ${m.dataAttr}="${m.matchIdx}"` : '';
      out += `<mark class="${cls}"${dataAttr}>${_ptvEsc(text.substring(start, end))}</mark>`;
      pos = end;
    }
    if (pos < text.length) out += _ptvEsc(text.substring(pos));
    return out;
  }

  // ── Public highlight API ────────────────────────────────────────────────

  /**
   * @param {{
   *   matchesByRow:   Map<number, Array<{charPos:number, length:number, matchIdx:number}>>,
   *   kind:           'yara'|'ioc',
   *   focusRow:       number|null,
   *   focusMatchIdx:  number|null,
   *   scroll:         'force'|'ifNotInView'|'never',
   * }} spec
   * @returns {Promise<HTMLElement|null>} resolves with the focus row el (after scroll)
   */
  async setMatchHighlights(spec) {
    const isIoc = spec.kind === 'ioc';
    this._matchHighlight = {
      matchesByRow:  spec.matchesByRow,
      kind:          spec.kind,
      lineClass:     isIoc ? 'ioc-highlight-line'  : 'yara-line-highlight',
      markClass:     isIoc ? 'ioc-highlight'       : 'yara-highlight',
      flashClass:    isIoc ? 'ioc-highlight-flash' : 'yara-highlight-flash',
      dataAttr:      isIoc ? 'data-ioc-match'      : 'data-yara-match',
      focusRow:      spec.focusRow,
      focusMatchIdx: spec.focusMatchIdx,
    };
    this._forceFullRender();

    if (spec.scroll === 'never' || spec.focusRow == null) return null;
    if (spec.scroll === 'ifNotInView' && this._isMarkInView(this._matchHighlight.markClass)) {
      return null;
    }
    return this.scrollToRow(spec.focusRow, /* focusMatchIdx */ spec.focusMatchIdx);
  }

  clearMatchHighlights() {
    if (!this._matchHighlight) return;
    this._matchHighlight = null;
    this._forceFullRender();
  }

  _isMarkInView(markClass) {
    const marks = this._sizer.querySelectorAll('mark.' + markClass);
    if (!marks.length) return false;
    const vh = window.innerHeight || document.documentElement.clientHeight;
    for (const m of marks) {
      const r = m.getBoundingClientRect();
      if (r.bottom > 0 && r.top < vh && r.width > 0 && r.height > 0) return true;
    }
    return false;
  }

  /**
   * @param {{
   *   startRow:     number,
   *   endRow:       number,
   *   slicesByRow:  Map<number, Array<{charPos:number, length:number}>>|null,
   *   flash:        boolean,
   *   scroll:       boolean,
   *   flashClearMs: number|undefined,
   * }} spec
   */
  async setEncodedHighlight(spec) {
    this._encHighlight = {
      startRow:    spec.startRow,
      endRow:      spec.endRow,
      slicesByRow: spec.slicesByRow || null,
      flash:       !!spec.flash,
    };
    this._forceFullRender();
    if (spec.scroll && spec.startRow >= 0) {
      await this.scrollToRow(spec.startRow);
    }
    if (spec.flash && spec.flashClearMs) {
      setTimeout(() => {
        if (this._destroyed || !this._encHighlight) return;
        this._encHighlight.flash = false;
        this._forceFullRender();
      }, spec.flashClearMs);
    }
  }

  clearEncodedHighlight() {
    if (!this._encHighlight) return;
    this._encHighlight = null;
    this._forceFullRender();
  }

  /**
   * Scroll a virtual row into view. Returns the row's DOM element after
   * the rAF settle so callers can position a focus mark inside it.
   * @param {number} rowIdx
   * @param {number|undefined} focusMatchIdx — when a match focus mark is
   *   present in the row, the function will scroll it into horizontal +
   *   vertical view via Element.scrollIntoView after the row renders.
   */
  scrollToRow(rowIdx, focusMatchIdx) {
    return new Promise((resolve) => {
      if (this._destroyed || rowIdx < 0 || rowIdx >= this.rowCount) {
        resolve(null);
        return;
      }
      if (this.wrap) {
        // Wrap mode: every row is in the live DOM, so we can grab the
        // row element directly and let the browser's scrollIntoView do
        // the smooth scroll. No virtualised render race → single rAF
        // settle is enough (no scroll-then-render second-frame guard).
        const row = this.getRowEl(rowIdx);
        if (!row) { resolve(null); return; }
        try { row.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
        catch (_) {
          // Fallback for browsers without smooth scroll: manual offsetTop.
          try { this._root.scrollTop = row.offsetTop - (this._root.clientHeight / 2); }
          catch (__) { /* best-effort */ }
        }
        requestAnimationFrame(() => {
          if (this._destroyed) { resolve(null); return; }
          if (focusMatchIdx !== undefined && focusMatchIdx !== null) {
            const sel = `mark[data-yara-match="${focusMatchIdx}"], ` +
                        `mark[data-ioc-match="${focusMatchIdx}"]`;
            const mark = row.querySelector(sel);
            if (mark) {
              try { mark.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' }); }
              catch (_) { /* best-effort */ }
            }
          }
          resolve(row);
        });
        return;
      }
      const rh = VirtualTextView.ROW_HEIGHT;
      const viewportH = this._root.clientHeight || 400;
      const targetTop = rowIdx * rh;
      const center    = Math.max(0, targetTop - (viewportH - rh) / 2);
      const distance  = Math.abs(center - this._root.scrollTop);
      const beh       = distance > viewportH * 1.5 ? 'instant' : 'smooth';
      try {
        this._root.scrollTo({ top: center, left: 0, behavior: beh });
      } catch (_) {
        this._root.scrollTop = center;
      }
      const settle = () => {
        if (this._destroyed) { resolve(null); return; }
        // Force a render so the row is in the live DOM by the time we
        // resolve. The double-rAF mirrors GridViewer's settle pattern —
        // the first frame paints, the second guarantees layout is done.
        this._forceFullRender();
        requestAnimationFrame(() => requestAnimationFrame(() => {
          if (this._destroyed) { resolve(null); return; }
          const row = this.getRowEl(rowIdx);
          if (row && (focusMatchIdx !== undefined && focusMatchIdx !== null)) {
            const sel = `mark[data-yara-match="${focusMatchIdx}"], ` +
                        `mark[data-ioc-match="${focusMatchIdx}"]`;
            const mark = row.querySelector(sel);
            if (mark) {
              try { mark.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' }); }
              catch (_) { /* best-effort */ }
            }
          }
          resolve(row);
        }));
      };
      if (beh === 'instant') requestAnimationFrame(settle);
      else                   setTimeout(settle, 360);
    });
  }

  /** Get the live row element for `rowIdx`, or null if it isn't currently
   *  materialised in the visible window. */
  getRowEl(rowIdx) {
    return this._sizer.querySelector(`.plaintext-row[data-row-idx="${rowIdx}"]`);
  }

  // ── Cleanup ────────────────────────────────────────────────────────────
  destroy() {
    if (this._destroyed) return;
    this._destroyed = true;
    if (this._renderRAF) {
      try { cancelAnimationFrame(this._renderRAF); } catch (_) { /* ignore */ }
      this._renderRAF = null;
    }
    if (this._resizeObs) {
      try { this._resizeObs.disconnect(); } catch (_) { /* ignore */ }
      this._resizeObs = null;
    }
    if (this._boundScroll) {
      try { this._root.removeEventListener('scroll', this._boundScroll); } catch (_) { /* ignore */ }
      this._boundScroll = null;
    }
    try { this._sizer.replaceChildren(); } catch (_) { /* ignore */ }
    this._matchHighlight = null;
    this._encHighlight   = null;
  }
}

function _ptvEsc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
