// ════════════════════════════════════════════════════════════════════════════
//  TimelineRowView — a thin RowStore-shaped adapter that lets GridViewer
//  consume a Timeline `{ baseStore, extractedCols, baseLen, idx }` tuple
//  via the same `rowCount` / `getCell(r, c)` / `getRow(r)` triplet it uses
//  for any other store. Three responsibilities:
//
//    1. Concatenate the timeline's base columns (live in `baseStore`,
//       a `RowStore`) with its extracted virtual columns
//       (`extractedCols[k].values[origIdx]`) so the grid sees one flat
//       column array of width `baseLen + extractedCols.length`.
//    2. Permute through `idx` (a Uint32Array | number[]) so the grid's
//       row 0 lands on the timeline's chronologically-first visible
//       row, row 1 on the second, etc. `idx === null` means "identity"
//       (no chip filter, no chrono sort applied — used by the Detections
//       sub-grid which renders the raw event order).
//    3. Allocate exactly the strings the grid will read — never a full
//       1M × N `string[][]` materialisation. `getRow` produces a fresh
//       `string[]` only when GridViewer needs the entire row at once
//       (drawer body / column-kind sniffer); per-cell hot loops go
//       through `getCell` and never allocate beyond the underlying
//       RowStore's per-cell substring.
//
//  This class is intentionally minimal — no caching, no stats, no
//  filtering. The Timeline already owns `_chipFilteredIdx` and the
//  chrono-sorted index; we just wrap the result. Callers that want a
//  different filter / sort just pass a different `idx`.
// ════════════════════════════════════════════════════════════════════════════
class TimelineRowView {
  /**
   * @param {object} opts
   * @param {RowStore}                  opts.baseStore   — base columns.
   * @param {Array<{values:string[]}>=} opts.extractedCols — per-column
   *                                                       virtual values
   *                                                       indexed by ORIG row.
   * @param {number}                    opts.baseLen     — base column count.
   * @param {Uint32Array|number[]|null=} opts.idx        — permutation /
   *                                                       filter (orig rows).
   *                                                       `null` ⇒ identity.
   */
  constructor(opts) {
    this._base = opts.baseStore;
    this._extracted = opts.extractedCols || [];
    this._baseLen = opts.baseLen | 0;
    this._idx = opts.idx || null;
    this._extLen = this._extracted.length;
    this._totalCols = this._baseLen + this._extLen;
  }

  get rowCount() {
    return this._idx
      ? this._idx.length
      : (this._base ? this._base.rowCount : 0);
  }

  // Resolve a grid-visible (`visIdx`) → original-row index. Inlined into
  // hot loops via `_idx` field access in `getCell`, but exposed here so
  // GridViewer back-compat hooks (e.g. the sidebar click-to-focus path)
  // can resolve a clicked grid row back to its source row when the
  // timeline filter / sort is active.
  _origIdx(visIdx) {
    return this._idx ? this._idx[visIdx] : visIdx;
  }

  getCell(visIdx, colIdx) {
    const orig = this._idx ? this._idx[visIdx] : visIdx;
    if (colIdx < this._baseLen) {
      return this._base ? this._base.getCell(orig, colIdx) : '';
    }
    const e = this._extracted[colIdx - this._baseLen];
    if (!e) return '';
    const v = e.values[orig];
    return v == null ? '' : String(v);
  }

  // Allocates a fresh `string[]` of length `_totalCols`. Callers should
  // prefer `getCell` when they only need a few cells (column-stat
  // sampler, single-cell rendering); `getRow` is only economical for
  // drawer / detail builders that read every column.
  getRow(visIdx) {
    const orig = this._idx ? this._idx[visIdx] : visIdx;
    // Base portion — the underlying RowStore's `getRow` already yields
    // a fresh `''`-padded array of `_baseLen`. Extend in-place when
    // extracted columns exist instead of copying twice.
    const out = this._base
      ? this._base.getRow(orig)
      : new Array(this._baseLen).fill('');
    if (this._extLen) {
      out.length = this._totalCols;
      for (let e = 0; e < this._extLen; e++) {
        const v = this._extracted[e].values[orig];
        out[this._baseLen + e] = v == null ? '' : String(v);
      }
    }
    return out;
  }
}
