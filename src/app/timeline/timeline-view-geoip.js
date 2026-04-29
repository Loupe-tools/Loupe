'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-geoip.js — TimelineView prototype mixin: GeoIP enrichment.
//
// Adds up to TWO columns next to every detected IPv4 column on first open:
//
//   `<ipcol>.geo` — IPv4 → country / iso / region / city, sourced from
//                   `this._app.geoip`. Always emitted when at least the
//                   bundled provider is available (which is always —
//                   bundled is set in App.init() synchronously).
//   `<ipcol>.asn` — IPv4 → AS number / organisation, sourced from
//                   `this._app.geoipAsn`. Only emitted when the analyst
//                   has uploaded an ASN MMDB; no bundled fallback (the
//                   bundled provider is RIR-country only).
//
// Both columns are inserted immediately after the source IP column in
// the grid's display order: `IP | IP.geo | IP.asn | …`.
//
// ── Provider surfaces ───────────────────────────────────────────────────────
//   `this._app.geoip` (geo provider — BundledGeoip OR MmdbReader):
//     `lookupIPv4(ip)` → { country, iso, region?, city? } | null
//     `formatRow(rec)` → 'United States/US/Louisiana/New Orleans'
//     `getFieldName()` → 'geo'
//
//   `this._app.geoipAsn` (ASN provider — MmdbReader only, optional):
//     `lookupAsn(ip)`     → { asn, org } | null
//     `formatAsnRow(rec)` → 'Google LLC (AS15169)'
//     `getAsnFieldName()` → 'asn'
//
// ── Detection — `_detectIpColumns` ──────────────────────────────────────────
// Walks every base column, sampling up to 200 rows. A column qualifies as
// "an IPv4 column" when ≥ 80 % of non-empty sampled cells parse as a strict
// dotted-quad. The threshold matches auto-extract (URL / host proposals).
//
// ── Skip heuristic — `_classifyColumnNeighbourhood(col, kind)` ──────────────
// If a column WITHIN ±3 positions of the IP column already looks like the
// SAME kind of enrichment, that kind is skipped for that IP. The two kinds
// have separate header / value vocabularies so geo and ASN skip
// independently:
//
//   geo  headers: country, city, region, state, geo, iso, location, …
//   geo  values : ISO-2 / ISO-3 shape, slash-delimited country/iso/…
//   asn  headers: asn, autonomous, isp, org, organization
//   asn  values : `^AS\d+` (case-insensitive), or `Some Org (AS12345)` shape
//
// Right-click → "Enrich IP" overrides the skip for both kinds.
//
// ── Idempotence ─────────────────────────────────────────────────────────────
// Same `loupe_timeline_autoextract_done_<fileKey>` per-file marker the
// auto-extract pass uses, scoped through TimelineView._loadAutoExtractDoneFor
// / _saveAutoExtractDoneFor. The marker is shared by both kinds — if either
// has been emitted (or skipped) on this file, we don't auto-run again.
// Right-click forces both providers regardless of marker.
//
// Dedup is per-kind: `_geoipDuplicateFor(sourceCol, kind)` walks
// `_extractedCols` for an existing entry of that kind against the same
// source. Re-running enrichment after a provider change rebuilds in place
// via `_dropAllGeoipCols(kinds)` (selective drop — geo can be refreshed
// without flushing ASN, and vice versa).
//
// ── Re-enrichment on provider change ────────────────────────────────────────
// When the user uploads / removes an MMDB in Settings, app-settings.js
// calls `_timelineCurrent._runGeoipEnrichment()`. `opts.force` may be:
//
//   true    — drop both kinds, rebuild whichever providers are wired.
//   'geo'   — drop only the geo cols (used when the geo MMDB changes).
//   'asn'   — drop only the ASN cols (used when the ASN MMDB changes).
//
// (At present, every settings-side caller passes plain `true`; the
// finer-grained slot values are intended for future use and are honoured
// by the loop below either way.)
//
// Bypass: nothing in this mixin pushes IOCs, mutates `app.findings`, or
// calls `EncodedContentDetector` / `pushIOC`. The Timeline route stays
// analyser-free. Geo / ASN cells are pure presentation data.
// ════════════════════════════════════════════════════════════════════════════

(function () {
  // ── IPv4 parser ────────────────────────────────────────────────────────
  function isStrictIPv4(s) {
    if (typeof s !== 'string') return false;
    const len = s.length;
    if (len < 7 || len > 15) return false;
    let octets = 0;
    let cur = 0;
    let curDigits = 0;
    for (let i = 0; i < len; i++) {
      const c = s.charCodeAt(i);
      if (c >= 48 && c <= 57) {
        if (curDigits === 0 && c === 48 && i + 1 < len && s.charCodeAt(i + 1) >= 48 && s.charCodeAt(i + 1) <= 57) {
          return false;
        }
        cur = cur * 10 + (c - 48);
        curDigits++;
        if (cur > 255 || curDigits > 3) return false;
      } else if (c === 46) {  // '.'
        if (curDigits === 0) return false;
        octets++;
        if (octets > 3) return false;
        cur = 0;
        curDigits = 0;
      } else {
        return false;
      }
    }
    return curDigits > 0 && octets === 3;
  }

  // ── Geo skip-heuristic vocabulary ─────────────────────────────────────
  const GEO_HEADER_TOKENS = [
    'country', 'city', 'region', 'state', 'province',
    'geo', 'geoip', 'location', 'iso', 'continent',
  ];
  const ISO2_SHAPE_RE = /^[A-Z]{2}$/;
  const ISO3_SHAPE_RE = /^[A-Z]{3}$/;
  const SLASH_GEO_RE = /^[A-Za-z][A-Za-z .'-]+\/[A-Z]{2}(?:\/[^/]+(?:\/[^/]+)?)?$/;

  function looksLikeGeoCell(s) {
    if (typeof s !== 'string') return false;
    const t = s.trim();
    if (!t) return false;
    if (t.length <= 4 && (ISO2_SHAPE_RE.test(t) || ISO3_SHAPE_RE.test(t))) return true;
    if (t.length >= 4 && t.length <= 80 && SLASH_GEO_RE.test(t)) return true;
    return false;
  }

  function looksLikeGeoHeader(name) {
    if (typeof name !== 'string') return false;
    const lower = name.toLowerCase();
    for (const tok of GEO_HEADER_TOKENS) {
      if (lower.indexOf(tok) >= 0) return true;
    }
    return false;
  }

  // ── ASN skip-heuristic vocabulary ─────────────────────────────────────
  const ASN_HEADER_TOKENS = [
    'asn', 'autonomous', 'isp', 'org', 'organization', 'organisation',
  ];
  // Bare AS number (with or without leading "AS"); accepts AS15169 and
  // 15169. Org-only cells are intentionally NOT a signal — too ambiguous
  // (any free-text column would trigger).
  const ASN_BARE_RE = /^AS?\d{1,10}$/i;
  // "Org Name (AS12345)" shape — exactly what `formatAsnRow` produces.
  const ASN_PARENS_RE = /\(AS\d{1,10}\)$/i;

  function looksLikeAsnCell(s) {
    if (typeof s !== 'string') return false;
    const t = s.trim();
    if (!t) return false;
    if (ASN_BARE_RE.test(t)) return true;
    if (t.length <= 120 && ASN_PARENS_RE.test(t)) return true;
    return false;
  }

  function looksLikeAsnHeader(name) {
    if (typeof name !== 'string') return false;
    const lower = name.toLowerCase();
    for (const tok of ASN_HEADER_TOKENS) {
      if (lower.indexOf(tok) >= 0) return true;
    }
    return false;
  }

  Object.assign(TimelineView.prototype, {

    // ── Public entry point ──────────────────────────────────────────────
    // `opts.force`    — true|'geo'|'asn'. true drops both kinds and
    //                   rebuilds; 'geo' / 'asn' drops only that kind.
    // `opts.forceCol` — index of a single base column to enrich
    //                   unconditionally — bypasses both the IPv4
    //                   detection threshold and the skip heuristic for
    //                   ALL configured providers.
    _runGeoipEnrichment(opts) {
      if (this._destroyed) return;
      if (!this._app) return;
      const geoProvider = this._app.geoip || null;
      const asnProvider = this._app.geoipAsn || null;
      if (!geoProvider && !asnProvider) return;
      const force = !!(opts && opts.force);
      const forceKind = (opts && (opts.force === 'geo' || opts.force === 'asn')) ? opts.force : null;
      const forceCol = (opts && Number.isInteger(opts.forceCol)) ? opts.forceCol : -1;

      // Forced-refresh path drops existing enrichment cols of the
      // affected kind first so the rebuild lands at the same logical
      // slot. forceCol always drops both kinds.
      if (forceCol >= 0) {
        this._dropAllGeoipCols(['geoip', 'geoip-asn']);
      } else if (force || forceKind) {
        const kinds = forceKind === 'geo' ? ['geoip']
                    : forceKind === 'asn' ? ['geoip-asn']
                    : ['geoip', 'geoip-asn'];
        this._dropAllGeoipCols(kinds);
      } else {
        // Per-file done-marker. Same key the auto-extract pass uses, so
        // an analyst who deleted an auto-extracted geo / asn col and
        // reopens the file does NOT see it return.
        if (TimelineView._loadAutoExtractDoneFor(this._fileKey)) {
          // Marker set — short-circuit only if at least one enrichment
          // column from any kind already exists.
          if (this._extractedCols.some(e => e && (e.kind === 'geoip' || e.kind === 'geoip-asn'))) return;
        }
      }

      const targetCols = (forceCol >= 0)
        ? [forceCol]
        : this._detectIpColumns();

      if (!targetCols.length) {
        // Nothing to do; only stamp the marker on the natural-detect
        // path so a forced override on a file with no auto-detected IP
        // cols doesn't poison future opens.
        if (!force && !forceKind && forceCol < 0) {
          TimelineView._saveAutoExtractDoneFor(this._fileKey);
        }
        return;
      }

      // Two-pass enrichment: each provider has its own skip heuristic,
      // so a column may produce a geo cell but no ASN cell (or vice
      // versa). Insertion order is geo first, then ASN, so the grid
      // shows IP | IP.geo | IP.asn | … left-to-right.
      let added = 0;
      for (const col of targetCols) {
        // Geo pass.
        if (geoProvider && (forceKind == null || forceKind === 'geo')) {
          const skipGeo = (forceCol < 0) && this._classifyColumnNeighbourhood(col, 'geo');
          if (!skipGeo) {
            if (this._enrichSingleIpCol(col, geoProvider, 'geo')) added++;
          }
        }
        // ASN pass.
        if (asnProvider && (forceKind == null || forceKind === 'asn')) {
          const skipAsn = (forceCol < 0) && this._classifyColumnNeighbourhood(col, 'asn');
          if (!skipAsn) {
            if (this._enrichSingleIpCol(col, asnProvider, 'asn')) added++;
          }
        }
      }

      // Re-render once after the batch — enrichment of a multi-IP CSV
      // is otherwise N grid blinks for N source columns.
      if (added > 0) {
        try { this._rebuildExtractedStateAndRender(); } catch (_) { /* noop */ }
        if (this._app && typeof this._app._toast === 'function') {
          this._app._toast(
            `IP enrichment: ${added} column${added === 1 ? '' : 's'} added`,
            'info'
          );
        }
      }

      // Mark the file as enriched so a deletion is sticky.
      if (!force && !forceKind && forceCol < 0) {
        TimelineView._saveAutoExtractDoneFor(this._fileKey);
      }
    },

    // ── IPv4 column detection ───────────────────────────────────────────
    _detectIpColumns() {
      if (!this.store || !this.store.rowCount || !this._baseColumns) return [];
      const baseCount = this._baseColumns.length;
      const sample = Math.min(this.store.rowCount, 200);
      const out = [];
      for (let c = 0; c < baseCount; c++) {
        let nonEmpty = 0;
        let hits = 0;
        for (let r = 0; r < sample; r++) {
          const v = this.store.getCell(r, c);
          if (!v) continue;
          nonEmpty++;
          if (isStrictIPv4(v)) hits++;
        }
        if (nonEmpty >= 8 && (hits / nonEmpty) >= 0.8) out.push(c);
        else if (nonEmpty < 8 && nonEmpty > 0 && hits === nonEmpty) out.push(c);
      }
      return out;
    },

    // ── Skip heuristic ──────────────────────────────────────────────────
    // True ⇒ column `colIdx` already has a neighbour matching `kind`
    // ('geo' | 'asn') and that kind should be skipped on the natural-
    // detect path.
    _classifyColumnNeighbourhood(colIdx, kind) {
      const headerFn = kind === 'asn' ? looksLikeAsnHeader : looksLikeGeoHeader;
      const cellFn = kind === 'asn' ? looksLikeAsnCell : looksLikeGeoCell;
      const baseCount = this._baseColumns.length;
      const lo = Math.max(0, colIdx - 3);
      const hi = Math.min(baseCount - 1, colIdx + 3);
      const sample = Math.min(this.store.rowCount, 60);
      for (let c = lo; c <= hi; c++) {
        if (c === colIdx) continue;
        if (headerFn(this._baseColumns[c])) return true;
        for (let r = 0; r < sample; r++) {
          const v = this.store.getCell(r, c);
          if (cellFn(v)) return true;
        }
      }
      return false;
    },

    // ── Per-column enrichment ───────────────────────────────────────────
    // `kind` is 'geo' or 'asn'. Each maps to:
    //   suffix:        '.geo'   / '.asn'
    //   extracted-kind:'geoip'  / 'geoip-asn'   (selective drop key)
    //   provider fns:  lookupIPv4 + formatRow / lookupAsn + formatAsnRow
    //
    // Returns true if a column was added.
    _enrichSingleIpCol(srcCol, provider, kind) {
      if (!provider) return false;
      const isAsn = (kind === 'asn');
      const lookupFn = isAsn ? provider.lookupAsn : provider.lookupIPv4;
      const formatFn = isAsn ? provider.formatAsnRow : provider.formatRow;
      if (typeof lookupFn !== 'function' || typeof formatFn !== 'function') return false;
      const extKind = isAsn ? 'geoip-asn' : 'geoip';
      if (this._geoipDuplicateFor(srcCol, extKind) >= 0) return false;
      let baseName;
      if (this._isExtractedCol(srcCol)) {
        const ext = this._extractedColFor(srcCol);
        baseName = (ext && ext.name) || ('col' + srcCol);
      } else {
        baseName = this._baseColumns[srcCol] || ('col' + srcCol);
      }
      const suffix = isAsn ? '.asn' : '.geo';
      const name = this._uniqueColName(baseName + suffix);
      const N = this.store.rowCount;
      const values = new Array(N);
      // Tiny per-IP cache — the same address typically appears many
      // times in a log.
      const cache = new Map();
      for (let r = 0; r < N; r++) {
        const ip = this._cellAt(r, srcCol);
        if (!ip) { values[r] = ''; continue; }
        let formatted = cache.get(ip);
        if (formatted === undefined) {
          let rec = null;
          try { rec = lookupFn.call(provider, ip); } catch (_) { rec = null; }
          formatted = rec ? formatFn.call(provider, rec) : '';
          cache.set(ip, formatted);
        }
        values[r] = formatted;
      }
      this._dataset.addExtractedCol({
        name,
        kind: extKind,
        sourceCol: srcCol,
        values,
        // Stamp the provider kind so we can tell (in tests, in future
        // export rows) which provider produced this column.
        providerKind: provider.providerKind || 'unknown',
      });
      // Insert the new column directly AFTER its IPv4 source in the
      // grid's display order. For dual-emit, the geo column is
      // inserted first (lands at IP+1), then the ASN column inserts
      // after the SAME source IP — _insertColAfterInDisplay walks the
      // current order and lands the new name immediately after the
      // source name, so ASN ends up at IP+2 (after the geo col that
      // was just inserted at IP+1). Result: IP | IP.geo | IP.asn.
      try { this._insertColAfterInDisplay(srcCol, name); } catch (_) { /* decorative only */ }
      return true;
    },

    // Mutate `this._gridColOrder` (an array of column NAMES) so that
    // `newName` lands immediately after the column at real index
    // `srcRealIdx`. Bootstraps a starter identity-order names array
    // when no saved order yet exists.
    _insertColAfterInDisplay(srcRealIdx, newName) {
      if (!newName || typeof newName !== 'string') return;
      const cols = this.columns;
      if (!Array.isArray(cols) || !cols.length) return;
      const srcName = (Number.isInteger(srcRealIdx) && srcRealIdx >= 0 && srcRealIdx < cols.length)
        ? cols[srcRealIdx]
        : null;
      if (!srcName) return;
      if (!Array.isArray(this._gridColOrder) || !this._gridColOrder.length) {
        const starter = [];
        for (let i = 0; i < cols.length; i++) {
          const nm = cols[i];
          if (nm === newName) continue;
          starter.push(nm || ('col' + i));
        }
        this._gridColOrder = starter;
      }
      const order = this._gridColOrder;
      for (let i = order.length - 1; i >= 0; i--) {
        if (order[i] === newName) order.splice(i, 1);
      }
      // Insert AFTER the source name AND after any sibling enrichment
      // that's already been emitted from the same source — this lets
      // dual-emit produce IP | IP.geo | IP.asn instead of clobbering
      // each other at the same slot. Walk forward from srcPos while the
      // next entry is an enrichment column whose name shares the source
      // prefix (i.e. `srcName.geo` / `srcName.asn`).
      const srcPos = order.indexOf(srcName);
      if (srcPos < 0) { order.push(newName); return; }
      let insertAt = srcPos + 1;
      while (insertAt < order.length) {
        const nm = order[insertAt];
        if (typeof nm === 'string' && nm.length > srcName.length
            && nm.charAt(srcName.length) === '.'
            && nm.startsWith(srcName)) {
          insertAt++;
        } else break;
      }
      order.splice(insertAt, 0, newName);
    },

    // Per-kind dedup. `extKind` is 'geoip' or 'geoip-asn'.
    _geoipDuplicateFor(sourceCol, extKind) {
      const cols = this._extractedCols || [];
      const target = extKind || 'geoip';
      for (let i = 0; i < cols.length; i++) {
        const e = cols[i];
        if (e && e.kind === target && e.sourceCol === sourceCol) return i;
      }
      return -1;
    },

    // Drop enrichment columns matching any of `kinds` (default: both).
    // Walks back-to-front so splice indices stay stable. Selective drop
    // lets a geo-only refresh leave ASN cols intact and vice versa.
    _dropAllGeoipCols(kinds) {
      const wanted = Array.isArray(kinds) && kinds.length
        ? kinds
        : ['geoip', 'geoip-asn'];
      const cols = this._extractedCols || [];
      const baseLen = this._dataset ? this._dataset.baseColCount : this._baseColumns.length;
      for (let i = cols.length - 1; i >= 0; i--) {
        const e = cols[i];
        if (e && wanted.indexOf(e.kind) >= 0) {
          this._queryRemoveClausesForCols([baseLen + i]);
          this._dataset.removeExtractedCol(i);
        }
      }
    },
  });
})();
