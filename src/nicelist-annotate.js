// nicelist-annotate.js — single canonical place that tags IOC refs with
// `_nicelisted` / `_nicelistSource` against the Default Nicelist
// (`isNicelisted`) and the user's custom nicelists (`_NicelistUser.match`).
//
// Why this file exists
// --------------------
// Historically the tagging only happened inside `_renderSidebar` (in
// `app-sidebar.js`), so the IOC sidebar correctly demoted nicelisted rows
// — but every downstream consumer that bypassed the sidebar (Copy
// Analysis Summary, STIX bundle, MISP event, IOC CSV) saw the
// un-annotated `findings.externalRefs` array and shipped CDN / Microsoft
// telemetry / Google Fonts hostnames into the analyst's TIP.
//
// Lifting the tagging here gives every consumer a single source of truth:
//   • `app-load.js` calls `annotateNicelist(this.findings)` exactly once
//     after the renderer's `analyzeForSecurity()` resolves (and once
//     more on the deferred-IOC merge path that runs after the IOC worker
//     completes — see `_patchIocFindingsFromWorker`).
//   • `app-sidebar.js` no longer recomputes the tags; it just reads the
//     fields that this helper sets. (A defensive recompute is kept for
//     safety so `_renderSidebar` still works when called against a
//     findings object that bypassed `_loadFile`.)
//   • `app-ui.js` `_collectIocs` carries the tags through into the IOC
//     export pipeline (CSV columns, STIX `confidence:25` + label, MISP
//     `to_ids:'0'` + comment).
//   • `app-copy-analysis.js` honours the `loupe_summary_include_nicelisted`
//     setting (`group` | `omit` | `inline`) when emitting the Summary.
//
// Contract
// --------
// `annotateNicelist(findings)` walks `findings.externalRefs` and
// `findings.interestingStrings` (the same two arrays the sidebar IOC
// section unions) and sets two fields on each entry:
//
//   • `_nicelisted`     — boolean (always set; never undefined)
//   • `_nicelistSource` — string | null
//                         'Default Nicelist' for built-in matches, or
//                         the user-list display name returned by
//                         `_NicelistUser.match` for user lists. `null`
//                         when `_nicelisted === false`.
//
// Idempotent: calling twice on the same findings is safe and cheap. The
// helper does NOT mutate `findings.detections`, `findings.modules`, or
// any other field.
//
// Detection-type refs (IOC.YARA / IOC.PATTERN / IOC.INFO) are skipped
// because they're not user-suppressible IOCs — they're rule hits and
// rendering hints.

(function () {
  'use strict';

  // We intentionally check IOC type strings directly (matches the same
  // pattern used inside `nicelist.js` itself — see comment there for why
  // string-equality against the constants in `constants.js` is fine).
  const _SKIP_TYPES = new Set(['YARA', 'Pattern', 'Info']);

  function _annotateRef(r) {
    if (!r || !r.url || !r.type) {
      if (r) { r._nicelisted = false; r._nicelistSource = null; }
      return;
    }
    if (_SKIP_TYPES.has(r.type)) {
      r._nicelisted = false;
      r._nicelistSource = null;
      return;
    }
    let source = null;
    if (typeof isNicelisted === 'function' && isNicelisted(r.url, r.type)) {
      source = 'Default Nicelist';
    } else if (typeof _NicelistUser !== 'undefined'
               && _NicelistUser
               && typeof _NicelistUser.match === 'function') {
      const userHit = _NicelistUser.match(r.url, r.type);
      if (userHit) source = userHit;
    }
    if (source) {
      r._nicelisted = true;
      r._nicelistSource = source;
    } else {
      r._nicelisted = false;
      r._nicelistSource = null;
    }
  }

  /**
   * Annotate every IOC ref in `findings` in place. Safe to call multiple
   * times. Returns `findings` (so callers can chain if they like).
   *
   * @param {object} findings  Object with `externalRefs` and / or
   *                           `interestingStrings` arrays. Either may be
   *                           absent or empty — the helper is tolerant
   *                           of partial findings (e.g. registry-dispatch
   *                           pre-decode shape).
   * @returns {object} same findings object
   */
  function annotateNicelist(findings) {
    if (!findings) return findings;
    const refs = findings.externalRefs;
    if (Array.isArray(refs)) {
      for (let i = 0; i < refs.length; i++) _annotateRef(refs[i]);
    }
    const strs = findings.interestingStrings;
    if (Array.isArray(strs)) {
      for (let i = 0; i < strs.length; i++) _annotateRef(strs[i]);
    }
    return findings;
  }

  // Expose on window/globalThis (concatenated-globals architecture; see
  // AGENTS.md).
  if (typeof window !== 'undefined') {
    window.annotateNicelist = annotateNicelist;
  } else if (typeof globalThis !== 'undefined') {
    globalThis.annotateNicelist = annotateNicelist;
  }
})();
