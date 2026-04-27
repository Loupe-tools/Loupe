'use strict';
// ════════════════════════════════════════════════════════════════════════════
// ioc-extract.worker.js — IOC mass-extract regex pass, off-thread
//
// Pure WorkerGlobalScope module: no DOM, no `window`, no `app.*` references.
// Runs the regex-only `extractInterestingStringsCore(text, opts)` pass off
// the main thread so multi-megabyte non-timeline files (huge mboxes, large
// plaintext logs, fat HTML reports, string-heavy PEs) no longer freeze the
// analyser sidebar for hundreds of milliseconds while every URL / email /
// IPv4 / Windows path / UNC path / Unix path / registry key / defanged
// variant regex sweeps the augmented `_rawText`.
//
// Scope = `extractInterestingStringsCore` only. **No DOM, no
// EncodedContentDetector, no nicelist, no findings mutation.**
// ────────────────────────────────────────────────────────────────────────────
// The host `app-load.js` post-scan loop still owns:
//   • merging `findings` rows into `findings.interestingStrings`
//     (the worker's output is identical to the host shim's output — the
//     host is responsible for de-duping against rows already pushed by the
//     renderer and for stamping the side-channel `_droppedByType` /
//     `_totalSeenByType` Maps onto the array exactly where the old code
//     did)
//   • running `EncodedContentDetector.scan()` — separate `encoded` channel
//   • all sidebar / nicelist / risk / STIX / MISP / copy-analysis logic
//
// Build-time inlining
// -------------------
// `scripts/build.py` reads each layer of the bundle and concatenates them in
// strict order — every preceding layer's globals must be defined before the
// next layer's module body runs:
//   1. src/workers/ioc-extract-worker-shim.js   (IOC table, looksLikeIpVersionString,
//                                                stripDerTail, _trimPathExtGarbage)
//   2. src/ioc-extract.js                       (extractInterestingStringsCore +
//                                                _unwrapSafeLink + _refangString)
//   3. src/workers/ioc-extract.worker.js        (this file — onmessage dispatcher)
//
// All three layers are concatenated, the result is wrapped in a JS template
// literal, and `src/worker-manager.js::runIocExtract()` blob-URL spawns it.
// `__IOC_EXTRACT_WORKER_BUNDLE_SRC` is the constant name. The worker file is
// NOT in `JS_FILES` for the same reason the YARA / Timeline / Encoded
// workers aren't — it must not run on the main thread.
//
// postMessage protocol
// --------------------
// in:  { text:             string,
//        vbaModuleSources: string[],
//        existingValues:   string[]   // pre-seeded `seen` URLs so per-type
//                                     // drop accounting matches the sync
//                                     // shim — see runIocExtract jsdoc
//        formatIsHtml:     boolean (currently unused — host still does the
//                                   HTML href/src extraction inline) }
//
// out (success):
//   { event: 'done',
//     findings:        Array<{type, url, severity, note?, _sourceOffset?,
//                              _sourceLength?, _highlightText?}>,
//     droppedByType:   Array<[type, count]>   // Map serialised as entry pairs
//     totalSeenByType: Array<[type, count]>   // (Maps don't survive structured
//                                             //  cloning cleanly across all
//                                             //  browsers we target)
//     parseMs:         number }
//
// out (any error):
//   { event: 'error', message: string }
//
// Host falls back to the synchronous `_extractInterestingStrings` shim on
// any rejection (workers-unavailable, watchdog timeout, supersession,
// reported error).
//
// CSP note
// --------
// Workers inherit the host CSP, so `default-src 'none'` continues to deny
// network access from inside the worker. `worker-src blob:` is the only
// relaxation — see SECURITY.md → Full Content-Security-Policy.
// ════════════════════════════════════════════════════════════════════════════

self.onmessage = function (ev) {
  const msg = ev && ev.data ? ev.data : {};
  const text             = typeof msg.text === 'string' ? msg.text : '';
  const vbaModuleSources = Array.isArray(msg.vbaModuleSources) ? msg.vbaModuleSources : [];
  const existingValues   = Array.isArray(msg.existingValues)   ? msg.existingValues   : [];

  const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
  try {
    if (typeof extractInterestingStringsCore !== 'function') {
      self.postMessage({ event: 'error', message: 'extractInterestingStringsCore missing from worker bundle' });
      return;
    }

    // `existingValues` is the host's current `findings.externalRefs ∪
    // findings.interestingStrings` URL set, snapshotted at dispatch time.
    // Seeding the worker's `seen` set with it makes the per-type cap and
    // `totalSeenByType` accounting byte-equivalent with the synchronous
    // shim — duplicates the renderer already pushed don't burn a quota
    // slot here. The host does an additional post-resolve dedup to catch
    // IOCs added between dispatch and resolve (e.g. encoded-content scan).
    const out = extractInterestingStringsCore(text, {
      existingValues:   existingValues,
      vbaModuleSources: vbaModuleSources,
    });

    const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

    // Maps are serialised as `[[k,v], ...]` arrays — see protocol comment
    // above. Host rehydrates with `new Map(arr)` in `runIocExtract`'s
    // `decodeDone`.
    const dropped = [];
    const seen    = [];
    if (out && out.droppedByType && typeof out.droppedByType.forEach === 'function') {
      out.droppedByType.forEach((v, k) => dropped.push([k, v]));
    }
    if (out && out.totalSeenByType && typeof out.totalSeenByType.forEach === 'function') {
      out.totalSeenByType.forEach((v, k) => seen.push([k, v]));
    }

    self.postMessage({
      event:           'done',
      findings:        (out && out.findings) || [],
      droppedByType:   dropped,
      totalSeenByType: seen,
      parseMs:         Math.max(0, t1 - t0),
    });
  } catch (e) {
    const message = (e && e.message) ? e.message : String(e);
    self.postMessage({ event: 'error', message });
  }
};
