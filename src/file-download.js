// ═══════════════════════════════════════════════════════════════════════════
//  file-download.js — single home for the "Blob → <a download> → revoke"
//  ceremony used by every Save / Export / Download button in the UI.
//
//  Exposed globals (via window.FileDownload):
//    • downloadText(text, filename, mime?)   — strings (UTF-8 text / CSV / JSON)
//    • downloadBytes(bytes, filename, mime?) — Uint8Array / ArrayBuffer / Blob
//    • downloadBlob(blob, filename)          — already-constructed Blob
//    • downloadJson(obj, filename)           — JSON.stringify then downloadText
//
//  Everything funnels through `downloadBlob`, which owns the URL lifecycle
//  (createObjectURL → synthetic <a> click → revokeObjectURL on next tick).
//  Do NOT re-implement this ceremony anywhere else — `App.prototype._downloadText`
//  and `App.prototype._downloadBytes` in `app-ui.js` are thin wrappers that
//  delegate here so app-level code and renderer code share one code path.
// ═══════════════════════════════════════════════════════════════════════════

(function () {
  'use strict';

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Defer revoke so the browser has time to kick off the download. The
    // spec doesn't guarantee the download has started by the time `click()`
    // returns; 60 s gives even very large blobs on slow machines time to
    // begin transfer while still eventually reclaiming the blob URL.
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  function downloadText(text, filename, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
    downloadBlob(blob, filename);
  }

  function downloadBytes(bytes, filename, mime) {
    const blob = (bytes instanceof Blob)
      ? bytes
      : new Blob([bytes], { type: mime || 'application/octet-stream' });
    downloadBlob(blob, filename);
  }

  function downloadJson(obj, filename) {
    downloadText(JSON.stringify(obj, null, 2), filename, 'application/json');
  }

  window.FileDownload = {
    downloadBlob,
    downloadText,
    downloadBytes,
    downloadJson,
  };
})();
