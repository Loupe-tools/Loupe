// ─────────────────────────────────────────────────────────────────────────────
// safeStorage — single chokepoint for every `localStorage` access in the
// bundle. Centralises the try/catch ceremony each call site used to repeat
// (private-mode browsers, file://-quota errors, blocked-storage policies all
// throw) and the JSON parse/stringify dance for object-shaped preferences.
//
// Why this exists
//   Direct `localStorage.*` calls leaked into ~50 sites across the bundle,
//   each with its own slightly different try/catch pattern (some swallowed,
//   some logged, some left writes un-guarded). Centralising the access:
//     • makes "storage blocked" failures uniformly silent / non-fatal,
//     • gives the build a single grep target (`scripts/build.py` enforces
//       allow-listed direct usage via `_check_storage_access()`),
//     • lets future migrations (IndexedDB, opt-in encryption, profile
//       export/import) swap one module instead of fifty call sites.
//
// API
//   safeStorage.get(key)              → string|null (never throws)
//   safeStorage.set(key, value)       → bool (false on quota / blocked)
//   safeStorage.remove(key)           → bool
//   safeStorage.getJSON(key, fb=null) → parsed JSON or `fb` on miss/parse-fail
//   safeStorage.setJSON(key, value)   → bool
//   safeStorage.keys()                → string[]  (snapshot of all keys)
//   safeStorage.removeMatching(pred)  → number    (count removed)
//
// All methods are best-effort: any thrown DOMException (private mode, quota
// exceeded, disabled by site policy) is caught and reported via the return
// value. Callers MUST tolerate `get` returning `null` and `set`/`remove`
// returning `false`.
//
// Persistence-key namespace: every key MUST start with `loupe_` per the
// CONTRIBUTING.md persistence-keys table. safeStorage does NOT enforce the
// prefix at runtime — the build gate `_check_storage_access()` is the
// canonical guard.
// ─────────────────────────────────────────────────────────────────────────────

(function () {
  'use strict';

  function _store() {
    // `localStorage` access itself can throw under strict site policies; do
    // the lookup lazily so module load never fails.
    try { return (typeof localStorage !== 'undefined') ? localStorage : null; }
    catch (_) { return null; }
  }

  const safeStorage = {
    get(key) {
      const s = _store();
      if (!s) return null;
      try { return s.getItem(key); }
      catch (_) { return null; }
    },

    set(key, value) {
      const s = _store();
      if (!s) return false;
      try { s.setItem(key, String(value)); return true; }
      catch (_) { return false; }
    },

    remove(key) {
      const s = _store();
      if (!s) return false;
      try { s.removeItem(key); return true; }
      catch (_) { return false; }
    },

    getJSON(key, fallback = null) {
      const raw = this.get(key);
      if (raw == null) return fallback;
      try {
        const parsed = JSON.parse(raw);
        return (parsed === undefined) ? fallback : parsed;
      } catch (_) { return fallback; }
    },

    setJSON(key, value) {
      let serialised;
      try { serialised = JSON.stringify(value); }
      catch (_) { return false; }
      if (serialised === undefined) return false;
      return this.set(key, serialised);
    },

    keys() {
      const s = _store();
      if (!s) return [];
      try {
        const out = [];
        for (let i = 0; i < s.length; i++) {
          const k = s.key(i);
          if (k != null) out.push(k);
        }
        return out;
      } catch (_) { return []; }
    },

    removeMatching(pred) {
      if (typeof pred !== 'function') return 0;
      const all = this.keys();
      let n = 0;
      for (const k of all) {
        let match = false;
        try { match = !!pred(k); } catch (_) { match = false; }
        if (match && this.remove(k)) n++;
      }
      return n;
    },
  };

  // Expose on `window` so every module sees the same singleton, mirroring
  // FileDownload / SandboxPreview / ArchiveTree.
  if (typeof window !== 'undefined') {
    window.safeStorage = safeStorage;
  }
})();
