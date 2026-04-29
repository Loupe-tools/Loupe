'use strict';
// ════════════════════════════════════════════════════════════════════════════
// geoip-store.js — IndexedDB persistence for user-uploaded MMDB blobs.
//
// localStorage is the canonical chokepoint for every other persistence
// surface in Loupe (`safeStorage` in `src/storage.js`). MMDB files are
// 8–80 MB, well past the 5 MB localStorage quota every browser caps at,
// so this is the one preference that has to live in IndexedDB instead.
//
// ── Slot model (v2) ─────────────────────────────────────────────────────────
// Two independent slots — the analyst can populate either or both:
//
//   'geo' — country / city MMDB (GeoLite2-City, DB-IP-City-Lite, …)
//   'asn' — ASN MMDB           (GeoLite2-ASN,  DB-IP-ASN-Lite,   …)
//
// Each slot persists `{ blob, meta }` under independent keys. The Settings
// dialog uploads them through separate file pickers; the timeline
// enrichment loop fires whichever providers hydrate.
//
// ── Surface ─────────────────────────────────────────────────────────────────
//   await GeoipStore.save(slot, blob, meta)  → bool
//   await GeoipStore.load(slot)              → { blob, meta } | null
//   await GeoipStore.clear(slot)             → bool
//   await GeoipStore.getMeta(slot)           → meta | null
//   await GeoipStore.getAllMeta()            → { geo: meta|null, asn: meta|null }
//
// `slot` is `'geo'` or `'asn'` (see SLOTS below). `meta` is a plain JSON
// object the caller chooses (we suggest `{ filename, size, savedAt,
// vintage, databaseType, schema }`); the store never inspects it.
//
// ── Migration v1 → v2 ───────────────────────────────────────────────────────
// v1 stored a single blob under literal keys `'mmdb'` + `'mmdb-meta'`.
// v2 namespaces by slot: `'mmdb-geo'` / `'mmdb-asn'` (+ `-meta` suffix).
// `onupgradeneeded` runs a one-shot migration that:
//   1. opens the old store
//   2. reads the legacy `'mmdb'` + `'mmdb-meta'` rows (if present)
//   3. writes them to `'mmdb-geo'` + `'mmdb-geo-meta'`
//   4. deletes the legacy rows
// All in the same versionchange transaction — atomic from the caller's
// POV. Existing analysts keep their uploaded GeoLite2-City; nothing
// silently disappears.
//
// ── Database / store shape ──────────────────────────────────────────────────
//   • DB name: `loupe-geoip`
//   • Version: 2  (was 1)
//   • Object store: `db` (out-of-line keys; one key per logical row)
//
// ── Quota / failure modes ───────────────────────────────────────────────────
// IndexedDB writes can fail on:
//   • Private-mode browsers (Firefox in 2024+: writes succeed but the DB
//     is wiped on tab close — caller sees the next `load()` return null)
//   • Quota exhaustion (Safari has aggressive eviction)
//   • Disabled-storage policies
// All five public methods catch every IndexedDB error path and return
// `false` / `null` rather than throwing — the Settings dialog renders
// "Could not save (storage blocked or full)" toasts on the boolean.
// ════════════════════════════════════════════════════════════════════════════

const GeoipStore = (function () {
  const DB_NAME = 'loupe-geoip';
  const DB_VERSION = 2;
  const STORE = 'db';
  const SLOTS = ['geo', 'asn'];

  // Legacy v1 keys — only referenced by the migration block in
  // `onupgradeneeded`. Do not use elsewhere.
  const LEGACY_KEY_BLOB = 'mmdb';
  const LEGACY_KEY_META = 'mmdb-meta';

  function _keys(slot) {
    return { blob: `mmdb-${slot}`, meta: `mmdb-${slot}-meta` };
  }

  function _isValidSlot(slot) {
    return SLOTS.indexOf(slot) >= 0;
  }

  function _hasIDB() {
    try { return typeof indexedDB !== 'undefined' && indexedDB; }
    catch (_) { return false; }
  }

  // Open the database, creating the object store on first run AND
  // migrating v1 data into the new slot layout. Returns a Promise that
  // resolves to an IDBDatabase (or rejects on the genuine "blocked /
  // disabled" cases — caller wraps in try/catch).
  function _openDB() {
    return new Promise((resolve, reject) => {
      if (!_hasIDB()) { reject(new Error('IndexedDB unavailable')); return; }
      let req;
      try { req = indexedDB.open(DB_NAME, DB_VERSION); }
      catch (e) { reject(e); return; }
      req.onupgradeneeded = (ev) => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE);   // out-of-line keys
          return; // fresh install — nothing to migrate
        }
        // v1 → v2: pull legacy rows into the geo slot.
        if (ev.oldVersion < 2) {
          try {
            // The version-change transaction is supplied by the upgrade
            // event itself — accessing it through `req.transaction` keeps
            // every read+write+delete in the SAME atomic transaction.
            const tx = req.transaction;
            const store = tx.objectStore(STORE);
            const blobReq = store.get(LEGACY_KEY_BLOB);
            const metaReq = store.get(LEGACY_KEY_META);
            blobReq.onsuccess = () => {
              const blob = blobReq.result;
              if (blob) {
                const k = _keys('geo');
                store.put(blob, k.blob);
                store.delete(LEGACY_KEY_BLOB);
              }
            };
            metaReq.onsuccess = () => {
              const meta = metaReq.result;
              if (meta) {
                const k = _keys('geo');
                store.put(meta, k.meta);
                store.delete(LEGACY_KEY_META);
              }
            };
          } catch (_) { /* migration is best-effort */ }
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error || new Error('open failed'));
      req.onblocked = () => reject(new Error('open blocked'));
    });
  }

  // Tiny `tx → request → promise` adapter. Every IDB operation is a
  // request inside a transaction; the transaction itself completes
  // separately from the request, so we have to wire BOTH `oncomplete`
  // (for writes) AND `request.onsuccess` (for reads) to be safe.
  function _runTx(db, mode, fn) {
    return new Promise((resolve, reject) => {
      let tx;
      try { tx = db.transaction(STORE, mode); }
      catch (e) { reject(e); return; }
      const store = tx.objectStore(STORE);
      let result;
      tx.oncomplete = () => resolve(result);
      tx.onabort = () => reject(tx.error || new Error('tx aborted'));
      tx.onerror = () => reject(tx.error || new Error('tx error'));
      try {
        const req = fn(store);
        if (req) req.onsuccess = () => { result = req.result; };
      } catch (e) { reject(e); }
    });
  }

  return {
    /** Persist the supplied Blob + meta object into the named slot.
     *  Returns true on success (transaction completed), false on any
     *  IDB error path or invalid slot. */
    async save(slot, blob, meta) {
      if (!_isValidSlot(slot)) return false;
      if (!blob) return false;
      const k = _keys(slot);
      let db;
      try { db = await _openDB(); }
      catch (_) { return false; }
      try {
        await _runTx(db, 'readwrite', (s) => {
          s.put(blob, k.blob);
          // Stamp the metadata together with the blob in the same
          // transaction so a partial save (one row written, the other
          // not) can never leave a Blob without its provenance.
          s.put(meta || {}, k.meta);
          return null;
        });
        return true;
      } catch (_) { return false; }
      finally { try { db.close(); } catch (_) { /* noop */ } }
    },

    /** Returns `{ blob, meta }` for the named slot or null on miss /
     *  IDB failure / invalid slot. The Blob keeps its original MIME
     *  type (typically empty / octet-stream — the caller pipes it
     *  straight into MmdbReader.fromBlob). */
    async load(slot) {
      if (!_isValidSlot(slot)) return null;
      const k = _keys(slot);
      let db;
      try { db = await _openDB(); }
      catch (_) { return null; }
      try {
        let blob = null, meta = null;
        await _runTx(db, 'readonly', (s) => {
          const r1 = s.get(k.blob);
          r1.onsuccess = () => { blob = r1.result || null; };
          const r2 = s.get(k.meta);
          r2.onsuccess = () => { meta = r2.result || null; };
          return null;
        });
        if (!blob) return null;
        return { blob, meta };
      } catch (_) { return null; }
      finally { try { db.close(); } catch (_) { /* noop */ } }
    },

    /** Cheap meta-only fetch — used by Settings to render the "currently
     *  loaded" panel without paying the full Blob deserialisation cost. */
    async getMeta(slot) {
      if (!_isValidSlot(slot)) return null;
      const k = _keys(slot);
      let db;
      try { db = await _openDB(); }
      catch (_) { return null; }
      try {
        let meta = null;
        await _runTx(db, 'readonly', (s) => {
          const r = s.get(k.meta);
          r.onsuccess = () => { meta = r.result || null; };
          return null;
        });
        return meta;
      } catch (_) { return null; }
      finally { try { db.close(); } catch (_) { /* noop */ } }
    },

    /** Convenience: fetch BOTH slots' meta in a single open. Used by
     *  Settings to render the dual-slot panel. Returns a plain object
     *  `{ geo: meta|null, asn: meta|null }` — never null itself. */
    async getAllMeta() {
      const out = { geo: null, asn: null };
      let db;
      try { db = await _openDB(); }
      catch (_) { return out; }
      try {
        await _runTx(db, 'readonly', (s) => {
          for (const slot of SLOTS) {
            const k = _keys(slot);
            const r = s.get(k.meta);
            r.onsuccess = () => { out[slot] = r.result || null; };
          }
          return null;
        });
        return out;
      } catch (_) { return out; }
      finally { try { db.close(); } catch (_) { /* noop */ } }
    },

    /** Drop both rows for the named slot. Returns true on success
     *  (or invalid slot → false). */
    async clear(slot) {
      if (!_isValidSlot(slot)) return false;
      const k = _keys(slot);
      let db;
      try { db = await _openDB(); }
      catch (_) { return false; }
      try {
        await _runTx(db, 'readwrite', (s) => {
          s.delete(k.blob);
          s.delete(k.meta);
          return null;
        });
        return true;
      } catch (_) { return false; }
      finally { try { db.close(); } catch (_) { /* noop */ } }
    },
  };
})();

// Mirror the FileDownload / SandboxPreview / safeStorage pattern — expose
// a single global so every module gets the same singleton without an
// import path. CommonJS export kept for the unit-test harness.
if (typeof window !== 'undefined') {
  window.GeoipStore = GeoipStore;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { GeoipStore };
}
