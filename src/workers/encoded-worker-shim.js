'use strict';
// ════════════════════════════════════════════════════════════════════════════
// encoded-worker-shim.js — Worker-bundle prelude for the EncodedContentDetector
//
// First file `scripts/build.py` concatenates into the
// `__ENCODED_WORKER_BUNDLE_SRC` template-literal that powers the encoded-
// content scan worker. It declares the small subset of constants
// and IOC-side helpers that `src/encoded-content-detector.js` and
// `src/decompressor.js` reach for at module load and must therefore be
// defined **before** them.
//
// Bundle order (set in `scripts/build.py`):
//   1. src/workers/encoded-worker-shim.js   ← this file
//   2. vendor/pako.min.js                   ← Decompressor's sync fallback
//   3. vendor/jszip.min.js                  ← embedded-ZIP validator
//   4. src/decompressor.js                  ← gzip/zlib/deflate inflate
//   5. src/encoded-content-detector.js      ← scanner (the actual workload)
//   6. src/workers/encoded.worker.js        ← onmessage dispatcher
//
// All six layers are concatenated, the result is wrapped in a JS template
// literal, and `src/worker-manager.js::runEncoded()` blob-URL spawns it.
// `src/workers/encoded.worker.js` carries the full design rationale
// (postMessage protocol, fallback contract, CSP note, etc.) — keep this
// shim deliberately tight.
//
// What lives here vs `src/constants.js`
// -------------------------------------
// Only the values the detector actually reads at runtime. Inlining the
// whole `src/constants.js` would pull in `escalateRisk`, `pushIOC`,
// `mirrorMetadataIOCs`, the full ICON.* table, NICELIST helpers, and other
// analyzer-side concerns the worker doesn't need. If `constants.js` ever
// changes one of these values, update this block too — the build will not
// catch the drift.
// ════════════════════════════════════════════════════════════════════════════

// ── Mirrored constants (codegen from src/constants.js) ─────────────────────
// @loupe-codegen:start
const IOC = Object.freeze({
  URL: 'URL',
  EMAIL: 'Email',
  IP: 'IP Address',
  FILE_PATH: 'File Path',
  UNC_PATH: 'UNC Path',
  ATTACHMENT: 'Attachment',
  YARA: 'YARA Match',
  PATTERN: 'Pattern',
  INFO: 'Info',
  HASH: 'Hash',
  COMMAND_LINE: 'Command Line',
  PROCESS: 'Process',
  HOSTNAME: 'Hostname',
  USERNAME: 'Username',
  REGISTRY_KEY: 'Registry Key',
  MAC: 'MAC Address',
  DOMAIN: 'Domain',
  GUID: 'GUID',
  FINGERPRINT: 'Fingerprint',
  PACKAGE_NAME: 'Package Name',
  CRYPTO_ADDRESS: 'Crypto Address',
  SECRET: 'Secret',
});

const PARSER_LIMITS = Object.freeze({
  MAX_UNCOMPRESSED: 256 * 1024 * 1024,  // generated from constants.js
});

const SAFE_REGEX_MAX_PATTERN_LEN = 2048;

const _REDOS_NESTED_QUANT_RE = /\((?:\?[:=!]|\?<[=!])?[^()]*(?:[+*]|\{\d+,\}|\{,\d+\})[^()]*\)\s*(?:[+*]|\{\d+,\}|\{,\d+\})/;

const _REDOS_DUPLICATE_GROUP_RE = /(\([^()]{2,80}\)[+*])\s*\1/;

const _KNOWN_EXT_RE = /^\.(exe|dll|sys|drv|ocx|cpl|scr|com|pdb|lib|obj|exp|pif|lnk|url|bat|cmd|ps1|py|vbs|vbe|js|jse|wsh|wsf|wsc|hta|sct|inf|reg|msi|msp|mst|txt|log|ini|cfg|conf|config|xml|html?|json|ya?ml|toml|csv|tsv|sql|sqlite|db|mdb|accdb|doc[xm]?|xls[xmb]?|ppt[xm]?|pdf|rtf|odt|ods|odp|one|eml|msg|pst|evtx?|zip|rar|7z|gz|tar|bz2|xz|cab|iso|img|vhdx?|vmdk|dmp|bak|tmp|old|dat|bin|pyc|pyo|pyw|rb|java|class|jar|war|apk|cpp|hpp|cs|go|rs|php|aspx?|jsp|sh|so|dylib|manifest|pem|crt|cer|der|key|pfx|ico|png|jpe?g|gif|bmp|svg|webp|tiff?|mp[34]|avi|mov|wmv|wav|ogg|woff2?|ttf|otf|eot)/i;

const _UNRESOLVED_SENTINEL_RE = /\u27E8[^\u27E8\u27E9]{0,256}\u27E9/;

function looksRedosProne(src) {
  if (typeof src !== 'string') return { warn: false, reject: false };
  if (src.length > SAFE_REGEX_MAX_PATTERN_LEN) {
    return { warn: false, reject: true, reason: 'pattern too long' };
  }
  if (_REDOS_DUPLICATE_GROUP_RE.test(src)) {
    return { warn: false, reject: true, reason: 'duplicate adjacent quantified groups' };
  }
  if (_REDOS_NESTED_QUANT_RE.test(src)) {
    return { warn: true, reject: false, reason: 'nested unbounded quantifier' };
  }
  return { warn: false, reject: false };
}

function safeRegex(pattern, flags) {
  const src = String(pattern == null ? '' : pattern);
  const heur = looksRedosProne(src);
  if (heur.reject) {
    return { ok: false, regex: null, warning: null, error: heur.reason };
  }
  let regex;
  try {
    /* safeRegex: builtin */
    regex = new RegExp(src, flags || '');
  } catch (e) {
    return { ok: false, regex: null, warning: null, error: e && e.message || 'invalid regex' };
  }
  return { ok: true, regex, warning: heur.warn ? heur.reason : null, error: null };
}

function _trimPathExtGarbage(path) {
  const ls = path.lastIndexOf('\\');
  if (ls < 0) return path;
  const fn = path.slice(ls + 1);
  const dot = fn.lastIndexOf('.');
  if (dot < 0) return path;
  const ext = fn.slice(dot + 1);
  if (ext.length <= 10) return path;           // extension is a reasonable length
  const tail = fn.slice(dot);                   // e.g. ".pdbtEXtSoftwareAdobe"
  const extM = tail.match(_KNOWN_EXT_RE);
  return extM ? path.slice(0, ls + 1 + dot + extM[0].length) : path;
}

function hasUnresolvedSentinel(s) {
  return typeof s === 'string' && _UNRESOLVED_SENTINEL_RE.test(s);
}
// @loupe-codegen:end

// ── throwIfAborted no-op (mirrors src/workers/timeline-worker-shim.js) ──────
//
// `throwIfAborted` is the render-epoch / watchdog poll site defined in
// `src/constants.js` for the host thread. Decoder helpers
// (`src/decoders/encoding-finders.js`, `src/decoders/cmd-obfuscation.js`)
// call it between candidate scans so the host can preempt long parses on
// supersession / watchdog timeout. Workers never participate in the host's
// render-epoch fence — they're terminated wholesale by `worker.terminate()`
// — so this is a no-op stub. Without it the finder helpers would throw
// `ReferenceError: throwIfAborted is not defined`, and the
// secondary-scan `catch` would surface the failure as the misleading
// "finder-budget — throwIfAborted is not defined" Info row.
function throwIfAborted() { /* no-op in worker */ }

function safeMatchAll(re, str, budgetMs, maxMatches) {
  const matches = [];
  if (!re || typeof str !== 'string') return { matches, truncated: false, timedOut: false };
  let rx = re;
  if (!rx.global) {
    /* safeRegex: builtin */
    try { rx = new RegExp(rx.source, rx.flags + 'g'); }
    catch (_e) { return { matches, truncated: false, timedOut: false }; }
  }
  rx.lastIndex = 0;
  const cap = maxMatches || 10000;
  const budget = budgetMs || 100;
  const start = Date.now();
  let truncated = false, timedOut = false;
  let i = 0;
  let m;
  try {
    while ((m = rx.exec(str)) !== null) {
      matches.push(m);
      if (m.index === rx.lastIndex) rx.lastIndex++;
      if (matches.length >= cap) { truncated = true; break; }
      if ((++i & 0xFF) === 0 && Date.now() - start > budget) { timedOut = true; break; }
    }
  } catch (_e) { /* swallow */ }
  return { matches, truncated, timedOut };
}

