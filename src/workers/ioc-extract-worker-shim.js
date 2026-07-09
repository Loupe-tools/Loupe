'use strict';
// ════════════════════════════════════════════════════════════════════════════
// ioc-extract-worker-shim.js — Worker-bundle prelude for the IOC extract worker
//
// First file `scripts/build.py` concatenates into the
// `__IOC_EXTRACT_WORKER_BUNDLE_SRC` template-literal that powers the
// `iocExtract` channel of `WorkerManager`. It declares the small subset of
// constants and host-side helpers that `src/ioc-extract.js` reaches for at
// module load and must therefore be defined **before** it.
//
// Bundle order (set in `scripts/build.py`):
//   1. src/workers/ioc-extract-worker-shim.js   ← this file
//   2. src/ioc-extract.js                       ← the regex-only IOC core
//   3. src/workers/ioc-extract.worker.js        ← onmessage dispatcher
//
// What lives here vs `src/constants.js`
// -------------------------------------
// Only the values `extractInterestingStringsCore` actually reads at runtime:
//   • IOC.* type constants (canonical strings — must match src/constants.js)
//   • `looksLikeIpVersionString`  — version-string suppression for IPv4
//   • `stripDerTail`              — DER tail-junk stripper for URLs
//   • `_trimPathExtGarbage`       — Windows-path tail-junk stripper
// Inlining the whole `src/constants.js` would pull in `escalateRisk`,
// `pushIOC`, `mirrorMetadataIOCs`, the full ICON.* table, NICELIST helpers,
// and other analyzer-side concerns the worker doesn't need. If
// `src/constants.js` ever changes one of these values, update this block too
// — the build's `scripts/check_shim_parity.py` gate diffs them.
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

const DER_TAIL_RX_TERMINATED = /([^0-9])0[\d]{0,2}[^a-zA-Z0-9]{1,3}$/;

const DER_TAIL_RX_TLD = /(\.[A-Za-z]{2,})[0-9]{1,3}$/;

const _KNOWN_EXT_RE = /^\.(exe|dll|sys|drv|ocx|cpl|scr|com|pdb|lib|obj|exp|pif|lnk|url|bat|cmd|ps1|py|vbs|vbe|js|jse|wsh|wsf|wsc|hta|sct|inf|reg|msi|msp|mst|txt|log|ini|cfg|conf|config|xml|html?|json|ya?ml|toml|csv|tsv|sql|sqlite|db|mdb|accdb|doc[xm]?|xls[xmb]?|ppt[xm]?|pdf|rtf|odt|ods|odp|one|eml|msg|pst|evtx?|zip|rar|7z|gz|tar|bz2|xz|cab|iso|img|vhdx?|vmdk|dmp|bak|tmp|old|dat|bin|pyc|pyo|pyw|rb|java|class|jar|war|apk|cpp|hpp|cs|go|rs|php|aspx?|jsp|sh|so|dylib|manifest|pem|crt|cer|der|key|pfx|ico|png|jpe?g|gif|bmp|svg|webp|tiff?|mp[34]|avi|mov|wmv|wav|ogg|woff2?|ttf|otf|eot)/i;

const _UNRESOLVED_SENTINEL_RE = /\u27E8[^\u27E8\u27E9]{0,256}\u27E9/;

function looksLikeIpVersionString(ipPart) {
  if (!ipPart) return false;
  return String(ipPart).replace(/\D/g, '').length < 4;
}

function stripDerTail(s) {
  if (typeof s !== 'string') return s;
  s = s.replace(DER_TAIL_RX_TERMINATED, '$1');
  // Bare-host scoping for the TLD rule: only fire when the string has no
  // path/query/fragment past the protocol (or none at all for IA5String /
  // raw hostname inputs). `_afterProto` slices off `proto://` so the test
  // ignores the slashes that are part of the protocol separator itself.
  const protoIdx = s.indexOf('://');
  const afterProto = protoIdx >= 0 ? s.slice(protoIdx + 3) : s;
  if (!/[\/?#]/.test(afterProto)) {
    s = s.replace(DER_TAIL_RX_TLD, '$1');
  }
  return s;
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

function safeMatchAll(re, str, budgetMs, maxMatches) {
  const matches = [];
  if (!re || typeof str !== 'string') return { matches, truncated: false, timedOut: false };
  // Force `g` flag so `exec` advances; otherwise we would infinite loop.
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
      // Always advance on zero-width match
      if (m.index === rx.lastIndex) rx.lastIndex++;
      if (matches.length >= cap) { truncated = true; break; }
      if ((++i & 0xFF) === 0 && Date.now() - start > budget) {
        timedOut = true;
        break;
      }
    }
  } catch (_e) { /* swallow */ }
  return { matches, truncated, timedOut };
}

function hasUnresolvedSentinel(s) {
  return typeof s === 'string' && _UNRESOLVED_SENTINEL_RE.test(s);
}
// @loupe-codegen:end
