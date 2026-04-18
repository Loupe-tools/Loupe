'use strict';
// ════════════════════════════════════════════════════════════════════════════
// constants.js — XML namespace constants, unit converters, DOM/XML helpers
// Loaded first; used by every other module.
// ════════════════════════════════════════════════════════════════════════════

// ── Parser safety limits ──────────────────────────────────────────────────────
const PARSER_LIMITS = Object.freeze({
  MAX_DEPTH:        32,                   // Max recursion / nesting depth
  MAX_UNCOMPRESSED: 50 * 1024 * 1024,     // 50 MB — max decompressed output
  MAX_RATIO:        100,                  // Per-entry compression ratio abort
  MAX_ENTRIES:      10_000,               // Max archive entries before truncation
  TIMEOUT_MS:       60_000,               // Parser timeout (60 s)
});

// ── XML namespace constants ───────────────────────────────────────────────────
const W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
const R_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
const A_NS = 'http://schemas.openxmlformats.org/drawingml/2006/main';
const WP_NS = 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing';
const V_NS = 'urn:schemas-microsoft-com:vml';
const MC_NS = 'http://schemas.openxmlformats.org/markup-compatibility/2006';
const PKG = 'http://schemas.openxmlformats.org/package/2006/relationships';

// ── Unit converters ───────────────────────────────────────────────────────────
const dxaToPx = v => (v / 1440) * 96;   // twentieths-of-a-point → CSS pixels
const emuToPx = v => (v / 914400) * 96; // English Metric Units  → CSS pixels
const twipToPt = v => v / 20;            // twips → points

// ── Namespaced attribute helpers ──────────────────────────────────────────────
function wa(el, name) {
  if (!el) return null;
  return el.getAttributeNS(W, name) || el.getAttribute('w:' + name) || null;
}
function ra(el, name) {
  if (!el) return null;
  return el.getAttributeNS(R_NS, name) || el.getAttribute('r:' + name) || null;
}

// ── Child-element helpers ─────────────────────────────────────────────────────
/** First child element in the W namespace with the given local name. */
function wfirst(parent, localName) {
  if (!parent) return null;
  const nl = parent.getElementsByTagNameNS(W, localName);
  return nl.length ? nl[0] : null;
}
/** Direct element children in the W namespace with the given local name. */
function wdirect(parent, localName) {
  if (!parent) return [];
  return Array.from(parent.childNodes).filter(
    n => n.nodeType === 1 && n.localName === localName
  );
}

// ── URL sanitiser ─────────────────────────────────────────────────────────────
/** Returns the URL if it is http/https/mailto, otherwise null. */
function sanitizeUrl(url) {
  if (!url) return null;
  try {
    const p = new URL(url, 'https://placeholder.invalid');
    if (['http:', 'https:', 'mailto:'].includes(p.protocol)) return url;
  } catch (e) { }
  return null;
}

// ── Standardised IOC types ────────────────────────────────────────────────────
/** IOC type constants used for all findings / externalRefs / interestingStrings. */
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
});

/** IOC types whose values are directly copyable in the sidebar. */
const IOC_COPYABLE = new Set([IOC.URL, IOC.EMAIL, IOC.IP, IOC.FILE_PATH, IOC.UNC_PATH, IOC.HASH, IOC.COMMAND_LINE, IOC.PROCESS, IOC.HOSTNAME, IOC.USERNAME, IOC.REGISTRY_KEY, IOC.MAC]);

/**
 * Canonical severity floors per IOC type. These are the default severities
 * renderers should emit for passive extractions (URLs in a document, emails
 * in a PGP UID, etc.) — renderers are free to *escalate* when context
 * demands it (e.g. a URL inside a phishing EML with authTripleFail), but
 * they should never emit below the floor.
 *
 * The values here are descriptive, not enforced at runtime; every renderer
 * passes the severity through unchanged. This table exists so the IOC
 * conformity audit has a single source of truth to grade against.
 */
const IOC_CANONICAL_SEVERITY = Object.freeze({
  [IOC.URL]:           'info',      // passive URL extraction; escalate for phishing/C2 context
  [IOC.EMAIL]:         'info',      // sender/recipient/UID; escalate on auth-fail + body-URL
  [IOC.IP]:            'info',
  [IOC.FILE_PATH]:     'info',
  [IOC.UNC_PATH]:      'medium',    // UNC in binary = credential-harvest candidate
  [IOC.ATTACHMENT]:    'medium',    // attachments carry macro/script risk by default
  [IOC.YARA]:          'info',      // severity comes from the rule meta; renderer mirrors it
  [IOC.PATTERN]:       'info',      // Detection → IOC mirror; severity carried from detection
  [IOC.INFO]:          'info',      // truncation markers and stats
  [IOC.HASH]:          'info',      // extraction only; no reputation lookup
  [IOC.COMMAND_LINE]:  'high',      // cmd/powershell strings are actionable on sight
  [IOC.PROCESS]:       'info',
  [IOC.HOSTNAME]:      'info',
  [IOC.USERNAME]:      'info',
  [IOC.REGISTRY_KEY]:  'medium',    // persistence-key indicator
  [IOC.MAC]:           'info',
});



// ── String helpers ────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function toRoman(n) {
  const v = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1];
  const s = ['M', 'CM', 'D', 'CD', 'C', 'XC', 'L', 'XL', 'X', 'IX', 'V', 'IV', 'I'];
  let r = ''; for (let i = 0; i < v.length; i++) while (n >= v[i]) { r += s[i]; n -= v[i]; } return r;
}

// ── File path trimming ────────────────────────────────────────────────────────
/**
 * Trim garbage appended after file extensions in binary-extracted path strings.
 * PE/ELF string extraction can fuse adjacent printable data into one string,
 * e.g. "file.pdbtEXtSoftwareAdobe..." → should be "file.pdb".
 * If the last component's extension part is unreasonably long (>10 chars) and
 * doesn't match a known extension, trim at the first recognized extension.
 */
const _KNOWN_EXT_RE = /^\.(exe|dll|sys|drv|ocx|cpl|scr|com|pdb|lib|obj|exp|pif|lnk|url|bat|cmd|ps1|py|vbs|vbe|js|jse|wsh|wsf|wsc|hta|sct|inf|reg|msi|msp|mst|txt|log|ini|cfg|conf|config|xml|html?|json|ya?ml|toml|csv|tsv|sql|sqlite|db|mdb|accdb|doc[xm]?|xls[xmb]?|ppt[xm]?|pdf|rtf|odt|ods|odp|one|eml|msg|pst|evtx?|zip|rar|7z|gz|tar|bz2|xz|cab|iso|img|vhdx?|vmdk|dmp|bak|tmp|old|dat|bin|pyc|pyo|pyw|rb|java|class|jar|war|apk|cpp|hpp|cs|go|rs|php|aspx?|jsp|sh|so|dylib|manifest|pem|crt|cer|der|key|pfx|ico|png|jpe?g|gif|bmp|svg|webp|tiff?|mp[34]|avi|mov|wmv|wav|ogg|woff2?|ttf|otf|eot)/i;
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

// ── Byte formatting ───────────────────────────────────────────────────────────
/** Format bytes to human-readable string (B, KB, MB, GB). */
function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  return (n / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

// ── Generic ASCII + UTF-16LE string scanner ──────────────────────────────────
/**
 * Extract printable ASCII and UTF-16LE strings from a byte range.
 *
 * Shared helper used by binary renderers (ELF, Mach-O, …) that need to
 * surface embedded strings for IOC extraction and YARA scanning. Two passes:
 *   1. UTF-16LE   — pairs of `[printable ASCII byte][0x00]`, minimum
 *                   `utf16Min` code units.
 *   2. ASCII 1-byte — runs of `0x20..0x7E`, minimum `asciiMin` bytes.
 *
 * Strings are deduplicated across both passes (ASCII wins; UTF-16 is only
 * emitted if not already seen in the ASCII output) so a single latin-script
 * string stored as UTF-16 doesn't show up twice. The scan stops after `cap`
 * total strings to bound memory.
 *
 * @param {Uint8Array} bytes
 * @param {{ start?: number, end?: number, asciiMin?: number, utf16Min?: number, cap?: number }} [opts]
 * @returns {{ ascii: string[], utf16: string[] }}
 */
function extractAsciiAndUtf16leStrings(bytes, opts) {
  const o = opts || {};
  const start = o.start | 0;
  const end = Math.min(o.end == null ? bytes.length : o.end, bytes.length);
  const asciiMin = o.asciiMin || 4;
  const utf16Min = o.utf16Min || 4;
  const cap = o.cap || 10000;

  const ascii = [];
  const utf16 = [];
  const seen = new Set();

  // Pass 1: ASCII runs
  let cur = '';
  for (let i = start; i < end; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b < 0x7F) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= asciiMin && !seen.has(cur)) {
        seen.add(cur);
        ascii.push(cur);
        if (ascii.length + utf16.length >= cap) return { ascii, utf16 };
      }
      cur = '';
    }
  }
  if (cur.length >= asciiMin && !seen.has(cur)) {
    seen.add(cur);
    ascii.push(cur);
  }

  // Pass 2: UTF-16LE runs
  cur = '';
  for (let i = start; i + 1 < end; i += 2) {
    const lo = bytes[i], hi = bytes[i + 1];
    if (hi === 0 && lo >= 0x20 && lo < 0x7F) {
      cur += String.fromCharCode(lo);
    } else {
      if (cur.length >= utf16Min && !seen.has(cur)) {
        seen.add(cur);
        utf16.push(cur);
        if (ascii.length + utf16.length >= cap) return { ascii, utf16 };
      }
      cur = '';
    }
  }
  if (cur.length >= utf16Min && !seen.has(cur)) {
    seen.add(cur);
    utf16.push(cur);
  }

  return { ascii, utf16 };
}

