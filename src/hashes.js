// hashes.js — Shared binary-analysis hash primitives.
//
// Loupe uses a few non-cryptographic fingerprint hashes as classic
// malware-clustering pivots. They are emitted as `IOC.HASH` entries by the
// PE / ELF / Mach-O renderers so an analyst can paste one into VT /
// Malpedia / MalwareBazaar and pull the family membership out directly.
//
// All helpers here are PURE FUNCTIONS over already-parsed inputs. None of
// them read the file more than once — the three renderers already parse
// their imports / symbols / dylibs / Rich header, and we just re-use those
// lists.
//
//   md5(bytesOrStr)              → 32-char hex MD5 of a Uint8Array or string.
//   computeImportHashFromList(items)
//                                → imphash-style MD5 over a pre-joined,
//                                  already-normalised `dll.func` / `sym`
//                                  list. Input list order matters (callers
//                                  pick imphash-faithful vs. sorted).
//   computeRichHash(bytes, danSOff, richOff, xorKey)
//                                → canonical Rich-header MD5 fingerprint
//                                  matching YARA's `pe.rich_signature.hash`
//                                  (MD5 of the de-XORed bytes from "DanS"
//                                  up to — but not including — "Rich").
//   computeSymHash(importedSymbols, dylibs)
//                                → Anomali-style Mach-O symhash: MD5 of
//                                  the ASCII-lowercased, de-duplicated,
//                                  sorted, comma-joined imported symbol
//                                  list concatenated with the sorted dylib
//                                  basenames. Mach-O's Rich-header
//                                  equivalent; clusters the exact same
//                                  toolchain output across re-signings.
//
// These helpers deliberately live outside the renderer classes so ELF and
// Mach-O can reach them without duplicating the compact MD5 that already
// ships inside pe-renderer.js. The MD5 impl here is the canonical RFC 1321
// compact form used by the imphash code — see pe-renderer.js for the long-
// form comment.

// ── MD5 ──────────────────────────────────────────────────────────────────────
function _md5Bytes(data) {
  // `data` is Uint8Array. Produces 32-char lowercase hex.
  const cmn = (q, a, b, x, s, t) => { a = (a + q + x + t) | 0; return (((a << s) | (a >>> (32 - s))) + b) | 0; };
  const ff = (a, b, c, d, x, s, t) => cmn((b & c) | (~b & d), a, b, x, s, t);
  const gg = (a, b, c, d, x, s, t) => cmn((b & d) | (c & ~d), a, b, x, s, t);
  const hh = (a, b, c, d, x, s, t) => cmn(b ^ c ^ d, a, b, x, s, t);
  const ii = (a, b, c, d, x, s, t) => cmn(c ^ (b | ~d), a, b, x, s, t);

  const n = data.length;
  const buf = new Uint8Array(((n + 72) >>> 6) << 6);
  buf.set(data);
  buf[n] = 0x80;
  const bits = n * 8;
  const lenOff = buf.length - 8;
  buf[lenOff]     = bits         & 0xFF;
  buf[lenOff + 1] = (bits >>> 8) & 0xFF;
  buf[lenOff + 2] = (bits >>> 16)& 0xFF;
  buf[lenOff + 3] = (bits >>> 24)& 0xFF;

  let a0 = 0x67452301, b0 = 0xEFCDAB89 | 0, c0 = 0x98BADCFE | 0, d0 = 0x10325476;

  for (let i = 0; i < buf.length; i += 64) {
    const w = new Int32Array(16);
    for (let j = 0; j < 16; j++) w[j] = buf[i+j*4] | (buf[i+j*4+1]<<8) | (buf[i+j*4+2]<<16) | (buf[i+j*4+3]<<24);
    let a = a0, b = b0, c = c0, d = d0;
    a=ff(a,b,c,d,w[0],7,-680876936);d=ff(d,a,b,c,w[1],12,-389564586);
    c=ff(c,d,a,b,w[2],17,606105819);b=ff(b,c,d,a,w[3],22,-1044525330);
    a=ff(a,b,c,d,w[4],7,-176418897);d=ff(d,a,b,c,w[5],12,1200080426);
    c=ff(c,d,a,b,w[6],17,-1473231341);b=ff(b,c,d,a,w[7],22,-45705983);
    a=ff(a,b,c,d,w[8],7,1770035416);d=ff(d,a,b,c,w[9],12,-1958414417);
    c=ff(c,d,a,b,w[10],17,-42063);b=ff(b,c,d,a,w[11],22,-1990404162);
    a=ff(a,b,c,d,w[12],7,1804603682);d=ff(d,a,b,c,w[13],12,-40341101);
    c=ff(c,d,a,b,w[14],17,-1502002290);b=ff(b,c,d,a,w[15],22,1236535329);
    a=gg(a,b,c,d,w[1],5,-165796510);d=gg(d,a,b,c,w[6],9,-1069501632);
    c=gg(c,d,a,b,w[11],14,643717713);b=gg(b,c,d,a,w[0],20,-373897302);
    a=gg(a,b,c,d,w[5],5,-701558691);d=gg(d,a,b,c,w[10],9,38016083);
    c=gg(c,d,a,b,w[15],14,-660478335);b=gg(b,c,d,a,w[4],20,-405537848);
    a=gg(a,b,c,d,w[9],5,568446438);d=gg(d,a,b,c,w[14],9,-1019803690);
    c=gg(c,d,a,b,w[3],14,-187363961);b=gg(b,c,d,a,w[8],20,1163531501);
    a=gg(a,b,c,d,w[13],5,-1444681467);d=gg(d,a,b,c,w[2],9,-51403784);
    c=gg(c,d,a,b,w[7],14,1735328473);b=gg(b,c,d,a,w[12],20,-1926607734);
    a=hh(a,b,c,d,w[5],4,-378558);d=hh(d,a,b,c,w[8],11,-2022574463);
    c=hh(c,d,a,b,w[11],16,1839030562);b=hh(b,c,d,a,w[14],23,-35309556);
    a=hh(a,b,c,d,w[1],4,-1530992060);d=hh(d,a,b,c,w[4],11,1272893353);
    c=hh(c,d,a,b,w[7],16,-155497632);b=hh(b,c,d,a,w[10],23,-1094730640);
    a=hh(a,b,c,d,w[13],4,681279174);d=hh(d,a,b,c,w[0],11,-358537222);
    c=hh(c,d,a,b,w[3],16,-722521979);b=hh(b,c,d,a,w[6],23,76029189);
    a=hh(a,b,c,d,w[9],4,-640364487);d=hh(d,a,b,c,w[12],11,-421815835);
    c=hh(c,d,a,b,w[15],16,530742520);b=hh(b,c,d,a,w[2],23,-995338651);
    a=ii(a,b,c,d,w[0],6,-198630844);d=ii(d,a,b,c,w[7],10,1126891415);
    c=ii(c,d,a,b,w[14],15,-1416354905);b=ii(b,c,d,a,w[5],21,-57434055);
    a=ii(a,b,c,d,w[12],6,1700485571);d=ii(d,a,b,c,w[3],10,-1894986606);
    c=ii(c,d,a,b,w[10],15,-1051523);b=ii(b,c,d,a,w[1],21,-2054922799);
    a=ii(a,b,c,d,w[8],6,1873313359);d=ii(d,a,b,c,w[15],10,-30611744);
    c=ii(c,d,a,b,w[6],15,-1560198380);b=ii(b,c,d,a,w[13],21,1309151649);
    a=ii(a,b,c,d,w[4],6,-145523070);d=ii(d,a,b,c,w[11],10,-1120210379);
    c=ii(c,d,a,b,w[2],15,718787259);b=ii(b,c,d,a,w[9],21,-343485551);
    a0 = (a0+a)|0; b0 = (b0+b)|0; c0 = (c0+c)|0; d0 = (d0+d)|0;
  }
  const hex = v => { let s=''; for(let i=0;i<4;i++) s+=((v>>>(i*8))&0xFF).toString(16).padStart(2,'0'); return s; };
  return hex(a0) + hex(b0) + hex(c0) + hex(d0);
}

/** MD5 of a Uint8Array or ASCII-safe string. */
function md5(input) {
  if (input == null) return null;
  if (typeof input === 'string') {
    const b = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) b[i] = input.charCodeAt(i) & 0xFF;
    return _md5Bytes(b);
  }
  if (input instanceof Uint8Array) return _md5Bytes(input);
  if (input && typeof input.length === 'number') return _md5Bytes(Uint8Array.from(input));
  return null;
}

// ── imphash-style hashes ─────────────────────────────────────────────────────
/**
 * Compute an MD5 of a list of already-normalised tokens joined by `,`.
 * Used by:
 *   • PE imphash (caller passes ['kernel32.createprocessa', …]; order matters)
 *   • ELF "Import Hash (MD5)" (caller passes sorted dedup'd dynsym names)
 *   • Mach-O "Import Hash (MD5)" (caller passes sorted dedup'd ext symbols)
 *
 * Returns `null` for an empty list so renderers can cheaply skip the metadata
 * row when there is nothing to hash.
 */
function computeImportHashFromList(items) {
  if (!Array.isArray(items) || items.length === 0) return null;
  return md5(items.join(','));
}

/**
 * Normalise a raw import entry into the imphash-faithful `dll.func` /
 * `dll.ord123` form. Works for PE `_parseImports()` output.
 */
function normalizePeImportToken(dllName, fn) {
  const dll = String(dllName || '').toLowerCase().replace(/\.(dll|ocx|sys)$/i, '');
  if (fn && fn.ordinal !== undefined && String(fn.name || '').startsWith('Ordinal #')) {
    return dll + '.ord' + fn.ordinal;
  }
  return dll + '.' + String((fn && fn.name) || '').toLowerCase();
}

/**
 * Canonical Rich-header fingerprint matching YARA's `pe.rich_signature.hash`.
 * The Rich header is an array of `(compId, buildId, count)` tuples XOR-masked
 * against a file-specific key. The hash is MD5 over the DE-XORED byte range
 * from "DanS" up to — but not including — the "Rich" marker itself.
 *
 * Accepts the three values the caller already knows from its own parse:
 *   bytes    — full file bytes
 *   danSOff  — offset of the "DanS" DWORD in the file
 *   richOff  — offset of the "Rich" DWORD in the file
 *   xorKey   — the 32-bit XOR mask (DWORD that follows "Rich")
 */
function computeRichHash(bytes, danSOff, richOff, xorKey) {
  if (!bytes || danSOff < 0 || richOff <= danSOff) return null;
  const len = richOff - danSOff;
  if (len < 16 || danSOff + len > bytes.length) return null;
  const k0 = xorKey & 0xFF;
  const k1 = (xorKey >>> 8) & 0xFF;
  const k2 = (xorKey >>> 16) & 0xFF;
  const k3 = (xorKey >>> 24) & 0xFF;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    const mask = (i & 3) === 0 ? k0 : (i & 3) === 1 ? k1 : (i & 3) === 2 ? k2 : k3;
    out[i] = bytes[danSOff + i] ^ mask;
  }
  return _md5Bytes(out);
}

/**
 * Anomali's Mach-O symhash: MD5 of the ASCII-lowercased, de-duplicated,
 * sorted, comma-joined list of imported external-symbol names, concatenated
 * with the sorted list of dylib basenames. Clusters Mach-O samples that
 * share the same import shape independently of code-signing / re-signing.
 *
 * See: https://github.com/anomalyinnovations/Mach-O-symhash
 */
function computeSymHash(importedSymbols, dylibs) {
  const syms = (Array.isArray(importedSymbols) ? importedSymbols : [])
    .map(s => String(s || '').replace(/^_/, '').toLowerCase())
    .filter(Boolean);
  const dls = (Array.isArray(dylibs) ? dylibs : [])
    .map(d => {
      const s = String(d || '');
      const slash = s.lastIndexOf('/');
      return (slash >= 0 ? s.slice(slash + 1) : s).toLowerCase();
    })
    .filter(Boolean);
  const uniqSort = arr => [...new Set(arr)].sort();
  const a = uniqSort(syms).join(',');
  const b = uniqSort(dls).join(',');
  if (!a && !b) return null;
  return md5(a + '|' + b);
}
