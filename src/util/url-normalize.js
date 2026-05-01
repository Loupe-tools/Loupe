'use strict';
// ════════════════════════════════════════════════════════════════════════════
// url-normalize.js — Decode common URL / host obfuscation tricks so the IOC
// extractor surfaces the canonical form alongside the original.
//
// Single source of truth for "given a URL string captured by the regex,
// is there a deobfuscated equivalent worth emitting as a sibling IOC?".
// Mounted alongside `src/util/ipv4.js` and consumed from
// `src/ioc-extract.js::processUrl` (host + IOC worker bundle) and
// `src/decoders/ioc-extract.js` (decoded-payload pass).
//
// Surface (single global, no module system per project conventions):
//
//   UrlNormalizeUtil.normalizeUrl(url) → {
//     original:        string,
//     normalized:      string,         // === original when nothing changed
//     changed:         boolean,
//     transformations: string[],       // e.g. ['unicode-escape','hex-ip']
//     hostIsIp:        boolean,        // true if normalized host is dotted-quad
//     normalizedHost:  string|null,    // bare host (no port/userinfo)
//   } | null
//
// Returns null only for non-strings or empty input. Otherwise always returns
// an object (`changed === false` when no transformation applied).
//
// Decoding scope (what we DO):
//   • `\uXXXX` and `\xHH` escape decoding inline (independent of the
//     run-length floors used by EncodedContentDetector finders — a single
//     escape is enough). Up to 3 stable passes for nested escapes.
//   • Percent-decoding inside the host AND path; query string is left alone
//     (legitimate `%20` etc. shouldn't be rewritten).
//   • Numeric host normalisation in classic `inet_aton` style:
//       - integer (`http://3232235521/`)
//       - hex integer (`http://0xC0A80101/`)
//       - dotted forms with mixed hex / octal / decimal parts, 1-4 parts
//         each (`http://0xC0.0xA8.0x01.0x01/`, `http://0300.0250.01.01/`)
//
// Out of scope (deliberately):
//   • IPv6 numeric obfuscation (rare in the wild, would balloon scope).
//   • HTML-entity-encoded URLs (the EncodedContentDetector finders catch
//     long contiguous runs already; embedded single entities are noise-prone).
//   • Punycode / IDN — already handled by `_parseUrlHost`/tldts in pushIOC.
//   • URL constructor canonicalisation (case-folding, port normalisation,
//     trailing `/`) — would over-normalise legitimate URLs and on some
//     hosts throw on otherwise-valid inputs.
//
// CSP-safe: pure string parsing, no `eval`, no `new Function`, no network.
// Worker-safe: no DOM, no globals beyond what's named here.
// ════════════════════════════════════════════════════════════════════════════

const UrlNormalizeUtil = (function () {
  // Defensive cap. URLs longer than this are almost certainly already noise
  // (binary garbage that happened to start with `http://`); skipping them
  // keeps the worker hot loop O(short-strings) regardless of the input size.
  const MAX_LEN = 8192;

  // ── Inline-escape decoder ──────────────────────────────────────────────
  // Decodes `\uXXXX`, `\u{X..}`, and `\xHH`. Returns the decoded string and
  // a flag indicating whether anything was actually replaced.
  function _decodeInlineEscapes(s) {
    if (typeof s !== 'string' || s.length === 0) return { out: s, changed: false };
    if (s.indexOf('\\') < 0) return { out: s, changed: false };
    let changed = false;
    // `\u{H..}` first — the braces contain a hex codepoint. Cap the inner
    // length at 6 hex digits (max valid Unicode codepoint is 0x10FFFF).
    let out = s.replace(/\\u\{([0-9A-Fa-f]{1,6})\}/g, (_, hex) => {
      const cp = parseInt(hex, 16);
      if (!Number.isFinite(cp) || cp > 0x10FFFF) return _;
      changed = true;
      try { return String.fromCodePoint(cp); } catch (_e) { return _; }
    });
    // `\uXXXX` — exactly 4 hex digits.
    out = out.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) => {
      changed = true;
      return String.fromCharCode(parseInt(hex, 16));
    });
    // `\xHH` — exactly 2 hex digits. Sequences like `\x` followed by
    // non-hex remain literal.
    out = out.replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => {
      changed = true;
      return String.fromCharCode(parseInt(hex, 16));
    });
    return { out, changed };
  }

  // ── Percent-decoder (best-effort; never throws) ────────────────────────
  // `decodeURIComponent` would throw on a stray `%` — fall back to per-token
  // decoding so a partially-encoded host still produces useful output.
  function _decodePercent(s) {
    if (typeof s !== 'string' || s.indexOf('%') < 0) return { out: s, changed: false };
    try {
      const decoded = decodeURIComponent(s);
      return { out: decoded, changed: decoded !== s };
    } catch (_) { /* fall through */ }
    let changed = false;
    const out = s.replace(/%([0-9A-Fa-f]{2})/g, (m, hex) => {
      try {
        const r = decodeURIComponent('%' + hex);
        if (r !== m) changed = true;
        return r;
      } catch (_) { return m; }
    });
    return { out, changed };
  }

  // ── Numeric-IP host classifier ──────────────────────────────────────────
  // Implements classic BSD `inet_aton`-style parsing:
  //   • 1 part — full 32-bit address.
  //   • 2 parts — A.(B as 24-bit).
  //   • 3 parts — A.B.(C as 16-bit).
  //   • 4 parts — A.B.C.D.
  // Each part may be decimal, hex (`0x…`), or octal (leading-`0`).
  // Returns the dotted-quad string when the input parses cleanly to a valid
  // 32-bit address, or null otherwise. Rejects parts with values outside
  // their allowed bit-width.
  function _normalizeNumericHost(host) {
    if (typeof host !== 'string' || host.length === 0) return null;
    // Strip a single trailing `.` (some BSD parsers accept it; we tolerate it).
    let h = host;
    if (h.endsWith('.') && h.length > 1) h = h.slice(0, -1);
    // Already a strict dotted-quad? Hand it back unchanged so the caller
    // can still emit the IP sibling. We don't reject leading-zero octets
    // here because the strict dotted form may have been the original input;
    // if the caller wants strict validation it has Ipv4Util.
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) {
      const partsDec = h.split('.').map(Number);
      if (partsDec.every(p => p >= 0 && p <= 255)) {
        // Reject the all-zeros sentinel only — every other 0.x.x.x value
        // is a plausible obfuscation result the analyst should see.
        if (partsDec[0] === 0 && partsDec[1] === 0 && partsDec[2] === 0 && partsDec[3] === 0) return null;
        return partsDec.join('.');
      }
      return null;
    }
    const parts = h.split('.');
    if (parts.length < 1 || parts.length > 4) return null;
    const numeric = [];
    for (const p of parts) {
      if (p.length === 0) return null;
      let n;
      if (/^0[xX][0-9A-Fa-f]+$/.test(p)) {
        if (p.length > 10) return null;          // 0x + 8 hex max → 32 bits
        n = parseInt(p.slice(2), 16);
      } else if (/^0[0-7]+$/.test(p)) {
        if (p.length > 12) return null;          // 11 octal digits ≥ 32 bits
        n = parseInt(p, 8);
      } else if (/^[0-9]+$/.test(p)) {
        if (p.length > 10) return null;          // 4294967295 has 10 digits
        n = parseInt(p, 10);
      } else {
        return null;
      }
      if (!Number.isFinite(n) || n < 0) return null;
      numeric.push(n);
    }
    // Bit-width caps per inet_aton rules.
    const caps = {
      1: [0xFFFFFFFF],
      2: [0xFF, 0xFFFFFF],
      3: [0xFF, 0xFF, 0xFFFF],
      4: [0xFF, 0xFF, 0xFF, 0xFF],
    }[numeric.length];
    for (let i = 0; i < numeric.length; i++) {
      if (numeric[i] > caps[i]) return null;
    }
    // Compose the 32-bit address.
    let addr;
    if (numeric.length === 1) {
      addr = numeric[0];
    } else if (numeric.length === 2) {
      addr = ((numeric[0] & 0xFF) << 24) >>> 0;
      addr = (addr + (numeric[1] & 0xFFFFFF)) >>> 0;
    } else if (numeric.length === 3) {
      addr = ((numeric[0] & 0xFF) << 24) >>> 0;
      addr = (addr + ((numeric[1] & 0xFF) << 16)) >>> 0;
      addr = (addr + (numeric[2] & 0xFFFF)) >>> 0;
    } else {
      addr = ((numeric[0] & 0xFF) << 24) >>> 0;
      addr = (addr + ((numeric[1] & 0xFF) << 16)) >>> 0;
      addr = (addr + ((numeric[2] & 0xFF) << 8)) >>> 0;
      addr = (addr + (numeric[3] & 0xFF)) >>> 0;
    }
    if (addr < 0 || addr > 0xFFFFFFFF) return null;
    const o0 = (addr >>> 24) & 0xFF;
    const o1 = (addr >>> 16) & 0xFF;
    const o2 = (addr >>> 8) & 0xFF;
    const o3 = addr & 0xFF;
    // Reject the all-zeros sentinel only. Anything else (including the
    // 0.x.y.z "this network" range) is a plausible obfuscation outcome
    // and should surface so the analyst can decide.
    if (addr === 0) return null;
    // For plain bare integers ≤ 255 the result is necessarily 0.0.0.N,
    // which is almost always a numeric coincidence rather than a URL —
    // suppress that specific shape to keep noise down. We can detect it
    // post-hoc: a 1-part numeric host that resolved to o0===o1===o2===0
    // came from an integer ≤ 255.
    if (numeric.length === 1 && o0 === 0 && o1 === 0 && o2 === 0) return null;
    return `${o0}.${o1}.${o2}.${o3}`;
  }

  // ── Minimal URL splitter (no `URL` constructor) ─────────────────────────
  // Produces { scheme, userinfo, host, port, path, query, fragment } so each
  // piece can be transformed independently. Avoids the `URL` constructor
  // which (a) over-canonicalises legitimate URLs and (b) throws on
  // obfuscated hosts on some engines, defeating the whole point.
  function _splitUrl(url) {
    if (typeof url !== 'string') return null;
    const m = /^([a-zA-Z][a-zA-Z0-9+.\-]*):\/\/([^\/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/.exec(url);
    if (!m) return null;
    const scheme = m[1];
    const authority = m[2];
    const path = m[3] || '';
    const query = m[4] || '';
    const fragment = m[5] || '';
    let userinfo = '';
    let hostport = authority;
    const at = authority.lastIndexOf('@');
    if (at >= 0) {
      userinfo = authority.slice(0, at);
      hostport = authority.slice(at + 1);
    }
    let host = hostport;
    let port = '';
    // IPv6 literal in brackets — preserve.
    if (hostport.startsWith('[')) {
      const close = hostport.indexOf(']');
      if (close < 0) return null;
      host = hostport.slice(0, close + 1);
      const rest = hostport.slice(close + 1);
      if (rest.startsWith(':')) port = rest.slice(1);
    } else {
      const colon = hostport.lastIndexOf(':');
      if (colon >= 0) {
        host = hostport.slice(0, colon);
        port = hostport.slice(colon + 1);
      }
    }
    return { scheme, userinfo, host, port, path, query, fragment };
  }

  function _joinUrl(p) {
    let auth = '';
    if (p.userinfo) auth = p.userinfo + '@';
    auth += p.host;
    if (p.port !== '' && p.port !== undefined && p.port !== null) auth += ':' + p.port;
    return p.scheme + '://' + auth + p.path + p.query + p.fragment;
  }

  // ── Public entry point ──────────────────────────────────────────────────
  function normalizeUrl(url) {
    if (typeof url !== 'string') return null;
    if (url.length === 0 || url.length > MAX_LEN) return null;

    const transformations = [];

    // Pass 1 — inline escape decoding on the whole URL. Iterate up to 3
    // times to handle nested escapes (`\\u005Cu0065…` shapes); stop early
    // on no-change.
    let working = url;
    let escapeChanged = false;
    for (let i = 0; i < 3; i++) {
      const r = _decodeInlineEscapes(working);
      if (!r.changed) break;
      working = r.out;
      escapeChanged = true;
    }
    if (escapeChanged) transformations.push('unicode-escape');

    // Re-split now that escapes are gone (the `://` may have been escaped).
    const parts = _splitUrl(working);
    if (!parts) {
      // Couldn't split; if we still applied an escape transform return the
      // partially-decoded form so callers can at least surface that.
      if (escapeChanged) {
        return {
          original: url,
          normalized: working,
          changed: working !== url,
          transformations,
          hostIsIp: false,
          normalizedHost: null,
        };
      }
      return {
        original: url,
        normalized: url,
        changed: false,
        transformations,
        hostIsIp: false,
        normalizedHost: null,
      };
    }

    // Pass 2 — percent-decode the HOST.
    const hostDec = _decodePercent(parts.host);
    if (hostDec.changed) {
      parts.host = hostDec.out;
      if (transformations.indexOf('percent-encoding') < 0) {
        transformations.push('percent-encoding');
      }
    }

    // Pass 3 — percent-decode the PATH (query left alone).
    if (parts.path) {
      const pathDec = _decodePercent(parts.path);
      if (pathDec.changed) {
        parts.path = pathDec.out;
        if (transformations.indexOf('percent-encoding') < 0) {
          transformations.push('percent-encoding');
        }
      }
    }

    // Pass 4 — numeric host normalisation. Only fires on hosts that look
    // numeric — letters in the host short-circuit so `evil.com` is left
    // alone. Bracketed IPv6 literals are also left alone.
    let hostIsIp = false;
    let normalizedHost = parts.host;
    if (parts.host && !parts.host.startsWith('[')) {
      // A host is "numeric-looking" if every char is a digit, dot, or hex
      // prefix — i.e. could plausibly be an inet_aton form.
      if (/^[0-9A-Fa-fxX.]+$/.test(parts.host) && /\d/.test(parts.host)) {
        const dotted = _normalizeNumericHost(parts.host);
        if (dotted) {
          hostIsIp = true;
          normalizedHost = dotted;
          if (dotted !== parts.host) {
            parts.host = dotted;
            // Tag the specific transformation kind so the IOC note is
            // useful; treat hex/octal/integer all as the same family.
            transformations.push('numeric-ip');
          }
        }
      } else if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(parts.host)) {
        // Strict dotted-quad — surface as an IP without claiming a transform.
        hostIsIp = true;
      }
    }

    const normalized = _joinUrl(parts);
    return {
      original: url,
      normalized,
      changed: normalized !== url,
      transformations,
      hostIsIp,
      normalizedHost,
    };
  }

  return {
    normalizeUrl,
    // Exported for direct unit tests; not part of the public consumer API.
    _normalizeNumericHost,
    _decodeInlineEscapes,
    _decodePercent,
    _splitUrl,
  };
})();

if (typeof window !== 'undefined') {
  window.UrlNormalizeUtil = UrlNormalizeUtil;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UrlNormalizeUtil };
}
