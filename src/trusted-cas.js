// trusted-cas.js — Hand-curated public CA recognition for Authenticode trust.
//
// Loupe is fully offline; we cannot fetch a real CA store, walk a chain, or
// validate signatures cryptographically. What we CAN do is recognise
// well-known public-CA Issuer DN patterns on the leaf cert's *issuer* field
// (or any chain cert's subject field) and, combined with a non-self-signed
// chain length ≥ 2, treat that as a "signed-trusted" trust tier.
//
// This is intentionally narrow — purpose is a *demote* signal for ubiquitous
// API noise (anti-debug, dynamic loading, generic networking) when the
// binary is signed by a real public code-signing CA. It is NEVER a
// "this binary is safe" signal:
//   • Stolen / leaked CA-issued code-signing certs happen, and a fully
//     valid Authenticode chain has been seen on real malware. So
//     `trustBoost = +2` only suppresses LOW-severity capability noise;
//     it never suppresses critical capabilities (process injection,
//     credential theft, ransomware-class crypto, hooking) and never
//     suppresses YARA detections.
//   • The match is a substring against the cert's issuer/subject CN or O
//     field. We're not validating cryptographic signatures — only that the
//     parsed leaf has a non-self-signed issuer matching a known-public CA.
//
// Adding entries: prefer the canonical public CN string from the CA's
// own published root certificates. Keep entries lower-case (matching is
// case-insensitive). Don't add private/enterprise CAs here — that is what
// the user nicelist concept is for (and a future `loupe_trusted_ca_user`
// list, not in scope yet).

const _TRUSTED_CA_PATTERNS = Object.freeze([
  // Microsoft Code Signing chains — by far the largest signer in the
  // Windows ecosystem. Drivers, SDK tooling, OS binaries, MSI installers.
  'microsoft code signing',
  'microsoft corporation',
  'microsoft root',
  'microsoft windows',
  'microsoft time-stamp',
  'microsoft authenticode',
  'microsoft id verified code signing',

  // Apple Worldwide Developer Relations — Mach-O code signing on macOS.
  'apple worldwide developer relations',
  'apple root ca',
  'developer id certification authority',
  'developer id application',
  'developer id installer',

  // Google — Chrome / Android / Cloud SDK signing.
  'google trust services',
  'google llc',
  'google internet authority',

  // Major public commercial CAs that issue Authenticode / EV code-signing
  // certs to corporate signers.
  'digicert',
  'digicert assured id',
  'digicert global root',
  'digicert high assurance',
  'digicert sha2 assured id code signing',
  'digicert trusted',
  'digicert ev code signing',
  'sectigo',                  // formerly Comodo CA
  'sectigo public code signing',
  'comodo ca',
  'comodo rsa code signing',
  'comodo time stamping',
  'usertrust',                // Sectigo intermediate
  'globalsign',
  'globalsign code signing',
  'globalsign ev code signing',
  'globalsign extended validation',
  'entrust',
  'entrust code signing',
  'entrust ev code signing',
  'identrust',
  'thawte',                   // legacy, still in use on long-lived chains
  'thawte code signing',
  'verisign',                 // legacy, rolled into DigiCert
  'verisign class 3 code signing',
  'go daddy',
  'godaddy secure code signing',
  'starfield',
  'certum',
  'certum code signing',
  'wisekey',
  'ssl.com',
  'ssl.com code signing',
  'ssl.com ev code signing',
  'amazon root ca',
  'amazon trust services',
  'symantec class 3 sha256 code signing',

  // Linux distro code-signing roots that show up on signed RPMs / Mach-O
  // builds shipped via cross-platform vendors.
  'red hat',
  'canonical ltd',
  'fedora',

  // Cloud provider / large vendor code-signing leaves that publish their
  // own public CAs.
  'amazon web services',
  'oracle america',
  'oracle corporation',
  'adobe systems',
  'adobe inc',
  'oracle root',
  'mozilla corporation',
  'jetbrains s.r.o',
  'nvidia corporation',
  'intel corporation',
  'amd inc',
  'broadcom corporation',
  'cisco systems',
  'vmware, inc',
  'vmware inc',
  'ibm corporation',
  'sun microsystems',
  'symantec corporation',
  'github, inc',
  'github inc',
  'gitlab inc',
  'docker inc',
  'cloudflare, inc',
]);

// Generic / placeholder issuer CNs that should NEVER count as trusted even
// if a substring would technically match. Useful as a defence against
// cert-CN homoglyph tricks (`Microsoft Software Inc`, `digicert-fake`, etc.).
// Match is exact-equal against lower-cased CN/O.
const _UNTRUSTED_CN_PLACEHOLDERS = Object.freeze(new Set([
  'localhost',
  'test',
  'test ca',
  'self-signed',
  'unknown',
  'example',
  'example ca',
  '',
]));

/**
 * Lower-case + collapse whitespace; helper for substring matching.
 */
function _norm(s) {
  return String(s || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

/**
 * True if `dn` (a DN string or `{CN, O, ...}` object) names a recognised
 * public CA from the curated list. Substring-match against the DN's CN or
 * O field, lower-cased.
 *
 * Intentionally generous — the curated patterns are themselves narrow, so
 * `'digicert sha2 assured id code signing ca'` matches `'digicert'`. The
 * cost of a false positive here is "we treat a signed binary as trusted
 * for low-severity noise demotion only" — see the file header for why
 * that's acceptable.
 */
function isTrustedIssuer(dn) {
  if (!dn) return false;
  let cn = '', o = '';
  if (typeof dn === 'string') {
    cn = _norm(dn);
  } else if (typeof dn === 'object') {
    cn = _norm(dn.CN);
    o  = _norm(dn.O);
  }
  if (_UNTRUSTED_CN_PLACEHOLDERS.has(cn)) return false;
  // Try CN first (more specific), fall back to O.
  for (const pat of _TRUSTED_CA_PATTERNS) {
    if (cn && cn.indexOf(pat) >= 0) return true;
    if (o  && o.indexOf(pat)  >= 0) return true;
  }
  return false;
}

/**
 * Classify the trust tier of a parsed Authenticode certificate list.
 *
 * @param {Array<{subject:object,issuer:object,subjectStr:string,issuerStr:string,isSelfSigned:boolean}>} certs
 * @returns {'unsigned'|'self-signed'|'signed'|'signed-trusted'}
 */
function classifyTrustTier(certs) {
  if (!Array.isArray(certs) || certs.length === 0) return 'unsigned';
  // Leaf is conventionally first in CMS SignedData certificates SET, but
  // be defensive — pick the cert that is NOT issuer of any other cert,
  // which is the leaf.
  let leaf = certs[0];
  if (certs.length > 1) {
    const subjectStrings = new Set(certs.map(c => _norm(c.subjectStr)));
    const issuerStrings  = new Set(certs.map(c => _norm(c.issuerStr)));
    // Leaf = subject that is not anyone's issuer.
    for (const c of certs) {
      const s = _norm(c.subjectStr);
      if (s && !issuerStrings.has(s) && subjectStrings.has(s)) {
        leaf = c;
        break;
      }
    }
  }
  if (leaf.isSelfSigned) return 'self-signed';
  // Look across the full chain — match if either the leaf's issuer OR any
  // intermediate's subject names a known public CA (covers the case where
  // the leaf's immediate issuer is a vendor sub-CA whose parent is the
  // recognised root).
  if (isTrustedIssuer(leaf.issuer) || isTrustedIssuer(leaf.issuerStr)) {
    return 'signed-trusted';
  }
  for (const c of certs) {
    if (c === leaf) continue;
    if (isTrustedIssuer(c.subject) || isTrustedIssuer(c.subjectStr)) {
      return 'signed-trusted';
    }
    if (isTrustedIssuer(c.issuer) || isTrustedIssuer(c.issuerStr)) {
      return 'signed-trusted';
    }
  }
  // Chain present, parseable, non-self-signed, but no recognised public CA.
  // Could be a corporate-internal CA, a fresh public CA we haven't curated
  // yet, or a malicious signer with a bespoke CA. Treat as plain 'signed'
  // — gets a small trust boost (+1) but not the strong demote.
  return 'signed';
}

/**
 * Map a trust tier to a numeric trust boost. Renderers feed this into the
 * weighting helpers in `binary-class.js` (and into per-cluster riskScore
 * gates in their `analyzeForSecurity`).
 *
 *   -1  unsigned / self-signed   →  no demote, no extra weight
 *    0  no Authenticode entry    →  baseline
 *   +1  signed (unknown CA)      →  halve low-severity noise
 *   +2  signed-trusted           →  zero out low-severity noise
 */
function trustBoostForTier(tier) {
  switch (tier) {
    case 'signed-trusted': return 2;
    case 'signed':         return 1;
    case 'self-signed':    return -1;
    case 'unsigned':       return -1;
    default:               return 0;
  }
}

const TrustedCAs = Object.freeze({
  isTrustedIssuer,
  classifyTrustTier,
  trustBoostForTier,
  // Exposed for tests / Settings UI introspection.
  _patterns: _TRUSTED_CA_PATTERNS,
  _untrustedPlaceholders: _UNTRUSTED_CN_PLACEHOLDERS,
});
