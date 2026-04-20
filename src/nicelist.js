// nicelist.js — Known-good global infrastructure whitelist ("NICELIST")
//
// Passive IOC extraction (URL regex, domain regex, email-address regex) on
// real-world samples almost always hauls in a lot of common global
// infrastructure: cloud-provider API endpoints, package registries, XML
// namespace URIs, CA / OCSP responders, OS update endpoints, etc. These
// are almost never the pivot that matters on a triage — they just push the
// actually-interesting IOC (e.g. `webhook.site/<uuid>` on a Shai-Hulud
// npm sample) further down the table.
//
// NICELIST is a hand-curated, category-grouped list of those benign
// surfaces. When a passive IOC's value matches one of these entries (exact
// host OR any subdomain), the sidebar demotes its row: sorts it to the
// bottom of the IOCs table and optionally hides it behind a toggle.
//
// Important non-goals — audit these before adding entries:
//   • Never suppresses YARA detections. If a rule names `github.com`,
//     the Detection fires at full severity regardless.
//   • Never suppresses findings on anything other than pure pivot types
//     (URL / DOMAIN / HOSTNAME / EMAIL). Hashes, file paths, command
//     lines, UNC paths, etc. cannot be nicelisted.
//   • No wildcard / regex entries. Every entry is a bare hostname and
//     matched as "exact or trailing-label" suffix. `amazonaws.com` covers
//     `sts.amazonaws.com` and `cognito-identity-fips.us-east-1.amazonaws.com`
//     but NOT `malicious-amazonaws.com` (different registrable domain).
//   • Additions should be surfaces that legitimate orgs use as their
//     canonical public API / registry / schema / CA / update endpoint,
//     NOT surfaces that attackers commonly abuse (those belong in the
//     `_ABUSE_SUFFIXES` list in `constants.js` and are flagged, not
//     nicelisted).
//
// The list is deliberately narrow; every entry should be pasteable into
// a threat-intel chat and get a nod of "yeah, that's infrastructure".

const NICELIST = Object.freeze([
  // ── Cloud provider APIs & instance metadata ─────────────────────────
  // AWS (STS, IAM, S3, metadata-service proxy endpoints, Cognito, …)
  'amazonaws.com', 'aws.amazon.com', 'awsstatic.com', 'amazon.com',
  // Google Cloud (GCE metadata, APIs, Firebase, gstatic CDN, …)
  'metadata.google.internal', 'googleapis.com', 'gstatic.com',
  'google.com', 'googleusercontent.com', 'appspot.com', 'firebaseio.com',
  // Azure / Microsoft Graph / M365 auth
  'azure.com', 'azureedge.net', 'windows.net', 'core.windows.net',
  'microsoftonline.com', 'microsoft.com', 'msft.net', 'msftauth.net',
  'live.com', 'office.com', 'office365.com', 'sharepoint.com',
  'outlook.com', 'onedrive.com',
  // CDNs used constantly by benign software
  'cloudflare.com', 'cloudfront.net', 'akamaihd.net', 'akamai.net',
  'akamaized.net', 'fastly.net', 'fastlylb.net',

  // ── Package registries & their CDNs ─────────────────────────────────
  'registry.npmjs.org', 'npmjs.com', 'npmjs.org',
  'pypi.org', 'pythonhosted.org', 'files.pythonhosted.org',
  'rubygems.org', 'crates.io', 'static.crates.io',
  'repo.maven.apache.org', 'repo1.maven.org', 'maven.apache.org',
  'nuget.org', 'api.nuget.org',
  'packagist.org', 'repo.packagist.org',
  'go.dev', 'proxy.golang.org', 'sum.golang.org',
  'hex.pm', 'cpan.org', 'metacpan.org',

  // ── VCS hosts (plain browsing + raw-content subdomains) ─────────────
  'github.com', 'githubusercontent.com', 'githubassets.com',
  'raw.githubusercontent.com', 'codeload.github.com', 'api.github.com',
  'gitlab.com', 'gitlab.io',
  'bitbucket.org', 'bitbucket.io',

  // ── OS / browser update endpoints ───────────────────────────────────
  // Windows Update / Microsoft Store / Defender def-channel
  'update.microsoft.com', 'download.microsoft.com', 'windowsupdate.com',
  'microsoft.com/pkiops', 'go.microsoft.com',
  // Apple software update / App Store
  'swcdn.apple.com', 'swscan.apple.com', 'mzstatic.com', 'apple.com',
  'itunes.apple.com', 'icloud.com',
  // Mozilla auto-updater / add-ons
  'mozilla.org', 'mozilla.net', 'firefox.com', 'addons.mozilla.org',
  // Chrome / Edge update
  'chromium.org', 'googlechrome.com',

  // ── XML namespace / schema URIs (identifiers, not network hosts) ────
  //
  // These show up in every single OOXML, ClickOnce, MSIX manifest, SVG,
  // RSS, plist, etc. They're namespace URIs — not meant to be
  // dereferenced — but they parse as URLs so the regex scoops them up.
  'w3.org', 'xmlns.com', 'schemas.microsoft.com',
  'schemas.openxmlformats.org', 'schemas.xmlsoap.org', 'openoffice.org',
  'oasis-open.org', 'purl.org', 'dublincore.org', 'adobe.com/xap',
  'ns.adobe.com', 'docbook.org', 'relaxng.org',

  // ── Time / NTP anchors ──────────────────────────────────────────────
  'pool.ntp.org', 'time.windows.com', 'time.apple.com', 'time.google.com',
  'time.nist.gov', 'ntp.org',

  // ── Certificate Authorities / OCSP / CRL (signed-binary noise) ──────
  'digicert.com', 'verisign.com', 'geotrust.com', 'thawte.com',
  'sectigo.com', 'entrust.net', 'letsencrypt.org', 'pki.goog',
  'symantec.com', 'globalsign.com', 'usertrust.com',
  'comodoca.com', 'godaddy.com/repository',
  'ocsp.apple.com', 'certs.apple.com',
  'crl.microsoft.com', 'ctldl.windowsupdate.com',
  'valicert.com', 'rootca.com',

  // ── JS / CSS library CDNs (benign dev tooling) ──────────────────────
  'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com', 'bootstrapcdn.com',
  'maxcdn.bootstrapcdn.com', 'jquery.com', 'googleapis.com/ajax',
  'ajax.googleapis.com', 'fonts.googleapis.com', 'fonts.gstatic.com',

  // ── Email / messaging anchors (email IOCs only, not attachment) ─────
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com',
  'yahoo.com', 'icloud.com', 'protonmail.com', 'proton.me',

  // ── Standards orgs / RFC / protocol docs (URLs, not network) ────────
  'ietf.org', 'rfc-editor.org', 'iana.org', 'unicode.org',
  'iso.org', 'itu.int', 'nist.gov',
]);

/**
 * Strip a URL down to its hostname (lower-cased). Pure string work; no
 * tldts dependency so this module can load before / without the vendor
 * library. Returns '' if the value doesn't look like a URL.
 */
function _nicelistHostFromUrl(url) {
  const s = String(url || '').trim();
  // Strip scheme + authority separator
  const m = s.match(/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\/([^/?#]+)/);
  if (!m) return '';
  let host = m[1];
  // Strip userinfo (user:pass@)
  const at = host.lastIndexOf('@');
  if (at >= 0) host = host.slice(at + 1);
  // Strip port
  const colon = host.lastIndexOf(':');
  // IPv6 literal is wrapped in []; only trim port if colon is after the ]
  if (colon >= 0 && host.indexOf(']') < colon) host = host.slice(0, colon);
  // Strip surrounding brackets for IPv6
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  return host.toLowerCase();
}

/**
 * Returns true when `host` equals a nicelist entry OR is a subdomain of
 * one (label-boundary match, so `malicious-amazonaws.com` does NOT match
 * `amazonaws.com`). Entries that contain a path fragment (e.g.
 * `microsoft.com/pkiops`) are ignored here — host-only check.
 */
function _nicelistHostMatches(host) {
  if (!host) return false;
  const h = String(host).toLowerCase();
  for (const entry of NICELIST) {
    // Skip entries with a path fragment; those are handled by the URL
    // branch below. Pure-host entries are the common case.
    if (entry.indexOf('/') >= 0) continue;
    if (h === entry) return true;
    if (h.length > entry.length && h.endsWith('.' + entry)) return true;
  }
  return false;
}

/**
 * Returns true when the URL's host or any path-qualified nicelist entry
 * matches. The path-qualified form (e.g. `microsoft.com/pkiops`) lets us
 * nicelist a narrow PKI sub-surface of a large domain without claiming
 * the whole domain is benign.
 */
function _nicelistUrlMatches(url) {
  const s = String(url || '');
  const host = _nicelistHostFromUrl(s);
  if (host && _nicelistHostMatches(host)) return true;
  // Path-qualified entries: match against the host+path prefix.
  const lower = s.toLowerCase();
  for (const entry of NICELIST) {
    if (entry.indexOf('/') < 0) continue;
    // Look for `://<entry>` OR `//<entry>` inside the URL. Keep simple.
    if (lower.indexOf('://' + entry) >= 0) return true;
  }
  return false;
}

/**
 * Public API: is this IOC value a known-good global-infrastructure
 * surface? Only URL / DOMAIN / HOSTNAME / EMAIL values are ever
 * considered; all other IOC types return false so the nicelist can't
 * ever accidentally suppress a hash, path, command line, etc.
 *
 * @param {string} value  IOC value (URL, domain, hostname, email, …)
 * @param {string} type   IOC.* type constant (from constants.js)
 * @returns {boolean}
 */
function isNicelisted(value, type) {
  if (!value || !type) return false;
  // Built-in nicelist can be disabled from Settings → Nicelists. Persisted
  // as `loupe_nicelist_builtin_enabled` — "0" means off, anything else (or
  // missing) means on. Kept opt-out so first-time users still get the
  // Default Nicelist demoting noise.
  try {
    if (localStorage.getItem('loupe_nicelist_builtin_enabled') === '0') return false;
  } catch (_) { /* storage blocked → treat as enabled */ }

  const v = String(value).trim();
  if (!v) return false;

  // Only these IOC types can be nicelisted. Defensive: we use the string
  // labels from `constants.js` directly rather than the IOC constants,
  // because nicelist.js loads right after constants.js and the values
  // are frozen strings ("URL", "Domain", "Hostname", "Email").
  switch (type) {
    case 'URL':
      return _nicelistUrlMatches(v);
    case 'Domain':
    case 'Hostname':
      return _nicelistHostMatches(v.toLowerCase());
    case 'Email': {
      // Unwrap display-name forms like `Bob Smith <bob.smith@example.com>`
      // so the host match sees `example.com` instead of `example.com>`.
      // We use the LAST `<…>` pair defensively — a quoted display name
      // could in theory contain `<`, and the real address is always the
      // tail bracketed pair.
      let addr = v;
      const lt = addr.lastIndexOf('<');
      const gt = addr.lastIndexOf('>');
      if (lt >= 0 && gt > lt) addr = addr.slice(lt + 1, gt);
      const at = addr.lastIndexOf('@');
      if (at < 0) return false;
      // Strip anything after the first non-host character (stray `>`,
      // trailing `)`, whitespace, …) so the matcher only sees the domain.
      const host = addr.slice(at + 1).toLowerCase().replace(/[^a-z0-9.-].*$/, '');
      return _nicelistHostMatches(host);
    }
    default:
      return false;
  }
}
