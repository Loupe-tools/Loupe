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
//   • Never suppresses YARA detections. If a rule names `apache.org`,
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
//   • **Free-webmail providers are explicitly out-of-scope.** Domains
//     like `gmail.com`, `outlook.com`, `yahoo.com`, `proton.me`,
//     `icloud.com`, `hotmail.com` etc. are deliberately NOT nicelisted:
//     on a triage, any email IOC at one of those hosts is almost
//     certainly the pivot the analyst wants first (phishing sender,
//     credential-stuffing recipient, throwaway exfil inbox). Demoting
//     them to the bottom of the IOC table is the wrong default. If an
//     MDR customer wants to demote their own employees' webmail addrs,
//     that is exactly what the user nicelist (`nicelist-user.js`) is
//     for.
//   • **Public VCS / code-hosting platforms are explicitly out-of-scope.**
//     Domains like `github.com`, `raw.githubusercontent.com`, `gitlab.com`,
//     `bitbucket.org`, `codeberg.org`, `sr.ht`, etc. are deliberately NOT
//     nicelisted: on a triage, any URL landing on one of those hosts is
//     almost certainly the pivot the analyst wants first (staged loader,
//     gist-hosted shell script, poisoned-dependency tarball, raw-content
//     payload drop, tunnelling-client binary). Same reasoning as the
//     free-webmail surfaces above. If an org wants to demote their own
//     internal GitLab mirror or enterprise VCS host, that is exactly what
//     the user nicelist (`nicelist-user.js`) is for.
//   • **Serverless / PaaS hosting surfaces are explicitly out-of-scope.**
//     `*.appspot.com` (App Engine) and `*.firebaseio.com` (Firebase RTDB)
//     in particular are heavily abused for phishing-kit hosting and
//     low-effort exfil / C2 via open Realtime-DB endpoints. Kept off the
//     list for the same reason as VCS hosts.
//
// The list is deliberately narrow; every entry should be pasteable into
// a threat-intel chat and get a nod of "yeah, that's infrastructure".

const NICELIST = Object.freeze([
  // ── Cloud provider APIs & instance metadata ─────────────────────────
  // AWS (STS, IAM, S3, metadata-service proxy endpoints, Cognito, …)
  'amazonaws.com', 'aws.amazon.com', 'awsstatic.com', 'amazon.com',
  // Google Cloud (GCE metadata, APIs, gstatic CDN, …). `appspot.com`
  // (App Engine) and `firebaseio.com` (Firebase RTDB) are deliberately
  // absent — see the out-of-scope note at the top of the file.
  'metadata.google.internal', 'googleapis.com', 'gstatic.com',
  'google.com', 'googleusercontent.com',
  // Azure / Microsoft Graph / M365 auth. `live.com` is Microsoft auth
  // plumbing here (login.live.com, onedrive.live.com), NOT the free
  // webmail surface — see the out-of-scope note at the top of the file.
  'azure.com', 'azureedge.net', 'windows.net', 'core.windows.net',
  'microsoftonline.com', 'msft.net', 'msftauth.net',
  'live.com', 'office.com', 'office365.com', 'sharepoint.com',
  'onedrive.com',
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
  'go.dev', 'pkg.go.dev', 'proxy.golang.org', 'sum.golang.org',
  'hex.pm', 'cpan.org', 'metacpan.org',
  'plugins.gradle.org', 'repo.gradle.org',

  // ── Container registries ────────────────────────────────────────────
  // Pulls and image references from benign Dockerfiles, Kubernetes
  // manifests, Helm charts, SBOMs, build logs, etc. `mcr.microsoft.com`
  // is the Microsoft Container Registry (distinct from the PKI/update
  // surfaces kept under `microsoft.com/...` path-scope).
  'docker.io', 'docker.com', 'quay.io',
  'ghcr.io', 'gcr.io', 'mcr.microsoft.com',
  'k8s.io', 'kubernetes.io',

  // ── Language ecosystems / toolchain homes ───────────────────────────
  // Documentation / download / release surfaces for major toolchains.
  // These show up in every sample that ships a runtime, a crash report,
  // or an installer stub.
  'nodejs.org', 'python.org', 'rust-lang.org', 'swift.org',
  'golang.org', 'java.com', 'hashicorp.com', 'terraform.io',

  // ── VCS hosts ───────────────────────────────────────────────────────
  // Deliberately empty. Public code-hosting platforms (GitHub, GitLab,
  // Bitbucket, Codeberg, sr.ht, Pagure, …) are out-of-scope for the
  // default nicelist — see the non-goals block at the top of the file.
  // Demote your own internal VCS mirrors via `nicelist-user.js`.

  // ── OS distributions (package mirrors, release notes, docs) ─────────
  'debian.org', 'ubuntu.com', 'archlinux.org', 'fedoraproject.org',
  'redhat.com', 'kernel.org',

  // ── OS / browser update endpoints ───────────────────────────────────
  // Windows Update / Microsoft Store / Defender def-channel
  'update.microsoft.com', 'download.microsoft.com', 'windowsupdate.com',
  'microsoft.com/pkiops', 'go.microsoft.com',
  // Microsoft PKI surfaces referenced in Authenticode-signed binaries:
  // `www.microsoft.com/pki/certs/...` (MicRootCA, MicCodSigPCA .crt)
  // and `www.microsoft.com/PKI/docs/CPS/...` CPS documents. Kept
  // path-scoped — the bare `microsoft.com` stays off the list because
  // it is a heavy homoglyph target (see top-of-file non-goals).
  'microsoft.com/pki', 'www.microsoft.com/pki',
  'www.microsoft.com/pkiops',
  // Apple software update / App Store. `icloud.com` is kept here for
  // shared-links / iCloud-Drive noise, NOT for @icloud.com mail pivots —
  // the Email branch in `isNicelisted` still matches, which is an
  // accepted trade-off: iCloud email IOCs are rare and the Apple
  // software-update surface is very noisy.
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
  // `microsoft.com` stays deliberately absent (huge homoglyph target);
  // only the narrow PKI and marketing-redirect paths are whitelisted,
  // and `schemas.microsoft.com` covers the namespace identifiers.
  'w3.org', 'xmlns.com', 'schemas.microsoft.com',
  'schemas.openxmlformats.org', 'schemas.xmlsoap.org', 'openoffice.org',
  'oasis-open.org', 'purl.org', 'dublincore.org', 'adobe.com/xap',
  'ns.adobe.com', 'docbook.org', 'relaxng.org',
  'schema.org', 'spdx.org', 'creativecommons.org',

  // ── Open-source foundations / licence homes ─────────────────────────
  // Referenced by every LICENSE / NOTICE / manifest.json / pom.xml.
  'apache.org', 'eclipse.org', 'opensource.org', 'gnu.org', 'fsf.org',
  // Oracle Java licence / release-notes URLs show up in every JAR
  // MANIFEST.MF and most Windows Java installers. Big corp tent, but
  // the noise-to-signal on Oracle.com in triage is genuinely dismal.
  'oracle.com',

  // ── Time / NTP anchors ──────────────────────────────────────────────
  'pool.ntp.org', 'time.windows.com', 'time.apple.com', 'time.google.com',
  'time.nist.gov', 'ntp.org',

  // ── Certificate Authorities / OCSP / CRL (signed-binary noise) ──────
  //
  // Parent-domain matching covers most CAs (e.g. `digicert.com` picks
  // up `ocsp.digicert.com`). The separate-reg-domain responders below
  // need explicit entries because they are NOT subdomains of their
  // parent CA: `lencr.org` is Let's Encrypt's OCSP/CRL CDN (not a
  // subdomain of `letsencrypt.org`), `identrust.com` cross-signs LE,
  // `starfieldtech.com` is GoDaddy's OCSP responder, `ssl.com` is a
  // mid-volume CA, and `trust-provider.com` is Sectigo's OCSP host.
  'digicert.com', 'verisign.com', 'geotrust.com', 'thawte.com',
  'sectigo.com', 'entrust.net', 'letsencrypt.org', 'pki.goog',
  'symantec.com', 'globalsign.com', 'usertrust.com',
  'comodoca.com', 'godaddy.com/repository',
  'ocsp.apple.com', 'certs.apple.com',
  'crl.microsoft.com', 'ctldl.windowsupdate.com',
  'valicert.com', 'rootca.com',
  'lencr.org', 'identrust.com', 'starfieldtech.com',
  'ssl.com', 'trust-provider.com',
  // Symantec's legacy code-signing OCSP/CRL CDNs (separate reg-domains,
  // NOT subdomains of `symantec.com`). Still referenced in Authenticode
  // signatures on older signed binaries: `symcb.com` = CRL distribution,
  // `symcd.com` = OCSP responder.
  'symcb.com', 'symcd.com',
  // Microsoft OCSP responder — separate reg-domain from `microsoft.com`,
  // referenced in Authenticode timestamp chains.
  'msocsp.com',
  // Other mainstream public CAs whose OCSP / CRL / timestamp fetches
  // turn up as IOCs on any signed executable, installer, driver, or
  // S/MIME message:
  'quovadisglobal.com', 'buypass.com', 'swisssign.net',
  'certum.pl', 'actalis.it', 'rapidsslonline.com',

  // ── JS / CSS library CDNs (benign dev tooling) ──────────────────────
  'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com', 'bootstrapcdn.com',
  'maxcdn.bootstrapcdn.com', 'jquery.com', 'googleapis.com/ajax',
  'ajax.googleapis.com', 'fonts.googleapis.com', 'fonts.gstatic.com',

  // ── Standards orgs / RFC / protocol docs (URLs, not network) ────────
  'ietf.org', 'rfc-editor.org', 'iana.org', 'unicode.org',
  'iso.org', 'itu.int', 'nist.gov',

  // NOTE: free-webmail providers (gmail.com, outlook.com, yahoo.com,
  // hotmail.com, proton.me, protonmail.com, googlemail.com, …), public
  // VCS hosts (github.com, gitlab.com, bitbucket.org, codeberg.org,
  // sr.ht, …), and serverless-abuse surfaces (appspot.com, firebaseio.com)
  // are deliberately NOT in this list. See the out-of-scope block at the
  // top of the file before re-adding any of them.
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
  if (safeStorage.get('loupe_nicelist_builtin_enabled') === '0') return false;

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
