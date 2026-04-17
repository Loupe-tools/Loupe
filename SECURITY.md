# Security Policy

## Threat Model

Loupe is a **100 % offline, single-file HTML security analyser**. Its threat
model is deliberately narrow:

| Property | Guarantee |
|----------|-----------|
| **No network access** | A strict `Content-Security-Policy` (`default-src 'none'`) blocks all outbound requests — fetch, XHR, WebSocket, `<img src="https://…">`, `<script src>`, etc. No telemetry, no analytics, no CDN loads. |
| **No server component** | The tool runs entirely inside a single HTML file opened with `file://` or a static host. There is no backend, no API, no database. |
| **No code evaluation** | `eval()`, `new Function()`, and inline event handlers from untrusted content are never used. |
| **Sandboxed previews** | HTML and SVG previews are rendered inside `<iframe sandbox="" srcdoc="…">` with an inner CSP of `default-src 'none'`. Script execution, form submission, and navigation are all blocked inside the preview frame. |
| **Parser safety limits** | Centralised `PARSER_LIMITS` constants enforce: max nesting depth (32), max decompressed size (50 MB), per-entry compression-ratio abort (100×), archive entry cap (10 000), and a 60-second parser timeout. |

### What Loupe does **not** protect against

- **Browser zero-days** — if the browser's own HTML/CSS/image parsers have
  vulnerabilities, Loupe inherits them (as does every web page).
- **Denial-of-service via CPU** — a synchronous parser that enters a tight
  loop cannot be interrupted by the main-thread timeout watchdog; it will
  eventually be killed by the browser's own tab-crash heuristics.
- **Side-channel attacks** — Spectre-class timing side-channels are out of
  scope for a file-analysis tool.

---

## Supported Versions

Only the **latest release** on the `main` branch (published to GitHub Pages)
receives security fixes. There are no LTS branches.

---

## Reporting a Vulnerability

If you discover a security issue in Loupe, please report it **privately**:

1. **GitHub Security Advisories (preferred)**
   → [Open a draft advisory](https://github.com/AuroraSec-dev/Loupe/security/advisories/new)

2. **Email**
   → Send details to the maintainer address listed in the repository's
   GitHub profile. Encrypt with the PGP key published there if available.

Please include:

- A clear description of the issue and its security impact.
- Steps to reproduce, or a proof-of-concept file if applicable.
- The Loupe version or commit hash you tested against.

### What to expect

| Step | Timeframe |
|------|-----------|
| Acknowledgement of your report | **≤ 48 hours** |
| Initial triage and severity assessment | **≤ 7 days** |
| Fix shipped (or mitigation documented) | **≤ 30 days** for critical/high; best-effort for lower severity |
| Public disclosure | Coordinated with reporter; default **90 days** after report |

We will credit reporters in the release notes unless they prefer anonymity.

---

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| Vanilla JS, no npm runtime deps | Zero supply-chain surface from transitive dependencies |
| Vendored libraries committed with pinned SHAs | Auditable, reproducible, air-gap friendly |
| `Content-Security-Policy` meta tag | Defence-in-depth even when served from `file://` (no HTTP headers) |
| `<iframe sandbox="">` for untrusted previews | Strongest browser-native isolation for rendered HTML/SVG |
| `PARSER_LIMITS` constants | Single source of truth for all safety thresholds; easy to audit and tighten |
