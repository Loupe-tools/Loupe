#!/usr/bin/env python3
"""Build script: assembles loupe.html from source files.

Reproducible-build support
--------------------------
Given a fixed commit, `python scripts/build.py` produces byte-identical
output. The only time-derived byte in the bundle is the embedded
``LOUPE_VERSION`` string, which is resolved in this order:

  1. ``SOURCE_DATE_EPOCH``  (the reproducible-builds.org standard) — used
     verbatim if set. This is the path CI takes at release time.
  2. The commit-author timestamp of ``HEAD`` in the current git checkout —
     used automatically when step 1 is unset. This makes local contributor
     builds deterministic too (two contributors at the same commit get the
     same bundle bytes), without anyone having to remember an env var.
  3. Wall-clock ``datetime.now()`` — last-resort fallback for source
     archives that are not a git checkout.

See SECURITY.md § Reproducible Build for the full recipe and non-goals.
"""
import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone

# scripts/build.py → repo root is the parent of this file's directory.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Local helper modules live alongside build.py in scripts/.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── --test-api flag ──────────────────────────────────────────────────────────
# When set, the build:
#   * appends `src/app/app-test-api.js` to APP_JS_FILES so the
#     `window.__loupeTest` test surface is wired up,
#   * prepends `const __LOUPE_TEST_API__ = true;` to Block 1 so other code
#     can statically detect the test build (and so the leak-gate has a
#     unique sentinel string to search for in the released bundle),
#   * writes the output to `docs/index.test.html` instead of
#     `docs/index.html`.
#
# This bundle is NEVER deployed to Pages and NEVER signed for release — the
# release pipeline (.github/workflows/release.yml + signed Sigstore artefact)
# only ever consumes `docs/index.html`. See `_check_no_test_api_in_release`
# below for the defence-in-depth gate that confirms the test-api markers
# never reach the released bundle.
_argparser = argparse.ArgumentParser(
    description='Build Loupe — emits docs/index.html (release) or '
                'docs/index.test.html (with --test-api, never released).',
)
_argparser.add_argument(
    '--test-api', action='store_true',
    help='Emit docs/index.test.html with window.__loupeTest exposed. '
         'Never ship — see scripts/build.py header comment.',
)
# `parse_known_args` so a future `python make.py build` orchestrator pass-
# through still works (make.py invokes this script with no extra args today).
_args, _unknown = _argparser.parse_known_args()
TEST_API = bool(_args.test_api)

_epoch = os.environ.get('SOURCE_DATE_EPOCH')
if not _epoch:
    # Git-checkout fallback: use HEAD's commit-author timestamp so local
    # builds are reproducible without the contributor having to export
    # SOURCE_DATE_EPOCH themselves. Silently falls through to wall-clock
    # time if this isn't a git checkout or git isn't on PATH.
    try:
        _res = subprocess.run(
            ['git', 'log', '-1', '--format=%ct', 'HEAD'],
            cwd=BASE, capture_output=True, text=True, timeout=5, check=False,
        )
        _out = _res.stdout.strip()
        if _res.returncode == 0 and _out.isdigit():
            _epoch = _out
    except (OSError, subprocess.TimeoutExpired):
        pass

if _epoch:
    VERSION = datetime.fromtimestamp(int(_epoch), tz=timezone.utc).strftime('%Y%m%d.%H%M')
else:
    VERSION = datetime.now().strftime('%Y%m%d.%H%M')

def read(rel):
    with open(os.path.join(BASE, rel), 'r', encoding='utf-8') as f:
        return f.read()

jszip        = read('vendor/jszip.min.js')
xlsx_js      = read('vendor/xlsx.full.min.js')
pdf_js       = read('vendor/pdf.min.js')
pdf_wrk_js   = read('vendor/pdf.worker.min.js')
highlight_js = read('vendor/highlight.min.js')
utif_js      = read('vendor/utif.min.js')
exifr_js     = read('vendor/exifr.min.js')
tldts_js     = read('vendor/tldts.min.js')
# Strip the sourceMappingURL comment — the map file doesn't exist inside the
# single-file build, so the browser would 404 and log a console error.
import re as _re
tldts_js = _re.sub(r'\n?//[#@]\s*sourceMappingURL=\S+', '', tldts_js)
pako_js      = read('vendor/pako.min.js')
lzma_js      = read('vendor/lzma-d-min.js')
jsqr_js      = read('vendor/jsqr.min.js')

# ── Bundled GeoIP IPv4-country binary ───────────────────────────────────────
# `vendor/geoip-country-ipv4.bin` is a hand-rolled fixed-record binary
# produced by `scripts/fetch_geoip.py` from the five RIR delegated-stats
# files (a public-domain source — no licence friction). 850 KB raw → 1.13 MB
# base64. Inlined as a JS string constant so `src/geoip/bundled-geoip.js`
# can decode it at module load and answer IPv4 → ISO-2 lookups offline.
# See `VENDORED.md` (Generated vendored assets) for the regenerate vs
# upgrade distinction; see `scripts/fetch_geoip.py` for the pipeline.
import base64 as _base64
with open(os.path.join(BASE, 'vendor', 'geoip-country-ipv4.bin'), 'rb') as _gf:
    _geoip_b64 = _base64.b64encode(_gf.read()).decode('ascii')
geoip_bundle_js = f"const __GEOIP_BUNDLE_B64 = '{_geoip_b64}';\n"

# CSS files — concatenated in order.
# Each optional theme overlay lives in src/styles/themes/<id>.css and contains
# `body.theme-<id> { … }` rules that layer on top of the base palette.
# To add a new theme: drop a file here AND add a row to the THEMES array in
# src/app/app-ui.js. No other wiring required.
CSS_FILES = [
    'src/styles/core.css',
    'src/styles/viewers.css',
    'src/styles/themes/midnight.css',
    'src/styles/themes/solarized.css',
    'src/styles/themes/mocha.css',
    'src/styles/themes/latte.css',
]

css = ''.join(read(f) for f in CSS_FILES)

# Default YARA rules — split by category, concatenated and injected as a JS constant
YARA_FILES = [
    'src/rules/office-macros.yar',
    'src/rules/script-threats.yar',
    'src/rules/document-threats.yar',
    'src/rules/windows-threats.yar',
    'src/rules/archive-threats.yar',
    'src/rules/encoding-threats.yar',
    'src/rules/network-indicators.yar',
    'src/rules/suspicious-patterns.yar',
    'src/rules/file-analysis.yar',
    'src/rules/pe-threats.yar',
    'src/rules/elf-threats.yar',
    'src/rules/macho-threats.yar',
    'src/rules/jar-threats.yar',
    'src/rules/svg-threats.yar',
    'src/rules/osascript-threats.yar',
    'src/rules/plist-threats.yar',
    'src/rules/clickonce-threats.yar',
    'src/rules/msix-threats.yar',
    'src/rules/browserext-threats.yar',
    'src/rules/macos-installer-threats.yar',
    'src/rules/npm-threats.yar',
    'src/rules/wasm-threats.yar',
    'src/rules/pcap-threats.yar',
    'src/rules/discovery-threats.yar',
    'src/rules/reassembled-payloads.yar',
]

YARA_CATEGORIES = {
    'src/rules/office-macros.yar': 'Office Macros',
    'src/rules/script-threats.yar': 'Script',
    'src/rules/document-threats.yar': 'Document',
    'src/rules/windows-threats.yar': 'Windows',
    'src/rules/archive-threats.yar': 'Archive',
    'src/rules/encoding-threats.yar': 'Encoding',
    'src/rules/network-indicators.yar': 'Network Indicators',
    'src/rules/suspicious-patterns.yar': 'Suspicious Patterns',
    'src/rules/file-analysis.yar': 'File Analysis',
    'src/rules/pe-threats.yar': 'PE',
    'src/rules/elf-threats.yar': 'ELF',
    'src/rules/macho-threats.yar': 'Mach-O',
    'src/rules/jar-threats.yar': 'JAR',
    'src/rules/svg-threats.yar': 'SVG',
    'src/rules/osascript-threats.yar': 'AppleScript/JXA',
    'src/rules/plist-threats.yar': 'Property List',
    'src/rules/clickonce-threats.yar': 'ClickOnce',
    'src/rules/msix-threats.yar': 'MSIX / APPX',
    'src/rules/browserext-threats.yar': 'Browser Extension',
    'src/rules/macos-installer-threats.yar': 'macOS Installer',
    'src/rules/npm-threats.yar': 'npm',
    'src/rules/wasm-threats.yar': 'WebAssembly',
    'src/rules/pcap-threats.yar': 'Packet Capture',
    'src/rules/discovery-threats.yar': 'Discovery',
    'src/rules/reassembled-payloads.yar': 'Reassembled Payloads',
}

# ── File-level `applies_to` injection ──────────────────────────────────────
#
# `YaraEngine` (src/yara-engine.js) supports `meta: applies_to = "..."` per-rule
# gates that short-circuit a rule when the host-detected file format
# (`formatTag`, computed in `render-route.js`) doesn't match. Rule files where
# every rule applies to the same format register a single value here and the
# build script auto-injects `applies_to = "<value>"` into each rule's meta
# block at concatenation time. This avoids 50+ duplicated meta lines across
# files like `plist-threats.yar` / `jar-threats.yar` / `osascript-threats.yar`
# without violating the no-`//`-comments-in-.yar constraint (the injection
# happens in build.py — the source files stay comment-free).
#
# Per-rule override: if a rule already declares its own `applies_to` value the
# injection is a no-op for that rule. Rules with no `meta:` block at all get a
# fresh `meta:` block prepended with the `applies_to` line.
#
# Empty by default. Populated as rule-migration PRs land for each format-bound
# file. Group aliases (`office`, `office_ooxml`, `script`, etc.) are accepted
# — see `YaraEngine.FORMAT_PREDICATES`.
YARA_APPLIES_TO = {
    # Native binaries — every rule is anchored on the format magic. Engine-
    # level gating skips them entirely on unrelated content.
    'src/rules/pe-threats.yar':              'pe',
    'src/rules/file-analysis.yar':           'pe',
    'src/rules/elf-threats.yar':             'elf',
    'src/rules/macho-threats.yar':           'macho',
    # Format-bound document/manifest/script files. Each rule's strings are
    # specific to the named format but lacked an anchored magic-byte gate;
    # `applies_to` provides that gate at the engine level.
    'src/rules/jar-threats.yar':             'jar',
    'src/rules/svg-threats.yar':             'svg',
    'src/rules/plist-threats.yar':           'plist',
    'src/rules/osascript-threats.yar':       'scpt',
    'src/rules/clickonce-threats.yar':       'clickonce',
    'src/rules/msix-threats.yar':            'msix',
    'src/rules/browserext-threats.yar':      'browserext',
    'src/rules/npm-threats.yar':             'npm',
    # Office-macro rules cover legacy OLE (doc/xls/ppt/msg), OOXML
    # (docx/xlsx/pptx) and ODF (odt/ods/odp) hosts plus RTF (the third
    # magic 0x74725C7B in most rules). `is_office` expands to the 12
    # office-host formats; `rtf` is appended as a bare formatTag so the
    # RTF-specific OLE-object / DDE rules in the file still fire on .rtf
    # input. Without this gate the rules' `uint16(0) == 0x4B50` clause
    # would also accept any non-office ZIP container (jar/msix/npm/etc).
    'src/rules/office-macros.yar':           'is_office, rtf',
    # NB: `wasm-threats.yar` is intentionally NOT in YARA_APPLIES_TO. The
    # `Info_Contains_WebAssembly` rule must fire on embedded WASM blobs in
    # *any* container (script, PE overlay, archive entry, etc.); gating the
    # whole file with `applies_to: wasm` would suppress that. Each rule
    # already short-circuits on `uint32(0) == 0x6d736100`, so the cost on
    # non-WASM input is one i32 read per rule.
    # Mixed files — the file-level value covers the majority case; the
    # exceptional rules carry their own `applies_to` in source which the
    # injector treats as a no-op (already-set ⇒ skip).
    'src/rules/macos-installer-threats.yar': 'dmg',     # PKG_Xar_Archive overrides to "pkg"
    'src/rules/archive-threats.yar':         'zip_plain', # RAR/7z/ISO rules override
}


# Inject `applies_to = "<value>"` into every rule body in `raw` that doesn't
# already declare its own. Pure source transformation — deterministic for any
# given (raw, value) pair. No regex backtracking pathologies (uses iterative
# brace-balance scanning). Rules without a `meta:` block get one inserted as
# the first section (before `strings:` / `condition:`).
def _inject_applies_to(raw: str, value: str) -> str:
    if not value:
        return raw
    out = []
    pos = 0
    n = len(raw)
    # Match `rule <name> [: tags] {` exactly the way the engine does. We
    # walk each rule block by brace balance because the rule body itself
    # contains `{ … }` for hex strings — a naive regex would mis-end at
    # the first `}`.
    import re
    rule_hdr = re.compile(r'\brule\s+\w+\s*(?::\s*[\w\s]+)?\s*\{', re.MULTILINE)
    for m in rule_hdr.finditer(raw):
        # Emit text up to and including the opening `{`.
        out.append(raw[pos:m.end()])
        # Find the matching `}` by brace balance, skipping over string
        # literals (where braces are data, not structure). Hex-pattern
        # braces (`{ AA BB CC }`) are part of `= { … }` assignments — they
        # legitimately balance because the YARA grammar always pairs them.
        depth = 1
        i = m.end()
        in_str = False
        in_regex = False
        while i < n and depth > 0:
            ch = raw[i]
            if in_str:
                if ch == '\\' and i + 1 < n:
                    i += 2
                    continue
                if ch == '"':
                    in_str = False
            elif in_regex:
                if ch == '\\' and i + 1 < n:
                    i += 2
                    continue
                if ch == '/':
                    in_regex = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        break
                elif ch == '/' and i + 1 < n and raw[i + 1] not in ('/', '*'):
                    # Only treat `/` as a regex delimiter when it follows
                    # an `=` (string assignment) — anything else (e.g. a
                    # division-like token in a YARA condition) doesn't
                    # exist in this engine's grammar.
                    j = i - 1
                    while j >= 0 and raw[j] in (' ', '\t'):
                        j -= 1
                    if j >= 0 and raw[j] == '=':
                        in_regex = True
            i += 1
        if depth != 0:
            # Malformed rule block — bail and emit the rest unmodified.
            out.append(raw[m.end():])
            return ''.join(out)
        body = raw[m.end():i]
        body = _inject_applies_to_into_body(body, value)
        out.append(body)
        out.append('}')
        pos = i + 1
    out.append(raw[pos:])
    return ''.join(out)


def _inject_applies_to_into_body(body: str, value: str) -> str:
    """Insert `applies_to = "<value>"` into a single rule's body. Skips the
    rule if it already declares its own applies_to. Adds a meta: block when
    none exists. Used by `_inject_applies_to`.

    The inserted line's indent matches the surrounding meta block (some rule
    files use 4-space indent, most use 8-space) and the line is placed
    immediately after the last meta entry — any trailing blank line in the
    meta block is preserved between applies_to and strings:/condition:, so
    house style is unchanged."""
    import re
    # Already has applies_to anywhere in the body — leave the rule alone.
    if re.search(r'\bapplies_to\s*=\s*"', body):
        return body
    meta_match = re.search(r'(\bmeta\s*:)([\s\S]*?)(?=\bstrings\s*:|\bcondition\s*:|$)',
                           body, re.IGNORECASE)
    if not meta_match:
        # No meta block — synthesise one as the first section. The opening
        # newline keeps us off whatever whitespace the rule body started
        # with.
        return f'\n    meta:\n        applies_to = "{value}"\n' + body
    meta_kw = meta_match.group(1)
    meta_inner = meta_match.group(2)
    # Detect the indent used by the first existing meta entry — fall back
    # to 8 spaces when the meta block is empty. Also detect the `=` column
    # used by surrounding entries so applies_to lines up visually.
    indent = '        '
    eq_col = None  # column index where `=` should land (None ⇒ 1 space pad)
    for ln in meta_inner.splitlines():
        stripped = ln.lstrip(' \t')
        if stripped:
            cur_indent = ln[:len(ln) - len(stripped)]
            if eq_col is None:
                indent = cur_indent
            # Track the column where `=` itself sits on any meta entry;
            # this is the column the source file aligns to.
            if '=' in stripped:
                col = len(cur_indent) + stripped.index('=')
                if eq_col is None or col > eq_col:
                    eq_col = col
    if eq_col is not None:
        pad_len = max(1, eq_col - len(indent) - len('applies_to'))
    else:
        pad_len = 1
    line = f'{indent}applies_to{" " * pad_len}= "{value}"\n'
    # Split the meta block into the last non-blank line and any trailing
    # whitespace-only suffix (typically a blank line + indented spaces
    # leading to `strings:`). Insert applies_to after the content, before
    # the trailing whitespace, so the file's house style is preserved.
    m_tail = re.search(r'\n([ \t]*(?:\n[ \t]*)*)$', meta_inner)
    if m_tail:
        head = meta_inner[:m_tail.start()] + '\n'
        tail = m_tail.group(0)[1:]  # drop the leading \n we kept on `head`
        new_meta = meta_kw + head + line + tail
    else:
        new_meta = meta_kw + meta_inner + line
    return body[:meta_match.start()] + new_meta + body[meta_match.end():]


_missing_applies_to = [f for f in YARA_APPLIES_TO if f not in YARA_FILES]
if _missing_applies_to:
    raise SystemExit(
        'YARA_APPLIES_TO references files not in YARA_FILES: '
        + ', '.join(_missing_applies_to)
    )


# H8 — Category-marker robustness.
#
# The pre-H8 marker was a `// @category: <NAME>` line comment matched
# by `app-yara.js` with a free-text regex. Two failure modes:
#
#   1. A rule string literal (e.g. `$s = "// @category: Hacked"`) anywhere
#      in any concatenated `.yar` file silently truncated the previous
#      category and started a new one with the wrong name.
#   2. A rule file added to `YARA_FILES` but missing from
#      `YARA_CATEGORIES` was silently labelled `Other`.
#
# Fix: emit a sentinel block comment that the rule files are statically
# verified not to contain (`@loupe-category` is a forbidden substring in
# `.yar` source — `_check_yara_category_sentinel` enforces it), and make
# the missing-category case a hard build failure.
_YARA_CATEGORY_SENTINEL = '@loupe-category'  # must never appear in .yar source

# Every file we concatenate must have an explicit category — silent fall-
# back to "Other" hides bugs (file added to YARA_FILES but the contributor
# forgot to add it to YARA_CATEGORIES). H8.
_missing_categories = [f for f in YARA_FILES if f not in YARA_CATEGORIES]
if _missing_categories:
    raise SystemExit(
        'YARA_CATEGORIES is missing entries for: '
        + ', '.join(_missing_categories)
        + '\nAdd a row to YARA_CATEGORIES in scripts/build.py.'
    )

yar_parts = []
for f in YARA_FILES:
    cat = YARA_CATEGORIES[f]
    raw = read(f)
    # Defence in depth: refuse to emit a bundle if any rule file already
    # contains the sentinel substring (an attacker-authored rule with a
    # `$s = "/*! @loupe-category: Spoofed */"` literal would otherwise
    # spoof the category split). H8.
    if _YARA_CATEGORY_SENTINEL in raw:
        raise SystemExit(
            f'{f} contains the reserved category sentinel '
            f'"{_YARA_CATEGORY_SENTINEL}". Rule files must not embed '
            'this token in any string, identifier, or (forbidden)'
            ' comment — see scripts/build.py:_YARA_CATEGORY_SENTINEL.'
        )
    # Optional file-level `applies_to` injection. Pure source rewrite;
    # deterministic for a given (raw, value) input pair.
    applies_to_val = YARA_APPLIES_TO.get(f)
    if applies_to_val:
        raw = _inject_applies_to(raw, applies_to_val)
    yar_parts.append(f'/*! @loupe-category: {cat} */')
    yar_parts.append(raw)
yar_rules = '\n'.join(yar_parts)

# Escape backticks and backslashes for JS template literal
yar_rules_escaped = yar_rules.replace('\\', '\\\\').replace('`', '\\`').replace('${', '\\${')
default_yara_js = f'const DEFAULT_YARA_RULES = `{yar_rules_escaped}`;\n'

# `EncodedContentDetector` is split across `src/encoded-content-detector.js`
# (the class root with constructor / static tables / scan orchestrator) and
# nine helper modules under `src/decoders/` that attach instance methods via
# `Object.assign(EncodedContentDetector.prototype, {...})` and one static
# (`unwrapSafeLink`). Order matters — the class root MUST load first; the
# helpers can load in any order after that, but we keep the listing
# deterministic for byte-reproducible builds. This list is splatted into
# `JS_FILES` (main bundle) and concatenated into `_encoded_worker_bundle_src`
# (worker bundle) so the two stay in sync. See CONTRIBUTING.md →
# Encoded-content split.
# _DETECTOR_FILES — authoritative list in build/js_sources.py.
from build.js_sources import _DETECTOR_FILES  # noqa: E402



# ── Three-group JS load order (Tier 3 reorder) ───────────────────────────────
# The bundle is emitted as **three** separate `<script>` blocks (instead of
# one mega-block sitting after every vendor) so the App's drag-and-drop
# listeners can be wired before the slowest vendor compiles. The breakdown:
#
#   • EARLY_JS_FILES   — pre-App essentials. Capture-phase drag/drop/paste
#                        glue that buffers files into
#                        `window.__loupePendingDrop` /
#                        `window.__loupePendingPaste` during the cold-load
#                        window. Must beat every other inline `<script>` to
#                        the parser. Today the only entry is
#                        `src/app/early-drop-bootstrap.js`.
#   • APP_JS_FILES     — the App bundle itself (constants, helpers, every
#                        renderer, the App class + Object.assign mixins).
#                        `Object.assign(App.prototype, …)` ordering is
#                        load-bearing inside this list — see the comments
#                        on individual entries. The trailing
#                        `new App().init();` call lives at the end of
#                        `app-breadcrumbs.js` — the LAST file in this list
#                        (synchronous — no DOMContentLoaded wrapper, see
#                        comment there) so it fires after every
#                        `Object.assign(App.prototype, …)` mixin has
#                        landed its methods on the prototype.
#   • Group C — heavy renderer-only vendors (JSZip / SheetJS / pdf.js /
#                        highlight.js / UTIF / exifr / tldts / pako / LZMA
#                        / jsQR). Emitted *after* the App `<script>` so
#                        their compile cost no longer blocks
#                        `App._setupDrop()` from binding listeners. They
#                        live as plain `read()` constants in this file —
#                        see the HTML template at the bottom for ordering.
#                        `pushIOC` and the renderer dispatch are the only
#                        consumers and both fire post-load (asynchronous
#                        FileReader → RenderRoute pipeline), so by the
#                        time any of them reach into a vendor global
#                        every Group C `<script>` has parsed.
#
# Build gates iterate `EARLY_JS_FILES + APP_JS_FILES` so coverage is
# preserved across the split.
# EARLY_JS_FILES / APP_JS_FILES — authoritative list in build/js_sources.py.
from build.js_sources import APP_JS_FILES, EARLY_JS_FILES  # noqa: E402


# `--test-api` builds append the `window.__loupeTest` surface AFTER every
# regular App mixin so it can reuse `extendApp(...)` and
# `_resetNavStack` / `_loadFile` / `_yaraScanInProgress`. Strictly opt-in:
# release builds never include this file. The leak-gate
# `_check_no_test_api_in_release` (run when TEST_API is False) re-validates
# the released bundle does not contain the `__loupeTest` /
# `__LOUPE_TEST_API__` markers.
#
# Note: `new App().init();` lives at the END of `app-breadcrumbs.js` and is
# already statically embedded in that file's source — so the test-api file
# loads AFTER the kick-off statement parsed, but BEFORE the app's first
# microtask resolves (everything is synchronous on the page-load tick), so
# the `(function(){ window.__loupeTest = … })()` IIFE at the bottom of
# `app-test-api.js` is guaranteed to see `window.app` already populated.
# That's why the IIFE polls instead of capturing once — the `init()` call
# may schedule a setTimeout / requestIdleCallback before the App handle is
# observable on the timeline; polling is cheap and tolerant.
if TEST_API:
    APP_JS_FILES.append('src/app/app-test-api.js')

# ── Pre-build gates (shared with make.py; skip via LOUPE_SKIP_GATES=1) ───────
if os.environ.get('LOUPE_SKIP_GATES') != '1':
    from build.pipeline import run_pre_build_gates  # noqa: E402
    _gate_rc = run_pre_build_gates()
    if _gate_rc != 0:
        raise SystemExit(_gate_rc)

# Group A — pre-App essentials. Emitted as a standalone <script> block
# *before* the heavy renderer vendors so its drag/drop/paste handlers
# beat the slowest vendor compile to the parser. See EARLY_JS_FILES
# above for the contract.
early_drop_js = '\n'.join(read(f) for f in EARLY_JS_FILES)


# ── Worker bundles ───────────────────────────────────────────────────────────
# `src/workers/*.worker.js` modules run inside `WorkerGlobalScope` (no DOM,
# no `window`, no `app.*`). They cannot share a `<script>` block with the
# main bundle, so each worker is read here, concatenated with the helpers
# it needs (in C1: `yara-engine.js`), and emitted as a single JS template-
# literal constant. `src/worker-manager.js` materialises a Worker at
# runtime via `URL.createObjectURL(new Blob([__YARA_WORKER_BUNDLE_SRC]))`.
#
# The worker files are deliberately NOT in `JS_FILES`:
#   • They must not run on the main thread.
#   • Excluding them keeps the existing build gates (risk pre-stamping,
#     bare-IOC types, `_rawText` LF-normalisation, worker-spawn allow-list)
#     from iterating worker-only code that has no business obeying any of
#     those rules.
# Worker source itself is still subject to the same `.clinerules` ban on
# `eval` / `new Function` / network — review at the file level, not via a
# build gate.
#
# These are defined here (before the Tier 5 block split below) so the
# `_block_srcs[0]` prepend sequence can reference them.
#
# See CONTRIBUTING.md → Worker subsystem.
def _esc_for_template(s: str) -> str:
    """Escape a string for a JS template literal (backticks, backslashes, ${)."""
    return s.replace('\\', '\\\\').replace('`', '\\`').replace('${', '\\${')

_yara_worker_bundle_src = read('src/yara-engine.js') + '\n' + read('src/workers/yara.worker.js')
yara_worker_js = (
    'const __YARA_WORKER_BUNDLE_SRC = `'
    + _esc_for_template(_yara_worker_bundle_src)
    + '`;\n'
)

# Timeline parse-only worker.
# Bundle order matters — the shim defines `RENDER_LIMITS`, `EVTX_COLUMN_ORDER`,
# `TIMELINE_MAX_ROWS`, the `IOC` proxy, and the `escalateRisk` / `pushIOC` /
# `lfNormalize` no-op stubs the renderer sources reach for at module load.
# `row-store.js` sits between the shim and the renderers so the worker-side
# `packRowChunk` / `RowStore` / `RowStoreBuilder` symbols are defined before
# `timeline.worker.js::_parseCsv` calls them; the SAME file is also in
# APP_JS_FILES (main bundle) so the host receives the chunks the worker
# packs and assembles them into a `RowStore` of its own.
# The renderers then concatenate in the same order the main bundle uses
# (csv → sqlite → evtx → pcap). The timeline.worker.js trailer carries the
# parse functions and the `self.onmessage` dispatcher. EvtxDetector and
# `PcapRenderer._analyzePcapInfo` are deliberately NOT invoked from the
# worker — analysis runs on the main thread (the analyser path uses
# `pushIOC` / `IOC.*` / `escalateRisk` globals that only the main bundle
# defines). The worker only calls `PcapRenderer._parsePcap` /
# `_parsePcapng` (pure parsers) plus `_streamPacketRows` / `_pktToRow`
# (pure formatters).
_timeline_worker_bundle_src = (
    read('src/workers/timeline-worker-shim.js') + '\n'
    + read('src/app/timeline/timeline-parser-helpers.js') + '\n'
    + read('src/row-store.js') + '\n'
    + read('src/renderers/csv-renderer.js') + '\n'
    + read('src/renderers/sqlite-renderer.js') + '\n'
    + read('src/renderers/evtx-renderer.js') + '\n'
    + read('src/renderers/pcap-renderer.js') + '\n'
    + read('src/workers/timeline.worker.js')
)

# ── Dual-bundle invariant: row-store.js MUST be in BOTH bundles ─────────────
# `src/row-store.js` defines `RowStore` / `RowStoreBuilder` / `packRowChunk`,
# which are referenced by main-thread consumers (GridViewer, every grid
# renderer, the Timeline route) AND by the timeline parse-only worker
# (which packs rows into chunks via `packRowChunk` and posts them as
# transferable typed-array buffers). The two copies must stay in sync —
# they're literally the same source file concatenated into both bundles.
#
# These asserts make a future "let's split row-store into a worker-only
# fork" PR fail loudly at build time rather than silently producing a
# main bundle without the class (no Timeline) or a worker bundle without
# `packRowChunk` (no streaming). Cheap: the asserts run once per build,
# the strings have already been read into memory.
assert 'src/row-store.js' in APP_JS_FILES, (
    'BUILD INVARIANT: src/row-store.js must be present in APP_JS_FILES '
    '(main bundle). It is the sole producer of the RowStore class type '
    'every grid renderer hands to GridViewer; without it the main '
    'bundle has no row container and Timeline + every grid view fails '
    'to mount.'
)
_ROW_STORE_SRC_FOR_ASSERT = read('src/row-store.js')
assert _ROW_STORE_SRC_FOR_ASSERT in _timeline_worker_bundle_src, (
    'BUILD INVARIANT: src/row-store.js must be concatenated into '
    '_timeline_worker_bundle_src (timeline parse-only worker bundle). '
    'The worker calls packRowChunk to pack streamed CSV/EVTX/SQLite '
    'rows into transferable typed-array chunks; without the file in '
    'the worker bundle the worker throws ReferenceError on the first '
    "rows-chunk post and Timeline receives a zero-row store. See the "
    'comment block above this assertion for the dual-home rationale.'
)
del _ROW_STORE_SRC_FOR_ASSERT

timeline_worker_js = (
    'const __TIMELINE_WORKER_BUNDLE_SRC = `'
    + _esc_for_template(_timeline_worker_bundle_src)
    + '`;\n'
)

# EncodedContentDetector worker.
# Bundle order matters — the shim defines the IOC table, the
# `PARSER_LIMITS.MAX_UNCOMPRESSED` cap, and the `_trimPathExtGarbage` helper
# the detector reads at module load. pako is the Decompressor sync fallback
# (DecompressionStream isn't always present in WorkerGlobalScope on every
# browser); JSZip is used by the detector to validate embedded ZIP candidates
# and prune false-positive zlib hits. The encoded.worker.js trailer carries
# the `self.onmessage` dispatcher that drives `EncodedContentDetector.scan()`
# and eagerly fires `lazyDecode()` on every cheap finding.
# `_DETECTOR_FILES` (defined above) lists the class root + nine helper
# modules under `src/decoders/`; concatenating them in that order is
# equivalent to what `JS_FILES` does on the main thread.
_encoded_worker_bundle_src = (
    read('src/workers/encoded-worker-shim.js') + '\n'
    + pako_js + '\n'
    + jszip + '\n'
    + read('src/decompressor.js') + '\n'
    # url-normalize.js — pure helper consumed by `src/decoders/ioc-extract.js`
    # (inside _DETECTOR_FILES) for the obfuscated-URL deobfuscation pass.
    # Mirrors the host-bundle wiring; must load BEFORE the detector files.
    + read('src/util/url-normalize.js') + '\n'
    + '\n'.join(read(f) for f in _DETECTOR_FILES) + '\n'
    + read('src/workers/encoded.worker.js')
)

encoded_worker_js = (
    'const __ENCODED_WORKER_BUNDLE_SRC = `'
    + _esc_for_template(_encoded_worker_bundle_src)
    + '`;\n'
)

# IOC mass-extract worker.
# Bundle order matters — the shim defines the IOC table plus the host-side
# helpers (`looksLikeIpVersionString`, `stripDerTail`, `_trimPathExtGarbage`)
# that `src/ioc-extract.js` reads at module load. The shim AND the host
# `src/ioc-extract.js` are mirrored into the worker bundle: the host bundle
# already loads `src/ioc-extract.js` as a regular `JS_FILES` entry (so the
# `_extractInterestingStrings` shim can call into the same core
# synchronously), and the worker bundle re-includes it here. The
# `ioc-extract.worker.js` trailer carries the `self.onmessage` dispatcher.
#
# `scripts/check_shim_parity.py` diffs the shim's IOC table / helper bodies
# against `src/constants.js` so silent drift is caught at build time.
_ioc_extract_worker_bundle_src = (
    read('src/workers/ioc-extract-worker-shim.js') + '\n'
    # url-normalize.js — pure helper consumed by `src/ioc-extract.js`'s
    # processUrl for the obfuscated-URL deobfuscation pass. Mirrors the
    # host-bundle wiring; must load BEFORE `src/ioc-extract.js`.
    + read('src/util/url-normalize.js') + '\n'
    + read('src/ioc-extract.js') + '\n'
    + read('src/workers/ioc-extract.worker.js')
)
ioc_extract_worker_js = (
    'const __IOC_EXTRACT_WORKER_BUNDLE_SRC = `'
    + _esc_for_template(_ioc_extract_worker_bundle_src)
    + '`;\n'
)


# ── Tier 5 — split the App bundle into FOUR inline `<script>` blocks ─────────

# Browsers can yield to layout / paint / event delivery **between**
# `<script>` tags. Splitting the App into four smaller blocks keeps total
# CPU the same but eliminates the single ≥50 ms compile task that drags
# TBT. Same load order as before — only the **emission shape** changes
# (one `<script>` per block instead of one mega-block).
#
# Boundary rules:
#   • Block 1 (primitives & shared helpers) — every entry up to but not
#     including the first docx renderer dep. Gets the worker-bundle
#     constants (`__YARA_WORKER_BUNDLE_SRC` / `__TIMELINE_WORKER_BUNDLE_SRC`
#     / `__ENCODED_WORKER_BUNDLE_SRC`), `LOUPE_VERSION`, and
#     `DEFAULT_YARA_RULES` prepended at the very top so `worker-manager.js`
#     and `app-core.js` find them at module-eval time.
#   • Block 2 (renderers + dispatch) — every renderer plus the docx
#     helper chain (`docx-parser.js`, `style-resolver.js`,
#     `numbering-resolver.js`, `content-renderer.js`,
#     `security-analyzer.js`), `renderer-registry.js`, `render-route.js`.
#   • Block 3 (App shell, part 1) — `app-bg.js`, `app-core.js`, every
#     `src/app/timeline/*.js`, `app-load.js`, `app-sidebar.js`,
#     `app-sidebar-focus.js`.
#   • Block 4 (App shell, part 2 + kick-off) — `app-yara.js`,
#     `app-ui.js`, `app-copy-analysis.js`, `app-settings.js`,
#     `app-breadcrumbs.js`. The trailing `new App().init();` lives at the
#     end of `app-breadcrumbs.js` — the LAST file in `APP_JS_FILES` and
#     therefore the LAST line of Block 4 — so every
#     `Object.assign(App.prototype, …)` mixin has landed its methods on
#     the prototype before `App.init()` runs.
#
# `Object.assign(App.prototype, …)` ordering invariants preserved by
# construction: every override sits **later** in `APP_JS_FILES` than the
# methods it overrides, and `APP_JS_FILES` is split here by **index range**
# (not re-ordered), so the across-block sequence is identical to today's
# single-block sequence. The block boundaries are aligned to natural
# subsystem seams so no Object.assign mixin straddles a boundary in a way
# that matters: `app-bg.js` (defines `BgCanvas`) is the first entry of
# Block 3; `app-core.js` and `app-ui.js` (both call into `BgCanvas`) are
# in Blocks 3 and 4 respectively, both after Block 3 starts. ✅
#
# Build gates (`_check_risk_pre_stamping`, `_check_bare_ioc_types`,
# `_check_raw_text_normalisation`, `_check_worker_spawn_allowlist`)
# iterate `EARLY_JS_FILES + APP_JS_FILES` so coverage is preserved across
# the split — they read the source list, not the emitted blocks.
def _index_of(rel):
    """Locate a file in `APP_JS_FILES`. Fails the build if missing — keeps
    the boundary anchors honest if a future refactor removes / renames
    one of the boundary files."""
    try:
        return APP_JS_FILES.index(rel)
    except ValueError:
        raise SystemExit(
            f"Tier-5 block split: boundary anchor {rel!r} missing from "
            "APP_JS_FILES. Re-pick a boundary or update _index_of() callers."
        )

_BLOCK2_START = _index_of('src/docx-parser.js')
_BLOCK3_START = _index_of('src/app/app-bg.js')
_BLOCK4_START = _index_of('src/app/app-yara.js')

APP_BLOCKS = [
    APP_JS_FILES[:_BLOCK2_START],                # Block 1 — primitives
    APP_JS_FILES[_BLOCK2_START:_BLOCK3_START],   # Block 2 — renderers + dispatch
    APP_JS_FILES[_BLOCK3_START:_BLOCK4_START],   # Block 3 — App shell, part 1
    APP_JS_FILES[_BLOCK4_START:],                # Block 4 — App shell, part 2 + kick-off
]

# Sanity check — the four slices must cover every entry exactly once.
_covered = APP_BLOCKS[0] + APP_BLOCKS[1] + APP_BLOCKS[2] + APP_BLOCKS[3]
assert _covered == APP_JS_FILES, (
    "Tier-5 block split: APP_BLOCKS slices don't cover APP_JS_FILES exactly."
)

_USE_ESBUILD = os.environ.get('LOUPE_ESBUILD') == '1'


def _join_app_block(files):
    """Concatenate an APP_BLOCKS slice, or esbuild-bundle it when opted in."""
    if not _USE_ESBUILD:
        return '\n'.join(read(f) for f in files)
    from pathlib import Path
    from build.bundle_esbuild import bundle_iife
    paths = [Path(BASE) / f for f in files]
    return bundle_iife(paths)


if _USE_ESBUILD:
    print('NOTE  LOUPE_ESBUILD=1 — app script blocks via esbuild IIFE (concat fallback when unset)')

_block_srcs = [_join_app_block(g) for g in APP_BLOCKS]

# Stamp `LOUPE_VERSION`, the YARA-rules constant, and the three worker-
# bundle constants at the top of Block 1. Order matters at runtime:
# `worker-manager.js` (inside Block 1) reads the bundle constants at
# module-eval time, and `app-core.js` (inside Block 3) reads
# `LOUPE_VERSION` and `DEFAULT_YARA_RULES`.
_block_srcs[0] = (
    f"const LOUPE_VERSION = '{VERSION}';\n"
    + (f"const __LOUPE_TEST_API__ = true;\n" if TEST_API else '')
    + default_yara_js
    + geoip_bundle_js          # __GEOIP_BUNDLE_B64 — read by src/geoip/bundled-geoip.js
    + yara_worker_js
    + timeline_worker_js
    + encoded_worker_js
    + ioc_extract_worker_js
    + _block_srcs[0]
)

# Emit one `<script>` tag per block. The `\n` padding around each block's
# content keeps the rendered HTML legible without affecting JS semantics.
app_blocks_html = '\n'.join(f'  <script>\n{src}\n  </script>' for src in _block_srcs)

# Source-tree gates run via build.pipeline / make.py (scripts/build/gates/).

# File extensions accepted by the open-file input. Keep as a list for sanity.
ACCEPT_EXTS = [
    '.docx','.docm','.xlsx','.xlsm','.xls','.ods','.pptx','.pptm','.ppt','.odt','.odp',
    '.csv','.tsv','.doc','.msg','.eml','.lnk','.hta','.rtf','.pdf',
    '.zip','.gz','.gzip','.tar','.tgz','.rar','.7z','.cab','.iso','.img','.one',
    '.dmg','.pkg','.mpkg',
    '.url','.webloc','.website','.iqy','.slk','.wsf','.wsc','.wsh','.reg','.inf','.sct','.msi',
    '.html','.htm','.mht','.mhtml','.xhtml','.xml','.vbs','.vbe','.js','.jse','.ps1','.bat','.cmd',
    '.ics','.vcf','.txt','.log','.json','.ndjson','.jsonl','.ini','.cfg','.yml','.yaml',
    '.jpg','.jpeg','.png','.gif','.bmp','.webp','.ico','.tif','.tiff','.avif','.svg',
    '.evtx','.sqlite','.db','.exe','.dll','.sys','.scr','.cpl','.ocx','.drv','.com','.xll',
    '.elf','.so','.o','.dylib','.bundle',
    '.pem','.der','.crt','.cer','.p12','.pfx','.key',
    '.pgp','.gpg','.asc','.sig',
    '.jar','.war','.ear','.class',
    '.applescript','.jxa','.scpt','.scptd','.plist',
    '.application','.manifest',
    '.msix','.msixbundle','.appx','.appxbundle','.appinstaller',
    '.crx','.xpi',
]
accept_attr = ','.join(ACCEPT_EXTS)

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data: blob:; frame-src blob:; worker-src blob:; form-action 'none'; base-uri 'none'; object-src 'none';">
  <meta name="description" content="Loupe — a 100% offline, single-file security analyser for suspicious files. No server, no uploads, no tracking.">
  <title>Loupe</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🕵🏻</text></svg>">
  <style>{css}</style>
  <!-- ── FOUC-prevention theme bootstrap ──────────────────────────────────
       Runs synchronously before <body> is painted so the correct theme
       class lives on <body> from the very first frame. Without this the
       page would flash the default light palette for a few hundred ms
       while app-ui.js loaded, even for users who had saved a dark theme.
       Logic mirrors _initTheme in src/app/app-ui.js:
         1. saved `localStorage.loupe_theme`  (if valid)
         2. OS `prefers-color-scheme: light`   (first boot only)
         3. hard-coded fallback ('dark')
       The theme IDs must be kept in sync with the THEMES array in
       src/app/app-ui.js — a stale entry here just means the bootstrap
       refuses to apply that theme and _initTheme does so one tick later.
       Allowed by CSP: `script-src 'unsafe-inline'` is already granted for
       the rest of the single-file bundle, so no extra relaxation. -->
  <script>
    (function () {{
      try {{
        var THEME_IDS = ['light','dark','midnight','solarized','mocha','latte'];
        var DARK_THEMES = {{ dark:1, midnight:1, solarized:1, mocha:1 }};
        var saved = null;
        try {{ saved = localStorage.getItem('loupe_theme'); }} catch (_) {{}}
        var id;
        if (saved && THEME_IDS.indexOf(saved) !== -1) {{
          id = saved;
        }} else {{
          var prefersLight = false;
          try {{
            prefersLight = !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches);
          }} catch (_) {{}}
          id = prefersLight ? 'light' : 'dark';
        }}
        var b = document.body || document.documentElement;
        // <body> doesn't exist yet — stash on <html> and re-apply once body lands
        var applyTo = function (el) {{
          for (var i = el.classList.length - 1; i >= 0; i--) {{
            var cls = el.classList[i];
            if (cls.indexOf('theme-') === 0) el.classList.remove(cls);
          }}
          el.classList.add('theme-' + id);
          el.classList.toggle('dark', !!DARK_THEMES[id]);
        }};
        // Once <body> exists we need the classes there, not on <html>.
        // If this script runs before </head> we schedule a one-shot
        // observer that copies the classes across the moment <body> is parsed.
        if (document.body) {{
          applyTo(document.body);
        }} else {{
          applyTo(document.documentElement);
          var mo = new MutationObserver(function () {{
            if (document.body) {{
              applyTo(document.body);
              document.documentElement.classList.remove('dark');
              for (var i = document.documentElement.classList.length - 1; i >= 0; i--) {{
                var cls = document.documentElement.classList[i];
                if (cls.indexOf('theme-') === 0) document.documentElement.classList.remove(cls);
              }}
              mo.disconnect();
            }}
          }});
          mo.observe(document.documentElement, {{ childList: true }});
        }}
      }} catch (_) {{ /* never let theme bootstrap break the page */ }}
    }})();
  </script>
</head>
<body>


  <!-- ── Toolbar ─────────────────────────────────────────────────────── -->
  <div id="toolbar">
    <span id="app-title"><span class="logo">🕵🏻 Loupe</span></span>
    <div class="tb-separator"></div>
    <!-- File operations group -->
    <div class="tb-group" id="file-ops">
      <div class="tb-menu-wrap">
        <button class="tb-btn" id="btn-open" aria-haspopup="menu" aria-expanded="false" title="Open a file or folder (or drag &amp; drop)">📁 Open <span class="tb-caret">▾</span></button>
        <div class="tb-menu hidden" id="open-menu" role="menu"></div>
      </div>
      <button class="tb-btn hidden" id="btn-close" title="Close file (Esc)">✕</button>
      <nav class="hidden" id="breadcrumbs" aria-label="File path"></nav>
    </div>
    <div class="tb-spacer"></div>
    <div class="tb-separator"></div>
    <button class="tb-btn tb-icon-btn" id="btn-security" title="Toggle security sidebar (S)">🛡</button>
    <div class="tb-separator"></div>
    <button class="tb-btn tb-icon-btn" id="btn-yara" title="YARA rule editor (Y)">📐</button>
    <button class="tb-btn tb-icon-btn" id="btn-settings" title="Settings (,) · Help (?)">⚙</button>
    <!-- File picker — `multiple` so multi-file selection reaches
         `_ingestLooseMultiFile`. `accept` is a hint only; analysts can
         always override via "All Files". -->
    <input type="file" id="file-input" accept="{accept_attr}" multiple style="display:none">
    <!-- Folder picker — `webkitdirectory` flips the native dialog into
         directory-selection mode. `accept` is deliberately omitted here:
         browsers ignore `accept` under `webkitdirectory` and in some
         versions it even suppresses legitimate sub-files. The picker
         silently flattens the tree; every leaf carries
         `webkitRelativePath` which `_ingestFolderFromRelativePaths`
         consumes. This exists because drag-dropping a folder on macOS
         Chrome is unreliable (known Chromium `EncodingError` on
         `readEntries()` for folders dragged from Finder). -->
    <input type="file" id="folder-input" webkitdirectory multiple style="display:none">

  </div>

  <!-- ── Main area (viewer + sidebar side-by-side) ──────────────────── -->
  <div id="main-area">

    <!-- viewer -->
    <div id="viewer">
      <div id="viewer-toolbar" class="hidden">
        <div class="vt-group">
          <button class="tb-btn tb-action-btn tb-accent-btn" id="btn-copy-analysis" title="Copy AI/SOC summary to clipboard (Ctrl+Enter)">⚡ Summarize</button>
          <div class="tb-menu-wrap">
            <button class="tb-btn tb-action-btn" id="btn-export" aria-haspopup="menu" aria-expanded="false" title="Export analysis in various formats">📤 Export <span class="tb-caret">▾</span></button>
            <div class="tb-menu hidden" id="export-menu" role="menu"></div>
          </div>
        </div>
        <div class="vt-search">
          <input type="text" id="doc-search" placeholder="Search content…" spellcheck="false">
          <button class="vt-search-nav" id="doc-search-prev" title="Previous match (Shift+Enter)">◀</button>
          <button class="vt-search-nav" id="doc-search-next" title="Next match (Enter)">▶</button>
          <span id="doc-search-count"></span>
        </div>
        <div class="vt-spacer"></div>
        <div class="vt-zoom">
          <button class="tb-btn vt-zoom-btn" id="btn-zoom-out" title="Zoom out">−</button>
          <span id="zoom-level">100%</span>
          <button class="tb-btn vt-zoom-btn" id="btn-zoom-in" title="Zoom in">+</button>
        </div>
      </div>
      <div id="drop-zone">
        <span class="dz-icon">📄</span>
        <div class="dz-text">Drop a file or folder here to analyse</div>
        <div class="dz-sub">Extracts IOCs, decodes obfuscated payloads, runs 500+ YARA rules, and renders 60+ formats — 100% offline in your browser.</div>
      </div>
      <div id="page-container"></div>
    </div>

    <!-- sidebar resize handle -->
    <div id="sidebar-resize" class="hidden"></div>

    <!-- sidebar -->
    <div id="sidebar" class="hidden">
      <div id="sb-risk" class="sb-risk risk-low">
        <span id="sb-risk-title">No threats detected</span>
      </div>
      <div id="sb-body"></div>
    </div>

    <!-- Timeline root — sibling of #viewer. Shown whenever a CSV / TSV /
         EVTX is loaded (the analyser surface hides via body.has-timeline).
         Populated by src/app/app-timeline.js::_loadFileInTimeline(). -->
    <div id="timeline-root"></div>

  </div><!-- /#main-area -->

  <!-- ── Loading overlay ─────────────────────────────────────────────── -->
  <!-- The overlay has two phrase pools: the default analyser pool (`.lm`)
       and a decode-specific pool (`.lm-decode`) shown when the overlay's
       `data-mode` attribute is `decode`. The selection-decode flow
       (src/app/app-selection-decode.js) sets `data-mode="decode"` before
       calling `_setLoading(true)`; `_setLoading(false)` clears it. CSS
       in src/styles/core.css toggles which set is visible. -->
  <div id="loading" class="hidden">
    <div class="loading-content">
      <span class="spinner"></span>
      <div class="loading-msg">
        <span class="lm" style="--i:0">Bonking it with a stick</span>

        <span class="lm" style="--i:1">Dusting for fingerprints</span>
        <span class="lm" style="--i:2">Connecting the dots</span>
        <span class="lm" style="--i:3">Putting it under the microscope</span>
        <span class="lm" style="--i:4">Running it through the centrifuge</span>
        <span class="lm" style="--i:5">Calibrating the instruments</span>
        <span class="lm" style="--i:6">Giving it a firm talking-to</span>
        <span class="lm" style="--i:7">Asking it nicely to explain itself</span>
        <span class="lm" style="--i:8">Staring at it until it blinks</span>
        <span class="lm" style="--i:9">Reading its diary</span>
        <span class="lm" style="--i:10">Asking it about its feelings</span>
        <span class="lm" style="--i:11">Casting a revealing spell</span>
        <span class="lm" style="--i:12">Whispering to the bytes</span>
        <span class="lm" style="--i:13">Waving the wand</span>
        <span class="lm" style="--i:14">Letting it simmer</span>
        <span class="lm" style="--i:15">Marinating the sample</span>
        <span class="lm" style="--i:16">Slow-roasting the results</span>
        <span class="lm" style="--i:17">Letting it breathe</span>
        <span class="lm" style="--i:18">Warming up the engines</span>
        <span class="lm" style="--i:19">Smoothing the edges</span>
        <span class="lm" style="--i:20">Piecing it together</span>
        <span class="lm" style="--i:21">Nearly there</span>
        <span class="lm" style="--i:22">Hang tight</span>
        <span class="lm" style="--i:23">On the case</span>
        <span class="lm" style="--i:24">Prodding it with a longer stick</span>
        <span class="lm" style="--i:25">Tapping it to see if it's hollow</span>
        <span class="lm" style="--i:26">Flipping it over to check underneath</span>
        <span class="lm" style="--i:27">Knocking to see if anyone's home</span>
        <span class="lm" style="--i:28">Squeezing it gently</span>
        <span class="lm" style="--i:29">Pinching it to see if it's real</span>
        <span class="lm" style="--i:30">Rattling the container</span>
        <span class="lm" style="--i:31">Pressing all the buttons</span>
        <span class="lm" style="--i:32">Following the money</span>
        <span class="lm" style="--i:33">Bringing it in for questioning</span>
        <span class="lm" style="--i:34">Building a psychological profile</span>
        <span class="lm" style="--i:35">Taking careful measurements</span>
        <span class="lm" style="--i:36">Weighing it on the scale</span>
        <span class="lm" style="--i:37">Checking under the cushions</span>
        <span class="lm" style="--i:38">Interrogating the metadata</span>
        <span class="lm" style="--i:39">Consulting the magic 8-ball</span>
        <span class="lm" style="--i:40">Shaking it like a snow globe</span>
        <span class="lm" style="--i:41">Holding it up to the light</span>
        <span class="lm" style="--i:42">Sniffing for anomalies</span>
        <span class="lm" style="--i:43">Polishing the magnifying glass</span>
        <span class="lm" style="--i:44">Unfolding the treasure map</span>
        <span class="lm" style="--i:45">Asking the rubber duck</span>
        <span class="lm" style="--i:46">Lifting the carpet</span>
        <span class="lm" style="--i:47">Peeling back the layers</span>
        <span class="lm" style="--i:48">Tuning the antenna</span>
        <span class="lm" style="--i:49">Deciphering the runes</span>
        <span class="lm" style="--i:50">Counting the breadcrumbs</span>
        <span class="lm" style="--i:51">Putting on the detective hat</span>
        <span class="lm" style="--i:52">Adjusting the monocle</span>
        <span class="lm" style="--i:53">Leafing through the evidence</span>
        <span class="lm" style="--i:54">Shining the UV light</span>
        <span class="lm" style="--i:55">Pulling the thread</span>
        <span class="lm" style="--i:56">Turning over every stone</span>
        <span class="lm" style="--i:57">Recalibrating the flux capacitor</span>

        <!-- Decode-selection phrase pool. Hidden by default; shown only
             when `#loading[data-mode="decode"]` is set by the
             selection-decode flow (src/app/app-selection-decode.js). The
             default `.lm` pool above is then hidden by the corresponding
             rule in src/styles/core.css. -->
        <span class="lm-decode" style="--i:0">Throwing every key at the lock</span>
        <span class="lm-decode" style="--i:1">Bruteforcing the XOR key</span>
        <span class="lm-decode" style="--i:2">Trying ROT-1 through ROT-25</span>
        <span class="lm-decode" style="--i:3">Walking the column cribs</span>
        <span class="lm-decode" style="--i:4">Peeling Base64 off Base64</span>
        <span class="lm-decode" style="--i:5">Reversing reversed reverses</span>
        <span class="lm-decode" style="--i:6">Sniffing for hidden separators</span>
        <span class="lm-decode" style="--i:7">Stripping interleaved nulls</span>
        <span class="lm-decode" style="--i:8">Unwrapping safe-link wrappers</span>
        <span class="lm-decode" style="--i:9">Rebuilding the char-array</span>
        <span class="lm-decode" style="--i:10">Inflating zlib payloads</span>
        <span class="lm-decode" style="--i:11">Dechunking the hex escapes</span>
        <span class="lm-decode" style="--i:12">Concatenating the fragments</span>
        <span class="lm-decode" style="--i:13">Defanging the IOCs</span>
        <span class="lm-decode" style="--i:14">Cycling Caesar shifts</span>
        <span class="lm-decode" style="--i:15">Splitting on every delimiter</span>
        <span class="lm-decode" style="--i:16">Comparing key-length 2, 3, 4</span>
        <span class="lm-decode" style="--i:17">Scoring against the dictionary</span>
        <span class="lm-decode" style="--i:18">Looking for the magic word</span>
        <span class="lm-decode" style="--i:19">Asking the cipher to confess</span>
        <span class="lm-decode" style="--i:20">Recursing one layer deeper</span>
        <span class="lm-decode" style="--i:21">Chaining decode pipelines</span>
        <span class="lm-decode" style="--i:22">Pulling at every loose thread</span>
        <span class="lm-decode" style="--i:23">Hunting for plaintext</span>
        <span class="lm-decode" style="--i:24">Reading between the bytes</span>
        <span class="lm-decode" style="--i:25">Spotting the powershell</span>
        <span class="lm-decode" style="--i:26">Catching the IEX in the act</span>
        <span class="lm-decode" style="--i:27">Holding it under UV</span>
        <span class="lm-decode" style="--i:28">Comparing every shift</span>
        <span class="lm-decode" style="--i:29">Trying the obvious passwords</span>
        <span class="lm-decode" style="--i:30">Brute-forcing politely</span>
        <span class="lm-decode" style="--i:31">Decoding all the way down</span>
      </div>
      <!-- Optional progress subtitle. Empty by default; populated by
           callers that have a meaningful progress signal (e.g.
           `timeline-router.js` sets "1.2M rows…" as RowStore chunks
           stream in from the worker). Lives below the rotating phrase
           pool so the existing animation keeps running unchanged. -->
      <div id="loading-subtitle" class="loading-subtitle"></div>
    </div>
  </div>


  <!-- ── Toast ───────────────────────────────────────────────────────── -->
  <div id="toast" class="hidden"></div>

  <!-- ── Noscript ────────────────────────────────────────────────────── -->
  <noscript>
    <div class="noscript-msg">
      <h2>🕵🏻 Loupe requires JavaScript</h2>
      <p>This is a client-side security analysis tool — all processing happens locally in your browser. Please enable JavaScript to continue.</p>
    </div>
  </noscript>

  <!-- ── Group A: pre-App essentials (Tier 3 reorder) ────────────────────
        Capture-phase drag/drop/paste glue. Buffers files into
        `window.__loupePendingDrop` / `window.__loupePendingPaste` during
        the cold-load window so a drop arriving before the App's own
        listeners are wired isn't lost to the browser's default
        navigate-to-file behaviour. Drained + torn down by
        `App._setupDrop()` once the constructor runs. Must beat every
        other inline `<script>` to the parser — see EARLY_JS_FILES in
        scripts/build.py and the file header in
        src/app/early-drop-bootstrap.js. -->
  <script>
{early_drop_js}
  </script>

  <!-- ── Application — emitted as FOUR `<script>` blocks (Tier 5 split) ───
        The App bundle is split into four inline `<script>` tags so the
        browser can yield to layout / paint / event delivery between
        compiles. Same load order as before — only the emission shape
        changed (one `<script>` per block instead of one mega-block).
        Block 1 prepends `LOUPE_VERSION`, `DEFAULT_YARA_RULES`, and the
        three `__*_WORKER_BUNDLE_SRC` constants so `worker-manager.js`
        (also in Block 1) and `app-core.js` (Block 3) find them at
        module-eval time.
        These blocks are emitted AHEAD of the heavy renderer vendors
        below (JSZip / SheetJS / pdf.js / pako / LZMA / jsQR / tldts /
        utif / exifr / hljs) — Tier 3 invariant — so the App owns
        drag/drop end-to-end before any vendor compiles. The trailing
        `new App().init();` lives at the end of `app-breadcrumbs.js`,
        the LAST entry in `APP_JS_FILES` and therefore the last line of
        Block 4, so every `Object.assign(App.prototype, …)` mixin has
        landed its methods on the prototype before `App.init()` fires.
        Synchronous call (no DOMContentLoaded wrapper) — every DOM id
        the App queries is already in the document above. -->
{app_blocks_html}


  <!-- ── Group C: heavy renderer-only vendors (Tier 3 reorder) ────────────
        These compiled AHEAD of the App before Tier 3, blocking
        `App._setupDrop()` from binding listeners until the slowest
        vendor (SheetJS, ~30 ms) finished parsing. Now they trail the
        App `<script>` so the App owns drag/drop end-to-end before any
        of them touch the parser. The early-drop bootstrap above
        remains as defence-in-depth for the sub-millisecond gap
        between the App `<script>` parsing and `_setupDrop()`
        running. -->

  <!-- ── JSZip (inlined) ─────────────────────────────────────────────── -->
  <script>
{jszip}
  </script>

  <!-- ── SheetJS (inlined) ──────────────────────────────────────────── -->
  <script>
{xlsx_js}
  </script>

  <!-- ── pdf.js worker (inlined — must load before pdf.js) ───────────── -->
  <script>
{pdf_wrk_js}
  </script>

  <!-- ── pdf.js (inlined) ────────────────────────────────────────────── -->
  <script>
{pdf_js}
  </script>

  <!-- ── highlight.js (inlined) ──────────────────────────────────────── -->
  <script>
{highlight_js}
  </script>

  <!-- ── UTIF.js (inlined — TIFF decoder used by image-renderer) ─────── -->
  <script>
{utif_js}
  </script>

  <!-- ── exifr (inlined — EXIF / XMP / IPTC / GPS parser for images) ──── -->
  <script>
{exifr_js}
  </script>

  <!-- ── tldts (inlined — public-suffix-aware domain extractor,
        used by pushIOC() to auto-derive IOC.DOMAIN from every URL) ──── -->
  <script>
{tldts_js}
  </script>

  <!-- ── pako (inlined — synchronous zlib/deflate/gzip fallback used by
        Decompressor when DecompressionStream is unavailable or the
        caller needs a sync inflate) ──────────────────────────────── -->
  <script>
{pako_js}
  </script>

  <!-- ── LZMA-JS (decoder-only, inlined — used by SevenZRenderer to
        decompress LZMA-encoded 7z end-headers so the file listing is
        available even for large archives that compress their own
        metadata) ───────────────────────────────────────────────── -->
  <script>
{lzma_js}
  </script>

  <!-- ── jsQR (inlined — QR-code decoder shared by QrDecoder; consumers
        are ImageRenderer, PdfRenderer, SvgRenderer, OneNoteRenderer,
        EmlRenderer — any raster surface Loupe renders is scanned for
        QR payloads and the decoded contents land in findings.metadata
        / interestingStrings as IOCs via pushIOC()) ─────────────── -->
  <script>
{jsqr_js}
  </script>
</body>
</html>"""

# Output path:
#   • release build → docs/index.html (served by GitHub Pages, signed at release)
#   • --test-api    → docs/index.test.html (NEVER deployed, NEVER signed)
docs = os.path.join(BASE, 'docs')
os.makedirs(docs, exist_ok=True)
out_filename = 'index.test.html' if TEST_API else 'index.html'
out = os.path.join(docs, out_filename)
with open(out, 'w', encoding='utf-8') as _f:
    _f.write(HTML)

size = os.path.getsize(out)
print(f"OK  Built {out}  ({size:,} bytes / {size//1024} KB)"
      + ('  [test-api]' if TEST_API else ''))


# ── Build gate: test-API markers must NEVER appear in release bundles ─────────
# Defence-in-depth against the test-API leaking into a shipped release. The
# `--test-api` flag is the only path that ever embeds these markers, and the
# CI release path never passes that flag — but if a future contributor edits
# the orchestrator wrong, this gate catches the leak before it reaches Pages
# / Sigstore signing.
#
# We re-read the just-written release bundle and assert neither
# `__LOUPE_TEST_API__` nor `__loupeTest` (the public surface name) appears
# in it. Both strings are unique enough that a false positive in vendored
# code or YARA rules is not a concern (we sanity-check that assumption on
# every build by greping rules + vendor for the same tokens — the gate
# prints a clear error if anyone introduces such a substring).
from build.gates.fuzz_path_leak import check_fuzz_path_leak  # noqa: E402
from build.gates.release_test_api import check_release_test_api  # noqa: E402


def _fail_bundle_gate(header: str, violations: list[str]) -> None:
    if violations:
        raise SystemExit(header + '\n  ' + '\n  '.join(violations))


if not TEST_API:
    _fail_bundle_gate(
        'Build gate failed — test-API marker(s) leaked into release bundle.',
        check_release_test_api(out),
    )

_fail_bundle_gate(
    'Build gate failed — fuzz harness path(s) leaked into bundle.',
    check_fuzz_path_leak(out),
)
