# Contributing to GloveBox

> Developer guide for GloveBox. See [README.md](README.md) for end-user documentation.
> For AI coding agents, see [`.clinerules`](.clinerules) and [`CODEMAP.md`](CODEMAP.md).

---

## Building from Source

Requires **Python 3.8+** (standard library only — no `pip install` needed).

```bash
python build.py                  # Concatenates src/ → docs/index.html
python generate-codemap.py       # Regenerates CODEMAP.md (run after code changes)
```

The build script reads CSS files from `src/styles/`, YARA rules from `src/rules/`, and JS source files, inlining all CSS and JavaScript (including vendor libraries) into a single self-contained HTML document:

| Output | Purpose |
|---|---|
| `docs/index.html` | GitHub Pages deployment (sole build output) |

### CSS Concatenation Order

```
src/styles/core.css                    # Base theme, toolbar, sidebar, dialogs ("Midnight Glass")
src/styles/viewers.css                 # All format-specific viewer styles
```

### YARA Rule Files

```
src/rules/office-macros.yar            # Office/VBA macro detection (33 rules)
src/rules/script-threats.yar           # Script threats: PS, JS, VBS, CMD, Python (64 rules)
src/rules/document-threats.yar         # PDF, RTF, OLE, HTML, SVG, OneNote (39 rules)
src/rules/windows-threats.yar          # LNK, HTA, MSI, registry, LOLBins (126 rules)
src/rules/archive-threats.yar          # Archive format threats (11 rules)
src/rules/encoding-threats.yar         # Base64, hex, obfuscation patterns (28 rules)
src/rules/network-indicators.yar       # UNC, WebDAV, credential theft (3 rules)
src/rules/suspicious-patterns.yar      # General suspicious patterns (7 rules)
src/rules/file-analysis.yar            # PE, image, forensic analysis (5 rules)
```

### JS Concatenation Order

The application code is concatenated in dependency order:

```
src/constants.js                       # Namespace constants, DOM helpers, unit converters
src/vba-utils.js                       # Shared VBA binary decoder + auto-exec pattern scanner
src/yara-engine.js                     # YaraEngine — in-browser YARA rule parser + matcher
src/decompressor.js                    # Decompressor — gzip/deflate/raw decompression via DecompressionStream
src/encoded-content-detector.js        # EncodedContentDetector — Base64/hex/Base32/compressed blob scanner
src/docx-parser.js                     # DocxParser — ZIP extraction for DOCX/DOCM
src/style-resolver.js                  # StyleResolver — resolves run/paragraph styles
src/numbering-resolver.js              # NumberingResolver — list counters and markers
src/content-renderer.js                # ContentRenderer — DOCX DOM → HTML elements
src/security-analyzer.js               # SecurityAnalyzer — findings, metadata, external refs
src/renderers/ole-cfb-parser.js        # OleCfbParser — CFB/OLE2 compound file reader
src/renderers/xlsx-renderer.js         # XlsxRenderer — spreadsheet view (SheetJS)
src/renderers/pptx-renderer.js         # PptxRenderer — slide canvas renderer
src/renderers/odt-renderer.js          # OdtRenderer — OpenDocument text renderer
src/renderers/odp-renderer.js          # OdpRenderer — OpenDocument presentation renderer
src/renderers/ppt-renderer.js          # PptRenderer — legacy .ppt slide extraction
src/renderers/rtf-renderer.js          # RtfRenderer — RTF text + OLE/exploit analysis
src/renderers/zip-renderer.js          # ZipRenderer — archive listing + threat flagging
src/renderers/iso-renderer.js          # IsoRenderer — ISO 9660 filesystem listing
src/renderers/url-renderer.js          # UrlRenderer — .url / .webloc shortcut parser
src/renderers/onenote-renderer.js      # OneNoteRenderer — .one embedded object extraction
src/renderers/iqy-slk-renderer.js      # IqySlkRenderer — Internet Query + Symbolic Link files
src/renderers/wsf-renderer.js          # WsfRenderer — Windows Script File parser
src/renderers/reg-renderer.js          # RegRenderer — Windows Registry File (.reg) parser
src/renderers/inf-renderer.js          # InfSctRenderer — .inf setup info + .sct scriptlet parser
src/renderers/msi-renderer.js          # MsiRenderer — Windows Installer (.msi) analyser
src/renderers/csv-renderer.js          # CsvRenderer — CSV/TSV table view
src/renderers/evtx-renderer.js         # EvtxRenderer — Windows Event Log parser
src/renderers/sqlite-renderer.js       # SqliteRenderer — SQLite + browser history
src/renderers/doc-renderer.js          # DocBinaryRenderer — legacy .doc text extraction
src/renderers/msg-renderer.js          # MsgRenderer — Outlook .msg email view
src/renderers/eml-renderer.js          # EmlRenderer — RFC 5322/MIME email parser
src/renderers/lnk-renderer.js         # LnkRenderer — Windows Shell Link (.lnk) parser
src/renderers/hta-renderer.js          # HtaRenderer — HTA source viewer + security scanner
src/renderers/html-renderer.js         # HtmlRenderer — sandboxed HTML preview + source view
src/renderers/pdf-renderer.js          # PdfRenderer — PDF page renderer + security scanner
src/renderers/image-renderer.js        # ImageRenderer — image preview + stego/polyglot detection
src/renderers/plaintext-renderer.js    # PlainTextRenderer — catch-all text/hex viewer
src/app/app-core.js                    # App class — constructor, init, drop-zone, toolbar
src/app/app-load.js                    # File loading, hashing (MD5/SHA), IOC extraction
src/app/app-sidebar.js                 # Sidebar rendering — risk bar + collapsible panes
src/app/app-yara.js                    # YARA rule editor dialog, scanning, result display
src/app/app-ui.js                      # UI helpers (zoom, theme, pan, toast) + bootstrap
```

Vendor libraries (`vendor/jszip.min.js`, `vendor/xlsx.full.min.js`, `vendor/pdf.min.js`, `vendor/pdf.worker.min.js`, `vendor/highlight.min.js`) are inlined into separate `<script>` blocks before the application code.

---

## Project Structure

```
GloveBox/
├── build.py                        # Build script — reads src/, writes docs/index.html
├── generate-codemap.py             # Generates CODEMAP.md (AI agent navigation map)
├── .clinerules                     # AI coding agent instructions
├── CODEMAP.md                      # Auto-generated code map with line-level symbol index
├── README.md
├── CONTRIBUTING.md
├── docs/
│   └── index.html                  # Built output (GitHub Pages) — DO NOT EDIT
├── vendor/
│   ├── jszip.min.js                # JSZip — ZIP parsing for DOCX/XLSX/PPTX
│   ├── xlsx.full.min.js            # SheetJS — spreadsheet parsing
│   ├── pdf.min.js                  # pdf.js — PDF rendering (Mozilla)
│   ├── pdf.worker.min.js           # pdf.js worker — PDF parsing backend
│   └── highlight.min.js            # highlight.js — syntax highlighting
├── src/
│   ├── styles/                     # CSS (split for manageable file sizes)
│   │   ├── core.css                # Base theme, toolbar, sidebar, dialogs (1,729 lines)
│   │   └── viewers.css             # Format-specific viewer styles (3,274 lines)
│   ├── rules/                      # YARA rules (split by threat category)
│   │   ├── office-macros.yar       # Office/VBA macro detection
│   │   ├── script-threats.yar      # PS, JS, VBS, CMD, Python threats
│   │   ├── document-threats.yar    # PDF, RTF, OLE, HTML, SVG threats
│   │   ├── windows-threats.yar     # LNK, HTA, MSI, registry, LOLBins
│   │   ├── archive-threats.yar     # Archive format threats
│   │   ├── encoding-threats.yar    # Encoding/obfuscation patterns
│   │   ├── network-indicators.yar  # UNC, WebDAV, credential theft
│   │   ├── suspicious-patterns.yar # General suspicious patterns
│   │   └── file-analysis.yar       # PE, image, forensic analysis
│   ├── constants.js                # Shared constants, DOM helpers, unit converters, sanitizers
│   ├── vba-utils.js                # Shared VBA binary decoder + auto-exec pattern scanner
│   ├── yara-engine.js              # YaraEngine — in-browser YARA rule parser + matcher
│   ├── decompressor.js             # Decompressor — gzip/deflate/raw via DecompressionStream
│   ├── encoded-content-detector.js # EncodedContentDetector — encoded blob scanner
│   ├── docx-parser.js              # DocxParser class
│   ├── style-resolver.js           # StyleResolver class
│   ├── numbering-resolver.js       # NumberingResolver class
│   ├── content-renderer.js         # ContentRenderer class
│   ├── security-analyzer.js        # SecurityAnalyzer class
│   ├── renderers/
│   │   ├── ole-cfb-parser.js       # OleCfbParser — CFB compound file parser
│   │   ├── xlsx-renderer.js        # XlsxRenderer
│   │   ├── pptx-renderer.js        # PptxRenderer
│   │   ├── odt-renderer.js         # OdtRenderer — OpenDocument text
│   │   ├── odp-renderer.js         # OdpRenderer — OpenDocument presentation
│   │   ├── ppt-renderer.js         # PptRenderer — legacy .ppt
│   │   ├── rtf-renderer.js         # RtfRenderer — RTF + OLE analysis
│   │   ├── zip-renderer.js         # ZipRenderer — archive listing
│   │   ├── iso-renderer.js         # IsoRenderer — ISO 9660 filesystem
│   │   ├── url-renderer.js         # UrlRenderer — .url / .webloc shortcuts
│   │   ├── onenote-renderer.js     # OneNoteRenderer — .one files
│   │   ├── iqy-slk-renderer.js     # IqySlkRenderer — .iqy / .slk files
│   │   ├── wsf-renderer.js         # WsfRenderer — Windows Script Files
│   │   ├── reg-renderer.js         # RegRenderer — .reg registry files
│   │   ├── inf-renderer.js         # InfSctRenderer — .inf / .sct files
│   │   ├── msi-renderer.js         # MsiRenderer — .msi installer packages
│   │   ├── csv-renderer.js         # CsvRenderer
│   │   ├── evtx-renderer.js        # EvtxRenderer — .evtx parser (2,852 lines)
│   │   ├── sqlite-renderer.js      # SqliteRenderer — SQLite + browser history
│   │   ├── doc-renderer.js         # DocBinaryRenderer
│   │   ├── msg-renderer.js         # MsgRenderer
│   │   ├── eml-renderer.js         # EmlRenderer
│   │   ├── lnk-renderer.js         # LnkRenderer
│   │   ├── hta-renderer.js         # HtaRenderer
│   │   ├── html-renderer.js        # HtmlRenderer — sandboxed HTML preview
│   │   ├── pdf-renderer.js         # PdfRenderer
│   │   ├── image-renderer.js       # ImageRenderer — image preview + stego detection
│   │   └── plaintext-renderer.js   # PlainTextRenderer
│   └── app/
│       ├── app-core.js             # App class definition + setup methods
│       ├── app-load.js             # File loading, hashing, IOC extraction
│       ├── app-sidebar.js          # Sidebar rendering (risk bar + collapsible panes)
│       ├── app-yara.js             # YARA rule editor, scanning, result display
│       └── app-ui.js               # UI helpers + DOMContentLoaded bootstrap
└── examples/                       # Sample files for testing various formats
```

---

## AI Agent Support

GloveBox is optimised for AI coding agents (Cline, Cursor, Copilot Workspace, etc.):

- **`.clinerules`** — Instructions for AI agents: architecture overview, patterns to follow, files to avoid, and context budget tips.
- **`CODEMAP.md`** — Auto-generated code map with precise line numbers for every class, method, CSS section, and YARA rule. Agents can read this file first (~24K tokens) and then use `read_file(path, start_line=X, end_line=Y)` for surgical edits without consuming their entire context window.
- **`generate-codemap.py`** — Regenerate `CODEMAP.md` after any code changes: `python generate-codemap.py`
- **Split CSS/YARA** — CSS and YARA rules are split into multiple files by category, keeping each file under 3,300 lines. No single file dominates the context budget.

---

## Architecture

- **Single output file** — `build.py` inlines all CSS and JavaScript so the viewer works by opening one `.html` file with zero external dependencies.
- **No eval, no network** — the Content-Security-Policy (`default-src 'none'`) blocks all external fetches; images are rendered only from `data:` and `blob:` URLs.
- **App class split** — `App` is defined in `app-core.js`; additional methods are attached via `Object.assign(App.prototype, {...})` in `app-load.js`, `app-sidebar.js`, `app-yara.js`, and `app-ui.js`, keeping each file focused.
- **YARA-based detection** — all threat detection is driven by YARA rules. Default rules are split across `src/rules/*.yar` by threat category and auto-scanned on file load. Users can edit, load, and save custom rules via the built-in YARA editor (`Y` key).
- **Shared VBA helpers** — `parseVBAText()` and `autoExecPatterns` live in `vba-utils.js` and are reused by `DocxParser`, `XlsxRenderer`, and `PptxRenderer`.
- **OLE/CFB parser** — `OleCfbParser` is shared by `DocBinaryRenderer` (`.doc`), `MsgRenderer` (`.msg`), and `PptRenderer` (`.ppt`) for reading compound binary files.
- **PDF rendering** — `PdfRenderer` uses Mozilla's pdf.js for canvas rendering plus raw-byte scanning for dangerous PDF operators. Hidden text layers enable IOC extraction from rendered pages.
- **EML parsing** — Full RFC 5322/MIME parser with multipart support, quoted-printable and base64 decoding, attachment extraction, and authentication header analysis.
- **LNK parsing** — Implements the MS-SHLLINK binary format, extracting target paths, arguments, timestamps, and environment variable paths. Flags dangerous executables and evasion patterns.
- **HTA analysis** — Treats `.hta` files as inherently high-risk, extracting embedded scripts, `<HTA:APPLICATION>` attributes, and scanning against 40+ suspicious patterns including obfuscation techniques.
- **HTML rendering** — `HtmlRenderer` provides a sandboxed iframe preview (with all scripts and network disabled) and a source-code view with line numbers.
- **Image analysis** — `ImageRenderer` renders image previews and checks for steganography indicators, polyglot file structures, and suspicious embedded data.
- **Archive drill-down** — `ZipRenderer` lists archive contents with threat flagging, and allows clicking individual entries to extract and open them for full analysis, with Back navigation.
- **Encoded content detection** — `EncodedContentDetector` scans file text for Base64, hex, and Base32 encoded blobs plus embedded compressed streams (gzip/deflate). High-confidence patterns (PE headers, gzip magic, PowerShell `-EncodedCommand`) are decoded eagerly; other candidates offer a manual "Decode" button. Decoded payloads are classified, IOCs are extracted, and a "Load for analysis" button feeds decoded content back through the full analysis pipeline with breadcrumb navigation.
- **Catch-all viewer** — `PlainTextRenderer` accepts any file type. Text files get line-numbered display; binary files get a hex dump. Both paths run IOC extraction and YARA scanning.

---

## How to Contribute

1. Fork the repo
2. Make your changes in `src/`
3. Run `python build.py` to rebuild
4. Test by opening `docs/index.html` in a browser
5. Run `python generate-codemap.py` to update the code map
6. Submit a pull request

YARA rule submissions, new format parsers, and build-process improvements are especially welcome.

The codebase is intentionally vanilla JavaScript (no frameworks, no bundlers beyond the simple `build.py` concatenator) to keep the tool auditable and easy to understand.
