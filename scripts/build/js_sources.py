"""Authoritative JS concat file lists for Loupe builds and gates."""
from __future__ import annotations

EARLY_JS_FILES = [
    # early-drop-bootstrap.js — pre-App drag-and-drop / paste capture.
    # Tiny IIFE (≈ 60 LOC of pure event-listener glue, < 1 ms compile)
    # that registers capture-phase `dragover` / `drop` / `paste` listeners
    # **before** the heavy vendor inlines (JSZip / SheetJS / pdf.js) and
    # the App `<script>` compile. Drops captured during the cold-load
    # window land on `window.__loupePendingDrop` (or `__loupePendingPaste`)
    # and are drained by `App._setupDrop()` once the constructor runs.
    # MUST stay the only entry in EARLY_JS_FILES — the whole point is to
    # beat every other inline `<script>` to the parser. See file header
    # for the contract and `App._setupDrop()` for the drain.
    'src/app/early-drop-bootstrap.js',
]

_DETECTOR_FILES = [
    'src/encoded-content-detector.js',
    'src/decoders/safelinks.js',
    'src/decoders/whitelist.js',
    'src/decoders/entropy.js',
    # xor-bruteforce.js depends on entropy.js (`_tryDecodeUTF8`,
    # `_shannonEntropyBytes`) and is consumed from `_processCandidate`
    # to emit a synthetic XOR-cleartext inner finding when the surrounding
    # source mentions an XOR operator. See PLAN.md → D1.
    'src/decoders/xor-bruteforce.js',
    'src/decoders/ioc-extract.js',
    # decoder-ioc.js — sentinel-gated pattern IOC helpers for encoded-content
    # decoders. Must load before cmd-obfuscation.js and siblings.
    'src/decoder-ioc.js',
    'src/decoders/base64-hex.js',
    'src/decoders/zlib.js',
    'src/decoders/encoding-finders.js',
    'src/decoders/encoding-decoders.js',
    'src/decoders/cmd-obfuscation.js',
    # ps-mini-evaluator.js depends on cmd-obfuscation.js (it emits
    # `cmd-obfuscation` candidates that flow through
    # `_processCommandObfuscation`). See PLAN.md → D3.
    'src/decoders/ps-mini-evaluator.js',
    # js-assembly.js — JS string-array obfuscation resolver (obfuscator.io
    # / javascript-obfuscator npm package shape). Same `cmd-obfuscation`
    # candidate emission contract as ps-mini-evaluator.js, so the
    # `_processCommandObfuscation` pipeline (severity, IOC extraction,
    # deobfuscated-command sidebar shape) is reused unchanged. Must load
    # AFTER cmd-obfuscation.js (it consumes `_processCommandObfuscation`).
    # See PLAN.md → D6.
    'src/decoders/js-assembly.js',
    # bash-obfuscation.js — POSIX-shell obfuscation/deobfuscation:
    # ${V:n:m} parameter slicing, $'…' ANSI-C quoting, printf '\xNN'
    # chains, curl|sh / base64-pipe-to-shell, eval $(…) command
    # substitution unrolling, IFS / brace-expansion fragmentation,
    # /dev/tcp reverse shells. Emits `cmd-obfuscation` candidates so
    # the `_processCommandObfuscation` pipeline (severity scoring, IOC
    # mirroring, ClickFix marks) is reused unchanged. Must load AFTER
    # cmd-obfuscation.js (consumes _processCommandObfuscation). No
    # cross-decoder state — independent of ps-mini-evaluator.js /
    # js-assembly.js load order.
    'src/decoders/bash-obfuscation.js',
    # python-obfuscation.js — Python obfuscation/deobfuscation:
    # exec(zlib.decompress(b64decode(b'…'))) carriers, marshal.loads
    # bytecode, codecs.decode rot13/hex/base64/zlib, char-array
    # reassembly (chr-join / bytes-list / chr-concat), builtin
    # string-concat lookup (getattr(__builtins__, 'e'+'val')),
    # subprocess/os.system/pty.spawn/socket sinks. Emits
    # `cmd-obfuscation` candidates so the `_processCommandObfuscation`
    # pipeline is reused unchanged. Must load AFTER cmd-obfuscation.js.
    # Calls Decompressor.inflateSync (defined in src/decompressor.js,
    # loaded earlier in JS_FILES) to unpack zlib-wrapped payloads.
    'src/decoders/python-obfuscation.js',
    # php-obfuscation.js — PHP webshell / dropper detection: PHP1
    # eval(gzinflate(base64_decode(...))) decoder onion (b374k / WSO /
    # r57 family), PHP2 variable-variables ($$x with concatenated
    # symbol-table lookup), PHP3 chr/pack reassembly resolving to
    # PHP_DANGEROUS_FNS names, PHP4 preg_replace('/.../e') deprecated
    # exec primitive, PHP5 superglobal callable patterns
    # ($_GET[0]($_POST[1]) and eval($_REQUEST[...])), PHP6
    # data://text/plain;base64,... and php://filter stream-wrapper
    # includes. Emits `cmd-obfuscation` candidates so the
    # `_processCommandObfuscation` pipeline is reused unchanged. Calls
    # Decompressor.inflateSync (deflate-raw / zlib / gzip) to unwrap
    # gzinflate / gzuncompress / gzdecode chains.
    'src/decoders/php-obfuscation.js',
    # applescript-obfuscation.js — AppleScript / JXA char-code reassembly:
    # `(ASCII character N)`, `(character id N)`, `(string id {N,N,…})`
    # concatenated with `&` and interleaved with literal string fragments
    # to hide the `curl -H "User-Agent: …" -d "…" https://C2` payload of
    # a `do shell script` invocation. Emits `cmd-obfuscation` candidates
    # so the `_processCommandObfuscation` pipeline is reused unchanged.
    # Must load AFTER cmd-obfuscation.js (consumes _processCommandObfuscation).
    # No cross-decoder state — independent of bash / python / php
    # decoder load order. Downstream: a candidate that decodes to a
    # `curl …` / `/bin/sh -c …` string is re-mined for URL / host /
    # User-Agent by bash-obfuscation.js at sidebar "Load for analysis".
    'src/decoders/applescript-obfuscation.js',
    # interleaved-separator.js — finds + decodes interleaved-separator
    # obfuscation (`$\x00W\x00C\x00=\x00…` → `$WC=…`). Two-pass finder:
    # (1) single-character separator at strides 2/3/4 (e.g. `a.b.c.d`),
    # (2) multi-character literal separator (`\x00`, `\u0000`, `&#0;`,
    # `&nbsp;`, `&#x00;`). Loaded last because it's a pure
    # `Object.assign(...prototype, …)` mixin with no internal deps
    # beyond `_tryDecodeUTF8` (entropy.js), and the `_decodeCandidate`
    # dispatch in `encoding-decoders.js` already routes
    # `Interleaved Separator` candidate types here via prefix match.
    'src/decoders/interleaved-separator.js',
]

APP_JS_FILES = [
    'src/constants.js',

    # renderer-helpers.js — shared pushExternalRef / mirrorDetectionsToExternalRefs /
    # calibrateRiskFromEvidence primitives for format handlers. Must load
    # immediately after constants.js (depends on pushIOC / escalateRisk / IOC.*).
    'src/renderer-helpers.js',

    # util/url-normalize.js — pure deobfuscator for URL strings (unicode /
    # hex inline escapes, percent-encoding in host+path, hex/octal/decimal
    # encoded IPs). Consumed by `src/ioc-extract.js::processUrl` and
    # `src/decoders/ioc-extract.js` to surface the canonical URL alongside
    # the original obfuscated form, and to emit a sibling `IOC.IP` when
    # the decoded host is a dotted-quad. Worker-safe (no DOM, no globals
    # beyond `UrlNormalizeUtil`); concatenated into the encoded-content and
    # IOC-extract worker bundles too. Must load BEFORE `src/ioc-extract.js`
    # and BEFORE the encoded-content split (which carries
    # `src/decoders/ioc-extract.js`).
    'src/util/url-normalize.js',

    # ioc-extract.js — pure regex-based IOC extraction core. Defines
    # `extractInterestingStringsCore(text, opts)` plus the `_unwrapSafeLink`
    # / `_refangString` worker-safe helpers. Loaded as a host module here AND
    # concatenated into `__IOC_EXTRACT_WORKER_BUNDLE_SRC` so the worker can
    # call the same core. Must load AFTER constants.js (uses IOC,
    # `_trimPathExtGarbage`, `looksLikeIpVersionString`, `stripDerTail`) and
    # BEFORE any consumer (`app-load.js` shim, EML / MSG renderers that share
    # `_refangString`). See CONTRIBUTING.md → Worker subsystem and
    # plans/2026-04-27-loupe-perf-redos-followup-finish-v1.md (Batch A).
    'src/ioc-extract.js',

    # storage.js — single chokepoint for every `localStorage.*` access in the
    # bundle. Exposes `window.safeStorage.{get,set,remove,getJSON,setJSON,
    # keys,removeMatching}`. Pure ceremony — try/catch + JSON serialise. Must
    # load AFTER constants.js (no constant deps today, but the namespacing
    # convention `loupe_*` lives there) and BEFORE any consumer that touches
    # storage. The build-gate `_check_storage_access()` allow-lists this file
    # plus `scripts/build.py` itself (FOUC theme bootstrap is hand-written
    # inline JS in <head>, not a `src/` module).
    'src/storage.js',

    # util/ipv4.js — strict IPv4 parser + non-routable-range classifier.
    # Single source of truth for "is this string a strict dotted-quad?"
    # and "is this address private / loopback / multicast / CGNAT?".
    # Consumed by:
    #   • src/app/timeline/timeline-view-geoip.js  (timeline GeoIP enrichment)
    #   • src/app/app-sidebar.js                   (sidebar IOC enrichment)
    #   • src/app/app-ui.js                        (Summary + JSON/CSV exports)
    # Pure JS, no dependencies. Must load BEFORE every consumer above.
    'src/util/ipv4.js',

    # nicelist.js — known-good global infrastructure (NICELIST) used by the
    # sidebar IOC table to demote / hide benign cloud / registry / CA /
    # XML-namespace surfaces. Pure data + string helpers, no dependencies,
    # must load after constants.js (for the type-string contract) and before
    # app-sidebar.js (which consumes `isNicelisted`).
    'src/nicelist.js',
    # nicelist-user.js — user-defined nicelists (custom "known-good" lists
    # managed from Settings → Nicelists). Exposes `_NicelistUser` as a
    # singleton with load/save/match/parse/export/import helpers. Must load
    # AFTER nicelist.js (built-in takes priority for the "Default Nicelist"
    # label) and BEFORE app-sidebar.js / app-settings.js (both consume it).
    'src/nicelist-user.js',
    # nicelist-annotate.js — single canonical IOC tagger. Walks every
    # `findings.externalRefs` / `interestingStrings` entry and stamps
    # `_nicelisted` / `_nicelistSource` so downstream consumers (sidebar
    # IOC table, Copy Analysis Summary, STIX bundle, MISP event, IOC CSV)
    # share a single source of truth instead of recomputing tags each
    # time. Must load AFTER nicelist.js and nicelist-user.js (consumes
    # both) and BEFORE app-load.js / app-sidebar.js / app-ui.js.
    'src/nicelist-annotate.js',

    'src/parser-watchdog.js',
    # file-download.js — single home for the Blob → <a download> → revoke
    # ceremony. Exposes `window.FileDownload.{downloadBlob, downloadText,
    # downloadBytes, downloadJson}`. Must load BEFORE any renderer or
    # app-* file that emits a download (every `_downloadText` /
    # `_downloadBytes` / renderer-local Save button funnels through this).
    # No dependencies — pure DOM + Blob ceremony.
    'src/file-download.js',
    # sandbox-preview.js — shared sandboxed-iframe + drag-shield helper
    # used by html-renderer.js and svg-renderer.js. Exposes
    # `window.SandboxPreview.create({...})`
    # which builds the `iframe` (with `sandbox='allow-same-origin'` +
    # inner CSP `<meta>` tag) and the overlay drag-shield `<div>` that
    # forwards wheel/touch scroll deltas and re-dispatches drag/drop
    # as `loupe-*` CustomEvents. Must load BEFORE the renderers that
    # consume it (`html-renderer.js`, `svg-renderer.js`). No
    # dependencies — pure DOM + closures.
    'src/sandbox-preview.js',
    # hashes.js — shared non-cryptographic fingerprint hashes (imphash
    # helpers, Rich-header hash, Mach-O symhash). Must load BEFORE any
    # native-binary renderer (pe/elf/macho) so they can call
    # `computeImportHashFromList`, `computeRichHash`, `computeSymHash`
    # without redefining their own MD5.
    'src/hashes.js',
    # mitre.js — canonical MITRE ATT&CK technique registry + rollup
    # helpers used by the sidebar "MITRE ATT&CK Coverage" section, the
    # Tier-A capability strip, and `Copy Analysis`. Exposes `window.MITRE`
    # with `lookup`, `rollupByTactic`, `primaryTactic`, `urlFor`,
    # `tacticMeta`. Must load BEFORE `capabilities.js` (and BEFORE the
    # three native-binary renderers) so every emit site can cite a
    # canonical technique id instead of rolling its own table.
    'src/mitre.js',
    'src/evtx-event-ids.js',
    # trusted-cas.js — curated public-CA recognition for Authenticode /
    # Mach-O code-sig trust tier classification. Exposes `TrustedCAs` with
    # `classifyTrustTier(certs) → 'unsigned'|'self-signed'|'signed'|'signed-trusted'`
    # and `trustBoostForTier(tier) → -1|0|+1|+2`. Consumed by binary-class.js
    # and the PE / Mach-O renderers. Must load BEFORE binary-class.js and
    # the native-binary renderers.
    'src/trusted-cas.js',
    # binary-class.js — shared binary-classification helper (size · trust ·
    # kind · family). Drives the `_weight()` and `_surface()` gates inside
    # the PE / ELF / Mach-O renderers so ubiquitous-API capability noise
    # (anti-debug, generic networking, dynamic loading) gets demoted on
    # large signed-trusted SDK / system / compiler-toolchain binaries while
    # critical capabilities (process injection, credential theft,
    # ransomware-class crypto) keep full weight. Must load BEFORE
    # capabilities.js consumers AND AFTER trusted-cas.js.
    'src/binary-class.js',
    # capabilities.js — static capability tagging (capa-lite). Consumed by
    # PE / ELF / Mach-O renderers via `Capabilities.detect({imports,strings,dylibs})`
    # to turn a wall of suspicious APIs into named behaviours with MITRE
    # ATT&CK IDs. Must load BEFORE the native-binary renderers.
    'src/capabilities.js',

    # binary-overlay.js — shared overlay detection + clickable drill-down
    # used by PE / ELF / Mach-O renderers. Exposes BinaryOverlay on window.
    # Must load BEFORE the native-binary renderers.
    'src/binary-overlay.js',
    # binary-strings.js — categorised string classification (mutex, named
    # pipe, PDB path, user-home/build-tree path, registry key) + Rust
    # panic-source mining. Consumed by PE / ELF / Mach-O renderers. Must
    # load BEFORE the native-binary renderers and AFTER constants.js so
    # it can reach pushIOC / IOC.* at emit-time.
    'src/binary-strings.js',
    # binary-exports.js — export-anomaly flags (DLL side-loading host,
    # forwarded / proxy-DLL exports, ordinal-only exports). Consumed by
    # PE / ELF / Mach-O renderers via `BinaryExports.emit(findings,
    # {isLib, fileName, exportNames, forwardedExports, ordinalOnlyCount})`.
    # Must load BEFORE the native-binary renderers and AFTER constants.js
    # (pushIOC / IOC.*).
    'src/binary-exports.js',
    # binary-summary.js — shared "binary pivot" triage card (file hash
    # trio, import hash / RichHash / SymHash, signer, compile timestamp
    # with "faked?" flag, entry-point + anomaly, overlay Y/N, packer
    # verdict). Consumed by PE / ELF / Mach-O renderers via
    # `BinarySummary.renderCard({...})`. Must load AFTER hashes.js (needs
    # `md5`) and BEFORE the native-binary renderers.
    'src/binary-summary.js',
    # binary-verdict.js — Tier-A verdict one-liner + coarse 0..100 risk
    # score derived from the parsed object, findings, and MITRE-tagged
    # capability counts. Exposes `window.BinaryVerdict.summarize({parsed,
    # findings, format, fileSize})`. Pure presentation — never mutates.
    # Must load AFTER binary-summary.js and BEFORE the native renderers.
    'src/binary-verdict.js',
    # binary-anomalies.js — anomaly-ribbon feeder + "should this card
    # auto-open?" predicate. Tier-C reference cards collapse by default
    # on clean samples and auto-open when this module flags them.
    # Exposes `window.BinaryAnomalies.detect({parsed, findings, format})`.
    # Must load AFTER binary-summary.js / binary-verdict.js and BEFORE
    # the native renderers.
    'src/binary-anomalies.js',
    # binary-triage.js — Tier-A "verdict band" composer. Glues
    # BinaryVerdict (one-liner + 0-100 risk), BinaryAnomalies (coloured
    # ribbon), and MITRE.rollupByTactic (tactic-grouped capability strip)
    # into a single DOM node the three native-binary renderers append
    # above the Binary Pivot card. Pure presentation — never mutates.
    # Must load AFTER binary-anomalies.js and BEFORE the native renderers.
    'src/binary-triage.js',
    'src/vba-utils.js',
    # lolbas-map.js — Living-Off-The-Land Binaries → ATT&CK lookup. Static
    # data + a small literal-substring scanner used by any renderer that
    # surfaces a Windows command-line / executable reference. Pure, no
    # dependencies, must load BEFORE any renderer that consults it (none
    # do mandatorily today — adoption is opportunistic).
    'src/lolbas-map.js',
    # email-spoof.js — display-name / brand-mismatch heuristics for the
    # `From:` header. Used by both eml-renderer and msg-renderer to flag
    # the canonical "PayPal Support <attacker@evil.tld>" phishing pretext
    # (the existing T2.4 freemail-only check misses non-freemail throwaway
    # domains; this closes that gap). Pure data + regex, no dependencies.
    'src/email-spoof.js',
    # xlsx-extras.js — XLSX-only scanners that probe attack surfaces not
    # reachable through `_rels/*.rels`: xl/connections.xml (external data
    # connections — OLEDB/ODBC/web/text, with refreshOnLoad gating) and
    # xl/customXml/item*.xml (Power Query DataMashup payloads). Used by
    # XlsxRenderer in addition to OoxmlRelScanner. Must load BEFORE
    # xlsx-renderer.js (the renderer references the helper classes).
    'src/xlsx-extras.js',

    'src/yara-engine.js',
    # worker-manager.js — central host-side spawner for src/workers/*.worker.js.
    # The build-gate `_check_worker_spawn_allowlist()` allow-lists this file
    # plus `src/workers/*.worker.js`; every other call site must funnel through
    # `window.WorkerManager.{runYara,…}`. Must load AFTER yara-engine.js (it
    # references the build-injected `__YARA_WORKER_BUNDLE_SRC` constant which
    # carries a copy of the engine's source) and BEFORE app-yara.js / app-load.js
    # (which call WorkerManager.runYara / WorkerManager.cancelYara at runtime).
    # See CONTRIBUTING.md → Worker subsystem.
    'src/worker-manager.js',

    'src/decompressor.js',
    # ── GeoIP providers — bundled IPv4-country (offline, public-domain RIR
    #    derivation) + user-uploaded MMDB override (IndexedDB-backed). Both
    #    expose the same provider contract — `lookupIPv4(ipStr) → {country,
    #    iso, region?, city?} | null`, `formatRow(rec) → string`,
    #    `getFieldName() → 'geo'`, `vintage`, `providerKind`. Resolved by
    #    `App.init()` in src/app/app-core.js into `app.geoip` (sync default
    #    = BundledGeoip; async hydrates to MmdbReader if one is persisted).
    #    Consumed by the Timeline GeoIP enrichment mixin
    #    (timeline-view-geoip.js) — every other surface ignores them.
    #    Must load AFTER decompressor.js (mmdb-reader uses Decompressor
    #    for `.mmdb.gz`) and BEFORE app-core.js (init() reads the
    #    providers). Independent of every renderer.
    'src/geoip/bundled-geoip.js',
    'src/geoip/mmdb-reader.js',
    'src/geoip/geoip-store.js',
    # tar-parser.js — shared TAR archive parser with PAX extended header,
    # GNU long-name/link, GNU sparse, and base-256 numeric support.
    # Consumed by ZipRenderer (tar/tar.gz) and NpmRenderer (tgz tarballs).
    # Must load AFTER constants.js (PARSER_LIMITS) and BEFORE both renderers.
    'src/tar-parser.js',
    # encoded-content-detector.js is the class root; the helper modules under
    # src/decoders/ attach instance methods via Object.assign(...prototype, ...)
    # and one static (`unwrapSafeLink`). They MUST load AFTER the class root and
    # in the order below — see `_DETECTOR_FILES` for the canonical list, which
    # is reused by `_encoded_worker_bundle_src` to keep the worker bundle in
    # sync. See CONTRIBUTING.md → Encoded-content split.
    *_DETECTOR_FILES,
    # decoded-yara-filter.js — second-pass YARA gate for decoded encoded-
    # content payloads (Phase 1 of the deobfuscation-triage work). Reads
    # `window.WorkerManager.runDecodedYara` and exposes
    # `window.DecodedYaraFilter.applyDecodedYaraGate`. Must load AFTER
    # `_DETECTOR_FILES` (the EncodedContentDetector class root + helpers
    # are what produces the findings tree this gate walks) and AFTER
    # `worker-manager.js` (whose `runDecodedYara` is the only thing the
    # filter calls). The host site is `src/app/app-load.js`'s post-encoded
    # block; see the call site there for the integration shape.
    'src/decoded-yara-filter.js',
    # encoded-reassembler.js — whole-file reconstruction of scripts whose
    # obfuscation is spread across MULTIPLE parallel techniques (Phase 1
    # of the parallel-obfuscation UX improvement). Pure helper that takes
    # the detector's `encodedFindings` tree + the file's analysisText
    # and splices each deepest-decoded span back into the source at its
    # byte offset. Exposes `window.EncodedReassembler.build()` for the
    # host-side caller in `app-load.js`, and `mapReconToSource` /
    # `stripSentinels` helpers for the sidebar composite card.
    #
    # Must load AFTER `_DETECTOR_FILES` (needs the detector's finding
    # shape documented via `_pickDeepestTextNode`) and AFTER
    # `decoded-yara-filter.js` (same phase ordering — yara-gate runs
    # first so reassembly sees the YARA-retained subset) and BEFORE
    # `src/app/app-load.js` (the host integration site). No worker
    # bundle duplication — reassembly is main-thread only (Phase 1).
    'src/encoded-reassembler.js',
    'src/qr-decoder.js',

    'src/docx-parser.js',
    'src/style-resolver.js',
    'src/numbering-resolver.js',
    'src/content-renderer.js',
    'src/security-analyzer.js',
    'src/renderers/protobuf-reader.js',
    'src/renderers/ole-cfb-parser.js',
    'src/renderers/xlsx-renderer.js',
    'src/renderers/pptx-renderer.js',
    'src/renderers/odt-renderer.js',
    'src/renderers/odp-renderer.js',
    'src/renderers/ppt-renderer.js',
    'src/renderers/rtf-renderer.js',
    # archive-budget.js — aggregate archive-expansion budget shared across
    # every archive renderer in the recursive drill-down chain (PLAN H5).
    # Each renderer consults `app._archiveBudget` before pushing each row;
    # when the entry-count or aggregate-decompressed-bytes cap fires the
    # renderer breaks its enumeration loop and surfaces a single
    # `IOC.INFO` row. Reset by `App._handleFiles` (top-level loads only —
    # drill-downs intentionally share the budget). Must load AFTER
    # constants.js (reads PARSER_LIMITS) and BEFORE every archive
    # renderer (archive-tree.js + cab/rar/seven7/zip/jar/msix/browserext/
    # npm/iso/dmg/pkg).
    'src/archive-budget.js',
    # archive-analysis.js — canonical EXEC / DECOY classifier sets +
    # strict Zip-Slip / Tar-Slip traversal detector + common warning
    # builder shared across every archive renderer (zip / rar / 7z /
    # cab). Extracted from `ZipRenderer._findTraversalEntries` +
    # per-renderer copies of EXEC_EXTS / _isDoubleExt / _checkWarnings
    # so all four formats produce identical warnings for identical
    # suspicious inputs. Must load AFTER constants.js (uses none of
    # its exports directly but follows the shared-helper convention)
    # and BEFORE every archive renderer that references
    # `ArchiveAnalysis.*` or the aliased `EXEC_EXTS`.
    'src/archive-analysis.js',
    # FolderFile — synthetic top-level "file" object for drag-dropped
    # directories, multi-file loose drops, and `webkitdirectory` picker
    # ingestion (see `App._handleFiles` in `src/app/app-core.js`). Holds
    # a flat `_loupeFolderEntries` list of leaf metadata + back-refs to
    # real `File` objects; carries a zero-byte `arrayBuffer()`. The
    # `FolderFile.fromEntries(rootName, sources)` static walker reads
    # `webkitGetAsEntry()` directories asynchronously up to
    # `PARSER_LIMITS.MAX_FOLDER_ENTRIES`. Used by `FolderRenderer`
    # (registered at the top of `RendererRegistry.ENTRIES`) and routed
    # through the standard drill-down path on click. Must load AFTER
    # constants.js (reads PARSER_LIMITS) and BEFORE app-core.js (the
    # ingress site that constructs FolderFile instances).
    'src/folder-file.js',
    # archive-tree.js — shared collapsible / searchable / sortable archive
    # browser. Must load BEFORE every renderer that uses `ArchiveTree`
    # (zip, jar, msix, browserext) so the class exists at construction time.
    'src/renderers/archive-tree.js',
    # FolderRenderer — synthetic root for drag-dropped directories +
    # multi-file loose drops + `webkitdirectory` picker (see
    # `src/folder-file.js`). Uses `ArchiveTree` for the body, so it MUST
    # load AFTER `archive-tree.js`. The renderer is registered at the
    # TOP of `RendererRegistry.ENTRIES` (magic predicate keyed on
    # `_loupeFolderEntries`), so order vs other renderers within this
    # block is not load-bearing — but it MUST be present BEFORE
    # `renderer-registry.js` runs `_bootstrap`, like every other entry.
    'src/renderers/folder-renderer.js',
    'src/renderers/zip-renderer.js',
    # Archive sub-formats that share the ArchiveTree browser but own their
    # own container parsers. Must load AFTER archive-tree.js (like zip) and
    # BEFORE renderer-registry.js so the registry's `_bootstrap` can attach
    # `static EXTS` / `canHandle()` to each class by global name.
    'src/renderers/cab-renderer.js',
    'src/renderers/rar-renderer.js',
    'src/renderers/seven7-renderer.js',

    'src/renderers/iso-renderer.js',
    'src/renderers/dmg-renderer.js',
    'src/renderers/pkg-renderer.js',
    'src/renderers/url-renderer.js',
    'src/renderers/ics-renderer.js',
    'src/renderers/onenote-renderer.js',
    'src/renderers/iqy-slk-renderer.js',
    'src/renderers/scf-renderer.js',
    'src/renderers/library-ms-renderer.js',
    'src/renderers/mof-renderer.js',
    'src/renderers/xslt-renderer.js',
    'src/renderers/wasm-renderer.js',
    'src/renderers/pcap-renderer.js',
    'src/renderers/wsf-renderer.js',
    'src/renderers/reg-renderer.js',
    'src/renderers/inf-renderer.js',
    'src/renderers/msi-renderer.js',
    # json-tree.js — shared lightweight collapsible JSON tree.
    # Exposes `window.JsonTree` with {render, pathGet, pathLabel,
    # maybeJson, tryParse, collectLeafPaths}. Used by GridViewer's drawer
    # (for auto-detected JSON cells in CSV / EVTX / SQLite / XLSX rows)
    # and by Timeline's "ƒx Extract" raw-cell popup. Must load BEFORE
    # grid-viewer.js (which references JsonTree at render time) and
    # BEFORE app-timeline.js (which replaced its local tree with this
    # shared one).
    'src/json-tree.js',
    # row-store.js — flat-buffer immutable row container shared by GridViewer
    # and the Timeline pipeline (worker + main thread). Fixes the OOM-tab-
    # crash failure mode the legacy `string[][]` accumulator hit on multi-
    # hundred-MB CSVs by replacing it with `{bytes: Uint8Array, offsets:
    # Uint32Array, rowCount}` chunks transferred zero-copy across the
    # worker boundary. Exposes `RowStore`, `RowStoreBuilder`, and the
    # `packRowChunk(rows, colCount)` helper the timeline worker uses to
    # pack `_parseCsv` batches before posting them. Must load AFTER
    # constants.js (consumes RENDER_LIMITS shape implicitly via callers)
    # and BEFORE grid-viewer.js (which reads RowStore via `setRows`) and
    # the renderers that build it (csv / sqlite / evtx). Same dual-bundle
    # pattern as `src/ioc-extract.js` — also concatenated into the
    # timeline parse-only worker bundle below.
    'src/row-store.js',
    # grid-viewer.js — bulletproof shared virtual-scroll grid (fixed-height
    # rows, absolute-positioned rows, right-side resizable drawer, unified
    # highlight state machine, chunked cooperative parse, mandatory
    # destroy()). Must load BEFORE every renderer that consumes it
    # (csv-renderer.js today; future evtx / xlsx / sqlite / json adopters).
    'src/renderers/grid-viewer.js',
    'src/renderers/csv-renderer.js',
    'src/renderers/json-renderer.js',
    'src/renderers/evtx-renderer.js',
    # evtx-detector.js — analysis-only EVTX threat-detection / IOC-extraction.
    # Extracted from evtx-renderer.js so the Timeline parse-only worker
    # bundle stays small: the worker never references this file,
    # and the analyzer runs on the main thread after the worker streams
    # parsed events back. EvtxRenderer.analyzeForSecurity now forwards to
    # EvtxDetector.analyzeForSecurity. Must load AFTER evtx-renderer.js
    # because the detector falls back to `new EvtxRenderer()._parse(bytes)`
    # when the caller doesn't supply prebuilt events.
    'src/evtx-detector.js',
    'src/renderers/sqlite-renderer.js',
    'src/renderers/doc-renderer.js',
    'src/renderers/msg-renderer.js',
    'src/renderers/eml-renderer.js',
    'src/renderers/lnk-renderer.js',
    'src/renderers/hta-renderer.js',
    'src/renderers/html-renderer.js',
    'src/renderers/pdf-renderer.js',
    # binary-reader.js — pure endian-aware byte-read helpers shared
    # by every native binary renderer (PE / ELF / Mach-O). Each
    # renderer wraps the static helpers as `_u8` / `_u16` / `_u32` /
    # `_u64` / `_str` / `_hex` / `_entropy` / `_esc` instance methods
    # that pass `this._le`. Must load BEFORE pe / elf / macho
    # renderers below.
    'src/binary-reader.js',
    'src/renderers/pe-renderer.js',
    'src/renderers/elf-renderer.js',
    'src/renderers/macho-renderer.js',
    'src/renderers/x509-renderer.js',
    'src/renderers/pgp-renderer.js',
    'src/renderers/jar-renderer.js',
    'src/renderers/svg-renderer.js',
    'src/renderers/osascript-renderer.js',
    'src/renderers/plist-renderer.js',
    'src/renderers/image-renderer.js',
    # virtual-text-view.js — virtual-scroll line-numbered text viewer used
    # by PlainTextRenderer. Must load BEFORE plaintext-renderer.js so the
    # `class VirtualTextView` global is defined when the renderer's
    # `_buildTextPane()` constructs it.
    'src/renderers/virtual-text-view.js',
    # code-formatter.js — best-efforts visual code pretty-printer used by
    # PlainTextRenderer's Format toggle. Pure function (no DOM, no
    # globals, no IO); see its header for the design contract. Lives at
    # `src/code-formatter.js` (not `src/renderers/`) because it's a pure
    # helper — the `src/renderers/` directory is gated by the renderer
    # contract (every file there must export a `render()` method). Must
    # load BEFORE plaintext-renderer.js so `CodeFormatter` is defined
    # when the renderer's `_buildTextPane()` checks for it.
    'src/code-formatter.js',
    'src/renderers/plaintext-renderer.js',
    'src/renderers/clickonce-renderer.js',
    'src/renderers/msix-renderer.js',
    'src/renderers/browserext-renderer.js',
    'src/renderers/npm-renderer.js',
    # Registry — concatenated AFTER every renderer so its `_bootstrap()`
    # can attach `static EXTS` + `static canHandle()` to each class by
    # name, and BEFORE app-core.js so `App._loadFile` can call
    # `RendererRegistry.detect()` / `RendererRegistry.makeContext()`.
    'src/renderer-registry.js',
    # render-route.js — central renderer dispatch helper. Exposes
    # `window.RenderRoute.run(file, buf, app, rctx?)` which calls
    # `RendererRegistry.detect()`, invokes the matched
    # `App._rendererDispatch[id]` handler under the parser-watchdog
    # (`PARSER_LIMITS.RENDERER_TIMEOUT_MS`), normalises the renderer's
    # return into the canonical `RenderResult` shape (centralised
    # `lfNormalize` of `_rawText`/`textContent`), and stamps
    # `app.currentResult`. Must load AFTER renderer-registry.js (the
    # detect/makeContext entrypoints) and AFTER parser-watchdog.js (read
    # via the global), and BEFORE app-core.js so `App._loadFile` can call
    # `RenderRoute.run(...)` without a forward reference. The
    # `_rendererDispatch` table itself lives in `app-load.js`.
    'src/render-route.js',
    # renderer-dispatch-factory.js — declarative `_rendererDispatch` handler
    # factory merged with bespoke overrides in app-load.js. Must load AFTER
    # every renderer class the SPEC references and BEFORE app-load.js.
    'src/renderer-dispatch-factory.js',
    # app-bg.js — subtle per-theme animated landing-surface background
    # (plasma drift on light/dark, floating hearts on mocha, floating
    # kittens on latte, golden-ratio phyllotaxis spiral on solarized,
    # nothing at all on midnight / prefers-reduced-motion). Exposes
    # `window.BgCanvas = { init, setTheme }`. Must load BEFORE
    # app-core.js (which calls `BgCanvas.init()` inside `App.init()`)
    # and BEFORE app-ui.js (which calls `BgCanvas.setTheme(id)` from
    # `_setTheme()` after applying the body class).
    'src/app/app-bg.js',
    'src/app/app-core.js',

    # src/app/timeline/ — Timeline mode (CSV / TSV / EVTX / SQLite browser
    # history), split into 7 cohesive modules under src/app/timeline/.
    # Must load AFTER app-core.js (defines `App`) and AFTER grid-viewer.js /
    # csv-renderer.js / evtx-renderer.js / sqlite-renderer.js (all under
    # src/renderers/, already concatenated above) since TimelineView reuses
    # them directly. Load order within the group matters:
    #   1. timeline-helpers.js       — TIMELINE_* constants + `_tl*` pure helpers
    #   2. timeline-query.js         — query language tokenizer / parser /
    #                                  compiler (consumes helpers)
    #   3. timeline-query-editor.js  — `TimelineQueryEditor` class (consumes
    #                                  query module)
    #   4. timeline-view.js          — `class TimelineView` core: DOM, state,
    #                                  scroll grid, scrubber, histogram, plus
    #                                  the `static fromCsvAsync / fromEvtx /
    #                                  fromSqlite` factories
    #   5. timeline-detections.js    — TimelineView.prototype mixin: Detections
    #                                  + Entities (EVTX-only, in-view only)
    #   6. timeline-summary.js       — TimelineView.prototype mixin: AI/LLM-ready
    #                                  Markdown "⚡ Summarize" export covering
    #                                  the whole EVTX file (entities, detections,
    #                                  relationships, time clusters, plus an
    #                                  active-view sub-section). EVTX-only.
    #   7. timeline-drawer.js        — TimelineView.prototype mixin: JSON
    #                                  drawer + extracted-column helpers
    #   8. timeline-router.js        — App.prototype mixin: `_timelineTryHandle`
    #                                  / `_loadFileInTimeline` /
    #                                  `_clearTimelineFile` (the analyser-bypass
    #                                  routing entrypoint).
    # **Analysis-bypass property.** Nothing in src/app/timeline/ pushes IOCs,
    # mutates `app.findings`, runs `EncodedContentDetector`, or invokes
    # `pushIOC`. EVTX is the sole controlled exception: the router calls
    # `EvtxDetector.analyzeForSecurity` and threads the result into
    # TimelineView purely to feed the in-view Detections + Entities sections.
    # timeline-parser-helpers.js — shared parser/tokenizer helpers used
    # by BOTH timeline-helpers.js (main thread) AND the timeline parse
    # worker bundle. Holds the truly-identical CLF / syslog / JSONL /
    # CloudTrail / CEF / LEEF / logfmt / W3C / Apache / access-log /
    # Zeek tokenizer functions and their constant tables. Must load
    # BEFORE timeline-helpers.js (which depends on these symbols) and
    # is concatenated into `_timeline_worker_bundle_src` after the
    # worker shim, see the bundle definition further below.
    'src/app/timeline/timeline-parser-helpers.js',
    'src/app/timeline/timeline-helpers.js',
    'src/app/timeline/timeline-query.js',
    'src/app/timeline/timeline-query-editor.js',
    # timeline-row-view.js — RowStore-shaped adapter wrapping
    # `{ baseStore, extractedCols, baseLen, idx }` so GridViewer can
    # consume Timeline rows without an intermediate `string[][]`
    # materialisation. Loads before timeline-view.js (which builds an
    # instance per render) and after row-store.js (already in
    # APP_JS_FILES; provides the `RowStore` class type the adapter
    # delegates to).
    'src/app/timeline/timeline-row-view.js',
    # timeline-dataset.js — owns the four parallel-array slots
    # (`store` / `_timeMs` / `_evtxEvents` / `_extractedCols`) and
    # enforces the `length === store.rowCount` invariant on every
    # mutation. Pure data class; no DOM, no globals beyond
    # `Float64Array`/`Array`. Loads AFTER row-store.js (uses RowStore
    # shape) and BEFORE timeline-view.js (which holds an instance and
    # forwards reads through it). NOT in the worker bundle — the
    # worker builds RowStore + timeMs + evtx events as separate
    # transferables and posts them; the dataset wrapper is consumed
    # only on the main thread when the view is constructed.
    'src/app/timeline/timeline-dataset.js',
    # timeline-mapper.js — pure per-format canonical column mappers and
    # the fusion predicate used by `buildCompositeSchema`. Consumed by
    # `timeline-composite.js`; touches no DOM, no TimelineView. Must
    # load AFTER `timeline-parser-helpers.js` (reads `_TL_*_COLS`
    # schema constants) and BEFORE `timeline-composite.js`.
    'src/app/timeline/timeline-mapper.js',
    # timeline-composite.js — composite RowStore / sourceOfRow /
    # enabled-bitmap / chrono-sort builders for merged Timelines.
    # Consumed by `TimelineView.fromSources` and `_timelineAddFile`.
    # Must load AFTER `row-store.js` + `timeline-mapper.js` and
    # BEFORE `timeline-view-factories.js`.
    'src/app/timeline/timeline-composite.js',
    # timeline-wheel.js — outer-host scroll-continuation handler. Loads
    # before timeline-view.js so the installer (`window.installTimeline-
    # WheelContinuation`) is in scope when `_buildDOM` mounts `.tl-host`.
    'src/app/timeline/timeline-wheel.js',
    'src/app/timeline/timeline-view.js',
    # timeline-view-factories.js — TimelineView static-method mixin
    # (B2a). Hosts `TimelineView.fromCsvAsync` / `fromEvtx` /
    # `fromSqlite` / `fromSources` (multi-source); attaches via
    # `Object.assign(TimelineView, {...})`.
    # MUST load AFTER timeline-view.js so the class identifier exists.
    'src/app/timeline/timeline-view-factories.js',
    # timeline-sources.js — SourceRecord factory that wraps the
    # `TimelineView.fromXxx` parsers, destructures the intermediate
    # view into a SourceRecord, and releases the heavy data references.
    # Must load AFTER timeline-view-factories.js (reads the static
    # factory methods off TimelineView) and BEFORE timeline-router.js
    # (which calls `timelineSourceFromFile`).
    'src/app/timeline/timeline-sources.js',
    # timeline-sources-bar.js — chip-bar mixin for merged timelines.
    # Renders one chip per SourceRecord with toggle + remove affordances
    # and Alt+1..9 shortcuts. Gated on `this._sources.length >= 2`.
    # Must load AFTER timeline-view.js (attaches to prototype) and
    # AFTER timeline-sources.js (uses the palette constant).
    'src/app/timeline/timeline-sources-bar.js',
    # timeline-view-persist.js — TimelineView static-method mixin
    # (B2b). Hosts the ~30 `_loadXxx` / `_saveXxx` localStorage
    # helpers (bucket pref, grid/chart heights, sections, per-file
    # card widths/order/pinned cols, entities pinned/order, regex
    # extracts, autoextract-done marker, pivot spec, query, sus
    # marks). All keys live in `TIMELINE_KEYS` (timeline-helpers.js)
    # and are documented in the **Persistence Keys** table in
    # CONTRIBUTING.md — never rename without bumping that table.
    # Loads AFTER timeline-view.js for the same reason as factories.
    'src/app/timeline/timeline-view-persist.js',
    # timeline-view-filter.js — TimelineView prototype mixin (B2c).
    # Hosts the filter + chart-data pipeline: timestamp parsing,
    # `_applyQueryString`, `_recomputeFilter`, sus + detection bitmap
    # rebuilds, the window-only fast path, sync + cooperative-async
    # column stats, distinct-values lookup, the ignore-one-column
    # index helper, the bucket-size resolver, and `_computeChartData`
    # (the histogram bucketer). Hot paths — bodies are byte-identical
    # with the pre-B2c `timeline-view.js`. Loads AFTER timeline-view.js.
    'src/app/timeline/timeline-view-filter.js',
    # timeline-view-popovers.js — TimelineView prototype mixin (B2d).
    # Hosts the Add-Sus popover, right-click row context menu, the
    # generic single-slot popover/dialog teardowns
    # (`_closePopover` / `_closeDialog`), the Excel-style column
    # header menu, and the multi-tab Extraction dialog (Smart-scan
    # + Regex + Clicker). The tiny utilities `_ellipsis`,
    # `_copyToClipboard`, `_positionFloating` remain in
    # timeline-view.js because the chart and grid mixins also call
    # them. Loads AFTER timeline-view.js.
    'src/app/timeline/timeline-view-popovers.js',
    # timeline-view-render-chart.js — TimelineView prototype mixin
    # (B2f1). Hosts the entire chart paint stack: scrubber rendering
    # + drag, the histogram canvas paint (`_renderChartInto` and its
    # stable-stack-color cache), the red-line "you are here" cursor
    # (paint, drag, grid-scroll sync), the rubber-band selection
    # (`_installChartDrag`), the chart-only height grab-bar, and the
    # legend click/dbl-click/context handlers. Hot paths — bodies
    # are byte-identical with pre-B2f1 `timeline-view.js`. Loads
    # AFTER timeline-view.js.
    'src/app/timeline/timeline-view-render-chart.js',
    # timeline-view-render-grid.js — TimelineView prototype mixin
    # (B2f2). Twin to render-chart but for the lower half of the
    # timeline UI: the grid table mount (`_renderGridInto`) and the
    # column top-values "cards" strip (`_paintColumnCards` and its
    # drag/resize/sus-resolve helpers). Hot paths — bodies are
    # byte-identical with the pre-B2f2 `timeline-view.js`. Loads
    # AFTER timeline-view.js.
    'src/app/timeline/timeline-view-render-grid.js',
    # timeline-view-query-chips.js — TimelineView prototype mixin
    # (B2f3). Hosts the query-AST manipulation surface (the
    # click-pivot mutators every Include/Exclude/Only/Pin path
    # routes through), the chips strip renderer, the
    # `_addOrToggleChip` and friends thin wrappers, and the
    # Ctrl+Click multi-select helpers. The query bar is the single
    # source of truth for row filtering, so this mixin is the
    # central point where UI clicks become AST edits. Loads AFTER
    # timeline-view.js.
    'src/app/timeline/timeline-view-query-chips.js',
    # timeline-view-export.js — TimelineView prototype mixin (B2f4).
    # Hosts the pivot-table auto-pick + builder, the per-section
    # "⋯" / export menu dispatcher (`_onSectionAction`), the
    # `_forensic*` filename helpers, and every CSV / PNG exporter.
    # All five exporters route through `FileDownload.downloadText`
    # / `downloadBlob` and share the
    # `<source-stem>__<section>__<UTC>.<ext>` naming convention
    # — keeping them in one mixin is what makes that convention a
    # single locked-down place. Loads AFTER timeline-view.js.
    'src/app/timeline/timeline-view-export.js',
    'src/app/timeline/timeline-detections.js',
    'src/app/timeline/timeline-summary.js',
    'src/app/timeline/timeline-drawer.js',
    # timeline-view-autoextract.js — TimelineView prototype mixin (B2e).
    # Hosts the silent best-effort auto-extract pass that runs on first
    # open (`_autoExtractBestEffort`), its per-proposal applier
    # (`_applyAutoProposal`), and the read-only heuristic scanner
    # (`_autoExtractScan`) used both there AND by the Auto tab inside
    # the Extraction dialog. MUST load AFTER `timeline-drawer.js`
    # because it calls `_addJsonExtractedColNoRender` /
    # `_addRegexExtractNoRender` / `_rebuildExtractedStateAndRender`
    # (all hosted there).
    'src/app/timeline/timeline-view-autoextract.js',
    # timeline-view-geoip.js — TimelineView prototype mixin that adds a
    # `<ipcol>.geo` enrichment column next to each detected IPv4 column on
    # first open. Reads `this._app.geoip` (resolved in App.init()) for the
    # active provider — `BundledGeoip` (RIR IPv4→ISO-2) by default,
    # `MmdbReader` if the user has uploaded one via Settings. Idempotent
    # via a `kind: 'geoip'` sentinel + the same `_loadAutoExtractDoneFor`
    # marker the auto-extract pass uses (so deletion is sticky).
    # Must load AFTER timeline-view-autoextract.js so its constructor
    # call sequence remains the canonical "post-mount enrichment" tail.
    # Pure mixin via Object.assign(TimelineView.prototype, …).
    'src/app/timeline/timeline-view-geoip.js',
    'src/app/timeline/timeline-router.js',

    # app-file-meta.js — pure file-metadata helpers (`_md5`, `_hashFile`,
    # `_detectMagic`, `_looksLikePgp`, `_computeEntropy`) extracted from
    # `app-load.js` so that file can shrink toward orchestration only.
    # Behaviour-preserving move; load order requires `app-core.js`
    # (defines `extendApp`) before us, and us before `app-load.js`
    # (the consumer).
    'src/app/app-file-meta.js',
    'src/app/app-load.js',
    'src/app/app-sidebar.js',
    # app-sidebar-focus.js holds the click-to-focus / highlighting engine:
    # _navigateToFinding, _findIOCMatches, _highlightMatchesInline, the
    # TreeWalker fallback, the 5 s idle clear, plus the Binary Metadata +
    # MITRE ATT&CK sections (their rows hang off the same navigation
    # plumbing). Split out of app-sidebar.js to keep the rendering half
    # below ~2 K lines. Must load AFTER app-sidebar.js because
    # _renderFindingsTableSection attaches click handlers that call into
    # _navigateToFinding defined here — but only by name (via `this`), so
    # the order is load-time, not lookup-time, and the Object.assign merge
    # simply lands both halves onto App.prototype.
    'src/app/app-sidebar-focus.js',
    'src/app/app-yara.js',
    'src/app/app-ui.js',
    # app-copy-analysis.js holds the 28 per-format _copyAnalysisXxx markdown
    # builders plus the _copyAnalysisFormatSpecific dispatcher they're called
    # from. Split out of app-ui.js to keep that file below ~2K lines. Must
    # load AFTER app-ui.js (which defines _formatMetadataValue + _sCaps that
    # these builders consume) and BEFORE app-settings.js (which overrides
    # _copyAnalysis itself with the Summary-budget variant).
    'src/app/app-copy-analysis.js',
    # app-settings.js attaches unified Settings/Help dialog methods onto
    # App.prototype. Must load AFTER app-ui.js because the Settings tab's
    # theme picker references the THEMES registry + _setTheme defined there.
    'src/app/app-settings.js',
    # app-selection-decode.js — the floating "🔍 Decode selection" chip that
    # spawns when the analyst click-drags a selection inside a supported text
    # viewer (`.plaintext-scroll`, `.html-source-pane`, `.hta-source-pane`,
    # `.url-source`, `.iqy-source`, `.eml-body`, `.json-tree`, `.csv-view`,
    # `.ps1-source`). Clicking the chip wraps the highlighted bytes in a
    # synthetic .txt File and dispatches via `App.openInnerFile(syn, null,
    # { _aggressiveDecode: true, … })` so the encoded-content pipeline runs
    # against just the selection — the deobfuscation sidebar then renders the
    # result like any other drill-down. Aggressive mode lowers finder
    # thresholds (consumed in `app-load.js`'s encoded-content scan block, then
    # threaded into `WorkerManager.runEncoded({ aggressive: true })` and the
    # `EncodedContentDetector` constructor). Pure mixin; no cross-mixin
    # dependencies; persistence key `loupe_deobf_selection_enabled`. Must
    # load AFTER `app-core.js` (defines `extendApp`) — the canonical late-
    # mixin slot.
    'src/app/app-selection-decode.js',
    # Dev-mode debug breadcrumbs ribbon. Pure mixin
    # (`Object.assign(App.prototype, {...})`) with no cross-mixin
    # dependencies; every consumer (`_initBreadcrumbs`, `_breadcrumb`,
    # `_toggleDevBreadcrumbs`) is guarded with
    # `typeof this._breadcrumb === 'function'` at the call sites
    # (`app-core.js::_reportNonFatal`, `app-load.js::_loadFile`,
    # `render-route.js`, `worker-manager.js`) so load order relative to
    # the other late mixins doesn't matter — only that it loads AFTER
    # `app-core.js` defines the `App` constructor. Kept last so the
    # diagnostics layer never hides a real bootstrap dependency.
    'src/app/app-breadcrumbs.js',
]
