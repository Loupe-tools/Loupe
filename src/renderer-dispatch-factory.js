'use strict';
// ════════════════════════════════════════════════════════════════════════════
// renderer-dispatch-factory.js — manifest-aligned dispatch handler factory
//
// Builds repetitive `App._rendererDispatch` entries from a declarative
// spec table. Bespoke overrides (folder, docx, csv, binaries, …) stay in
// app-load.js and are merged on top via Object.assign.
// ════════════════════════════════════════════════════════════════════════════

const RendererDispatchFactory = {

  /**
   * Declarative factory spec. Each row becomes one `_rendererDispatch` handler
   * unless the id is listed in DISPATCH_OVERRIDE_IDS (those live in app-load).
   *
   * Flags:
   *   awaitAnalyze  — `analyzeForSecurity` returns a Promise
   *   awaitRender   — `render` returns a Promise
   *   wireInner     — call `this._wireInnerFileListener(docEl, file.name)`
   *   analyzeBufferOnly — analyzeForSecurity(buffer) without fileName
   *   renderBufferOnly  — render(buffer) without fileName
   *   augmentedYara  — hoist findings.augmentedBuffer → currentResult.yaraBuffer
   *   pinYaraRaw     — pin currentResult.yaraBuffer = buffer (wasm/pcap pattern)
   */
  SPEC: [
    { id: 'msg', Class: MsgRenderer, analyzeBufferOnly: true, renderBufferOnly: true, wireInner: true },
    { id: 'msi', Class: MsiRenderer, wireInner: true },
    { id: 'doc', Class: DocBinaryRenderer, analyzeBufferOnly: true, renderBufferOnly: true, awaitAnalyze: true },
    { id: 'ppt', Class: PptBinaryRenderer, analyzeBufferOnly: true, renderBufferOnly: true, awaitAnalyze: true },
    { id: 'xlsx', Class: XlsxRenderer, awaitAnalyze: true },
    { id: 'pptx', Class: PptxRenderer, awaitAnalyze: true, awaitRender: true },
    { id: 'odt', Class: OdtRenderer, awaitAnalyze: true, awaitRender: true },
    { id: 'odp', Class: OdpRenderer, awaitAnalyze: true, awaitRender: true },
    { id: 'evtx', Class: EvtxRenderer, awaitAnalyze: true },
    { id: 'sqlite', Class: SqliteRenderer },
    { id: 'lnk', Class: LnkRenderer, analyzeBufferOnly: true, renderBufferOnly: true },
    { id: 'iso', Class: IsoRenderer, wireInner: true },
    { id: 'dmg', Class: DmgRenderer },
    { id: 'pkg', Class: PkgRenderer, awaitAnalyze: true, awaitRender: true, wireInner: true },
    { id: 'onenote', Class: OneNoteRenderer, awaitAnalyze: true },
    { id: 'eml', Class: EmlRenderer, awaitAnalyze: true, wireInner: true },
    { id: 'zip', Class: ZipRenderer, awaitAnalyze: true, awaitRender: true, wireInner: true },
    { id: 'cab', Class: CabRenderer, awaitAnalyze: true, awaitRender: true, wireInner: true },
    { id: 'rar', Class: RarRenderer, awaitAnalyze: true, awaitRender: true, wireInner: true },
    { id: 'sevenz', Class: SevenZRenderer, awaitAnalyze: true, awaitRender: true, wireInner: true },
    { id: 'msix', Class: MsixRenderer, awaitAnalyze: true, awaitRender: true, wireInner: true },
    { id: 'browserext', Class: BrowserExtRenderer, awaitAnalyze: true, awaitRender: true, wireInner: true },
    { id: 'npm', Class: NpmRenderer, awaitAnalyze: true, awaitRender: true, wireInner: true },
    { id: 'rtf', Class: RtfRenderer },
    { id: 'hta', Class: HtaRenderer, analyzeBufferOnly: true, renderBufferOnly: true },
    { id: 'url', Class: UrlShortcutRenderer },
    { id: 'ics', Class: IcsRenderer },
    { id: 'scf', Class: ScfRenderer },
    { id: 'libraryms', Class: LibraryMsRenderer },
    { id: 'mof', Class: MofRenderer },
    { id: 'xslt', Class: XsltRenderer },
    { id: 'reg', Class: RegRenderer },
    { id: 'inf', Class: InfSctRenderer },
    { id: 'iqyslk', Class: IqySlkRenderer },
    { id: 'wsf', Class: WsfRenderer },
    { id: 'clickonce', Class: ClickOnceRenderer },
    { id: 'plist', Class: PlistRenderer, augmentedYara: true },
    { id: 'scpt', Class: OsascriptRenderer, augmentedYara: true },
    { id: 'pgp', Class: PgpRenderer },
    { id: 'x509', Class: X509Renderer },
    { id: 'image', Class: ImageRenderer, awaitAnalyze: true },
  ],

  /** Ids with bespoke handlers in app-load.js — factory must not emit these. */
  OVERRIDE_IDS: Object.freeze(new Set([
    'folder', 'docx', 'csv', 'json', 'jar', 'pdf', 'html', 'svg',
    'wasm', 'pcap', 'pe', 'elf', 'macho', 'plaintext',
    'xls', 'ods',
  ])),

  _makeHandler(spec) {
    const {
      Class: RendererClass,
      awaitAnalyze = false,
      awaitRender = false,
      wireInner = false,
      analyzeBufferOnly = false,
      renderBufferOnly = false,
      augmentedYara = false,
      pinYaraRaw = false,
    } = spec;

    const run = async function(file, buffer) {
      const r = new RendererClass();
      const analyzeArgs = analyzeBufferOnly
        ? [buffer]
        : [buffer, file.name];
      if (awaitAnalyze) {
        this.findings = await r.analyzeForSecurity.apply(r, analyzeArgs);
      } else {
        this.findings = r.analyzeForSecurity.apply(r, analyzeArgs);
      }
      if (augmentedYara && this.findings && this.findings.augmentedBuffer) {
        this.currentResult.yaraBuffer = this.findings.augmentedBuffer;
      }
      if (pinYaraRaw) {
        this.currentResult.yaraBuffer = buffer;
      }
      const renderArgs = renderBufferOnly
        ? [buffer]
        : [buffer, file.name];
      let docEl;
      if (awaitRender) {
        docEl = await r.render.apply(r, renderArgs);
      } else {
        docEl = r.render.apply(r, renderArgs);
      }
      if (wireInner) this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    };

    if (awaitAnalyze || awaitRender) return run;
    return function(file, buffer) { return run.call(this, file, buffer); };
  },

  build() {
    const out = {};
    for (const spec of RendererDispatchFactory.SPEC) {
      if (RendererDispatchFactory.OVERRIDE_IDS.has(spec.id)) continue;
      out[spec.id] = RendererDispatchFactory._makeHandler(spec);
    }
    return out;
  },
};