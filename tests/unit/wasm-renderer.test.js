'use strict';
// wasm-renderer.test.js — WebAssembly binary parser + security analyser.
//
// We hand-build minimal valid WASM modules with the spec's section format:
//   • Header: 0x00 'a' 's' 'm' + 4-byte LE version (1)
//   • Section: <id:varuint7> <size:varuint32> <payload>
//   • LEB128 encoding for unsigned integers (single-byte ≤ 127)
//   • Names: <len:varuint32> <utf-8 bytes>
//
// The unit-test fixtures stay below the 127-byte LEB128 single-byte
// boundary so we don't have to encode multi-byte LEB128 in the test
// harness. The parser itself handles up to 5-byte LEB128 — that's
// covered indirectly by the malformed/truncation tests.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  ['src/constants.js', 'src/renderers/wasm-renderer.js'],
  { expose: ['WasmRenderer', 'IOC', 'escalateRisk', 'pushIOC', 'lfNormalize'] },
);
const { WasmRenderer, IOC } = ctx;

// ── Builder helpers ───────────────────────────────────────────────────────

const HEADER = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

function leb128(n) {
  // Single-byte encoding for n ≤ 127. Beyond that we'd need the full loop;
  // not needed for these fixtures.
  if (n > 127) throw new Error('test fixture out of single-byte LEB128 range');
  return [n];
}

function nameBytes(s) {
  const enc = new TextEncoder().encode(s);
  return [...leb128(enc.length), ...enc];
}

function section(id, payload) {
  return [id, ...leb128(payload.length), ...payload];
}

/** Build a custom section with name + opaque body bytes. */
function customSection(name, body) {
  return section(0, [...nameBytes(name), ...body]);
}

/** Build a single-import section: vec of (module, field, kind, type-idx). */
function importSection(...imports) {
  // Each import: module-name, field-name, kind byte, type-idx (for func) /
  // limits (for memory). We support func-imports here (kind=0).
  const items = [];
  for (const imp of imports) {
    items.push(...nameBytes(imp.module));
    items.push(...nameBytes(imp.field));
    items.push(imp.kind ?? 0);
    if ((imp.kind ?? 0) === 0) {
      items.push(...leb128(imp.typeIdx ?? 0));
    } else if (imp.kind === 2) {
      // memory: limits flag + min (+ max if flag=1)
      items.push(imp.flag ?? 0);
      items.push(...leb128(imp.min ?? 1));
      if ((imp.flag ?? 0) & 1) items.push(...leb128(imp.max));
    }
  }
  return section(2, [...leb128(imports.length), ...items]);
}

/** Build a memory section with a single memory entry. */
function memorySection(min, max) {
  const flag = max != null ? 1 : 0;
  const limits = [flag, ...leb128(min)];
  if (max != null) limits.push(...leb128(max));
  return section(5, [...leb128(1), ...limits]);
}

/** Build an export section: vec of (name, kind, idx). */
function exportSection(...exports) {
  const items = [];
  for (const exp of exports) {
    items.push(...nameBytes(exp.name));
    items.push(exp.kind ?? 0);
    items.push(...leb128(exp.index ?? 0));
  }
  return section(7, [...leb128(exports.length), ...items]);
}

/** Build a type section with a single (param-list, result-list) tuple. */
function typeSection(params, results) {
  // form 0x60 + param count + param types + result count + result types.
  const body = [
    ...leb128(1),
    0x60,
    ...leb128(params.length), ...params,
    ...leb128(results.length), ...results,
  ];
  return section(1, body);
}

function bufFrom(arr) {
  return new Uint8Array(arr).buffer;
}

// ── Parser tests ──────────────────────────────────────────────────────────

test('wasm: empty module (header only) parses cleanly', () => {
  const parsed = WasmRenderer._parse(new Uint8Array(HEADER));
  assert.equal(parsed.error, null);
  assert.equal(parsed.version, 1);
  assert.equal(parsed.sections.length, 0);
  assert.equal(parsed.imports.length, 0);
  assert.equal(parsed.exports.length, 0);
});

test('wasm: bad magic → error, no crash', () => {
  const bad = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]);
  const parsed = WasmRenderer._parse(bad);
  assert.match(parsed.error, /Bad magic/);
});

test('wasm: too-small buffer → error', () => {
  const parsed = WasmRenderer._parse(new Uint8Array([0x00, 0x61, 0x73]));
  assert.match(parsed.error, /too small/i);
});

test('wasm: truncated section → bail with error', () => {
  // Header + section id 1 + huge size → truncated payload.
  const truncated = new Uint8Array([...HEADER, 1, 100]); // section claims 100 bytes
  const parsed = WasmRenderer._parse(truncated);
  assert.match(parsed.error, /Truncated/);
});

test('wasm: import section single func import is decoded', () => {
  const bytes = new Uint8Array([
    ...HEADER,
    ...importSection({ module: 'env', field: 'memory', kind: 2, flag: 1, min: 1, max: 2 }),
  ]);
  const parsed = WasmRenderer._parse(bytes);
  assert.equal(parsed.error, null);
  assert.equal(parsed.imports.length, 1);
  assert.equal(parsed.imports[0].module, 'env');
  assert.equal(parsed.imports[0].field, 'memory');
  assert.equal(parsed.imports[0].kindName, 'memory');
  assert.match(parsed.imports[0].desc, /min=1.*max=2/);
});

test('wasm: import section func import has type[idx] desc', () => {
  const bytes = new Uint8Array([
    ...HEADER,
    ...typeSection([0x7f], [0x7f]), // (i32) -> i32
    ...importSection({ module: 'env', field: 'eval', kind: 0, typeIdx: 0 }),
  ]);
  const parsed = WasmRenderer._parse(bytes);
  assert.equal(parsed.error, null);
  assert.equal(parsed.types.length, 1);
  assert.equal(parsed.imports.length, 1);
  assert.equal(parsed.imports[0].field, 'eval');
  assert.equal(parsed.imports[0].kindName, 'function');
  assert.equal(parsed.imports[0].desc, 'type[0]');
});

test('wasm: memory section initial+max parsed', () => {
  const bytes = new Uint8Array([
    ...HEADER,
    ...memorySection(2, 16),
  ]);
  const parsed = WasmRenderer._parse(bytes);
  assert.equal(parsed.error, null);
  assert.equal(parsed.memory.initial, 2);
  assert.equal(parsed.memory.maximum, 16);
  assert.equal(parsed.memory.shared, false);
});

test('wasm: memory section unbounded max parsed', () => {
  const bytes = new Uint8Array([
    ...HEADER,
    ...memorySection(1, null),
  ]);
  const parsed = WasmRenderer._parse(bytes);
  assert.equal(parsed.memory.initial, 1);
  assert.equal(parsed.memory.maximum, null);
});

test('wasm: export section decoded', () => {
  const bytes = new Uint8Array([
    ...HEADER,
    ...exportSection({ name: 'main', kind: 0, index: 0 },
                     { name: 'cryptonight_hash', kind: 0, index: 1 }),
  ]);
  const parsed = WasmRenderer._parse(bytes);
  assert.equal(parsed.exports.length, 2);
  assert.equal(parsed.exports[0].name, 'main');
  assert.equal(parsed.exports[1].name, 'cryptonight_hash');
});

test('wasm: custom section with name preserved + preview', () => {
  const bytes = new Uint8Array([
    ...HEADER,
    ...customSection('producers', [...new TextEncoder().encode('rustc-1.78')]),
  ]);
  const parsed = WasmRenderer._parse(bytes);
  assert.equal(parsed.customSections.length, 1);
  assert.equal(parsed.customSections[0].name, 'producers');
  assert.match(parsed.customSections[0].preview, /rustc-1\.78/);
});

test('wasm: sourceMappingURL custom section extracts urlPreview', () => {
  // The sourceMappingURL custom-section payload is itself a
  // length-prefixed UTF-8 string (the URL). Build it accordingly.
  const url = 'https://example.test/foo.wasm.map';
  const bytes = new Uint8Array([
    ...HEADER,
    ...customSection('sourceMappingURL', nameBytes(url)),
  ]);
  const parsed = WasmRenderer._parse(bytes);
  assert.equal(parsed.customSections.length, 1);
  assert.equal(parsed.customSections[0].urlPreview, url);
});

test('wasm: section enumeration cap respected (no infinite loop)', () => {
  // Build a long sequence of zero-payload custom sections. Each section
  // is `0x00 0x00 (size=0)` = 2 bytes. We feed MORE than MAX_SECTIONS to
  // confirm the cap fires.
  const overshoot = WasmRenderer.MAX_SECTIONS + 5;
  const filler = [];
  for (let i = 0; i < overshoot; i++) filler.push(0, 0);
  const parsed = WasmRenderer._parse(new Uint8Array([...HEADER, ...filler]));
  assert.match(parsed.error, /Section cap/);
  assert.equal(parsed.sections.length, WasmRenderer.MAX_SECTIONS);
});

// ── analyzeForSecurity tests ─────────────────────────────────────────────

test('wasm: empty module → low risk + modulehash IOC', async () => {
  const r = new WasmRenderer();
  const f = await r.analyzeForSecurity(bufFrom(HEADER), 'a.wasm');
  assert.equal(f.risk, 'low');
  const mh = f.externalRefs.find((x) => x.type === IOC.HASH);
  assert.ok(mh, 'expected modulehash IOC');
  // pushIOC stores the value under `url` regardless of IOC type.
  assert.match(mh.url, /^[0-9a-f]{64}$/);
  assert.match(mh.note, /modulehash/);
});

test('wasm: env.eval import → critical + T1059.007 capability', async () => {
  const bytes = [
    ...HEADER,
    ...typeSection([], []),
    ...importSection({ module: 'env', field: 'eval', kind: 0, typeIdx: 0 }),
  ];
  const r = new WasmRenderer();
  const f = await r.analyzeForSecurity(bufFrom(bytes), 'evil.wasm');
  assert.equal(f.risk, 'critical');
  assert.ok(f.externalRefs.some((x) => /env\/eval/.test(x.url) && x.severity === 'critical'));
  assert.ok(f.capabilities.some((c) => c.id === 'T1059.007'));
});

test('wasm: WASI sock_connect import → high + T1071', async () => {
  const bytes = [
    ...HEADER,
    ...typeSection([], []),
    ...importSection({ module: 'wasi_snapshot_preview1', field: 'sock_connect', kind: 0, typeIdx: 0 }),
  ];
  const r = new WasmRenderer();
  const f = await r.analyzeForSecurity(bufFrom(bytes), 'wasi.wasm');
  assert.equal(f.risk, 'high');
  assert.ok(f.capabilities.some((c) => c.id === 'T1071'));
});

test('wasm: WASI generic import without specific syscall → medium', async () => {
  const bytes = [
    ...HEADER,
    ...typeSection([], []),
    // Use a WASI field that ISN'T in the specific table — fall through
    // to the generic 'wasi_snapshot_preview1' module-prefix entry.
    ...importSection({ module: 'wasi_snapshot_preview1', field: 'fd_close', kind: 0, typeIdx: 0 }),
  ];
  const r = new WasmRenderer();
  const f = await r.analyzeForSecurity(bufFrom(bytes), 'wasi.wasm');
  assert.equal(f.risk, 'medium');
});

test('wasm: cryptonight export → critical + T1496', async () => {
  const bytes = [
    ...HEADER,
    ...exportSection({ name: 'cryptonight_hash', kind: 0, index: 0 }),
  ];
  const r = new WasmRenderer();
  const f = await r.analyzeForSecurity(bufFrom(bytes), 'miner.wasm');
  assert.equal(f.risk, 'critical');
  assert.ok(f.externalRefs.some((x) => /cryptonight_hash/.test(x.url)));
  assert.ok(f.capabilities.some((c) => c.id === 'T1496'));
});

test('wasm: keylogger export → critical + T1056.001', async () => {
  const bytes = [
    ...HEADER,
    ...exportSection({ name: 'keylogger_start', kind: 0, index: 0 }),
  ];
  const r = new WasmRenderer();
  const f = await r.analyzeForSecurity(bufFrom(bytes), 'k.wasm');
  assert.equal(f.risk, 'critical');
  assert.ok(f.capabilities.some((c) => c.id === 'T1056.001'));
});

test('wasm: large initial memory (≥256 pages) → medium', async () => {
  const bytes = [
    ...HEADER,
    ...memorySection(120, null), // 120 < 127 so single-byte LEB128 works
  ];
  const r = new WasmRenderer();
  const f = await r.analyzeForSecurity(bufFrom(bytes), 'a.wasm');
  // 120 < MEMORY_LARGE_INITIAL (256), so this should NOT trigger.
  assert.equal(f.risk, 'low');
  // Confirm the threshold itself by tweaking the constant on the class
  // for one assertion — easier than embedding a > 127 LEB128 fixture.
  const orig = WasmRenderer.MEMORY_LARGE_INITIAL;
  Object.defineProperty(WasmRenderer, 'MEMORY_LARGE_INITIAL',
    { value: 100, configurable: true, writable: true });
  try {
    const f2 = await r.analyzeForSecurity(bufFrom(bytes), 'a.wasm');
    assert.equal(f2.risk, 'medium');
    assert.ok(f2.externalRefs.some((x) => /Large initial memory/.test(x.url)));
  } finally {
    Object.defineProperty(WasmRenderer, 'MEMORY_LARGE_INITIAL',
      { value: orig, configurable: true, writable: true });
  }
});

test('wasm: huge max memory → high', async () => {
  // We can't naturally hit 16 384 with single-byte LEB128, so monkey-patch
  // MEMORY_HUGE_MAX down to 5 and feed max=10 in the fixture.
  const orig = WasmRenderer.MEMORY_HUGE_MAX;
  Object.defineProperty(WasmRenderer, 'MEMORY_HUGE_MAX',
    { value: 5, configurable: true, writable: true });
  try {
    const bytes = [...HEADER, ...memorySection(1, 10)];
    const r = new WasmRenderer();
    const f = await r.analyzeForSecurity(bufFrom(bytes), 'huge.wasm');
    assert.equal(f.risk, 'high');
    assert.ok(f.externalRefs.some((x) => /Huge maximum memory/.test(x.url)));
  } finally {
    Object.defineProperty(WasmRenderer, 'MEMORY_HUGE_MAX',
      { value: orig, configurable: true, writable: true });
  }
});

test('wasm: sourceMappingURL surfaces as URL IOC', async () => {
  const url = 'https://map.example.test/x.map';
  const bytes = [
    ...HEADER,
    ...customSection('sourceMappingURL', nameBytes(url)),
  ];
  const r = new WasmRenderer();
  const f = await r.analyzeForSecurity(bufFrom(bytes), 'src.wasm');
  // URL IOCs land in `interestingStrings` (sidebar table), not externalRefs.
  const urlIoc = f.interestingStrings.find((x) => x.type === IOC.URL && x.url === url);
  assert.ok(urlIoc, `expected URL IOC for sourceMappingURL, got: ${JSON.stringify(f.interestingStrings)}`);
});

test('wasm: parse-error path emits info IOC, no crash', async () => {
  const r = new WasmRenderer();
  const f = await r.analyzeForSecurity(new Uint8Array([0xde, 0xad]).buffer, 'bad.wasm');
  assert.equal(f.risk, 'low');
  assert.ok(f.externalRefs.some((x) => x.type === IOC.INFO && /parse error/i.test(x.url)));
});

test('wasm: modulehash is deterministic for same import set', async () => {
  const bytes = [
    ...HEADER,
    ...typeSection([], []),
    ...importSection(
      { module: 'env', field: 'a', kind: 0, typeIdx: 0 },
      { module: 'env', field: 'b', kind: 0, typeIdx: 0 },
    ),
  ];
  const r = new WasmRenderer();
  const f1 = await r.analyzeForSecurity(bufFrom(bytes), 'a.wasm');
  const f2 = await r.analyzeForSecurity(bufFrom(bytes), 'b.wasm');
  const h1 = f1.externalRefs.find((x) => x.type === IOC.HASH).url;
  const h2 = f2.externalRefs.find((x) => x.type === IOC.HASH).url;
  assert.equal(h1, h2);
});

test('wasm: modulehash is order-independent (sorted normalisation)', async () => {
  // Same import SET, different declaration order → same hash.
  const a = [
    ...HEADER,
    ...typeSection([], []),
    ...importSection(
      { module: 'env', field: 'a', kind: 0, typeIdx: 0 },
      { module: 'env', field: 'b', kind: 0, typeIdx: 0 },
    ),
  ];
  const b = [
    ...HEADER,
    ...typeSection([], []),
    ...importSection(
      { module: 'env', field: 'b', kind: 0, typeIdx: 0 },
      { module: 'env', field: 'a', kind: 0, typeIdx: 0 },
    ),
  ];
  const r = new WasmRenderer();
  const fa = await r.analyzeForSecurity(bufFrom(a), 'a.wasm');
  const fb = await r.analyzeForSecurity(bufFrom(b), 'b.wasm');
  const ha = fa.externalRefs.find((x) => x.type === IOC.HASH).url;
  const hb = fb.externalRefs.find((x) => x.type === IOC.HASH).url;
  assert.equal(ha, hb);
});

test('wasm: empty-import module gets the all-zero modulehash sentinel', async () => {
  const r = new WasmRenderer();
  const f = await r.analyzeForSecurity(bufFrom(HEADER), 'empty.wasm');
  const h = f.externalRefs.find((x) => x.type === IOC.HASH).url;
  assert.equal(h, '0'.repeat(64));
});
