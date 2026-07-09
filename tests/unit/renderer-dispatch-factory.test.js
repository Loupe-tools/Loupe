'use strict';
// renderer-dispatch-factory.test.js — real factory handlers (not empty shims).

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const REPO = path.resolve(__dirname, '..', '..');
const factorySrc = fs.readFileSync(
  path.join(REPO, 'src/renderer-dispatch-factory.js'),
  'utf8',
);
const classNames = [...new Set(
  [...factorySrc.matchAll(/Class:\s*(\w+)/g)].map(m => m[1]),
)];

function loadFactory(shims) {
  const merged = { ...shims };
  for (const name of classNames) {
    if (!merged[name]) {
      merged[name] = class {
        analyzeForSecurity() { return {}; }
        render() { return { _tag: name }; }
      };
    }
  }
  return loadModules(['src/renderer-dispatch-factory.js'], {
    shims: merged,
    expose: ['RendererDispatchFactory'],
  });
}

test('RendererDispatchFactory.build(): pptx awaits analyze then render', async () => {
  const order = [];
  const ctx = loadFactory({
    PptxRenderer: class {
      async analyzeForSecurity() { order.push('analyze'); return {}; }
      async render() { order.push('render'); return { _tag: 'pptx-doc' }; }
    },
  });
  const dispatch = ctx.RendererDispatchFactory.build();
  assert.equal(typeof dispatch.pptx, 'function');
  const app = {
    findings: null,
    currentResult: { yaraBuffer: null },
    _wireInnerFileListener() {},
  };
  const file = { name: 'deck.pptx' };
  const buffer = new ArrayBuffer(4);
  const out = await dispatch.pptx.call(app, file, buffer);
  assert.deepEqual(order, ['analyze', 'render']);
  assert.equal(out.docEl._tag, 'pptx-doc');
  assert.ok(app.findings);
});

test('RendererDispatchFactory.build(): plist stamps augmentedBuffer to yaraBuffer', () => {
  const augmented = new Uint8Array([0x50, 0x4c, 0x49, 0x53]);
  const ctx = loadFactory({
    PlistRenderer: class {
      analyzeForSecurity() { return { augmentedBuffer: augmented }; }
      render() { return { _tag: 'plist-doc' }; }
    },
  });
  const dispatch = ctx.RendererDispatchFactory.build();
  const app = {
    findings: null,
    currentResult: { yaraBuffer: null },
    _wireInnerFileListener() {},
  };
  const file = { name: 'prefs.plist' };
  const buffer = new ArrayBuffer(8);
  dispatch.plist.call(app, file, buffer);
  assert.equal(app.currentResult.yaraBuffer, augmented);
});

test('RendererDispatchFactory.build(): pkg awaits analyze/render and wires inner listener', async () => {
  const order = [];
  let wired = null;
  const ctx = loadFactory({
    PkgRenderer: class {
      async analyzeForSecurity() { order.push('analyze'); return {}; }
      async render() { order.push('render'); return { _tag: 'pkg-doc' }; }
    },
  });
  const dispatch = ctx.RendererDispatchFactory.build();
  const app = {
    findings: null,
    currentResult: { yaraBuffer: null },
    _wireInnerFileListener(el, name) { wired = { el, name }; },
  };
  const file = { name: 'installer.pkg' };
  const buffer = new ArrayBuffer(4);
  const out = await dispatch.pkg.call(app, file, buffer);
  assert.deepEqual(order, ['analyze', 'render']);
  assert.equal(out.docEl._tag, 'pkg-doc');
  assert.deepEqual(wired, { el: out.docEl, name: 'installer.pkg' });
});

test('RendererDispatchFactory._makeHandler: pinYaraRaw stamps yaraBuffer', () => {
  const ctx = loadFactory({});
  const handler = ctx.RendererDispatchFactory._makeHandler({
    Class: class {
      analyzeForSecurity() { return {}; }
      render() { return { _tag: 'raw-yara' }; }
    },
    pinYaraRaw: true,
  });
  const buffer = new ArrayBuffer(16);
  const app = {
    findings: null,
    currentResult: { yaraBuffer: null },
    _wireInnerFileListener() {},
  };
  handler.call(app, { name: 'capture.pcap' }, buffer);
  assert.equal(app.currentResult.yaraBuffer, buffer);
});