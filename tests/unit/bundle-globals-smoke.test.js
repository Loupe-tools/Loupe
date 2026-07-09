'use strict';

// Smoke-test a built bundle preserves Loupe's flat-global runtime contract.
// Opt-in: LOUPE_BUNDLE_SMOKE=1 (set alongside LOUPE_ESBUILD=full test-build).
// Status-quo (Option A per PLAN-code-review-followups S8 / CONTRIBUTING.md:86):
// concat is the supported release path; smoke is deliberately not wired into
// DEFAULT_STEPS / TEST_STEPS / CI until a cutover decision. See cutover recipe
// in CONTRIBUTING.md near "Concat remains the supported release path".

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const REPO = path.resolve(__dirname, '..', '..');
const BUNDLE = path.join(REPO, 'docs', 'index.test.html');

test('bundle globals smoke (LOUPE_BUNDLE_SMOKE=1)', { skip: process.env.LOUPE_BUNDLE_SMOKE !== '1' ? 'set LOUPE_BUNDLE_SMOKE=1' : false }, async () => {
  assert.ok(fs.existsSync(BUNDLE), `${BUNDLE} missing — run LOUPE_ESBUILD=full LOUPE_ESBUILD_MINIFY=1 python make.py test-build first`);
  const html = fs.readFileSync(BUNDLE, 'utf8');
  assert.match(html, /__LOUPE_TEST_API__/,
    'index.test.html lacks __LOUPE_TEST_API__ — rebuild with python make.py test-build');

  let chromium;
  try {
    chromium = require('playwright').chromium;
  } catch {
    const modPath = path.join(REPO, 'dist', 'test-deps', 'node_modules', 'playwright');
    chromium = require(modPath).chromium;
  }

  const errors = [];
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => errors.push(String(e.message)));
    await page.goto(`file://${BUNDLE}`);
    await page.waitForFunction(() => {
      const w = window;
      return !!(w.__loupeTest && w.__loupeTest.ready);
    }, { timeout: 30_000 });
    await page.evaluate(() => window.__loupeTest.ready);

    const globals = await page.evaluate(() => ({
      pushIOC: typeof pushIOC === 'function',
      App: typeof App === 'function',
      X509Renderer: typeof X509Renderer === 'function',
      RenderRoute: typeof RenderRoute === 'object' && typeof RenderRoute.run === 'function',
      WorkerManager: typeof WorkerManager === 'object',
      yaraRules: typeof DEFAULT_YARA_RULES === 'string' && DEFAULT_YARA_RULES.length > 1000,
      geoip: typeof __GEOIP_BUNDLE_B64 === 'string' && __GEOIP_BUNDLE_B64.length > 1000,
    }));

    for (const [name, ok] of Object.entries(globals)) {
      assert.ok(ok, `global ${name} must be defined in built bundle`);
    }
    assert.equal(errors.length, 0, `page errors: ${errors.join('; ')}`);
  } finally {
    await browser.close();
  }
});