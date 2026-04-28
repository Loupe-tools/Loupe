// ════════════════════════════════════════════════════════════════════════════
// dump-fixtures.spec.ts — Programmatic exploration over `examples/`.
//
// This is NOT a regression test. It loops every file under `examples/`,
// loads each one through the production ingress path
// (`__loupeTest.loadBytes`), and writes a per-fixture snapshot of the
// canonical findings shape into `dist/fixture-report.json`. The output
// is what Phase 2 / 3 / 4 of the test PR uses to author golden-fixture
// assertions and to surface anomalies (renderers emitting bare-string
// IOC types, fixtures with zero IOCs that should have many, missing
// IOC.PATTERN mirrors of detections, etc.).
//
// Cost: ~2 minutes wall-clock for the full 138-fixture corpus on a
// modern laptop. The spec self-skips unless `LOUPE_EXPLORE=1` is set
// in the env so it never fires in the default CI loop. Run with:
//
//     LOUPE_EXPLORE=1 python make.py test-e2e
// or  LOUPE_EXPLORE=1 python scripts/run_tests_e2e.py tests/explore
//
// The output JSON is gitignored under `dist/` and is regenerated on
// every run.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { gotoBundle, loadFixture, REPO_ROOT } from '../helpers/playwright-helpers';

// Skip the entire spec unless the user opts in. Playwright evaluates
// `test.skip(<bool>, <reason>)` per-test; we wrap in a `describe` so
// the gate fires once. Using `test.beforeAll` would let later
// per-test skips race; this is the simplest correct shape.
const ENABLED = process.env.LOUPE_EXPLORE === '1';

// All examples sub-directories. We deliberately avoid `fs.readdirSync`
// recursion across the whole repo — the `examples/` tree is shallow
// (one level of categories, files inside) and we want deterministic
// ordering for the report.
const EXAMPLES_DIR = path.join(REPO_ROOT, 'examples');
const REPORT_PATH = path.join(REPO_ROOT, 'dist', 'fixture-report.json');

// Fixtures that genuinely take a long time to render (overlay-bearing
// PEs, recursive ZIPs, large archives). Bumping the per-fixture budget
// here keeps the dump from spuriously skipping them; the real e2e
// smokes don't share this cap because they run one fixture per test.
const PER_FIXTURE_TIMEOUT_MS = 60_000;

interface FixtureRow {
  category: string;
  file: string;
  path: string;
  bytes: number;
  ok: boolean;
  error?: string;
  formatTag?: string | null;
  filename?: string | null;
  rawTextLength?: number;
  risk?: string | null;
  iocCount?: number;
  iocTypes?: string[];
  externalRefCount?: number;
  interestingStringCount?: number;
  detectionCount?: number;
  metadataKeys?: string[];
  yaraRules?: string[];
  yaraSeverityCounts?: Record<string, number>;
  // Anomaly flags computed by the dumper itself — surface obvious
  // contract violations without having to grep the JSON afterwards.
  anomalies?: string[];
}

function listFixtures(): { category: string; abs: string; rel: string }[] {
  const out: { category: string; abs: string; rel: string }[] = [];
  if (!fs.existsSync(EXAMPLES_DIR)) return out;
  for (const cat of fs.readdirSync(EXAMPLES_DIR).sort()) {
    const catDir = path.join(EXAMPLES_DIR, cat);
    if (!fs.statSync(catDir).isDirectory()) continue;
    for (const f of fs.readdirSync(catDir).sort()) {
      const abs = path.join(catDir, f);
      if (!fs.statSync(abs).isFile()) continue;
      out.push({ category: cat, abs, rel: path.relative(REPO_ROOT, abs) });
    }
  }
  return out;
}

// Heuristic anomaly detection on the snapshot we just produced. These
// mirror the renderer-contract invariants documented in
// `CONTRIBUTING.md` and `AGENTS.md`. We surface them at dump-time so
// the Phase 1 review can act on them without re-reading the full JSON.
const VALID_IOC_TYPES = new Set([
  'URL', 'Email', 'IP Address', 'File Path', 'UNC Path', 'Attachment',
  'YARA Match', 'Pattern', 'Info', 'Hash', 'Command Line', 'Process',
  'Hostname', 'Username', 'Registry Key', 'MAC Address', 'Domain',
  'GUID', 'Fingerprint', 'Package Name',
]);

function computeAnomalies(row: FixtureRow): string[] {
  const a: string[] = [];
  if (!row.ok) return a;
  // Bare-string IOC type leak (e.g. 'url' instead of IOC.URL).
  for (const t of row.iocTypes || []) {
    if (!VALID_IOC_TYPES.has(t)) a.push(`bare-string-ioc-type:${t}`);
  }
  // `risk` outside the canonical band set.
  const RISK_BANDS = new Set(['low', 'medium', 'high', 'critical', null, undefined]);
  if (!RISK_BANDS.has(row.risk as any)) a.push(`unexpected-risk:${row.risk}`);
  // Zero findings on a fixture deeper than empty heuristic threshold.
  if ((row.iocCount || 0) === 0 && (row.externalRefCount || 0) === 0
      && (row.detectionCount || 0) === 0
      && (row.bytes || 0) > 256) {
    a.push('zero-findings');
  }
  // Detection without an IOC.PATTERN mirror.
  if ((row.detectionCount || 0) > 0
      && !(row.iocTypes || []).includes('Pattern')) {
    a.push('detections-without-pattern-mirror');
  }
  // _rawText empty when the renderer probably should populate it
  // (text-shaped formats — html/eml/rtf/plaintext/svg etc.). The
  // formatTag is the renderer's own claim; we use it as a coarse
  // proxy and only flag when bytes > 0 but rawText is 0.
  const TEXT_TAGS = new Set([
    'html', 'eml', 'rtf', 'svg', 'plaintext', 'reg', 'inf', 'wsf',
    'csv', 'json', 'iqyslk', 'url',
  ]);
  if (TEXT_TAGS.has(row.formatTag || '')
      && (row.rawTextLength || 0) === 0
      && (row.bytes || 0) > 0) {
    a.push('text-renderer-empty-rawtext');
  }
  return a;
}

test.describe('explore: dump every fixture', () => {
  test.skip(!ENABLED, 'set LOUPE_EXPLORE=1 to run the exploration dump');

  // One Page per fixture so a renderer-side hang on fixture N doesn't
  // poison fixture N+1. Playwright re-creates a fresh page+context per
  // test by default, so we get isolation for free.
  test('dump fixtures into dist/fixture-report.json', async ({ page }) => {
    test.setTimeout(20 * 60_000); // 20 min hard cap on the whole loop.
    const fixtures = listFixtures();
    expect(fixtures.length).toBeGreaterThan(0);

    const rows: FixtureRow[] = [];
    await gotoBundle(page);

    for (const f of fixtures) {
      const stat = fs.statSync(f.abs);
      const row: FixtureRow = {
        category: f.category,
        file: path.basename(f.abs),
        path: f.rel,
        bytes: stat.size,
        ok: false,
      };
      try {
        // One per-fixture wall-clock budget. We can't use page.goto's
        // navigationTimeout here because the page is already loaded;
        // we wrap loadFixture in a Promise.race against a timer.
        const findings = await Promise.race([
          loadFixture(page, f.rel),
          new Promise((_, rej) =>
            setTimeout(() => rej(new Error('per-fixture timeout')),
              PER_FIXTURE_TIMEOUT_MS)),
        ]);
        const result = await page.evaluate(() => {
          const w = window as unknown as { __loupeTest: { dumpResult(): unknown } };
          return w.__loupeTest.dumpResult();
        }) as { formatTag?: string; filename?: string; rawTextLength?: number } | null;
        const f2 = findings as Awaited<ReturnType<typeof loadFixture>>;
        row.ok = true;
        row.formatTag = result?.formatTag ?? null;
        row.filename = result?.filename ?? null;
        row.rawTextLength = result?.rawTextLength ?? 0;
        row.risk = f2.risk ?? null;
        row.iocCount = f2.iocCount;
        row.iocTypes = f2.iocTypes;
        row.externalRefCount = f2.externalRefCount;
        row.interestingStringCount = f2.interestingStringCount;
        row.detectionCount = f2.detectionCount;
        row.metadataKeys = Object.keys(f2.metadata || {}).sort();
        const ruleNames = (f2.yaraHits || [])
          .map(h => h.rule).filter(Boolean) as string[];
        row.yaraRules = Array.from(new Set(ruleNames)).sort();
        const sevCounts: Record<string, number> = {};
        for (const h of (f2.yaraHits || [])) {
          const k = (h.severity || 'info') as string;
          sevCounts[k] = (sevCounts[k] || 0) + 1;
        }
        row.yaraSeverityCounts = sevCounts;
        row.anomalies = computeAnomalies(row);
      } catch (e: unknown) {
        row.ok = false;
        row.error = (e instanceof Error) ? e.message : String(e);
        // After a thrown error the page state is undefined; reload the
        // bundle so the next iteration starts clean.
        await gotoBundle(page);
      }
      rows.push(row);
      // Reload between fixtures so each load starts from a fresh App
      // state — drill-down stack, idle YARA, etc.
      await gotoBundle(page);
    }

    // Aggregate stats — useful at the top of the JSON for quick grep.
    const totals = {
      totalFixtures: rows.length,
      ok: rows.filter(r => r.ok).length,
      failed: rows.filter(r => !r.ok).length,
      withAnomalies: rows.filter(r => (r.anomalies || []).length > 0).length,
      anomalyTypeCounts: {} as Record<string, number>,
      formatTagCounts: {} as Record<string, number>,
    };
    for (const r of rows) {
      for (const a of r.anomalies || []) {
        const key = a.split(':')[0];
        totals.anomalyTypeCounts[key] = (totals.anomalyTypeCounts[key] || 0) + 1;
      }
      const ft = r.formatTag || (r.ok ? 'unknown' : 'errored');
      totals.formatTagCounts[ft] = (totals.formatTagCounts[ft] || 0) + 1;
    }

    fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
    fs.writeFileSync(REPORT_PATH, JSON.stringify({
      generatedAt: new Date().toISOString(),
      totals,
      rows,
    }, null, 2) + '\n');

    // Console preview so the run log shows progress at a glance.
    /* eslint-disable no-console */
    console.log(`[explore] dumped ${rows.length} fixtures → ${path.relative(REPO_ROOT, REPORT_PATH)}`);
    console.log(`[explore] totals:`, totals);
    /* eslint-enable no-console */

    expect(totals.failed).toBeLessThan(rows.length); // sanity
  });
});
