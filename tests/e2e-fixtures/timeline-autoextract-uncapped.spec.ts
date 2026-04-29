// ════════════════════════════════════════════════════════════════════════════
// timeline-autoextract-uncapped.spec.ts — End-to-end smoke for two
// behavioural changes that landed together:
//
//   1. Auto-extract no longer caps at 12 columns below the
//      `LARGE_FILE_THRESHOLD` (200 MB) byte boundary. The analyst sees
//      every extractable column on small / medium files.
//
//   2. After auto-extract settles, if the natural-detect GeoIP pass
//      found no IP-shaped BASE columns, a retry runs over the
//      extracted-column plane. JSON-shaped logs whose IPv4 lives
//      inside a nested key now get a `<json-leaf>.geo` enrichment
//      column without analyst intervention.
//
// Fixture: `examples/forensics/json-example.csv` — 8 base columns,
// the last (`Raw Data`) holds a JSON blob with `client.ip_address`
// (public-routable IPv4) on every row. Pre-uncap, auto-extract clipped
// to 12 columns and the IP-bearing leaf was sometimes lost; post-uncap
// every leaf surfaces, AND the retry hook detects + enriches the
// IP-bearing leaf without a right-click.
//
// What we DO NOT cover here:
//   • The 200 MB cap-fallback path — synthetic 200 MB fixtures are
//     too expensive for CI; that branch is pinned by static-text tests
//     in `tests/unit/timeline-view-autoextract-uncapped.test.js`.
//   • Reopen idempotence — pinned by the unit-side reopen-path test.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = 'examples/forensics/json-example.csv';

test.describe('Timeline auto-extract — uncapped + GeoIP retry', () => {
  const ctx = useSharedBundlePage();

  test('JSON-heavy CSV produces > 12 extracted columns (no 12-cap)', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);
    // CSV → Timeline route, so no findings are stamped.
    expect(findings.iocCount).toBe(0);

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);

    // Wait for auto-extract to land more than 12 cols. The pump
    // schedules one idle tick per proposal; for this fixture we
    // expect ~15-25 cols. 10 s budget is generous on cold CI and
    // covers the worst-case idle-tick drain.
    await ctx.page.waitForFunction(() => {
      const w = window as unknown as {
        app: { _timelineCurrent?: { _extractedCols?: unknown[] } }
      };
      const tl = w.app && w.app._timelineCurrent;
      if (!tl || !Array.isArray(tl._extractedCols)) return false;
      return tl._extractedCols.length > 12;
    }, null, { timeout: 10_000 });

    const extractedCount = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { _timelineCurrent: { _extractedCols: unknown[] } }
      };
      return w.app._timelineCurrent._extractedCols.length;
    });

    // The fixture has > 12 distinct JSON leaves at depth ≤ 4 (verified
    // empirically by `tests/unit/timeline-view-autoextract-real-fixture.test.js`
    // which asserts the scanner emits > 12 proposals). Pin > 12 to
    // catch a regression that re-introduces a hard cap; the upper
    // bound 60 catches a regression in the scanner-internal
    // JSON_LEAF_CAP soft-cap.
    expect(extractedCount).toBeGreaterThan(12);
    expect(extractedCount).toBeLessThanOrEqual(60);
  });

  test('IP-bearing JSON leaf gets auto-enriched via the GeoIP retry hook', async () => {
    // The JSON fixture's `client.ip_address` field contains public-
    // routable IPv4 on every row. Pre-uncap behaviour: even if the
    // leaf was extracted as a column (within the 12-cap), the GeoIP
    // pass only ever scanned base columns and never saw it. Post-fix:
    // the auto-extract terminal hook fires `_runGeoipEnrichment({
    // retryExtractedCols: true })` when the natural-detect pass
    // returned empty (this fixture has no IP-shaped base cols), and
    // the retry detects the JSON-leaf column by value shape and
    // produces a `*.geo` sibling.

    // Confirm the bundled provider is wired (mirror existing GeoIP spec).
    const providerKind = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { geoip?: { providerKind?: string } }
      };
      return (w.app && w.app.geoip && w.app.geoip.providerKind) || null;
    });
    expect(providerKind).toBe('bundled');

    // Wait for at least one geoip-kind extracted column to appear.
    // The retry fires after auto-extract settles, so the budget here
    // covers: idle-pumped auto-extract (~25 ticks for this fixture)
    // + the synchronous retry → enrichment pass.
    await ctx.page.waitForFunction(() => {
      const w = window as unknown as {
        app: { _timelineCurrent?: { _extractedCols?: Array<{ kind?: string }> } }
      };
      const tl = w.app && w.app._timelineCurrent;
      if (!tl || !Array.isArray(tl._extractedCols)) return false;
      return tl._extractedCols.some(e => e && e.kind === 'geoip');
    }, null, { timeout: 10_000 });

    // Inspect the geoip column. We don't pin its exact name (depends
    // on the auto-extract's proposed-name heuristic — could be
    // `client.ip_address.geo`, `Raw Data.client.ip_address.geo`, or
    // a shortened form), but we do pin:
    //   • exactly one geoip column (no double-enrichment)
    //   • providerKind === 'bundled' (synchronous lookup path)
    //   • the source col is an EXTRACTED col (not a base col) —
    //     this is the whole point of the retry hook.
    //   • non-empty geo cells in the sample (public IPs all resolve
    //     under the bundled provider).
    const geoCols = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { _timelineCurrent: {
          _extractedCols: Array<{
            name: string;
            kind?: string;
            sourceCol?: number;
            values: unknown[];
            providerKind?: string;
          }>;
          _baseColumns: string[];
        } }
      };
      const tl = w.app._timelineCurrent;
      const baseLen = tl._baseColumns.length;
      return tl._extractedCols
        .filter(c => c && c.kind === 'geoip')
        .map(c => ({
          name: c.name,
          sourceCol: c.sourceCol,
          providerKind: c.providerKind,
          isExtractedSource: typeof c.sourceCol === 'number'
            && c.sourceCol >= baseLen,
          sampleValues: Array.isArray(c.values)
            ? c.values.slice(0, 8).map(v => String(v || ''))
            : [],
        }));
    });

    expect(geoCols.length).toBe(1);
    const geo = geoCols[0];
    expect(geo.providerKind).toBe('bundled');
    expect(geo.isExtractedSource).toBe(true);

    // At least 50% of the sampled cells should be non-empty (the
    // fixture's IPs are deliberately mixed-RIR public-routable, but
    // the bundled provider may return empty on a couple of edge-case
    // ranges; we don't need 100% to confirm the wiring works).
    const nonEmpty = geo.sampleValues.filter(v => v && v.length > 2);
    expect(nonEmpty.length).toBeGreaterThanOrEqual(4);
  });
});
