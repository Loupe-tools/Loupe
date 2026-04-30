// ════════════════════════════════════════════════════════════════════════════
// timeline-leef.spec.ts — End-to-end coverage for the LEEF (IBM
// QRadar Log Event Extended Format) Timeline route.
//
// LEEF is QRadar's analogue to ArcSight CEF. Two on-disk shapes:
//   • LEEF 1.0:  LEEF:1.0|Vendor|Product|Ver|EventID|<TAB>k=v<TAB>k=v…
//   • LEEF 2.0:  LEEF:2.0|Vendor|Product|Ver|EventID|<delim>|k=v<delim>k=v
// LEEF 1.0 hard-codes the extension delimiter to TAB; LEEF 2.0
// adds an optional 6th header field declaring the delimiter
// character (single char, or `\xHH` hex escape). Like CEF, LEEF
// is overwhelmingly tunnelled inside syslog — the fixture mixes
// raw LEEF, syslog-wrapped LEEF, and both versions to exercise
// the full router.
//
// What this spec proves:
//   1. A `.leef` fixture routes via `kindHint='leef'` with
//      `formatTag: 'LEEF'` and parses all 10 fixture rows.
//   2. The schema is the 5-column LEEF header (Version, Vendor,
//      Product, ProductVersion, EventID) followed by extension
//      keys locked from the first record's `key=value` block,
//      then `_extra`. The LEEF 2.0 delimiter spec is consumed
//      internally and is NOT emitted as a column.
//   3. Syslog-wrapped LEEF lines (rows 4-5) are unwrapped — the
//      Vendor / Product / EventID cells reflect the LEEF body.
//   4. Records carrying ext keys not in the locked schema (rows
//      2 with `act`, 3 with `proto`, 5 with `fname`, etc.)
//      populate `_extra` rather than dropping the data.
//   5. Zero IOCs are emitted despite the fixture carrying public
//      IPv4s — the LEEF Timeline route is analyser-free.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = 'tests/e2e-fixtures/leef-sample.leef';
const EXPECTED_ROWS = 10;

test.describe('Timeline — LEEF', () => {
  const ctx = useSharedBundlePage();

  test('routes to LEEF parser, schema is header + ext keys + _extra', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    expect((result as { formatTag?: string }).formatTag).toBe('LEEF');

    const cols = (result as { timelineColumns?: string[] }).timelineColumns!;
    expect(cols).toBeDefined();
    // 5 canonical header columns in canonical order.
    expect(cols[0]).toBe('Version');
    expect(cols[1]).toBe('Vendor');
    expect(cols[2]).toBe('Product');
    expect(cols[3]).toBe('ProductVersion');
    expect(cols[4]).toBe('EventID');
    // Extension keys from the first record: src, dst, sev, cat,
    // usrName.
    expect(cols).toContain('src');
    expect(cols).toContain('dst');
    expect(cols).toContain('sev');
    expect(cols).toContain('cat');
    expect(cols).toContain('usrName');
    // The LEEF 2.0 delimiter spec is parser-internal and must NOT
    // surface as a column.
    expect(cols).not.toContain('Delimiter');
    expect(cols).not.toContain('delim');
    // `_extra` is the trailing column from the parser; GeoIP /
    // hostname enrichment may append further `.geo` / `(host)`
    // columns after it. Just check `_extra` exists and sits past
    // every parser-emitted column.
    expect(cols).toContain('_extra');
    expect(cols.indexOf('_extra')).toBeGreaterThan(cols.indexOf('usrName'));
  });

  test('grid renders header cells and ext values from raw + syslog-wrapped LEEF (v1 + v2)', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);
    const gridText = await rows.evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    // Vendor / Product values present (IBM QRadar + Juniper SRX).
    expect(gridText).toMatch(/IBM/);
    expect(gridText).toMatch(/QRadar/);
    expect(gridText).toMatch(/Juniper/);
    expect(gridText).toMatch(/SRX/);
    // EventIDs spanning v1 + v2 + syslog-wrapped + Juniper.
    expect(gridText).toMatch(/EVT100/);          // raw v1
    expect(gridText).toMatch(/EVT103/);          // syslog-wrapped v1
    expect(gridText).toMatch(/EVT200/);          // v2 caret-delim
    expect(gridText).toMatch(/EVT202/);          // v2 \x09 (tab) delim
    expect(gridText).toMatch(/RT_FLOW_SESSION_CREATE/);
    // Ext IPs visible.
    expect(gridText).toMatch(/10\.0\.0\.1/);
    expect(gridText).toMatch(/185\.220\.101\.33/);
  });

  test('extension keys not in the locked schema spill into _extra', async () => {
    // The first record locks the schema as
    // src/dst/sev/cat/usrName. Subsequent records introduce `act`
    // (row 2), `proto` (row 3), `fname` (row 5), `policy` (rows
    // 9-10). None are in the locked schema → they must surface
    // in the `_extra` cell as a JSON sub-object.
    const result = await dumpResult(ctx.page);
    const cols = (result as { timelineColumns?: string[] }).timelineColumns!;
    const extraIdx = cols.indexOf('_extra');
    expect(extraIdx).toBeGreaterThanOrEqual(0);

    const gridText = await ctx.page.locator('.grid-row').evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    // Unknown keys must appear inside the JSON-encoded _extra cell.
    expect(gridText).toMatch(/"act":\s*"block"/);
    expect(gridText).toMatch(/"proto":\s*"TCP"/);
    expect(gridText).toMatch(/"fname":\s*"evil\.exe"/);
    expect(gridText).toMatch(/"policy":\s*"allow-web"/);
  });
});
