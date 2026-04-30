// ════════════════════════════════════════════════════════════════════════════
// timeline-w3c.spec.ts — End-to-end coverage for the W3C Extended
// Log File Format Timeline route, exercised through both an IIS
// fixture (Microsoft Internet Information Services) and an AWS
// ALB (Application Load Balancer) fixture. The same tokeniser
// handles both — source labelling is driven by the `#Software`
// directive (IIS) and `#Fields:` schema fingerprint (ALB / ELB /
// CloudFront).
//
// What this spec proves:
//   1. An IIS `.log` fixture sniff-promotes via `kindHint='w3c'`
//      with `formatTag: 'IIS W3C'` and parses all 10 fixture rows.
//   2. The schema reflects the `#Fields:` directive verbatim
//      (15 IIS canonical columns) plus a synthesised `Timestamp`
//      column at index 0 from `date` + `time`.
//   3. `+`-encoded spaces in `cs(User-Agent)` decode back to
//      regular spaces; `-` becomes the empty cell.
//   4. An ALB tab-delimited fixture is recognised independently
//      (no `#Software` line) and the format label resolves to
//      `'AWS ALB'` because `target_status_code` is in the
//      schema.
//   5. Zero IOCs are emitted despite both fixtures carrying
//      public IPv4s and a URL — the W3C Timeline route is
//      analyser-free.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const IIS_FIXTURE_REL = 'tests/e2e-fixtures/iis-sample.log';
const ALB_FIXTURE_REL = 'tests/e2e-fixtures/alb-sample.log';
const IIS_EXPECTED_ROWS = 10;
const ALB_EXPECTED_ROWS = 5;

test.describe('Timeline — W3C Extended (IIS)', () => {
  const ctx = useSharedBundlePage();

  test('sniff-promotes `.log` → IIS W3C; schema includes synthesised Timestamp', async () => {
    const findings = await loadFixture(ctx.page, IIS_FIXTURE_REL);
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(IIS_EXPECTED_ROWS);
    expect((result as { formatTag?: string }).formatTag).toBe('IIS W3C');

    const cols = (result as { timelineColumns?: string[] }).timelineColumns!;
    expect(cols).toBeDefined();
    // Synthesised Timestamp at index 0; original date + time
    // preserved at their declared positions.
    expect(cols[0]).toBe('Timestamp');
    expect(cols).toContain('date');
    expect(cols).toContain('time');
    // Canonical IIS 10 default fields.
    expect(cols).toContain('s-ip');
    expect(cols).toContain('cs-method');
    expect(cols).toContain('cs-uri-stem');
    expect(cols).toContain('cs(User-Agent)');
    expect(cols).toContain('cs(Referer)');
    expect(cols).toContain('sc-status');
    expect(cols).toContain('time-taken');
  });

  test('grid: `+` decodes to space; `-` is blank; status codes visible', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);
    const gridText = await rows.evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    // `+`-encoded UA decodes to space.
    expect(gridText).toMatch(/Mozilla\/5\.0 \(Windows NT 10\.0;/);
    expect(gridText).toMatch(/Mozilla\/5\.0 \(Macintosh\)/);
    // URI / method values intact.
    expect(gridText).toMatch(/\/default\.aspx/);
    expect(gridText).toMatch(/\/api\/login/);
    expect(gridText).toMatch(/\/wp-admin\//);
    // Varied status codes from the canonical sc-status column.
    expect(gridText).toMatch(/200/);
    expect(gridText).toMatch(/304/);
    expect(gridText).toMatch(/401/);
    expect(gridText).toMatch(/404/);
    expect(gridText).toMatch(/500/);
    // Public IPs from c-ip column survive.
    expect(gridText).toMatch(/185\.220\.101\.33/);
    expect(gridText).toMatch(/198\.51\.100\.42/);
    expect(gridText).toMatch(/203\.0\.113\.99/);
  });
});

test.describe('Timeline — W3C Extended (AWS ALB)', () => {
  const ctx = useSharedBundlePage();

  test('tab-delimited ALB log gets `AWS ALB` format label via schema fingerprint', async () => {
    const findings = await loadFixture(ctx.page, ALB_FIXTURE_REL);
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(ALB_EXPECTED_ROWS);
    expect((result as { formatTag?: string }).formatTag).toBe('AWS ALB');

    const cols = (result as { timelineColumns?: string[] }).timelineColumns!;
    expect(cols).toBeDefined();
    // No `date` + `time` pair → no synthesised Timestamp; the
    // `time` column from ALB is already ISO 8601.
    expect(cols[0]).toBe('type');
    expect(cols).toContain('time');
    expect(cols).toContain('elb');
    expect(cols).toContain('target_status_code');
    expect(cols).toContain('target_group_arn');

    // Tab delimiter detection: the request column carries spaces
    // and would have shattered if the parser had used space as
    // the delimiter.
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    const gridText = await rows.evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    expect(gridText).toMatch(/GET https:\/\/www\.example\.com:443\//);
    expect(gridText).toMatch(/POST https:\/\/www\.example\.com:443\/api\/login/);
    expect(gridText).toMatch(/sqlmap\/1\.6\.4/);
  });
});
