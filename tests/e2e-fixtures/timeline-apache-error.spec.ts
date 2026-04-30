// ════════════════════════════════════════════════════════════════════════════
// timeline-apache-error.spec.ts — End-to-end coverage for the
// Apache HTTP Server `error_log` Timeline route. Apache error
// logs are the output of the `ErrorLog` directive — distinct
// from access logs (which Loupe handles via the CLF / Combined
// Log Format pathway) — and start every line with a bracketed
// timestamp + day-name + month-name + 4-digit-year token, e.g.
//
//   [Tue Apr 30 14:23:11.123456 2024] [core:error]
//   [pid 12345:tid 140737] [client 10.0.0.5:51234]
//   AH00037: Symbolic link not allowed
//
// What this spec proves:
//   1. A `.log` fixture sniff-promotes via `kindHint='apache-error'`
//      (no canonical extension; the bracketed-timestamp + module
//      probe in `timeline-router.js` does the work) with
//      `formatTag: 'Apache error_log'` and parses all 10 fixture
//      rows.
//   2. The schema is the fixed 8-column projection
//      `[Timestamp, Module, Severity, PID, TID, Client,
//        ErrorCode, Message]` — emitted in that exact order
//      regardless of which optional brackets are present.
//   3. Severity values populate (notice / error / warn / trace3)
//      so the histogram has something to stack on (the default
//      stack column is `Severity`).
//   4. Zero IOCs are emitted despite the fixture carrying
//      multiple public IPv4s plus a `referer` URL — the Apache
//      error Timeline route is analyser-free.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = 'tests/e2e-fixtures/apache-error-sample.log';
const EXPECTED_ROWS = 10;

test.describe('Timeline — Apache error_log', () => {
  const ctx = useSharedBundlePage();

  test('sniff-promotes `.log` → Apache error_log with 8-col schema', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);
    // No IOC enrichment on the Timeline path — IPs and the
    // referer URL in the fixture must NOT show up.
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    expect((result as { formatTag?: string }).formatTag).toBe('Apache error_log');

    const cols = (result as { timelineColumns?: string[] }).timelineColumns!;
    expect(cols).toBeDefined();
    // Fixed 8-column projection emitted in canonical order.
    expect(cols.length).toBe(8);
    expect(cols[0]).toBe('Timestamp');
    expect(cols[1]).toBe('Module');
    expect(cols[2]).toBe('Severity');
    expect(cols[3]).toBe('PID');
    expect(cols[4]).toBe('TID');
    expect(cols[5]).toBe('Client');
    expect(cols[6]).toBe('ErrorCode');
    expect(cols[7]).toBe('Message');
  });

  test('grid: severity values, AH error codes, and free-text messages all populate', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);
    const gridText = await rows.evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));

    // Severities present in the fixture (default stack column).
    expect(gridText).toMatch(/notice/);
    expect(gridText).toMatch(/error/);
    expect(gridText).toMatch(/warn/);
    expect(gridText).toMatch(/trace3/);

    // Modules from the `[module:level]` token.
    expect(gridText).toMatch(/core/);
    expect(gridText).toMatch(/mpm_event/);
    expect(gridText).toMatch(/proxy_fcgi/);
    expect(gridText).toMatch(/authz_core/);
    expect(gridText).toMatch(/ssl/);
    expect(gridText).toMatch(/http2/);

    // AH<5digits>: codes pulled into the dedicated ErrorCode
    // column and free-text after them preserved in Message.
    expect(gridText).toMatch(/AH00094/);
    expect(gridText).toMatch(/AH00489/);
    expect(gridText).toMatch(/AH01075/);
    expect(gridText).toMatch(/AH00037/);
    expect(gridText).toMatch(/AH01630/);
    expect(gridText).toMatch(/AH01906/);
    expect(gridText).toMatch(/AH00491/);

    // Message body fragments survive across the (parens) and
    // status-text decorations Apache emits inline.
    expect(gridText).toMatch(/Symbolic link not allowed/);
    expect(gridText).toMatch(/client denied by server configuration/);
    expect(gridText).toMatch(/caught SIGTERM/);

    // PID / TID / Client column populates from the optional
    // bracket tokens.
    expect(gridText).toMatch(/12345/);
    expect(gridText).toMatch(/12346/);
    expect(gridText).toMatch(/10\.0\.0\.5/);
    expect(gridText).toMatch(/192\.0\.2\.50/);
    expect(gridText).toMatch(/198\.51\.100\.7/);
  });

  test('timestamp normalisation: ISO 8601 with optional microsecond fraction', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    const gridText = await rows.evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));

    // Mixed precision in the fixture — both forms must appear
    // in the rendered Timestamp column.
    expect(gridText).toMatch(/2024-04-30T14:23:11\.123456/);
    expect(gridText).toMatch(/2024-04-30T14:25:42(?!\d)/);
    expect(gridText).toMatch(/2024-04-30T14:27:15\.987654/);
    expect(gridText).toMatch(/2024-04-30T14:30:00(?!\d)/);
  });
});
