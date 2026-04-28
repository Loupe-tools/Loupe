// ════════════════════════════════════════════════════════════════════════════
// timeline-large-csv.spec.ts — End-to-end coverage for the RowStore
// migration (CSV → worker → RowStoreBuilder → GridViewer single-mode).
//
// What this spec proves:
//   1. A freshly-generated CSV (5,000 rows, deterministic seed) lands
//      in the Timeline route via `_timelineTryHandle` and the worker
//      `rows-chunk` packed-typed-array path.
//   2. `dumpResult()` reports `timeline: true` with `timelineRowCount`
//      equal to the row count we generated (header excluded). This
//      reads `tlView.store.rowCount` — i.e. the assertion fails if
//      RowStore wiring regresses to a `string[][]` field on the view.
//   3. The Timeline grid actually paints rows from the store. We
//      assert the visible viewport contains at least one
//      `.grid-row` (GridViewer's only window-renderer DOM tag).
//   4. The Timeline query DSL filters via the RowStore. Typing a
//      bareword that matches a known seed-stable token narrows the
//      visible row count below total — proving `getCell()` reads
//      land on the same store the predicate evaluator binds against.
//
// The fixture is materialised at test-run time by
// `scripts/misc/generate_sample_csv.py` (stdlib-only, deterministic
// with `--seed`). The generated file lives under `dist/` (gitignored)
// so test-run side effects never leak into a commit. Generation is
// done once per spec-file via `beforeAll`.
//
// Why generate at runtime instead of committing a fixture?
//   • The CSV is ~8 MB at 5 K rows; committing a binary of that size
//     would dominate the repo. The generator script is ~25 KB and
//     produces deterministic output for a given `--seed`.
//   • The generator is itself part of the "test surface" — keeping
//     it on the runtime path means a regression that breaks its
//     output schema (column order, header row, JSON-quoted Raw
//     column) is caught here.
//
// Performance: 5 K rows × ~9 columns × ~1.7 KB/row = ~8 MB transferred
// to the page over CDP. End-to-end ~6 s on a warm Chromium worker.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  loadFixture,
  dumpResult,
  REPO_ROOT,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

// ────────────────────────────────────────────────────────────────────────────
// Fixture parameters. `ROWS` is small enough that a single worker pack
// chunk (CSV_WORKER_CHUNK_ROWS = 50 000) carries the whole file — the
// multi-chunk RowStoreBuilder.append path is exercised separately by
// the unit tests under `tests/unit/row-store.test.js`. The bareword
// query has been chosen so that it matches a stable subset of rows:
// `Outcome:Success` is invariant under the seed when the generator's
// outcome-distribution table doesn't drift, but using a free-text
// bareword (`Success`) is simpler and equally narrowing — and it
// exercises the "any-column contains" path of the query compiler.
// ────────────────────────────────────────────────────────────────────────────
const ROWS = 5_000;
const SEED = 42;
const FIXTURE_REL = path.join('dist', 'loupe-rowstore-test.csv');
const FIXTURE_ABS = path.join(REPO_ROOT, FIXTURE_REL);

test.describe('Timeline RowStore — generated CSV', () => {
  test.beforeAll(() => {
    // Always regenerate. Cheap (~1 s) and avoids stale-fixture
    // confusion when the generator's column schema evolves.
    fs.mkdirSync(path.dirname(FIXTURE_ABS), { recursive: true });
    const py = process.env.PYTHON || 'python3';
    const script = path.join(REPO_ROOT, 'scripts', 'misc', 'generate_sample_csv.py');
    const r = spawnSync(
      py,
      [script, '--rows', String(ROWS), '--seed', String(SEED), '--output', FIXTURE_ABS],
      { stdio: ['ignore', 'ignore', 'pipe'] });
    if (r.status !== 0) {
      const stderr = r.stderr ? r.stderr.toString() : '(no stderr)';
      throw new Error(
        `generate_sample_csv.py exit=${r.status}: ${stderr}\n` +
        `(set $PYTHON if 'python3' is not on PATH)`);
    }
    if (!fs.existsSync(FIXTURE_ABS)) {
      throw new Error(`generator did not produce ${FIXTURE_ABS}`);
    }
  });

  const ctx = useSharedBundlePage();

  test('generated CSV lands in Timeline with all rows in the RowStore', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);
    // Timeline-routed loads never stamp findings — no IOCs, no risk,
    // identical to the existing example.csv assertion in office.spec.ts.
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    // `timelineRowCount` reads `tlView.store.rowCount` first
    // (Phase-3 invariant). Header is excluded by the timeline
    // ingestor. A regression that re-introduces a `string[][]`
    // field here would silently disagree with the store and
    // surface as a row-count mismatch.
    expect(result!.timelineRowCount).toBe(ROWS);
  });

  test('Timeline grid paints rows from the store', async () => {
    // Reuse the same load — `useSharedBundlePage` shares page state
    // across tests in this describe block. A single load is enough to
    // assert both row count (above) and grid paint (here); separating
    // them just keeps the failure messages targeted.
    const rows = ctx.page.locator('.grid-row');
    // The window renderer mounts visible rows on the first paint;
    // the exact count depends on viewport height, but it's always
    // ≥ 1 for a non-empty store. Asserting an exact count would
    // make the test viewport-dependent.
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
    // Cell content sourced from `store.getCell(rowIdx, colIdx)`:
    // assert the first visible row's first non-row-number cell is
    // non-empty. (`.grid-row-num` is the leading row-number cell.)
    const firstDataCell = rows.first().locator('.grid-cell:not(.grid-row-num)').first();
    const text = await firstDataCell.textContent();
    expect(text && text.length).toBeTruthy();
  });

  test('Timeline query DSL narrows the row count via store reads', async () => {
    // The query input is mounted by `TimelineQueryEditor.mount` —
    // selectors mirror `src/app/timeline/timeline-query-editor.js`.
    const input = ctx.page.locator('.tl-query-input');
    await expect(input).toBeVisible();

    // Bareword query → "any-column contains" branch in the
    // compiler. `Success` is the dominant Outcome value in the
    // generator's distribution but not the only one — narrowing
    // is non-trivial but always non-empty.
    await input.fill('Success');
    // Commit the query so the status line repaints. The editor
    // commits on Enter (see `_queryEditor.onCommit`), and the
    // status line updates synchronously inside the same tick.
    await input.press('Enter');

    // Status line format is fixed by `timeline-view.js:988`:
    //   "✓ <vis> / <tot> rows"
    // We assert it appears with `vis < tot` and `tot === ROWS`.
    const status = ctx.page.locator('.tl-query-status-msg');
    await expect(status).toBeVisible({ timeout: 5_000 });
    const txt = (await status.textContent()) || '';
    const m = txt.match(/([\d,]+)\s*\/\s*([\d,]+)\s*rows/);
    expect(m).not.toBeNull();
    const vis = Number(m![1].replace(/,/g, ''));
    const tot = Number(m![2].replace(/,/g, ''));
    expect(tot).toBe(ROWS);
    expect(vis).toBeGreaterThan(0);
    expect(vis).toBeLessThan(tot);
  });
});
