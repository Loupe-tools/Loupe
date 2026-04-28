// ════════════════════════════════════════════════════════════════════════════
// timeline-rowstore-parity.spec.ts — End-to-end coverage for Phase 6
// (EVTX + SQLite worker streaming) and the heap-budget pre-flight gate.
//
// Phase 5's `timeline-large-csv.spec.ts` proved the CSV → worker →
// `rows-chunk` → `RowStoreBuilder` → `GridViewer` pipeline. Phase 6
// promoted EVTX and SQLite to the same streaming protocol; this file
// asserts the wiring is identical for those kinds:
//
//   1. The Timeline route fires (`dumpResult().timeline === true`).
//   2. `_timelineCurrent.store` is a real `RowStore` — its chunks
//      array is non-empty AND the first chunk's `bytes` / `offsets`
//      slots are typed-array views (`Uint8Array` / `Uint32Array`).
//      A regression that re-introduced a `string[][]` body field on
//      the view would fail this check immediately.
//   3. `store.rowCount === dumpResult().timelineRowCount` — the
//      synthetic `dumpResult` projection reads from the same
//      `tlView.store.rowCount` field renderers consume, so the two
//      must agree.
//   4. The grid paints at least one `.grid-row` (window-renderer
//      DOM tag), proving GridViewer single-mode resolved cells via
//      `store.getCell` rather than a stale `string[][]` adapter.
//
// Heap-budget gate (Chromium-only):
//   The pre-flight gate at `_loadFileInTimeline:204-224` refuses
//   loads whose projected RowStore footprint exceeds
//   `jsHeapSizeLimit * ROWSTORE_HEAP_BUDGET_FRACTION`. We override
//   `performance.memory.jsHeapSizeLimit` via `addInitScript` BEFORE
//   the bundle navigates, then drop the 70 KB EVTX fixture and
//   assert (a) a "too large" toast appears, (b) no Timeline view
//   mounts, (c) `currentResult` stays null. Firefox / Safari don't
//   expose `performance.memory` so the gate is silently skipped on
//   those engines — the spec is explicit about its Chromium scope.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  loadFixture,
  dumpResult,
  REPO_ROOT,
  useSharedBundlePage,
  gotoBundle,
} from '../helpers/playwright-helpers';

// ── Direct store-shape inspection ────────────────────────────────────────────
// Drops below the public test-API surface to read the live `RowStore`
// off `app._timelineCurrent.store`. This is the assertion that makes
// the spec a *parity* check rather than a smoke test — without it we
// would only be re-running the same `timelineRowCount > 0` check the
// `forensics.spec.ts` smoke already covers.
//
// Returned shape is JSON-safe (booleans + numbers) so it crosses the
// CDP bridge without serialisation oddities.
interface StoreShape {
  rowCount: number;
  colCount: number;
  chunkCount: number;
  firstChunkBytesIsUint8: boolean;
  firstChunkOffsetsIsUint32: boolean;
  firstChunkRowCount: number;
  // The total byte length of all packed chunks. Non-zero confirms the
  // worker actually produced UTF-8 cell data — a degenerate "empty
  // chunks" path would still pass the typed-array checks above.
  totalByteLength: number;
}

async function dumpStoreShape(page: import('@playwright/test').Page): Promise<StoreShape | null> {
  return page.evaluate(() => {
    const w = window as unknown as {
      app?: { _timelineCurrent?: { store?: unknown } };
    };
    const store = w.app && w.app._timelineCurrent && w.app._timelineCurrent.store;
    if (!store || typeof (store as { rowCount?: unknown }).rowCount !== 'number') {
      return null;
    }
    const s = store as {
      rowCount: number;
      colCount: number;
      chunks: Array<{ bytes: unknown; offsets: unknown; rowCount: number }>;
      byteLength: number;
    };
    const chunks = Array.isArray(s.chunks) ? s.chunks : [];
    const first = chunks[0];
    return {
      rowCount: s.rowCount,
      colCount: s.colCount,
      chunkCount: chunks.length,
      firstChunkBytesIsUint8: !!(first && first.bytes instanceof Uint8Array),
      firstChunkOffsetsIsUint32: !!(first && first.offsets instanceof Uint32Array),
      firstChunkRowCount: (first && first.rowCount) || 0,
      totalByteLength: s.byteLength,
    };
  });
}

// ── EVTX + SQLite RowStore parity ────────────────────────────────────────────
// Both fixtures are committed under `examples/forensics/` and tracked
// by the existing snapshot matrix (`expected.jsonl`); this describe
// adds the RowStore-shape assertions on top of the smoke that already
// exists in `forensics.spec.ts`.
test.describe('Timeline RowStore parity — EVTX + SQLite (Phase 6)', () => {
  const ctx = useSharedBundlePage();

  test('EVTX worker path produces a RowStore with typed-array chunks', async () => {
    await loadFixture(ctx.page, 'examples/forensics/example-security.evtx');

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount || 0).toBeGreaterThan(0);

    const shape = await dumpStoreShape(ctx.page);
    expect(shape).not.toBeNull();
    // The dumpResult projection and the store agree on row count —
    // proves the synthetic `_testApiDumpResult` shape is reading from
    // the same `RowStore` the renderer consumes.
    expect(shape!.rowCount).toBe(result!.timelineRowCount);
    // EVTX writes 7 columns (Timestamp · Event ID · Level · Provider ·
    // Channel · Computer · Event Data — matches `EVTX_COLUMN_ORDER`).
    expect(shape!.colCount).toBe(7);
    expect(shape!.chunkCount).toBeGreaterThan(0);
    expect(shape!.firstChunkBytesIsUint8).toBe(true);
    expect(shape!.firstChunkOffsetsIsUint32).toBe(true);
    expect(shape!.firstChunkRowCount).toBeGreaterThan(0);
    expect(shape!.totalByteLength).toBeGreaterThan(0);

    // Grid actually paints from the store. `.grid-row` is virtualised
    // so we assert visibility of the first row rather than a count —
    // the count() flickers when the window-renderer recycles row DOM
    // mid-frame.
    await expect(ctx.page.locator('.grid-row').first()).toBeVisible({ timeout: 5_000 });
  });

  test('Chrome history SQLite worker path produces a RowStore with typed-array chunks', async () => {
    await loadFixture(ctx.page, 'examples/forensics/chromehistory-example.sqlite');

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount || 0).toBeGreaterThan(0);
    // Chrome history is recognised by the SQLite Timeline factory and
    // gets a "SQLite – Chrome History" formatLabel — pin it so a
    // schema-pack regression that mis-labels the fixture is caught.
    expect(result!.formatTag).toContain('Chrome History');

    const shape = await dumpStoreShape(ctx.page);
    expect(shape).not.toBeNull();
    expect(shape!.rowCount).toBe(result!.timelineRowCount);
    // Chrome's per-event `historyEventColumns` is at least 5 cols
    // (Timestamp · Type · URL · Title · Visit Count).
    expect(shape!.colCount).toBeGreaterThanOrEqual(5);
    expect(shape!.chunkCount).toBeGreaterThan(0);
    expect(shape!.firstChunkBytesIsUint8).toBe(true);
    expect(shape!.firstChunkOffsetsIsUint32).toBe(true);
    expect(shape!.firstChunkRowCount).toBeGreaterThan(0);
    expect(shape!.totalByteLength).toBeGreaterThan(0);

    await expect(ctx.page.locator('.grid-row').first()).toBeVisible({ timeout: 5_000 });
  });
});

// ── Heap-budget pre-flight gate ──────────────────────────────────────────────
// Independent describe so we can install `addInitScript` BEFORE
// navigating to the bundle — `useSharedBundlePage` does the goto in
// its own `beforeAll`, by which point a memory override would arrive
// too late to affect the gate.
test.describe('Timeline heap-budget gate (Chromium)', () => {
  test('refuses load when projected RowStore exceeds heap budget', async ({ browser }) => {
    const page = await browser.newPage();
    try {
      // Install the override before navigation. We pin
      // `jsHeapSizeLimit` to 100 KB; with `ROWSTORE_HEAP_BUDGET_FRACTION
      // = 0.6` the budget is 60 KB, which the 70 KB EVTX fixture's
      // projected footprint (size × ROWSTORE_HEAP_OVERHEAD_FACTOR =
      // 70 KB × 1.6 ≈ 112 KB) overshoots by nearly 2×.
      await page.addInitScript(() => {
        // `performance.memory` is a getter on Chromium's Performance
        // prototype. Define a configurable own property so the
        // production read in `_loadFileInTimeline` sees our shim.
        Object.defineProperty(performance, 'memory', {
          configurable: true,
          get() {
            return {
              jsHeapSizeLimit: 100_000,
              totalJSHeapSize: 0,
              usedJSHeapSize: 0,
            };
          },
        });
      });
      await gotoBundle(page);

      // Confirm the override took effect inside the page realm.
      const limit = await page.evaluate(() =>
        (performance as unknown as { memory?: { jsHeapSizeLimit: number } }).memory?.jsHeapSizeLimit);
      expect(limit).toBe(100_000);

      // Drive the load via `_loadFile` directly — `__loupeTest.loadBytes`
      // calls `_testApiWaitForIdle`, which spins for 15 s when no
      // result mounts (which is exactly what the gate produces). We
      // bypass that by running `_loadFile` ourselves and awaiting the
      // tracked Timeline-load promise that `_timelineTryHandle` parks
      // on `_timelineLoadInFlight`.
      const abs = path.join(REPO_ROOT, 'examples/forensics/example.evtx');
      const bytes = fs.readFileSync(abs);
      const b64 = bytes.toString('base64');
      await page.evaluate(async ({ b64, name }) => {
        const bin = atob(b64);
        const u8 = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        const file = new File([u8], name);
        const w = window as unknown as {
          app: {
            _loadFile: (f: File) => Promise<void>;
            _timelineLoadInFlight?: Promise<void> | null;
          };
        };
        await w.app._loadFile(file);
        if (w.app._timelineLoadInFlight) {
          await w.app._timelineLoadInFlight.catch(() => { /* gate path doesn't reject */ });
        }
      }, { b64, name: 'example.evtx' });

      // Toast surface — the gate calls `_toast(..., 'error')` which
      // sets `#toast` text and adds class `toast-error`.
      const toast = page.locator('#toast');
      const toastText = (await toast.textContent()) || '';
      expect(toastText).toContain('too large');
      expect(toastText).toContain('memory');

      // Critically: no Timeline view should have mounted.
      const tlMounted = await page.evaluate(() =>
        !!(window as unknown as { app: { _timelineCurrent: unknown } }).app._timelineCurrent);
      expect(tlMounted).toBe(false);

      // ...and `currentResult` stays null — the gate refuses BEFORE
      // any renderer pipeline runs.
      const cr = await page.evaluate(() =>
        (window as unknown as { app: { currentResult: unknown } }).app.currentResult);
      expect(cr).toBeNull();
    } finally {
      await page.close();
    }
  });
});
