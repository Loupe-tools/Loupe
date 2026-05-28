import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  loadFixture,
  REPO_ROOT,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = path.join('dist', 'loupe-timeline-width-fit.csv');
const FIXTURE_ABS = path.join(REPO_ROOT, FIXTURE_REL);
const TS = '2026-05-28T12:34:56Z';
const LONG_EMAIL = 'very.long.timeline.userid.for.width.check@example.security.test';

function buildCsv(): string {
  const rows = ['Timestamp,UserID,Category,Note'];
  for (let i = 0; i < 500; i++) {
    const user = i === 150 ? LONG_EMAIL : `u${i}@ex.co`;
    rows.push(`${TS},${user},login,short note ${i}`);
  }
  return rows.join('\n') + '\n';
}

async function widthMetrics(page: Page) {
  return page.locator('.tl-grid').evaluate((grid, args) => {
    const tsHead = grid.querySelector('.grid-header-cell[data-col="0"]');
    const userHead = grid.querySelector('.grid-header-cell[data-col="1"]');
    const sampleCell = grid.querySelector('.grid-cell[data-col="0"]') || grid.querySelector('.grid-cell');
    if (!tsHead || !userHead || !sampleCell) throw new Error('grid cells not found');
    const cs = getComputedStyle(sampleCell);
    const measure = (text) => {
      const probe = document.createElement('span');
      probe.style.position = 'absolute';
      probe.style.visibility = 'hidden';
      probe.style.whiteSpace = 'pre';
      probe.style.fontFamily = cs.fontFamily;
      probe.style.fontSize = cs.fontSize;
      probe.style.fontWeight = cs.fontWeight;
      probe.textContent = text;
      document.body.appendChild(probe);
      const w = probe.getBoundingClientRect().width;
      probe.remove();
      return w;
    };
    const pad = (Number.parseFloat(cs.paddingLeft) || 0) + (Number.parseFloat(cs.paddingRight) || 0);
    return {
      timestampW: tsHead.getBoundingClientRect().width,
      userW: userHead.getBoundingClientRect().width,
      timestampTextW: measure(args.ts),
      emailTextW: measure(args.email),
      pad,
    };
  }, { ts: TS, email: LONG_EMAIL });
}

test.describe('Timeline grid column auto-width', () => {
  test.beforeAll(() => {
    fs.mkdirSync(path.dirname(FIXTURE_ABS), { recursive: true });
    fs.writeFileSync(FIXTURE_ABS, buildCsv(), 'utf8');
  });

  const ctx = useSharedBundlePage();

  test('keeps fixed timestamps tight and fits email-like user IDs', async () => {
    await ctx.page.evaluate(() => {
      try { localStorage.removeItem('loupe_timeline_sections'); } catch (_) { /* ignore */ }
      try {
        for (let i = localStorage.length - 1; i >= 0; i--) {
          const k = localStorage.key(i) || '';
          if (k.startsWith('loupe_grid_colW_tl-grid-inner_loupe-timeline-width-fit_csv')) {
            localStorage.removeItem(k);
          }
        }
      } catch (_) { /* ignore */ }
    });

    await loadFixture(ctx.page, FIXTURE_REL);
    await expect(ctx.page.locator('.tl-grid .grid-header-cell[data-col="0"]')).toBeVisible();

    await ctx.page.waitForFunction(({ email }) => {
      const grid = document.querySelector('.tl-grid');
      if (!grid) return false;
      const userHead = grid.querySelector('.grid-header-cell[data-col="1"]');
      const sampleCell = grid.querySelector('.grid-cell[data-col="1"]') || grid.querySelector('.grid-cell');
      if (!userHead || !sampleCell) return false;
      const cs = getComputedStyle(sampleCell);
      const probe = document.createElement('span');
      probe.style.position = 'absolute';
      probe.style.visibility = 'hidden';
      probe.style.whiteSpace = 'pre';
      probe.style.fontFamily = cs.fontFamily;
      probe.style.fontSize = cs.fontSize;
      probe.style.fontWeight = cs.fontWeight;
      probe.textContent = email;
      document.body.appendChild(probe);
      const textW = probe.getBoundingClientRect().width;
      probe.remove();
      const pad = (Number.parseFloat(cs.paddingLeft) || 0) + (Number.parseFloat(cs.paddingRight) || 0);
      return userHead.getBoundingClientRect().width >= textW + pad - 2;
    }, { email: LONG_EMAIL }, { timeout: 5000 });

    const m = await widthMetrics(ctx.page);
    expect(m.timestampW).toBeLessThanOrEqual(m.timestampTextW + m.pad + 10);
    expect(m.userW).toBeGreaterThanOrEqual(m.emailTextW + m.pad - 2);
    expect(m.userW).toBeLessThanOrEqual(490);
  });
});
