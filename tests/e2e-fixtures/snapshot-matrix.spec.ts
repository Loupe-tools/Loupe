// ════════════════════════════════════════════════════════════════════════════
// snapshot-matrix.spec.ts — Coarse-grained regression net across the
// entire 138-fixture corpus.
//
// Every record in `expected.jsonl` carries range-based assertions for
// one fixture: format-tag pin, Timeline-route bool, risk floor, IOC
// type subset, IOC count lower bound, and a small set of must-include
// YARA rules. The matrix walks the corpus and asserts each fixture
// against its record.
//
// Why ranges, not exact pins?
//
//   • Renderer evolution: a renderer that adds a new IOC row (e.g. a
//     URL parsed from an additional certificate field) shouldn't
//     break the matrix. Lower-bound assertions absorb growth.
//
//   • Risk floor escalation: most fixtures are at the lowest band
//     they'll ever be at — a future high-severity Pattern row may
//     bump 'medium' to 'high'. Floor assertions absorb upward drift.
//     The exception is `riskFloor: 'any'` for clean-baseline fixtures
//     where any escalation would still be an acceptable change.
//
//   • Rule pinning: only family-anchor rules
//     (`BAT_Download_Execute`, `MSIX_AppInstaller_HTTP`, etc) are
//     pinned. `Info_*` and `Embedded_Compressed_Stream` are dropped
//     during generation — they're too volatile to anchor cleanly.
//
// To regenerate after a deliberate baseline shift:
//
//     LOUPE_EXPLORE=1 python scripts/run_tests_e2e.py tests/explore/dump-fixtures.spec.ts
//     python scripts/gen_expected.py
//     git diff tests/e2e-fixtures/expected.jsonl
//
// Eyeball the diff. Every flipped line should map to a real renderer
// change. A line that drops IOC types, drops rules, or demotes a
// risk floor IS a regression.
// ════════════════════════════════════════════════════════════════════════════

import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import {
  REPO_ROOT,
  gotoBundle,
  loadFixture,
  dumpResult,
  isRiskAtLeast,
  ruleNames,
} from '../helpers/playwright-helpers';

interface ExpectedRecord {
  path: string;
  formatTag: string | null;
  timeline: boolean;
  riskFloor: 'low' | 'medium' | 'high' | 'critical' | 'any' | null;
  iocTypeMustInclude: string[];
  iocCountAtLeast: number;
  yaraRulesMustInclude: string[];
}

function loadExpected(): ExpectedRecord[] {
  const expectedPath = path.join(
    REPO_ROOT, 'tests', 'e2e-fixtures', 'expected.jsonl');
  if (!fs.existsSync(expectedPath)) {
    throw new Error(
      `expected.jsonl not found at ${expectedPath} — `
      + 'regenerate with `python scripts/gen_expected.py`');
  }
  const lines = fs.readFileSync(expectedPath, 'utf-8').split('\n');
  return lines
    .filter(l => l.trim().length > 0)
    .map((l, i) => {
      try {
        return JSON.parse(l) as ExpectedRecord;
      } catch (e) {
        throw new Error(`expected.jsonl: parse error on line ${i + 1}: ${e}`);
      }
    });
}

// ── Sanity-check the file early so a malformed line shows up in
//    discover-time rather than mid-run.
const RECORDS = loadExpected();

test.describe.configure({ mode: 'serial' });

test.describe('snapshot matrix', () => {
  test.beforeEach(async ({ page }) => {
    await gotoBundle(page);
  });

  for (const rec of RECORDS) {
    test(rec.path, async ({ page }) => {
      const findings = await loadFixture(page, rec.path);
      const result = await dumpResult(page);

      // ── 1. Routing assertion: Timeline vs renderer.
      if (rec.timeline) {
        expect(result, `${rec.path}: dumpResult must not be null`).not.toBeNull();
        expect(
          result!.timeline,
          `${rec.path}: expected Timeline route`,
        ).toBe(true);
      } else {
        // Renderer route. `result` may legitimately be null only when
        // the fixture failed to load entirely — that's a regression.
        expect(result, `${rec.path}: dumpResult must not be null`).not.toBeNull();
        expect(
          result!.timeline,
          `${rec.path}: expected renderer route, got Timeline`,
        ).toBe(false);
      }

      // ── 2. Format tag pin.
      if (rec.formatTag !== null) {
        expect(
          result!.formatTag,
          `${rec.path}: formatTag drift`,
        ).toBe(rec.formatTag);
      }

      // ── 3. Risk floor.
      if (rec.riskFloor !== null && rec.riskFloor !== 'any') {
        expect(
          isRiskAtLeast(findings.risk, rec.riskFloor),
          `${rec.path}: risk '${findings.risk}' below floor '${rec.riskFloor}'`,
        ).toBe(true);
      }

      // ── 4. IOC count lower bound.
      expect(
        findings.iocCount,
        `${rec.path}: iocCount ${findings.iocCount} < floor ${rec.iocCountAtLeast}`,
      ).toBeGreaterThanOrEqual(rec.iocCountAtLeast);

      // ── 5. IOC type subset.
      for (const t of rec.iocTypeMustInclude) {
        expect(
          findings.iocTypes,
          `${rec.path}: missing IOC type '${t}'`,
        ).toContain(t);
      }

      // ── 6. Must-include YARA rules.
      const seenRules = ruleNames(findings);
      for (const rule of rec.yaraRulesMustInclude) {
        expect(
          seenRules,
          `${rec.path}: missing YARA rule '${rule}'`,
        ).toContain(rule);
      }
    });
  }
});
