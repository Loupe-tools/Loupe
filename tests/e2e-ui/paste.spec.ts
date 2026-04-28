// ════════════════════════════════════════════════════════════════════════════
// paste.spec.ts — UI-interaction e2e for the paste-into-page ingress
// path.
//
// The handler lives in `src/app/app-core.js:334` and forks based on
// what's on the clipboard:
//
//   1. `clipboardData.files[0]`            → load as a File
//   2. `clipboardData.items[*].type` is
//      `image/*`                           → load `getAsFile()` blob
//   3. `clipboardData.getData('text/plain')` → load as `clipboard.txt`
//   4. `clipboardData.getData('text/html')`  → load as `clipboard.html`
//
// We can't construct a real `ClipboardEvent` with a populated
// `clipboardData` attribute (it's read-only and not init-dict-settable
// per spec), and `navigator.clipboard.write` is permission-gated on
// `file://` URLs. The simplest reliable approach is to dispatch an
// event whose shape the handler accepts — `_handlePasteEvent(e)` only
// reads `e.clipboardData`, never `e instanceof ClipboardEvent`. We
// build a plain `Event('paste')` and assign a fake `clipboardData`
// object that mirrors the `DataTransfer` interface the handler uses
// (`files`, `items`, `getData`, `types`).
//
// This faithfully exercises the full paste handler chain
// (`_handlePasteEvent` → `_loadPastePayload` → `_loadFile`), guarding
// against regressions like:
//
//   • A future refactor that gates on `e instanceof ClipboardEvent`
//     would silently drop the synthetic event AND every legitimate
//     non-Chromium browser's paste — failing this test is the right
//     signal.
//   • Routing the text fork through a different `File` constructor
//     (e.g., dropping the `'clipboard.txt'` filename) would change
//     the renderer registry's dispatch and likely zero out IOCs.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { gotoBundle, dumpFindings, REPO_ROOT } from '../helpers/playwright-helpers';

test.describe('paste ingress', () => {
  test.beforeEach(async ({ page }) => {
    await gotoBundle(page);
  });

  test('plain-text paste lands a defanged-IOC fixture', async ({ page }) => {
    // Use `defanged-iocs.txt` — short, deterministic, and the
    // renderer-registry route is `plaintext`, which guarantees the
    // text fork was taken (a file-fork would produce a different
    // formatTag / extension dispatch).
    const fixture = path.join(
      REPO_ROOT, 'examples', 'encoded-payloads', 'defanged-iocs.txt');
    const text = fs.readFileSync(fixture, 'utf8');

    await page.evaluate(async ({ text }) => {
      // Fake DataTransfer surface — the handler only touches the four
      // members below. Crucially `files` is empty AND `items` is
      // empty (no image fork), so the handler falls through to the
      // text fork.
      const dt = {
        files: [] as File[],
        items: [] as DataTransferItem[],
        types: ['text/plain'],
        getData(kind: string) {
          if (kind === 'text/plain') return text;
          return '';
        },
      };
      const e = new Event('paste', { bubbles: true, cancelable: true });
      // `clipboardData` on a real ClipboardEvent is read-only — but
      // we're synthesising onto a plain Event whose own properties
      // are writable.
      Object.defineProperty(e, 'clipboardData', { value: dt });
      document.dispatchEvent(e);

      // Paste handler is synchronous through `_loadPastePayload`,
      // which calls `_loadFile` (async). Yield, then await idle.
      await new Promise(r => setTimeout(r, 0));
      const w = window as unknown as {
        __loupeTest: { waitForIdle(): Promise<void> };
      };
      await w.__loupeTest.waitForIdle();
    }, { text });

    const findings = await dumpFindings(page);
    // `defanged-iocs.txt` defangs URLs / emails — the renderer must
    // un-defang them and surface both as IOCs. Zero results means
    // the paste path failed to dispatch.
    expect(findings.iocTypes).toContain('URL');
    expect(findings.iocTypes).toContain('Email');
  });

  test('paste with both text/plain and text/html prefers plain', async ({ page }) => {
    // Regression guard: the handler MUST prefer `text/plain` over
    // `text/html` (see `app-core.js` comment "Prefer plain text over
    // HTML so that pasting from apps like Slack gives the actual
    // text content"). Build a clipboard that carries both — if the
    // handler ever inverts the priority, the renderer dispatch
    // changes (HTML → html renderer, plain → plaintext renderer)
    // and the assertion below fails.
    const plainText = 'http://example.com/from-plain-paste';
    const htmlText = '<a href="http://example.com/from-html-paste">link</a>';

    await page.evaluate(async ({ plainText, htmlText }) => {
      const dt = {
        files: [],
        items: [],
        types: ['text/plain', 'text/html'],
        getData(kind: string) {
          if (kind === 'text/plain') return plainText;
          if (kind === 'text/html') return htmlText;
          return '';
        },
      } as unknown as DataTransfer;
      const e = new Event('paste', { bubbles: true, cancelable: true });
      Object.defineProperty(e, 'clipboardData', { value: dt });
      document.dispatchEvent(e);
      await new Promise(r => setTimeout(r, 0));
      const w = window as unknown as {
        __loupeTest: { waitForIdle(): Promise<void> };
      };
      await w.__loupeTest.waitForIdle();
    }, { plainText, htmlText });

    const findings = await dumpFindings(page);
    // The plain text contains `from-plain-paste`. We don't pin the
    // exact URL list (the IOC extractor may normalise), but if the
    // handler routed the html fork the URL would carry
    // `from-html-paste` instead. Assert via substring.
    const urlValues = findings.iocs
      .filter(i => i.type === 'URL')
      .map(i => i.value)
      .join('|');
    expect(urlValues).toContain('from-plain-paste');
    expect(urlValues).not.toContain('from-html-paste');
  });

  test('paste falls through to text/html when text/plain is absent', async ({ page }) => {
    // Symmetric guard: if the handler can't get plain text, the
    // html fork MUST be taken. Without this the paste of an
    // HTML-only clipboard (e.g. Outlook copy-of-cell) silently
    // drops with a "Nothing to paste" toast.
    const htmlText = '<html><body><a href="http://example.com/html-only">x</a></body></html>';
    await page.evaluate(async ({ htmlText }) => {
      const dt = {
        files: [],
        items: [],
        types: ['text/html'],
        getData(kind: string) {
          if (kind === 'text/html') return htmlText;
          return '';
        },
      } as unknown as DataTransfer;
      const e = new Event('paste', { bubbles: true, cancelable: true });
      Object.defineProperty(e, 'clipboardData', { value: dt });
      document.dispatchEvent(e);
      await new Promise(r => setTimeout(r, 0));
      const w = window as unknown as {
        __loupeTest: { waitForIdle(): Promise<void> };
      };
      await w.__loupeTest.waitForIdle();
    }, { htmlText });

    const findings = await dumpFindings(page);
    // The HTML renderer extracts hrefs as URLs.
    expect(findings.iocTypes).toContain('URL');
  });

  test('paste inside a textarea is NOT intercepted (focus gate)', async ({ page }) => {
    // The handler bails out early for paste events whose target is
    // an `<input>` or `<textarea>` (so the YARA editor / search
    // bars work normally). Exercise this gate: focus the YARA
    // editor textarea (if it exists) and fire a paste — the page
    // must NOT load any file.
    await page.evaluate(async () => {
      // Inject a temporary textarea and focus it. Using a fresh
      // element keeps the test independent of UI surface changes.
      const ta = document.createElement('textarea');
      ta.id = '__paste_test_textarea__';
      document.body.appendChild(ta);
      ta.focus();

      const dt = {
        files: [],
        items: [],
        types: ['text/plain'],
        getData() { return 'http://example.com/should-not-load'; },
      } as unknown as DataTransfer;
      const e = new Event('paste', { bubbles: true, cancelable: true });
      Object.defineProperty(e, 'clipboardData', { value: dt });
      Object.defineProperty(e, 'target', { value: ta });
      ta.dispatchEvent(e);
      await new Promise(r => setTimeout(r, 50));
      ta.remove();
    });

    // Read findings — should remain at the empty-page state, NOT
    // the result of loading `http://example.com/should-not-load`.
    const findings = await dumpFindings(page);
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
  });
});
