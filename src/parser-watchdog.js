'use strict';
// ════════════════════════════════════════════════════════════════════════════
// parser-watchdog.js — Timeout guard for parser invocations
// Wraps sync or async parser calls with a configurable deadline.
// If a parser hangs (e.g. on a maliciously crafted file), the promise rejects
// after PARSER_LIMITS.TIMEOUT_MS (default 60 s) so the UI can recover.
// ════════════════════════════════════════════════════════════════════════════

const ParserWatchdog = {

  /**
   * Run a function with a timeout guard.
   * @param {Function} fn        — sync or async function to execute
   * @param {number}   [ms]      — timeout in milliseconds (default: PARSER_LIMITS.TIMEOUT_MS)
   * @returns {Promise<*>}       — resolves with fn's return value or rejects on timeout
   */
  run(fn, ms) {
    const timeout = ms || (typeof PARSER_LIMITS !== 'undefined' ? PARSER_LIMITS.TIMEOUT_MS : 60000);
    return new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          reject(new Error(`Parser timed out after ${(timeout / 1000).toFixed(0)}s — file may be malicious or too complex.`));
        }
      }, timeout);

      try {
        const result = fn();
        if (result && typeof result.then === 'function') {
          // Async path
          result.then(
            v => { if (!settled) { settled = true; clearTimeout(timer); resolve(v); } },
            e => { if (!settled) { settled = true; clearTimeout(timer); reject(e); } }
          );
        } else {
          // Sync path
          if (!settled) { settled = true; clearTimeout(timer); resolve(result); }
        }
      } catch (e) {
        if (!settled) { settled = true; clearTimeout(timer); reject(e); }
      }
    });
  },
};
