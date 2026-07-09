'use strict';
// ════════════════════════════════════════════════════════════════════════════
// decoder-ioc.js — encoded-content decoder IOC helpers
//
// Decoders emit IOC-shaped rows on encoded-finding candidates (`iocs[]`,
// `_patternIocs[]`) that ultimately merge via `App._mergeEncodedFindingIocs`.
// This module centralises sentinel filtering for pattern labels.
// ════════════════════════════════════════════════════════════════════════════

const _SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);

const DecoderIoc = {
  /**
   * Build a `_patternIocs` / IOC.PATTERN row, or null if the label carries
   * an unresolved decoder sentinel.
   * @param {string} url
   * @param {string} [severity='high']
   * @returns {{url: string, severity: string}|null}
   */
  pattern(url, severity = 'high') {
    if (url == null || url === '') return null;
    const label = String(url);
    if (hasUnresolvedSentinel(label)) return null;
    const sev = severity || 'high';
    if (!_SEVERITIES.has(sev)) {
      throw new RangeError(`DecoderIoc.pattern: invalid severity "${sev}"`);
    }
    return { url: label, severity: sev };
  },

  /**
   * Map an array of `{ url, severity }` (or plain strings) to sanitised rows.
   * @param {Array<{url?: string, severity?: string}|string>} entries
   * @returns {Array<{url: string, severity: string}>}
   */
  patternList(entries) {
    const out = [];
    if (!Array.isArray(entries)) return out;
    for (const e of entries) {
      const url = (e && typeof e === 'object') ? e.url : e;
      const sev = (e && typeof e === 'object') ? e.severity : 'high';
      const row = DecoderIoc.pattern(url, sev);
      if (row) out.push(row);
    }
    return out;
  },
};