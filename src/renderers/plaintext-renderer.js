'use strict';
// ════════════════════════════════════════════════════════════════════════════
// plaintext-renderer.js — Catch-all viewer for unsupported file types
// Shows plain text (with line numbers) or hex dump depending on content.
// ════════════════════════════════════════════════════════════════════════════
class PlainTextRenderer {

  // Extensions treated as known script / config types for keyword highlighting
  static SCRIPT_EXTS = new Set([
    'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'ps1', 'psm1', 'psd1',
    'bat', 'cmd', 'sh', 'bash', 'py', 'rb', 'pl',
    'hta', 'htm', 'html', 'mht', 'mhtml', 'xhtml', 'svg',
    'xml', 'xsl', 'xslt', 'xaml',
    'reg', 'inf', 'ini', 'cfg', 'conf', 'yml', 'yaml', 'toml', 'json',
    'rtf', 'eml', 'ics', 'vcf', 'url', 'desktop', 'lnk',
    'sql', 'php', 'asp', 'aspx', 'jsp', 'cgi',
    'txt', 'log', 'md', 'csv', 'tsv',
  ]);

  // ── Render ──────────────────────────────────────────────────────────────

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const isText = this._isTextContent(bytes);
    if (isText) return this._renderText(bytes, fileName);
    return this._renderHex(bytes, fileName);
  }

  // ── Security analysis ───────────────────────────────────────────────────

  analyzeForSecurity(buffer, fileName) {
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const isText = this._isTextContent(bytes);

    if (!isText) {
      // For binary files, note that this is an unsupported binary format
      f.externalRefs.push({
        type: IOC.INFO,
        url: `Binary file rendered as hex dump (.${ext})`,
        severity: 'info'
      });
    }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  // ── Text rendering with line numbers ────────────────────────────────────

  _renderText(bytes, fileName) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    const ext = (fileName || '').split('.').pop().toLowerCase();

    const wrap = document.createElement('div');
    wrap.className = 'plaintext-view';

    // Info bar
    const info = document.createElement('div');
    info.className = 'plaintext-info';
    info.textContent = `${lines.length} line${lines.length !== 1 ? 's' : ''}  ·  ${this._fmtBytes(bytes.length)}  ·  Plain text view`;
    wrap.appendChild(info);

    // Code block with line numbers
    const scr = document.createElement('div');
    scr.className = 'plaintext-scroll';

    const table = document.createElement('table');
    table.className = 'plaintext-table';

    const maxLines = 50000;
    const count = Math.min(lines.length, maxLines);
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td');
      tdNum.className = 'plaintext-ln';
      tdNum.textContent = i + 1;
      const tdCode = document.createElement('td');
      tdCode.className = 'plaintext-code';
      tdCode.textContent = lines[i];
      tr.appendChild(tdNum);
      tr.appendChild(tdCode);
      table.appendChild(tr);
    }
    if (lines.length > maxLines) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 2;
      td.className = 'plaintext-truncated';
      td.textContent = `… truncated (${lines.length - maxLines} more lines)`;
      tr.appendChild(td);
      table.appendChild(tr);
    }

    scr.appendChild(table);
    wrap.appendChild(scr);
    return wrap;
  }

  // ── Hex dump rendering ──────────────────────────────────────────────────

  _renderHex(bytes, fileName) {
    const wrap = document.createElement('div');
    wrap.className = 'hex-view';

    const info = document.createElement('div');
    info.className = 'plaintext-info';
    info.textContent = `${this._fmtBytes(bytes.length)}  ·  Binary file  ·  Hex dump view`;
    wrap.appendChild(info);

    const scr = document.createElement('div');
    scr.className = 'plaintext-scroll';

    const pre = document.createElement('pre');
    pre.className = 'hex-dump';

    const maxBytes = 64 * 1024; // 64 KB cap
    const cap = Math.min(bytes.length, maxBytes);
    const lines = [];

    for (let off = 0; off < cap; off += 16) {
      const hex = [];
      const ascii = [];
      for (let j = 0; j < 16; j++) {
        if (off + j < cap) {
          const b = bytes[off + j];
          hex.push(b.toString(16).padStart(2, '0'));
          ascii.push(b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.');
        } else {
          hex.push('  ');
          ascii.push(' ');
        }
      }
      const addr = off.toString(16).padStart(8, '0');
      lines.push(`${addr}  ${hex.slice(0, 8).join(' ')}  ${hex.slice(8).join(' ')}  |${ascii.join('')}|`);
    }
    if (bytes.length > maxBytes) {
      lines.push(`\n… truncated at ${maxBytes.toLocaleString()} bytes (file is ${bytes.length.toLocaleString()} bytes)`);
    }

    pre.textContent = lines.join('\n');
    scr.appendChild(pre);
    wrap.appendChild(scr);
    return wrap;
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  /** Heuristic: check if the first 8 KB is mostly printable UTF-8. */
  _isTextContent(bytes) {
    const sample = bytes.subarray(0, 8192);
    let printable = 0;
    for (let i = 0; i < sample.length; i++) {
      const b = sample[i];
      // Printable ASCII, common whitespace, or high bytes (UTF-8 continuation)
      if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d || b >= 0x80) {
        printable++;
      }
    }
    return sample.length > 0 && (printable / sample.length) >= 0.90;
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
