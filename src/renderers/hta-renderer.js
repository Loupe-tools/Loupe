'use strict';
// ════════════════════════════════════════════════════════════════════════════
// hta-renderer.js — Renders HTA (HTML Application) files with security focus
// Shows source code with danger banner, script extraction, pattern scanning.
// ════════════════════════════════════════════════════════════════════════════
class HtaRenderer {

  render(buffer) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const wrap = document.createElement('div');
    wrap.className = 'hta-view';

    // Danger banner — always shown for HTA
    const ban = document.createElement('div');
    ban.className = 'hta-danger-banner';
    ban.textContent = '⚠ HTML Application (HTA) — This file type runs with full system access when opened with mshta.exe';
    wrap.appendChild(ban);

    // HTA:APPLICATION attributes
    const htaTag = text.match(/<HTA:APPLICATION([^>]*)>/i);
    if (htaTag) {
      const attrs = this._parseAttributes(htaTag[1]);
      if (attrs.length) {
        const attrH = document.createElement('div');
        attrH.className = 'hta-section-hdr';
        attrH.textContent = 'HTA:APPLICATION Attributes';
        wrap.appendChild(attrH);
        const tbl = document.createElement('table');
        tbl.className = 'lnk-info-table';
        for (const [name, val] of attrs) {
          const tr = document.createElement('tr');
          const tdL = document.createElement('td');
          tdL.className = 'lnk-lbl';
          tdL.textContent = name;
          const tdV = document.createElement('td');
          tdV.className = 'lnk-val';
          tdV.textContent = val;
          tr.appendChild(tdL);
          tr.appendChild(tdV);
          tbl.appendChild(tr);
        }
        wrap.appendChild(tbl);
      }
    }

    // Script block summary
    const scriptBlocks = this._extractScripts(text);
    if (scriptBlocks.length) {
      const sh = document.createElement('div');
      sh.className = 'hta-section-hdr';
      sh.textContent = `Embedded Scripts (${scriptBlocks.length} block${scriptBlocks.length !== 1 ? 's' : ''})`;
      wrap.appendChild(sh);

      for (const sb of scriptBlocks) {
        const label = document.createElement('div');
        label.className = 'hta-script-label';
        label.textContent = `<script${sb.language ? ' language="' + sb.language + '"' : ''}> — ${sb.lines} line${sb.lines !== 1 ? 's' : ''}`;
        wrap.appendChild(label);
        const pre = document.createElement('pre');
        pre.className = 'vba-code';
        pre.textContent = sb.source;
        wrap.appendChild(pre);
      }
    }

    // Full source with line numbers
    const srcH = document.createElement('div');
    srcH.className = 'hta-section-hdr';
    srcH.textContent = 'Full Source';
    wrap.appendChild(srcH);

    const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    const info = document.createElement('div');
    info.className = 'plaintext-info';
    info.textContent = `${lines.length} line${lines.length !== 1 ? 's' : ''}  ·  ${this._fmtBytes(bytes.length)}`;
    wrap.appendChild(info);

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
    scr.appendChild(table);
    wrap.appendChild(scr);

    return wrap;
  }

  analyzeForSecurity(buffer) {
    const f = {
      risk: 'high', // HTA files are inherently high-risk
      hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);

    f.externalRefs.push({
      type: IOC.INFO,
      url: 'HTML Application (HTA) — runs with full system access via mshta.exe',
      severity: 'high'
    });

    // Script block count (structural check)
    const scriptBlocks = this._extractScripts(text);
    if (scriptBlocks.length) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${scriptBlocks.length} embedded <script> block(s): ${scriptBlocks.map(s => s.language || 'unknown').join(', ')}`,
        severity: 'medium'
      });
    }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  _extractScripts(text) {
    const blocks = [];
    const rx = /<script([^>]*)>([\s\S]*?)<\/script>/gi;
    let m;
    while ((m = rx.exec(text)) !== null) {
      const attrs = m[1] || '';
      const source = m[2].trim();
      const langMatch = attrs.match(/language\s*=\s*["']?(\w+)/i);
      const typeMatch = attrs.match(/type\s*=\s*["']?([^"'\s>]+)/i);
      blocks.push({
        language: langMatch ? langMatch[1] : (typeMatch ? typeMatch[1] : ''),
        source,
        lines: source.split('\n').length,
      });
    }
    return blocks;
  }

  _parseAttributes(attrStr) {
    const result = [];
    const rx = /(\w+)\s*=\s*"([^"]*)"/gi;
    let m;
    while ((m = rx.exec(attrStr)) !== null) {
      result.push([m[1], m[2]]);
    }
    // Also try unquoted
    const rx2 = /(\w+)\s*=\s*([^\s"]+)/gi;
    const seen = new Set(result.map(r => r[0].toLowerCase()));
    while ((m = rx2.exec(attrStr)) !== null) {
      if (!seen.has(m[1].toLowerCase())) {
        result.push([m[1], m[2]]);
      }
    }
    return result;
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
