'use strict';
// ════════════════════════════════════════════════════════════════════════════
// onenote-renderer.js — OneNote (.one) file analysis and embedded object extraction
// OneNote became a major phishing vector after Microsoft disabled macros by default.
// Depends on: constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class OneNoteRenderer {

  // GUID for OneNote revision store file format
  static ONE_MAGIC = [0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
    0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3];

  // Known dangerous extensions for embedded objects
  static DANGEROUS_EXTS = new Set([
    'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'bat', 'cmd', 'ps1',
    'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'wsc', 'hta', 'lnk', 'inf',
    'reg', 'sct', 'chm', 'jar',
  ]);

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const wrap = document.createElement('div'); wrap.className = 'onenote-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>OneNote File Analysis</strong> — .one files are a common phishing vector. ' +
      'Attackers embed malicious scripts behind fake "Double-click to view" buttons.';
    wrap.appendChild(banner);

    // Verify format
    const isOneNote = this._isOneNote(bytes);
    if (!isOneNote) {
      const info = document.createElement('div'); info.style.cssText = 'padding:20px;';
      info.innerHTML = `<p>File does not appear to be a valid OneNote file.</p>` +
        `<p><strong>File size:</strong> ${this._fmtBytes(bytes.length)}</p>`;
      wrap.appendChild(info);
      return wrap;
    }

    // Extract embedded objects
    const objects = this._findEmbeddedObjects(bytes);
    const strings = this._extractStrings(bytes);

    // Summary
    const summ = document.createElement('div'); summ.className = 'zip-summary';
    summ.textContent = `OneNote file — ${this._fmtBytes(bytes.length)}` +
      (objects.length ? ` — ${objects.length} embedded object(s) detected` : ' — no embedded objects found');
    wrap.appendChild(summ);

    // Warnings
    if (objects.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      const w = document.createElement('div'); w.className = 'zip-warning zip-warning-high';
      w.textContent = `⚠ ${objects.length} embedded file object(s) — OneNote files with embedded objects are a known phishing technique`;
      warnDiv.appendChild(w);

      const dangerous = objects.filter(o => {
        const ext = (o.name || '').split('.').pop().toLowerCase();
        return OneNoteRenderer.DANGEROUS_EXTS.has(ext);
      });
      if (dangerous.length) {
        const w2 = document.createElement('div'); w2.className = 'zip-warning zip-warning-high';
        w2.textContent = `⚠ ${dangerous.length} executable/script file(s) embedded: ${dangerous.map(o => o.name).join(', ')}`;
        warnDiv.appendChild(w2);
      }
      wrap.appendChild(warnDiv);
    }

    // Embedded objects table
    if (objects.length) {
      const sec = document.createElement('div'); sec.className = 'onenote-objects';
      const h = document.createElement('h3'); h.textContent = 'Embedded Objects';
      h.style.cssText = 'margin:16px 0 8px 0;padding:0 8px;'; sec.appendChild(h);

      const tbl = document.createElement('table'); tbl.className = 'zip-table';
      const thead = document.createElement('thead');
      const hr = document.createElement('tr');
      for (const col of ['', 'Name', 'Size', 'Type']) {
        const th = document.createElement('th'); th.textContent = col; hr.appendChild(th);
      }
      thead.appendChild(hr); tbl.appendChild(thead);

      const tbody = document.createElement('tbody');
      for (const obj of objects) {
        const tr = document.createElement('tr');
        const ext = (obj.name || '').split('.').pop().toLowerCase();
        const isDangerous = OneNoteRenderer.DANGEROUS_EXTS.has(ext);
        if (isDangerous) tr.className = 'zip-row-danger';

        const tdIcon = document.createElement('td'); tdIcon.className = 'zip-icon';
        tdIcon.textContent = isDangerous ? '⚠️' : '📎';
        tr.appendChild(tdIcon);

        const tdName = document.createElement('td'); tdName.className = 'zip-path';
        tdName.textContent = obj.name || `Object (${this._fmtBytes(obj.size)})`;
        if (isDangerous) {
          const badge = document.createElement('span'); badge.className = 'zip-badge-danger';
          badge.textContent = 'EXECUTABLE'; tdName.appendChild(badge);
        }
        tr.appendChild(tdName);

        const tdSize = document.createElement('td'); tdSize.className = 'zip-size';
        tdSize.textContent = this._fmtBytes(obj.size);
        tr.appendChild(tdSize);

        const tdType = document.createElement('td'); tdType.className = 'zip-date';
        tdType.textContent = obj.type || ext || '—';
        tr.appendChild(tdType);

        tbody.appendChild(tr);
      }
      tbl.appendChild(tbody); sec.appendChild(tbl);
      wrap.appendChild(sec);
    }

    // Extracted text
    if (strings.length) {
      const textSec = document.createElement('div'); textSec.style.cssText = 'padding:8px;';
      const details = document.createElement('details'); details.className = 'rtf-raw-details';
      const summary = document.createElement('summary');
      summary.textContent = `Extracted Text Strings (${strings.length})`;
      details.appendChild(summary);
      const pre = document.createElement('pre'); pre.className = 'rtf-raw-source';
      pre.textContent = strings.join('\n');
      details.appendChild(pre); textSec.appendChild(details);
      wrap.appendChild(textSec);
    }

    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'medium', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    // OneNote files are inherently suspicious in email context
    f.externalRefs.push({
      type: IOC.PATTERN,
      url: 'OneNote file — commonly used as phishing vector since macro-blocking',
      severity: 'medium'
    });

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const objects = this._findEmbeddedObjects(bytes);

    if (objects.length) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${objects.length} embedded file object(s) in OneNote`,
        severity: 'high'
      });
      f.risk = 'high';

      for (const obj of objects) {
        const ext = (obj.name || '').split('.').pop().toLowerCase();
        if (OneNoteRenderer.DANGEROUS_EXTS.has(ext)) {
          f.externalRefs.push({ type: IOC.FILE_PATH, url: obj.name, severity: 'high' });
        } else if (obj.name) {
          f.externalRefs.push({ type: IOC.FILE_PATH, url: obj.name, severity: 'medium' });
        }
      }
    }

    // Extract URLs from text content
    const strings = this._extractStrings(bytes);
    const fullText = strings.join('\n');
    for (const m of fullText.matchAll(/https?:\/\/[^\s"'<>]{6,}/g)) {
      f.externalRefs.push({ type: IOC.URL, url: m[0], severity: 'medium' });
    }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  // ── OneNote format detection ────────────────────────────────────────────────

  _isOneNote(bytes) {
    if (bytes.length < 16) return false;
    for (let i = 0; i < 16; i++) {
      if (bytes[i] !== OneNoteRenderer.ONE_MAGIC[i]) return false;
    }
    return true;
  }

  // ── Embedded object detection ───────────────────────────────────────────────
  // OneNote embeds files with a FileDataStoreObject structure.
  // We scan for known GUIDs and patterns that indicate embedded files.

  _findEmbeddedObjects(bytes) {
    const objects = [];

    // Scan for embedded file data store objects
    // The GUID for FileDataStoreObject is: {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
    const FDS_GUID = [0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
      0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC];

    // Also scan for embedded file names by looking for common patterns
    // OneNote stores filenames as UTF-16LE strings near embedded data

    // Method 1: Look for FileDataStoreObject GUIDs
    for (let i = 0; i < bytes.length - 20; i++) {
      if (this._matchGuid(bytes, i, FDS_GUID)) {
        // Found a file data store object
        // The data follows after the GUID + some header bytes
        const obj = this._parseFileDataStore(bytes, i);
        if (obj) objects.push(obj);
      }
    }

    // Method 2: If GUID scan didn't find anything, look for embedded PE/script signatures
    if (objects.length === 0) {
      // Look for PE headers (MZ)
      for (let i = 256; i < bytes.length - 2; i++) {
        if (bytes[i] === 0x4D && bytes[i + 1] === 0x5A) {
          // Check for PE header
          if (i + 64 < bytes.length) {
            const peOff = bytes[i + 60] | (bytes[i + 61] << 8) | (bytes[i + 62] << 16) | (bytes[i + 63] << 24);
            if (peOff > 0 && peOff < 0x1000 && i + peOff + 4 < bytes.length) {
              if (bytes[i + peOff] === 0x50 && bytes[i + peOff + 1] === 0x45) {
                objects.push({ name: 'embedded.exe', size: 0, type: 'PE Executable', offset: i });
              }
            }
          }
        }
      }

      // Look for ZIP signatures (Office docs, JARs)
      for (let i = 256; i < bytes.length - 4; i++) {
        if (bytes[i] === 0x50 && bytes[i + 1] === 0x4B && bytes[i + 2] === 0x03 && bytes[i + 3] === 0x04) {
          objects.push({ name: 'embedded.zip', size: 0, type: 'ZIP Archive', offset: i });
          break; // Just report first one
        }
      }
    }

    // Method 3: Scan for filename patterns (UTF-16LE) near embedded data
    this._findEmbeddedFilenames(bytes, objects);

    return objects;
  }

  _matchGuid(bytes, offset, guid) {
    if (offset + guid.length > bytes.length) return false;
    for (let i = 0; i < guid.length; i++) {
      if (bytes[offset + i] !== guid[i]) return false;
    }
    return true;
  }

  _parseFileDataStore(bytes, guidOffset) {
    // After the GUID (16 bytes), there's a header with size info
    const dataOff = guidOffset + 16;
    if (dataOff + 8 > bytes.length) return null;

    // Try to read the data size (stored as uint64, but we only use lower 32 bits)
    const size = bytes[dataOff] | (bytes[dataOff + 1] << 8) |
      (bytes[dataOff + 2] << 16) | ((bytes[dataOff + 3] << 24) >>> 0);

    if (size > 0 && size < bytes.length) {
      // Try to find filename nearby
      const name = this._findNearbyFilename(bytes, guidOffset - 200, guidOffset + 200) || 'embedded_object';
      const type = this._guessType(name, bytes, dataOff + 8);
      return { name, size, type, offset: guidOffset };
    }
    return null;
  }

  _findNearbyFilename(bytes, start, end) {
    start = Math.max(0, start);
    end = Math.min(bytes.length - 2, end);

    // Look for UTF-16LE filename with extension
    for (let i = start; i < end - 10; i++) {
      // Look for a dot followed by a 2-4 letter extension in UTF-16LE
      if (bytes[i] === 0x2E && bytes[i + 1] === 0x00) { // "." in UTF-16LE
        // Read backwards to find the start of the filename
        let nameStart = i;
        while (nameStart > start + 2 &&
          ((bytes[nameStart - 2] >= 0x20 && bytes[nameStart - 2] < 0x7F && bytes[nameStart - 1] === 0x00) ||
            (bytes[nameStart - 2] >= 0x80 && bytes[nameStart - 1] !== 0x00))) {
          nameStart -= 2;
        }

        // Read the extension after the dot
        let extEnd = i + 2;
        while (extEnd < end - 1 && bytes[extEnd] >= 0x61 && bytes[extEnd] <= 0x7A && bytes[extEnd + 1] === 0x00) {
          extEnd += 2;
        }

        const extLen = (extEnd - i - 2) / 2;
        if (extLen >= 2 && extLen <= 5) {
          let name = '';
          for (let j = nameStart; j < extEnd; j += 2) {
            if (j + 1 < bytes.length) {
              const code = bytes[j] | (bytes[j + 1] << 8);
              if (code >= 0x20 && code < 0xFFFE) name += String.fromCharCode(code);
            }
          }
          if (name.length >= 3 && name.includes('.')) return name;
        }
      }
    }
    return null;
  }

  _findEmbeddedFilenames(bytes, objects) {
    // Scan entire file for UTF-16LE filenames with dangerous extensions
    const extPattern = /\.(exe|dll|bat|cmd|ps1|vbs|hta|js|scr|lnk|wsf)\x00/;
    for (let i = 0; i < bytes.length - 20; i++) {
      if (bytes[i] === 0x2E && bytes[i + 1] === 0x00) {
        // Potential extension start
        let ext = '';
        let j = i + 2;
        while (j < bytes.length - 1 && j < i + 12 && bytes[j] >= 0x61 && bytes[j] <= 0x7A && bytes[j + 1] === 0x00) {
          ext += String.fromCharCode(bytes[j]);
          j += 2;
        }
        if (ext.length >= 2 && ext.length <= 5 && OneNoteRenderer.DANGEROUS_EXTS.has(ext)) {
          // Read back for filename
          let nameStart = i;
          let nameChars = 0;
          while (nameStart > 2 && nameChars < 100 &&
            bytes[nameStart - 2] >= 0x20 && bytes[nameStart - 1] === 0x00) {
            nameStart -= 2;
            nameChars++;
          }
          if (nameChars >= 2) {
            let name = '';
            for (let k = nameStart; k < j; k += 2) {
              const code = bytes[k] | (bytes[k + 1] << 8);
              if (code >= 0x20 && code < 0xFFFE) name += String.fromCharCode(code);
            }
            if (name.length >= 3 && !objects.some(o => o.name === name)) {
              objects.push({ name, size: 0, type: 'Embedded file (name found)', offset: nameStart });
            }
          }
        }
      }
    }
  }

  _guessType(name, bytes, offset) {
    const ext = (name || '').split('.').pop().toLowerCase();
    if (['exe', 'dll', 'scr', 'com'].includes(ext)) return 'PE Executable';
    if (['bat', 'cmd'].includes(ext)) return 'Batch Script';
    if (['ps1'].includes(ext)) return 'PowerShell Script';
    if (['vbs', 'vbe'].includes(ext)) return 'VBScript';
    if (['js', 'jse'].includes(ext)) return 'JavaScript';
    if (['hta'].includes(ext)) return 'HTML Application';
    if (['lnk'].includes(ext)) return 'Windows Shortcut';
    if (['wsf'].includes(ext)) return 'Windows Script File';

    // Check magic bytes
    if (offset + 4 < bytes.length) {
      if (bytes[offset] === 0x4D && bytes[offset + 1] === 0x5A) return 'PE Executable';
      if (bytes[offset] === 0x50 && bytes[offset + 1] === 0x4B) return 'ZIP/Office Archive';
    }
    return ext || 'Unknown';
  }

  // ── Text string extraction ──────────────────────────────────────────────────

  _extractStrings(bytes) {
    const strings = [];
    const seen = new Set();

    // Extract UTF-16LE strings
    let current = '';
    for (let i = 0; i < bytes.length - 1; i += 2) {
      const code = bytes[i] | (bytes[i + 1] << 8);
      if (code >= 0x20 && code < 0xFFFE && code !== 0xFFFD) {
        current += String.fromCharCode(code);
      } else {
        if (current.length >= 8 && !seen.has(current)) {
          seen.add(current);
          strings.push(current);
        }
        current = '';
      }
    }
    if (current.length >= 8 && !seen.has(current)) strings.push(current);

    // Also extract ASCII strings
    current = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b >= 0x20 && b < 0x7F) {
        current += String.fromCharCode(b);
      } else {
        if (current.length >= 12 && !seen.has(current)) {
          seen.add(current);
          strings.push(current);
        }
        current = '';
      }
    }
    if (current.length >= 12 && !seen.has(current)) strings.push(current);

    return strings.slice(0, 500); // Cap at 500
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
