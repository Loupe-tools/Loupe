'use strict';
// ════════════════════════════════════════════════════════════════════════════
// msi-renderer.js — Windows Installer (.msi) analysis (lightweight)
// Uses OleCfbParser in metadata-only mode to avoid loading large stream content.
// Extracts: Summary Information, MSI table names, stream listing (name+size).
// Depends on: ole-cfb-parser.js, constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════

const MSI_SIZE_LIMIT = 50 * 1024 * 1024; // 50MB - show simplified view above this

class MsiRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const wrap = document.createElement('div'); wrap.className = 'msi-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    const bannerStrong = document.createElement('strong'); bannerStrong.textContent = 'Windows Installer Package (.msi)';
    banner.appendChild(bannerStrong);
    banner.appendChild(document.createTextNode(' — click any stream to analyze its contents. MSI files execute with elevated privileges and can run custom actions, modify the registry, and install services.'));
    wrap.appendChild(banner);

    // Cleanup previous OLE parser reference to prevent memory leaks
    this._ole = null;

    // Check for large files
    if (bytes.length > MSI_SIZE_LIMIT) {
      return this._renderLargeFileView(wrap, bytes, fileName);
    }

    let analysis;
    try {
      analysis = this._analyze(bytes);
    } catch (e) {
      const err = document.createElement('div'); err.className = 'error-box';
      err.textContent = `Failed to parse MSI: ${e.message}`;
      wrap.appendChild(err);
      return wrap;
    }

    // Summary info line
    const infoDiv = document.createElement('div'); infoDiv.className = 'plaintext-info';
    infoDiv.textContent = `${analysis.streams.length} stream(s)  ·  ${this._fmtBytes(bytes.length)}  ·  Windows Installer Package`;
    wrap.appendChild(infoDiv);

    // Warnings
    if (analysis.warnings.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      for (const w of analysis.warnings) {
        const d = document.createElement('div');
        d.className = `zip-warning zip-warning-${w.sev}`;
        d.textContent = `${w.sev === 'critical' ? '🚨' : '⚠'} ${w.label}`;
        warnDiv.appendChild(d);
      }
      wrap.appendChild(warnDiv);
    }

    // Summary Information (document properties)
    if (analysis.summaryInfo && Object.keys(analysis.summaryInfo).length) {
      const siH = document.createElement('div'); siH.className = 'hta-section-hdr';
      siH.textContent = 'Summary Information';
      wrap.appendChild(siH);

      const tbl = document.createElement('table'); tbl.className = 'lnk-info-table';
      for (const [key, val] of Object.entries(analysis.summaryInfo)) {
        const tr = document.createElement('tr');
        const tdL = document.createElement('td'); tdL.className = 'lnk-lbl'; tdL.textContent = key;
        const tdV = document.createElement('td'); tdV.className = 'lnk-val'; tdV.textContent = val;
        tr.appendChild(tdL); tr.appendChild(tdV); tbl.appendChild(tr);
      }
      wrap.appendChild(tbl);
    }

    // MSI tables detected
    if (analysis.tables.length) {
      const tH = document.createElement('div'); tH.className = 'hta-section-hdr';
      tH.textContent = `MSI Database Tables (${analysis.tables.length})`;
      wrap.appendChild(tH);

      const tblDiv = document.createElement('div'); tblDiv.style.cssText = 'padding:4px 8px;';
      const chips = document.createElement('div');
      chips.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;';
      for (const t of analysis.tables) {
        const chip = document.createElement('span');
        chip.style.cssText = `display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-family:monospace;${t.isSuspicious ? 'background:rgba(255,136,136,0.15);color:#f88;border:1px solid rgba(255,136,136,0.3);' : 'background:rgba(68,170,255,0.08);color:#8cf;border:1px solid rgba(68,170,255,0.15);'}`;
        chip.textContent = t.name;
        chip.title = t.isSuspicious ? 'Potentially dangerous table' : '';
        chips.appendChild(chip);
      }
      tblDiv.appendChild(chips); wrap.appendChild(tblDiv);
    }

    // Custom Actions / Security Warnings
    if (analysis.customActions.length) {
      const caH = document.createElement('div'); caH.className = 'hta-section-hdr';
      caH.textContent = `Security Concerns (${analysis.customActions.length})`;
      wrap.appendChild(caH);

      const caDiv = document.createElement('div'); caDiv.style.cssText = 'padding:0 8px;';
      for (const ca of analysis.customActions) {
        const d = document.createElement('div');
        d.className = `zip-warning zip-warning-${ca.sev}`;
        d.textContent = ca.label;
        caDiv.appendChild(d);
      }
      wrap.appendChild(caDiv);
    }

    // OLE Streams (clickable for analysis)
    if (analysis.streams.length) {
      const stH = document.createElement('div'); stH.className = 'hta-section-hdr';
      stH.textContent = `OLE Streams (${analysis.streams.length})`;
      wrap.appendChild(stH);

      const stTbl = document.createElement('table'); stTbl.className = 'lnk-info-table';
      // Header
      const hdr = document.createElement('tr');
      for (const h of ['Stream Name', 'Size', 'Action']) {
        const th = document.createElement('td'); th.className = 'lnk-lbl';
        th.style.cssText = 'font-weight:bold;'; th.textContent = h;
        hdr.appendChild(th);
      }
      stTbl.appendChild(hdr);

      for (const s of analysis.streams) {
        const tr = document.createElement('tr');
        tr.classList.add('zip-row-clickable');

        const tdN = document.createElement('td'); tdN.className = 'lnk-val';
        tdN.textContent = s.name;
        tdN.style.cssText = 'font-family:monospace;font-size:12px;';

        const tdS = document.createElement('td'); tdS.className = 'lnk-val';
        tdS.textContent = this._fmtBytes(s.size);
        tdS.style.cssText = 'min-width:80px;';

        const tdAction = document.createElement('td'); tdAction.className = 'lnk-val';
        if (s.size > 0) {
          const openBtn = document.createElement('span'); openBtn.className = 'zip-badge-open';
          openBtn.textContent = '🔍 Open';
          openBtn.title = `Open ${s.name} for analysis`;
          openBtn.addEventListener('click', (ev) => {
            ev.stopPropagation();
            this._extractAndOpenStream(s.rawName, s.name, s.size, wrap);
          });
          tdAction.appendChild(openBtn);
        }

        tr.appendChild(tdN); tr.appendChild(tdS); tr.appendChild(tdAction);
        stTbl.appendChild(tr);
      }
      wrap.appendChild(stTbl);
    }

    return wrap;
  }

  /**
   * Render a simplified view for very large MSI files (>50MB)
   */
  _renderLargeFileView(wrap, bytes, fileName) {
    const infoDiv = document.createElement('div'); infoDiv.className = 'plaintext-info';
    infoDiv.textContent = `${this._fmtBytes(bytes.length)}  ·  Windows Installer Package  ·  Large file mode`;
    wrap.appendChild(infoDiv);

    const noteDiv = document.createElement('div');
    noteDiv.className = 'zip-warning zip-warning-info';
    noteDiv.style.cssText = 'margin:8px;';
    noteDiv.textContent = 'Large MSI file — showing summary information only for performance.';
    wrap.appendChild(noteDiv);

    // Try to extract just the Summary Information
    try {
      const ole = new OleCfbParser(bytes.buffer).parseMetadataOnly();
      const summaryInfo = this._extractSummaryInfoLazy(ole);

      if (summaryInfo && Object.keys(summaryInfo).length) {
        const siH = document.createElement('div'); siH.className = 'hta-section-hdr';
        siH.textContent = 'Summary Information';
        wrap.appendChild(siH);

        const tbl = document.createElement('table'); tbl.className = 'lnk-info-table';
        for (const [key, val] of Object.entries(summaryInfo)) {
          const tr = document.createElement('tr');
          const tdL = document.createElement('td'); tdL.className = 'lnk-lbl'; tdL.textContent = key;
          const tdV = document.createElement('td'); tdV.className = 'lnk-val'; tdV.textContent = val;
          tr.appendChild(tdL); tr.appendChild(tdV); tbl.appendChild(tr);
        }
        wrap.appendChild(tbl);
      }

      // Show stream count and list table names only
      const streamCount = ole.streamMeta.size;
      const tables = [];
      for (const [name] of ole.streamMeta) {
        const tableName = this._decodeMsiTableName(name);
        if (tableName) tables.push({ name: tableName, isSuspicious: this._isSuspiciousTable(tableName) });
      }

      if (streamCount > 0) {
        const countDiv = document.createElement('div'); countDiv.className = 'plaintext-info';
        countDiv.style.cssText = 'margin-top:8px;';
        countDiv.textContent = `Contains ${streamCount} OLE stream(s), ${tables.length} MSI table(s)`;
        wrap.appendChild(countDiv);
      }

      // Show suspicious tables if any
      const suspicious = tables.filter(t => t.isSuspicious);
      if (suspicious.length) {
        const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
        for (const t of suspicious) {
          const d = document.createElement('div');
          d.className = 'zip-warning zip-warning-medium';
          d.textContent = `⚠ Contains ${t.name} table`;
          warnDiv.appendChild(d);
        }
        wrap.appendChild(warnDiv);
      }

    } catch (e) {
      const err = document.createElement('div'); err.className = 'error-box';
      err.textContent = `Could not extract metadata: ${e.message}`;
      wrap.appendChild(err);
    }

    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'medium', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    f.externalRefs.push({
      type: IOC.INFO,
      url: 'Windows Installer Package (.msi) — executes with elevated privileges during installation',
      severity: 'high'
    });

    try {
      // Use metadata-only parsing for security analysis too
      const ole = new OleCfbParser(bytes.buffer).parseMetadataOnly();

      // Extract summary info (loads one small stream)
      const summaryInfo = this._extractSummaryInfoLazy(ole);
      f.metadata = summaryInfo || {};

      // Identify tables from stream names
      const tables = [];
      for (const [name] of ole.streamMeta) {
        const tableName = this._decodeMsiTableName(name);
        if (tableName) tables.push(tableName);
      }

      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${ole.streamMeta.size} OLE stream(s), ${tables.length} MSI table(s)`,
        severity: 'info'
      });

      // Check for dangerous tables
      const hasCustomAction = tables.includes('CustomAction');
      const hasBinary = tables.includes('Binary');
      const hasServiceInstall = tables.includes('ServiceInstall');
      const hasRegistry = tables.includes('Registry');

      if (hasCustomAction) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'CustomAction table present — installer can execute arbitrary code',
          severity: 'high'
        });
        f.risk = 'high';
      }

      if (hasBinary) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'Binary table present — contains embedded executables, DLLs, or scripts',
          severity: 'medium'
        });
      }

      if (hasServiceInstall) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'ServiceInstall table — MSI will install Windows service(s)',
          severity: 'high'
        });
        if (f.risk !== 'critical') f.risk = 'high';
      }

      if (hasRegistry) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'Registry table — MSI modifies Windows registry',
          severity: 'medium'
        });
      }

      // Escalate to high if multiple concerning tables
      const concernCount = [hasCustomAction, hasBinary, hasServiceInstall].filter(Boolean).length;
      if (concernCount >= 2 && f.risk !== 'critical') {
        f.risk = 'high';
      }

    } catch (e) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `MSI parse error: ${e.message}`,
        severity: 'info'
      });
    }

    return f;
  }

  // ── MSI analysis (lightweight, metadata-only) ────────────────────────────

  _analyze(bytes) {
    const result = {
      streams: [],
      tables: [],
      summaryInfo: {},
      warnings: [],
      customActions: [],
    };

    // Parse OLE structure in metadata-only mode (no stream content loading)
    const ole = new OleCfbParser(bytes.buffer).parseMetadataOnly();
    // Store OLE parser for on-demand stream extraction when user clicks
    this._ole = ole;

    // Enumerate streams (metadata only - name and size, decoded + raw for extraction)
    for (const [name, meta] of ole.streamMeta) {
      result.streams.push({
        name: this._decodeMsiStreamName(name),  // Decoded display name
        rawName: name,                           // Raw name for getStream() lookup
        size: meta.size
      });
    }

    // Identify MSI database tables from stream names
    for (const [name] of ole.streamMeta) {
      const tableName = this._decodeMsiTableName(name);
      if (tableName) {
        const isSuspicious = this._isSuspiciousTable(tableName);
        result.tables.push({ name: tableName, isSuspicious });

        if (isSuspicious) {
          result.warnings.push({
            label: `Suspicious MSI table: ${tableName}`,
            sev: 'medium'
          });
        }
      }
    }

    // Detect CustomAction table presence
    if (result.tables.some(t => t.name === 'CustomAction')) {
      result.customActions.push({
        label: 'CustomAction table present — installer can execute arbitrary code',
        sev: 'high'
      });
    }

    // Detect Binary table
    if (result.tables.some(t => t.name === 'Binary')) {
      result.customActions.push({
        label: 'Binary table present — contains embedded executables, DLLs, or scripts',
        sev: 'medium'
      });
    }

    // Check for specific dangerous tables
    if (result.tables.some(t => t.name === 'ServiceInstall')) {
      result.warnings.push({
        label: 'Service installation: MSI will install Windows service(s)',
        sev: 'high'
      });
    }
    if (result.tables.some(t => t.name === 'ServiceControl')) {
      result.warnings.push({
        label: 'Service control: MSI modifies Windows service state',
        sev: 'medium'
      });
    }
    if (result.tables.some(t => t.name === 'Registry')) {
      result.warnings.push({
        label: 'Registry modification: MSI writes to Windows registry',
        sev: 'medium'
      });
    }
    if (result.tables.some(t => t.name === 'LaunchCondition')) {
      result.warnings.push({
        label: 'Launch conditions: MSI checks system conditions before install',
        sev: 'info'
      });
    }
    if (result.tables.some(t => t.name === 'AppSearch')) {
      result.warnings.push({
        label: 'Application search: MSI searches for installed applications',
        sev: 'info'
      });
    }

    // Extract Summary Information (loads one small stream on demand)
    result.summaryInfo = this._extractSummaryInfoLazy(ole) || {};

    // Deduplicate warnings
    const seen = new Set();
    result.warnings = result.warnings.filter(w => {
      if (seen.has(w.label)) return false;
      seen.add(w.label); return true;
    });

    return result;
  }

  // ── MSI stream name decoding ──────────────────────────────────────────────
  // MSI encodes stream names using a base-64-like scheme:
  // - 0x4840 = start marker (skip)
  // - 0x3800-0x383F = single character (base-64 digit)
  // - 0x3840-0x483F = two characters (high = val/64, low = val%64)
  // Base-64 mapping: 0-9=0-9, A-Z=10-35, a-z=36-61, _=62, .=63

  _decodeMsiStreamName(encoded) {
    let result = '';
    const decodeDigit = (val) => {
      if (val < 10) return String.fromCharCode(0x30 + val);        // 0-9
      if (val < 36) return String.fromCharCode(0x41 + val - 10);   // A-Z
      if (val < 62) return String.fromCharCode(0x61 + val - 36);   // a-z
      if (val === 62) return '_';
      if (val === 63) return '.';
      return '?';
    };

    for (const c of encoded) {
      const code = c.charCodeAt(0);
      if (code === 0x4840) continue; // Skip start marker

      if (code >= 0x3800 && code < 0x3840) {
        // Single character encoding
        result += decodeDigit(code - 0x3800);
      } else if (code >= 0x3840 && code < 0x4840) {
        // Two-character encoding
        const val = code - 0x3840;
        result += decodeDigit(Math.floor(val / 64));
        result += decodeDigit(val % 64);
      } else {
        // Pass through other characters (e.g., regular ASCII)
        result += c;
      }
    }
    return result;
  }

  _decodeMsiTableName(streamName) {
    // Skip known non-table streams (check original name before decoding)
    const lowerName = streamName.toLowerCase();
    const skip = [
      '\x05summaryinformation', '\x05documentsummaryinformation',
      '\x01comptobj', '\x05digital signature',
    ];
    if (skip.includes(lowerName)) return null;
    if (streamName.charAt(0) === '\x05' || streamName.charAt(0) === '\x01') return null;

    // Decode MSI-encoded stream name
    const decoded = this._decodeMsiStreamName(streamName);
    if (!decoded) return null;

    // Known MSI table names (for proper casing in output)
    const knownTables = [
      'ActionText', 'AdminExecuteSequence', 'AdminUISequence', 'AdvtExecuteSequence',
      'AdvtUISequence', 'AppId', 'AppSearch', 'BBControl', 'Billboard', 'Binary',
      'BindImage', 'CCPSearch', 'CheckBox', 'Class', 'ComboBox', 'CompLocator',
      'Complus', 'Component', 'Condition', 'Control', 'ControlCondition',
      'ControlEvent', 'CreateFolder', 'CustomAction', 'Dialog', 'Directory',
      'DrLocator', 'DuplicateFile', 'Environment', 'Error', 'EventMapping',
      'Extension', 'Feature', 'FeatureComponents', 'File', 'FileSFPCatalog',
      'Font', 'Icon', 'IniFile', 'IniLocator', 'InstallExecuteSequence',
      'InstallUISequence', 'IsolatedComponent', 'LaunchCondition', 'ListBox',
      'ListView', 'LockPermissions', 'Media', 'MIME', 'MoveFile',
      'MsiAssembly', 'MsiAssemblyName', 'MsiDigitalCertificate',
      'MsiDigitalSignature', 'MsiEmbeddedChainer', 'MsiEmbeddedUI',
      'MsiFileHash', 'MsiLockPermissionsEx', 'MsiPackageCertificate',
      'MsiPatchCertificate', 'MsiPatchHeaders', 'MsiPatchMetadata',
      'MsiPatchOldAssemblyFile', 'MsiPatchOldAssemblyName',
      'MsiPatchSequence', 'MsiServiceConfig', 'MsiServiceConfigFailureActions',
      'MsiShortcutProperty', 'ODBCAttribute', 'ODBCDataSource', 'ODBCDriver',
      'ODBCSourceAttribute', 'ODBCTranslator', 'Patch', 'PatchPackage',
      'ProgId', 'Property', 'PublishComponent', 'RadioButton', 'Registry',
      'RegLocator', 'RemoveFile', 'RemoveIniFile', 'RemoveRegistry',
      'ReserveCost', 'SelfReg', 'ServiceControl', 'ServiceInstall',
      'SFPCatalog', 'Shortcut', 'Signature', 'TextStyle', 'TypeLib',
      'UIText', 'Upgrade', 'Verb', '_Validation', '_Columns', '_Tables',
      '_StringData', '_StringPool',
    ];

    // Check against known tables (case-insensitive) and return proper casing
    const lowerDecoded = decoded.toLowerCase();
    for (const tableName of knownTables) {
      if (tableName.toLowerCase() === lowerDecoded) return tableName;
    }

    // Check if it looks like a valid MSI identifier (alphanumeric + underscore)
    if (/^[A-Za-z_][A-Za-z0-9_.]*$/.test(decoded) && decoded.length <= 64) {
      return decoded;
    }

    return null;
  }

  _isSuspiciousTable(tableName) {
    const suspicious = [
      'CustomAction', 'Binary', 'ServiceInstall', 'ServiceControl',
      'Registry', 'RemoveRegistry', 'Environment', 'SelfReg',
      'MsiEmbeddedChainer', 'MsiEmbeddedUI',
    ];
    return suspicious.includes(tableName);
  }

  // ── Summary Information extraction (lazy loading) ────────────────────────

  _extractSummaryInfoLazy(ole) {
    // Load Summary Information stream on demand
    const siStream = ole.getStream('\x05summaryinformation') || ole.getStream('\u0005summaryinformation');
    if (!siStream || siStream.length < 48) return null;

    return this._parseSummaryInfo(siStream);
  }

  _parseSummaryInfo(siStream) {
    const result = {};

    try {
      const dv = new DataView(siStream.buffer, siStream.byteOffset, siStream.byteLength);

      // Property Set Header
      const numSets = dv.getUint32(24, true);
      if (numSets < 1) return result;

      // First property set offset
      const setOffset = dv.getUint32(44, true);
      if (setOffset >= siStream.length) return result;

      const numProps = dv.getUint32(setOffset + 4, true);

      const propNames = {
        2: 'Title', 3: 'Subject', 4: 'Author', 5: 'Keywords',
        6: 'Comments', 7: 'Template', 8: 'Last Author',
        9: 'Revision Number', 12: 'Create Time', 13: 'Last Save Time',
        14: 'Page Count', 15: 'Word Count', 16: 'Character Count',
        18: 'Application', 19: 'Security',
      };

      for (let i = 0; i < Math.min(numProps, 30); i++) {
        const pidOff = setOffset + 8 + i * 8;
        if (pidOff + 8 > siStream.length) break;

        const pid = dv.getUint32(pidOff, true);
        const valOff = setOffset + dv.getUint32(pidOff + 4, true);
        if (valOff + 4 > siStream.length) continue;

        const propName = propNames[pid];
        if (!propName) continue;

        const vType = dv.getUint32(valOff, true);

        if (vType === 30) { // VT_LPSTR
          const len = dv.getUint32(valOff + 4, true);
          if (valOff + 8 + len <= siStream.length) {
            const str = new TextDecoder('utf-8', { fatal: false })
              .decode(siStream.subarray(valOff + 8, valOff + 8 + len - 1));
            if (str.trim()) result[propName] = str.trim();
          }
        } else if (vType === 3) { // VT_I4
          result[propName] = dv.getInt32(valOff + 4, true).toString();
        } else if (vType === 64) { // VT_FILETIME
          try {
            const lo = dv.getUint32(valOff + 4, true);
            const hi = dv.getUint32(valOff + 8, true);
            const ft = (BigInt(hi) << 32n) | BigInt(lo);
            const ms = Number(ft / 10000n) - 11644473600000;
            if (ms > 0 && ms < 4102444800000) {
              result[propName] = new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
            }
          } catch (e) { }
        }
      }
    } catch (e) {
      // Silently fail — summary info is optional
    }

    return result;
  }

  // ── Stream extraction for click-to-open ───────────────────────────────────

  _extractAndOpenStream(rawName, displayName, size, wrap) {
    if (!this._ole) {
      console.warn('OLE parser not available for stream extraction');
      return;
    }

    try {
      // Get stream content from OLE parser (on-demand loading)
      const data = this._ole.getStream(rawName);
      if (!data || data.length === 0) {
        console.warn('Stream empty or not found:', rawName);
        return;
      }

      // Create a File object with the stream content
      // Use displayName for the filename (decoded MSI name)
      const file = new File([data], displayName, { type: 'application/octet-stream' });

      // Dispatch custom event for the app to handle (same pattern as ZIP renderer)
      wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
    } catch (e) {
      console.warn('Failed to extract stream:', rawName, e.message);
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
