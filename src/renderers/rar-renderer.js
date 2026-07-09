'use strict';
// ════════════════════════════════════════════════════════════════════════════
// rar-renderer.js — RAR archive analyser
//
// Parses both RAR v4 ("Rar!\x1A\x07\x00") and RAR v5 ("Rar!\x1A\x07\x01\x00")
// headers to enumerate file entries, their sizes, timestamps, and the
// compression / encryption flags.
//
// Store (uncompressed) entries are extractable for drill-down when not
// encrypted. Compressed entries (proprietary LZSS/PPMd) remain listing-only
// because no small pure-JS decoder is shipped.
//
// The listing still surfaces exec/script classifications, encrypted-header
// detection, solid/multi-volume flags, etc. A banner explains the limits.
//
// Emits the usual archive signals (exec/script/HTA/LNK content, double
// extensions, nested archives, path-traversal patterns, encrypted
// headers, solid / multi-volume flags).
//
// Depends on: constants.js (IOC, PARSER_LIMITS, fmtBytes,
//             pushIOC), ArchiveTree (archive-tree.js)
// ════════════════════════════════════════════════════════════════════════════
class RarRenderer {

  // Delegates to the shared `ArchiveAnalysis` helper so ZIP / RAR / 7z /
  // CAB all agree on the classifier set. The alias keeps legacy
  // `RarRenderer.EXEC_EXTS.has(...)` call sites working unchanged.
  static EXEC_EXTS = ArchiveAnalysis.EXEC_EXTS;
  static DECOY_EXTS = ArchiveAnalysis.DECOY_EXTS;

  // ── Render ────────────────────────────────────────────────────────────

  async render(buffer, fileName) {
    const wrap = document.createElement('div');
    wrap.className = 'zip-view';
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>RAR Archive</strong> — Loupe lists contents and extracts <em>store</em> (uncompressed) entries for drill-down. Compressed entries (LZSS/PPMd) remain listing-only because the algorithms are proprietary.';
    wrap.appendChild(banner);

    let parsed;
    try {
      parsed = this._parse(bytes);
    } catch (e) {
      const err = document.createElement('div');
      err.style.cssText = 'padding:12px 20px;color:var(--risk-high);';
      err.textContent = `⚠ Failed to parse RAR archive: ${e.message}`;
      wrap.appendChild(err);
      return wrap;
    }

    this._parsed = parsed;

    // Summary chip
    const files = parsed.files.length;
    const totalSize = parsed.files.reduce((s, e) => s + (e.size || 0), 0);
    const totalPacked = parsed.files.reduce((s, e) => s + (e.packedSize || 0), 0);
    const summ = document.createElement('div');
    summ.className = 'zip-summary';
    const bits = [`RAR ${parsed.version}`];
    if (parsed.solid) bits.push('<span style="color:var(--risk-med)">solid</span>');
    if (parsed.encryptedHeaders) bits.push('<span style="color:var(--risk-high)">encrypted headers</span>');
    if (parsed.multiVolume) bits.push('<span style="color:var(--risk-med)">multi-volume</span>');
    if (parsed.recoveryRecord) bits.push('recovery record');
    summ.innerHTML = `${files} file${files !== 1 ? 's' : ''} — ${fmtBytes(totalSize)} uncompressed` +
      (totalPacked ? ` / ${fmtBytes(totalPacked)} packed` : '') +
      ` · ${bits.join(' · ')}`;
    wrap.appendChild(summ);

    // Per-archive warnings
    const warnings = this._checkWarnings(parsed);
    if (warnings.length) {
      const warnDiv = document.createElement('div');
      warnDiv.className = 'zip-warnings';
      for (const w of warnings) {
        const d = document.createElement('div');
        d.className = `zip-warning zip-warning-${w.sev}`;
        d.textContent = w.msg;
        warnDiv.appendChild(d);
      }
      wrap.appendChild(warnDiv);
    }

    // File browser. Store (uncompressed) entries carry `data` (or a slice ref)
    // so _maybeOpenRarEntry can turn them into real drill-down Files.
    // Compressed or encrypted entries stay locked (encrypted:true or no data).
    const archEntries = parsed.files.map(f => {
      const e = {
        path: f.path,
        dir: !!f.isDir,
        size: f.size,
        compressedSize: f.packedSize,
        date: f.date || null,
        encrypted: !!f.encrypted,
        _rarRef: f,
      };
      if (f.data) e.data = f.data;
      return e;
    });

    const tree = ArchiveTree.render({
      entries: archEntries,
      onOpen: (entry) => this._maybeOpenRarEntry(entry, wrap),
      execExts: RarRenderer.EXEC_EXTS,
      decoyExts: RarRenderer.DECOY_EXTS,
      showCompressed: true,
      showDate: true,
      expandAll: 'auto',
    });
    wrap.appendChild(tree);

    return wrap;
  }

  // ── Parsing ───────────────────────────────────────────────────────────

  _parse(bytes) {
    if (bytes.length < 8) throw new Error('Buffer too small for RAR header');
    if (bytes[0] !== 0x52 || bytes[1] !== 0x61 || bytes[2] !== 0x72 || bytes[3] !== 0x21
      || bytes[4] !== 0x1A || bytes[5] !== 0x07) {
      throw new Error('RAR signature missing');
    }
    // Byte 6: 0x00 = RAR 1.5 – 4.x ; 0x01 = RAR 5.x (followed by 0x00).
    if (bytes[6] === 0x00) {
      return this._parseV4(bytes);
    } else if (bytes[6] === 0x01) {
      if (bytes[7] !== 0x00) throw new Error('Malformed RAR5 signature');
      return this._parseV5(bytes);
    } else {
      throw new Error(`Unknown RAR variant byte 0x${bytes[6].toString(16)}`);
    }
  }

  // ── RAR4 parser ───────────────────────────────────────────────────────
  //
  // RAR4 block layout:
  //   HEAD_CRC   u16
  //   HEAD_TYPE  u8   (0x73 main, 0x74 file, 0x7A newsub, 0x7B end, …)
  //   HEAD_FLAGS u16
  //   HEAD_SIZE  u16
  //   [ADD_SIZE  u32] — present if flags & 0x8000 (LHD_LONG_BLOCK)
  //   … type-specific body …
  //
  // For FILE blocks the body carries packed/unpacked sizes, name length,
  // file attributes, and the filename. We walk until we hit HEAD_TYPE
  // 0x7B (end-of-archive) or run out of buffer.
  _parseV4(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let off = 7; // skip the 7-byte marker block
    const files = [];
    let solid = false;
    let multiVolume = false;
    let encryptedHeaders = false;
    let recoveryRecord = false;
    let passedMainHeader = false;
    // H5: aggregate archive-expansion budget shared across the recursive
    // drill-down chain (top-level ZIP → JAR → MSIX → 7z → RAR…). When
    // exhausted, we stop appending entries and surface the cap upstream.
    const aggBudget = (typeof window !== 'undefined' && window.app)
      ? window.app._archiveBudget
      : null;
    let aggExhausted = false;


    const MAX_BLOCKS = PARSER_LIMITS.MAX_ENTRIES * 2;
    for (let iter = 0; iter < MAX_BLOCKS; iter++) {
      if (off + 7 > bytes.length) break;
      const _headCrc = dv.getUint16(off, true);
      const headType = bytes[off + 2];
      const headFlags = dv.getUint16(off + 3, true);
      const headSize = dv.getUint16(off + 5, true);
      if (headSize < 7) break; // malformed
      let addSize = 0;
      // Body begins immediately after the 7-byte header prefix. For FILE_HEAD
      // blocks the generic ADD_SIZE field and the body's first field PACK_SIZE
      // occupy the SAME 4 bytes at off+7 (see unrar TechInfo.txt §3.3 "File
      // header" — PACK_SIZE is ADD_SIZE for FILE blocks). Advancing bodyOff
      // to off+11 would shift every subsequent read by 4 bytes and make
      // NAME_SIZE land on garbage, silently truncating the listing.
      const bodyOff = off + 7;
      if (headFlags & 0x8000) {
        if (off + 11 > bytes.length) break;
        addSize = dv.getUint32(off + 7, true); // used only for blockEnd math below
      }
      const blockEnd = off + headSize + addSize;
      if (blockEnd > bytes.length || headSize > 0x10000) break;

      if (headType === 0x73) {
        // MAIN_HEAD
        passedMainHeader = true;
        if (headFlags & 0x0001) multiVolume = true;    // MHD_VOLUME
        if (headFlags & 0x0008) solid = true;          // MHD_SOLID
        if (headFlags & 0x0080) encryptedHeaders = true; // MHD_PASSWORD (headers+data)
        if (headFlags & 0x0002) ; // MHD_COMMENT
        // RR flag (recovery record) is 0x0040 on older versions.
        if (headFlags & 0x0040) recoveryRecord = true;
      } else if (headType === 0x74) {
        // FILE_HEAD — bodyOff points at the file-header body.
        //   u32 PACK_SIZE     — already the low 32 bits of add_size usually
        //   u32 UNP_SIZE
        //   u8  HOST_OS
        //   u32 FILE_CRC
        //   u32 FTIME (DOS)
        //   u8  UNP_VER
        //   u8  METHOD
        //   u16 NAME_SIZE
        //   u32 ATTR
        //   [u32 HIGH_PACK_SIZE] if LHD_LARGE (0x0100)
        //   [u32 HIGH_UNP_SIZE ] if LHD_LARGE
        //   name[NAME_SIZE]
        //   [SALT (8 bytes)] if LHD_SALT (0x0400)
        //   [EXT_TIME] if LHD_EXTTIME (0x1000)
        if (bodyOff + 25 > bytes.length) break;
        let bp = bodyOff;
        let packSize = dv.getUint32(bp, true); bp += 4;
        let unpSize  = dv.getUint32(bp, true); bp += 4;
        const hostOs   = bytes[bp]; bp += 1;
        /* const fileCrc  = */ dv.getUint32(bp, true); bp += 4;
        const ftime    = dv.getUint32(bp, true); bp += 4;
        /* const unpVer = */ bytes[bp]; bp += 1;
        const method   = bytes[bp]; bp += 1;
        const nameSize = dv.getUint16(bp, true); bp += 2;
        const attr     = dv.getUint32(bp, true); bp += 4;
        if (headFlags & 0x0100) { // LHD_LARGE
          if (bp + 8 > bytes.length) break;
          const highPack = dv.getUint32(bp, true); bp += 4;
          const highUnp  = dv.getUint32(bp, true); bp += 4;
          packSize += highPack * 0x100000000;
          unpSize  += highUnp  * 0x100000000;
        }
        if (bp + nameSize > bytes.length) break;
        const nameBytes = bytes.subarray(bp, bp + nameSize);
        let name;
        if (headFlags & 0x0200) { // LHD_UNICODE — dual ASCII/Unicode encoding
          const nul = nameBytes.indexOf(0);
          if (nul >= 0) {
            name = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes.subarray(0, nul));
            // Remainder is a compressed Unicode table; fall back to ASCII head.
          } else {
            name = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes);
          }
        } else {
          name = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes);
        }
        const path = name.replace(/\\/g, '/');
        const encrypted = !!(headFlags & 0x0004); // LHD_PASSWORD
        // RAR4 LHD_DIRECTORY is flags & 0xE0 === 0xE0 (equality, not
        // "any bit set in the mask" — the lower dictionary-size bits
        // share 0xE0). The Windows DIR attribute is platform-specific
        // so we accept either signal.
        const isDir = ((headFlags & 0xE0) === 0xE0) && !!(attr & 0x10);
        // Fallback for RAR4 dirs on non-Windows hosts: METHOD=0x30
        // (stored) + size=0 + DIR attribute bit.
        const dir2 = (method === 0x30 && unpSize === 0 && !!(attr & 0x10));
        const date = this._dosDate(ftime);
        if (encrypted) encryptedHeaders = encryptedHeaders || encrypted;
        // H5: gate the push against the shared aggregate budget. The
        // per-archive `MAX_ENTRIES` cap below still fires for a single
        // pathological RAR; this consult fires when the *recursion*
        // through nested archives has already burned through the
        // shared budget.
        if (aggBudget && !aggBudget.consume(1, unpSize | 0)) {
          aggExhausted = true;
          break;
        }
        const fileObj = {
          path,
          size: unpSize,
          packedSize: packSize,
          date,
          method,
          attr,
          hostOs,
          encrypted,
          isDir: dir2 || isDir,
          headFlags,
        };
        // Store-method (0x30) candidates record their payload offset; solid
        // archives defer slicing until we know which entry ends the block.
        if (method === 0x30 && !encrypted && !(dir2 || isDir) && packSize > 0) {
          fileObj.dataStart = off + headSize;
        }
        files.push(fileObj);
        if (files.length >= PARSER_LIMITS.MAX_ENTRIES) break;

      } else if (headType === 0x7B) {
        // END_ARC
        break;
      } else if (!passedMainHeader && headType !== 0x72) {
        // Something is wrong — expected MAIN before FILE.
        // (0x72 is MARK_HEAD which we already skipped via the offset.)
      }

      off = blockEnd;
      if (off <= 0 || off > bytes.length) break;
    }

    this._attachRar4StorePayloads(files, bytes, solid);

    return {
      version: '4',
      solid, multiVolume, encryptedHeaders, recoveryRecord,
      files,
      aggExhausted,
      aggReason: aggExhausted && aggBudget ? aggBudget.reason : '',
    };
  }


  // ── RAR5 parser ───────────────────────────────────────────────────────
  //
  // RAR5 uses vuint-encoded fields throughout. Each block:
  //   vuint header_crc32
  //   vuint header_size          — size of the rest of the header
  //   vuint header_type          — 1=main, 2=file, 3=service, 4=encryption, 5=end
  //   vuint header_flags
  //   [vuint extra_area_size]    — if flags & 0x0001
  //   [vuint data_size]          — if flags & 0x0002
  //   … type-specific body …
  //   [extra_area ...]
  //   [data ...]
  _parseV5(bytes) {
    let off = 8; // skip 8-byte RAR5 signature
    const files = [];
    let solid = false;
    let multiVolume = false;
    let encryptedHeaders = false;
    let recoveryRecord = false;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // H5: aggregate archive-expansion budget — see `_parseV4` for context.
    const aggBudget = (typeof window !== 'undefined' && window.app)
      ? window.app._archiveBudget
      : null;
    let aggExhausted = false;


    const readVuint = (p) => {
      let shift = 0, result = 0, count = 0;
      while (p < bytes.length && count < 10) {
        const b = bytes[p++];
        result += (b & 0x7F) * Math.pow(2, shift);
        if ((b & 0x80) === 0) return { value: result, pos: p };
        shift += 7;
        count++;
      }
      return { value: result, pos: p };
    };

    const MAX_BLOCKS = PARSER_LIMITS.MAX_ENTRIES * 2;
    for (let iter = 0; iter < MAX_BLOCKS; iter++) {
      if (off + 7 > bytes.length) break;
      // header_crc32 (4 raw bytes)
      off += 4;
      let v = readVuint(off); const headerSize = v.value; off = v.pos;
      const headerStart = off;
      if (headerSize === 0 || off + headerSize > bytes.length) break;
      v = readVuint(off); const headerType = v.value; off = v.pos;
      v = readVuint(off); const headerFlags = v.value; off = v.pos;
      // RAR5 header flags 0x0001 / 0x0002 carry extra-area-size and
      // data-size vuints that we read structurally to advance `off`
      // but don't otherwise use here.
      let dataSize = 0;
      if (headerFlags & 0x0001) { v = readVuint(off); off = v.pos; }
      if (headerFlags & 0x0002) { v = readVuint(off); dataSize = v.value; off = v.pos; }

      if (headerType === 1) {
        // Main archive header.
        //   vuint archive_flags
        //   [vuint volume_number] if flags & 0x0002
        v = readVuint(off); const archFlags = v.value; off = v.pos;
        if (archFlags & 0x0001) multiVolume = true;
        if (archFlags & 0x0004) solid = true;
        if (archFlags & 0x0008) recoveryRecord = true;
      } else if (headerType === 4) {
        // Encryption header — all subsequent headers are encrypted.
        encryptedHeaders = true;
      } else if (headerType === 2 || headerType === 3) {
        // File or service header — both share the same layout. Services
        // carry things like STM (data stream), CMT (comment), RR, QO etc.
        // We surface FILE headers only.
        v = readVuint(off); const fileFlags = v.value; off = v.pos;
        v = readVuint(off); const unpSize    = v.value; off = v.pos;
        v = readVuint(off); /* attributes  */ off = v.pos;
        let mtime = 0;
        if (fileFlags & 0x0002) {
          // mtime present — may be unix (flags & 0x0001 of compression_info? no,
          // that's controlled by its own flag in common layout. RAR5 uses
          // flag 0x0002 for presence, and a separate "unix time" toggle at
          // the field level which is normally on in modern RAR). We'll just
          // treat it as a unix timestamp; if it looks nonsensical, discard.
          if (off + 4 > bytes.length) break;
          mtime = dv.getUint32(off, true);
          off += 4;
        }
        if (fileFlags & 0x0004) off += 4; // CRC32 present
        v = readVuint(off); const compressionInfo = v.value; off = v.pos;
        v = readVuint(off); /* host OS        */ off = v.pos;
        v = readVuint(off); const nameLength = v.value; off = v.pos;
        if (off + nameLength > bytes.length) break;
        const name = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(off, off + nameLength));
        off += nameLength;

        const headerEnd = headerStart + headerSize;
        const extraStart = off;
        const extraEnd = headerEnd;
        let fileEncrypted = encryptedHeaders || !!(fileFlags & 0x0004);
        if (extraEnd > extraStart) {
          fileEncrypted = fileEncrypted || RarRenderer._rar5ExtraHasCrypt(bytes, extraStart, extraEnd, readVuint);
        }

        if (headerType === 2) {
          // Actual file entry
          const path = name.replace(/\\/g, '/');
          const isDir = !!(fileFlags & 0x0001);
          let date = null;
          if (mtime) {
            const t = new Date(mtime * 1000);
            if (!isNaN(t.getTime()) && t.getFullYear() > 1980 && t.getFullYear() < 2200) date = t;
          }
          // H5: shared aggregate budget consult before push (see _parseV4).
          if (aggBudget && !aggBudget.consume(1, unpSize | 0)) {
            aggExhausted = true;
            break;
          }
          const fileRec = {
            path,
            size: unpSize,
            packedSize: dataSize,
            date,
            isDir,
            encrypted: fileEncrypted,
            compressionInfo,
            dataSize,
          };
          // Store (algorithm 0) candidates record payload offset; solid blocks
          // and encryption are resolved in _attachRar5StorePayloads.
          if ((compressionInfo & 0x7) === 0 && !fileEncrypted && !isDir && dataSize > 0 && dataSize === unpSize) {
            fileRec.dataStart = headerEnd;
          }
          files.push(fileRec);
          if (files.length >= PARSER_LIMITS.MAX_ENTRIES) break;
        }

      } else if (headerType === 5) {
        // End of archive
        break;
      }

      // Advance past the rest of the header + data payload.
      off = headerStart + headerSize + dataSize;
      if (off <= 0 || off > bytes.length) break;
    }

    this._attachRar5StorePayloads(files, bytes, solid);

    return {
      version: '5',
      solid, multiVolume, encryptedHeaders, recoveryRecord,
      files,
      aggExhausted,
      aggReason: aggExhausted && aggBudget ? aggBudget.reason : '',
    };
  }


  // ── Helpers ───────────────────────────────────────────────────────────

  _attachRar4StorePayloads(files, bytes, solid) {
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      if (f.dataStart == null || f.method !== 0x30 || f.encrypted || f.isDir || !f.packedSize) {
        delete f.headFlags;
        delete f.dataStart;
        continue;
      }
      if (solid) {
        const nextContinuesSolid = i + 1 < files.length && !!(files[i + 1].headFlags & 0x0010);
        if (nextContinuesSolid) {
          delete f.headFlags;
          delete f.dataStart;
          continue;
        }
      }
      const dataStart = f.dataStart;
      const packSize = f.packedSize;
      if (dataStart + packSize > bytes.length) {
        delete f.headFlags;
        delete f.dataStart;
        continue;
      }
      f.data = bytes.subarray(dataStart, dataStart + packSize);
      delete f.headFlags;
      delete f.dataStart;
    }
  }

  _attachRar5StorePayloads(files, bytes, solid) {
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      if (f.dataStart == null || f.encrypted || f.isDir || !f.dataSize) {
        delete f.compressionInfo;
        delete f.dataStart;
        delete f.dataSize;
        continue;
      }
      if ((f.compressionInfo & 0x7) !== 0 || f.dataSize !== f.size) {
        delete f.compressionInfo;
        delete f.dataStart;
        delete f.dataSize;
        continue;
      }
      if (solid) {
        const nextContinuesSolid = i + 1 < files.length && !!(files[i + 1].compressionInfo & 0x8);
        if (nextContinuesSolid) {
          delete f.compressionInfo;
          delete f.dataStart;
          delete f.dataSize;
          continue;
        }
      }
      const dataStart = f.dataStart;
      const dataSize = f.dataSize;
      if (dataStart + dataSize > bytes.length) {
        delete f.compressionInfo;
        delete f.dataStart;
        delete f.dataSize;
        continue;
      }
      f.data = bytes.subarray(dataStart, dataStart + dataSize);
      delete f.compressionInfo;
      delete f.dataStart;
      delete f.dataSize;
    }
  }

  static _rar5ExtraHasCrypt(bytes, start, end, readVuint) {
    let p = start;
    while (p < end) {
      const recordStart = p;
      const v = readVuint(p);
      const totalSize = v.value;
      p = v.pos;
      if (totalSize < 1 || recordStart + totalSize > end) break;
      const v2 = readVuint(p);
      if (v2.value === 0x01) return true;
      p = recordStart + totalSize;
    }
    return false;
  }

  _dosDate(ftime) {
    if (!ftime) return null;
    try {
      const dosDate = (ftime >>> 16) & 0xFFFF;
      const dosTime = ftime & 0xFFFF;
      const y = ((dosDate >> 9) & 0x7F) + 1980;
      const mo = ((dosDate >> 5) & 0x0F) || 1;
      const d  = (dosDate & 0x1F) || 1;
      const h  = (dosTime >> 11) & 0x1F;
      const mi = (dosTime >> 5) & 0x3F;
      const s  = (dosTime & 0x1F) * 2;
      const t = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
      if (isNaN(t.getTime())) return null;
      return t;
    } catch (_) { return null; }
  }

  _checkWarnings(parsed) {
    const w = [];
    const files = parsed.files;

    // RAR-specific metadata warnings (unique to this format).
    if (parsed.encryptedHeaders) {
      w.push({ sev: 'high', msg: '🔐 Encrypted archive — file content cannot be inspected; only the listing (if unencrypted) is available' });
    }
    if (parsed.multiVolume) {
      w.push({ sev: 'medium', msg: '📦 Multi-volume archive — this is only one part of a larger set; payload is incomplete on its own' });
    }
    if (parsed.solid) {
      w.push({ sev: 'info', msg: 'ℹ Solid archive — files compressed together as a single stream (common for delivery of coordinated payloads)' });
    }

    // Shared archive-family warnings (executables, double extensions,
    // nested archives, .hta / .lnk, strict Zip-Slip / Tar-Slip). Same
    // helper every archive renderer calls — see src/archive-analysis.js.
    for (const warning of ArchiveAnalysis.buildCommonWarnings(files, { kind: 'archive' })) {
      w.push(warning);
    }

    if (parsed.aggExhausted) {
      w.push({ sev: 'info', msg: `ℹ ${parsed.aggReason || 'Aggregate archive-expansion budget exhausted — listing truncated'}` });
    }

    return w;
  }


  _isDoubleExt(path) {
    return ArchiveAnalysis.isDoubleExt(path);
  }

  // ── Security analysis ─────────────────────────────────────────────────

  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: [],
    };
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    let parsed;
    try { parsed = this._parse(bytes); }
    catch (e) {
      pushIOC(f, { type: IOC.INFO, value: `RAR parse failed: ${e.message}`, severity: 'info', bucket: 'externalRefs' });
      return f;
    }

    f.metadata = {
      'RAR Version': parsed.version,
      'Files': parsed.files.length,
      'Solid': parsed.solid ? 'yes' : 'no',
      'Multi-volume': parsed.multiVolume ? 'yes' : 'no',
      'Encrypted Headers': parsed.encryptedHeaders ? 'yes' : 'no',
      'Recovery Record': parsed.recoveryRecord ? 'yes' : 'no',
    };

    if (parsed.encryptedHeaders) {
      pushIOC(f, {
        type: IOC.PATTERN,
        value: 'RAR archive has encrypted headers — file content cannot be inspected without the password',
        severity: 'high',
        bucket: 'externalRefs',
      });
      escalateRisk(f, 'high');
    }
    if (parsed.multiVolume) {
      pushIOC(f, {
        type: IOC.PATTERN,
        value: 'Multi-volume RAR — this volume is part of a larger set; contents may be incomplete on its own',
        severity: 'medium',
        bucket: 'externalRefs',
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }
    if (parsed.solid) {
      pushIOC(f, {
        type: IOC.INFO,
        value: 'Solid archive — all files compressed together as a single stream (extraction requires sequential decode)',
        severity: 'info',
        bucket: 'externalRefs',
      });
    }

    // Warnings → externalRefs + risk
    const warnings = this._checkWarnings(parsed);
    for (const w of warnings) {
      pushIOC(f, { type: IOC.PATTERN, value: w.msg, severity: w.sev , bucket: 'externalRefs' });
      if (w.sev === 'high') escalateRisk(f, 'high');
      else if (w.sev === 'medium' && f.risk !== 'high') escalateRisk(f, 'medium');
    }

    // H5: surface aggregate-budget exhaustion as a clean IOC.INFO row so
    // sidebar filtering can pick it up without trawling the PATTERN
    // warning blob.
    if (parsed.aggExhausted) {
      pushIOC(f, {
        type: IOC.INFO,
        value: parsed.aggReason || 'Aggregate archive-expansion budget exhausted — listing truncated',
        severity: 'info',
        bucket: 'externalRefs',
      });
    }


    // Surface executable/script paths as FILE_PATH IOCs
    const dangerous = parsed.files.filter(e => !e.isDir && RarRenderer.EXEC_EXTS.has((e.path || '').split('.').pop().toLowerCase()));
    if (dangerous.length) {
      for (const e of dangerous.slice(0, 50)) {
        pushIOC(f, { type: IOC.FILE_PATH, value: e.path, severity: 'high' , bucket: 'externalRefs' });
      }
    }

    // Listing: path IOCs for every file, capped so pathological archives
    // don't flood the sidebar.
    const listingCap = 100;
    const seen = new Set(dangerous.map(e => e.path));
    let surfaced = 0;
    for (const e of parsed.files) {
      if (e.isDir) continue;
      if (seen.has(e.path)) continue;
      if (surfaced >= listingCap) break;
      pushIOC(f, { type: IOC.FILE_PATH, value: e.path, severity: 'info' , bucket: 'externalRefs' });
      surfaced++;
    }
    if (parsed.files.length > listingCap + dangerous.length) {
      pushIOC(f, { type: IOC.INFO, value: `+${parsed.files.length - listingCap - dangerous.length} more file path(s) truncated`, severity: 'info' , bucket: 'externalRefs' });
    }

    return f;
  }

  // Called by ArchiveTree for rows that the tree thinks are openable.
  // If the parsed entry carried raw bytes (store method + not encrypted)
  // we synthesise a File and dispatch open-inner-file exactly like ZIP.
  _maybeOpenRarEntry(entry, wrap) {
    const ref = entry && entry._rarRef;
    if (!ref) return;
    let data = entry.data || ref.data;
    if (!data || entry.encrypted || ref.encrypted) return;
    try {
      const name = (entry.path || ref.path || 'rar-entry').split(/[\\/]/).pop();
      const ab = (data instanceof Uint8Array) ? data.slice().buffer : data;
      const file = new File([ab], name, { type: 'application/octet-stream' });
      wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
    } catch (e) {
      console.warn('RAR store entry open failed:', e);
    }
  }
}
