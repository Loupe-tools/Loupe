'use strict';
// ════════════════════════════════════════════════════════════════════════════
// image-renderer.js — Renders image files (PNG, JPEG, GIF, BMP, WEBP, ICO)
// Shows the image with metadata and checks for steganography indicators.
//
// EXIF / XMP / IPTC parsing uses the vendored `exifr` library (Tier-1 dep).
// Classic-pivot fields (GPS coordinates, camera serial, XMP document/
// instance IDs, creator toolkit) are mirrored into `findings.interestingStrings`
// via pushIOC() so they appear in the sidebar's IOC table, while attribution
// fluff (Camera Make / Model / artist name) stays metadata-only per the
// "Option B" classic-pivot policy.
//
// Depends on: constants.js (IOC, pushIOC, mirrorMetadataIOCs)
//             vendor/exifr.min.js (window.exifr, optional — falls back gracefully)
// ════════════════════════════════════════════════════════════════════════════
class ImageRenderer {

  static MIME_MAP = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    bmp: 'image/bmp', webp: 'image/webp', ico: 'image/x-icon', tif: 'image/tiff',
    tiff: 'image/tiff', avif: 'image/avif',
  };

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const mime = ImageRenderer.MIME_MAP[ext] || 'image/png';
    const wrap = document.createElement('div'); wrap.className = 'image-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    const bannerStrong = document.createElement('strong'); bannerStrong.textContent = 'Image Preview';
    banner.appendChild(bannerStrong);
    banner.appendChild(document.createTextNode(` — ${ext.toUpperCase()} image (${this._fmtBytes(bytes.length)})`));
    wrap.appendChild(banner);

    // Image element
    const imgWrap = document.createElement('div'); imgWrap.className = 'image-preview-wrap';
    const infoDiv = document.createElement('div'); infoDiv.className = 'image-info';

    // TIFF branch — browsers don't render TIFF in <img>, so we decode via the
    // vendored UTIF.js and paint the first page onto a <canvas>. We probe by
    // extension AND by magic bytes (II*\0 / MM\0*) so mis-labelled files still
    // get the canvas path, and fall through to the <img> path on any failure
    // so Safari users (who CAN decode TIFF natively) aren't regressed.
    const isTiffMagic =
      bytes.length >= 4 &&
      ((bytes[0] === 0x49 && bytes[1] === 0x49 && bytes[2] === 0x2A && bytes[3] === 0x00) ||
       (bytes[0] === 0x4D && bytes[1] === 0x4D && bytes[2] === 0x00 && bytes[3] === 0x2A));
    const isTiff = (ext === 'tif' || ext === 'tiff' || isTiffMagic) && typeof UTIF !== 'undefined';

    let canvasRendered = false;
    if (isTiff) {
      try {
        const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        const ifds = UTIF.decode(ab);
        if (ifds && ifds.length) {
          UTIF.decodeImage(ab, ifds[0]);
          const rgba = UTIF.toRGBA8(ifds[0]);
          const w = ifds[0].width, h = ifds[0].height;
          if (w > 0 && h > 0 && rgba && rgba.length === w * h * 4) {
            const canvas = document.createElement('canvas');
            canvas.className = 'image-preview';
            canvas.width = w; canvas.height = h;
            const ctx = canvas.getContext('2d');
            const imgData = ctx.createImageData(w, h);
            imgData.data.set(rgba);
            ctx.putImageData(imgData, 0, 0);
            imgWrap.appendChild(canvas);
            const pageSuffix = ifds.length > 1 ? `  ·  page 1 of ${ifds.length}` : '';
            infoDiv.textContent = `${w} × ${h} px  ·  TIFF${pageSuffix}  ·  ${this._fmtBytes(bytes.length)}`;
            canvasRendered = true;
          }
        }
      } catch (e) {
        // Swallow and fall through to the <img> path below — it will surface
        // the standard "Failed to render image" message if the browser also
        // can't handle it.
      }
    }

    if (!canvasRendered) {
      const img = document.createElement('img');
      img.className = 'image-preview';
      const blob = new Blob([bytes], { type: mime });
      const blobUrl = URL.createObjectURL(blob);
      img.src = blobUrl;
      img.alt = fileName || 'Image preview';
      img.title = 'Right-click to save or inspect';

      infoDiv.textContent = `Loading image…`;
      img.addEventListener('load', () => {
        infoDiv.textContent = `${img.naturalWidth} × ${img.naturalHeight} px  ·  ${ext.toUpperCase()}  ·  ${this._fmtBytes(bytes.length)}`;
        // Revoke blob URL after image is loaded to free memory
        URL.revokeObjectURL(blobUrl);
      });
      img.addEventListener('error', () => {
        infoDiv.textContent = `Failed to render image — file may be corrupted or unsupported format`;
        infoDiv.style.color = 'var(--risk-high)';
        // Revoke blob URL on error to free memory
        URL.revokeObjectURL(blobUrl);
      });

      imgWrap.appendChild(img);
    }

    wrap.appendChild(imgWrap);
    wrap.appendChild(infoDiv);

    // Hex header (first 32 bytes)
    const headerDiv = document.createElement('div'); headerDiv.className = 'image-hex-header';
    const hexStr = Array.from(bytes.subarray(0, Math.min(32, bytes.length)))
      .map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    headerDiv.textContent = `Header: ${hexStr}`;
    wrap.appendChild(headerDiv);

    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], interestingStrings: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const ext = (fileName || '').split('.').pop().toLowerCase();

    // ── Appended-data steganography checks ──────────────────────────────
    if (ext === 'png' || ext === 'PNG') {
      // PNG ends with IEND chunk: 49 45 4E 44 AE 42 60 82
      const iend = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
      for (let i = bytes.length - 8; i >= 8; i--) {
        let match = true;
        for (let j = 0; j < 8; j++) { if (bytes[i + j] !== iend[j]) { match = false; break; } }
        if (match) {
          const endPos = i + 8;
          if (endPos < bytes.length) {
            const extra = bytes.length - endPos;
            f.externalRefs.push({
              type: IOC.PATTERN,
              url: `${this._fmtBytes(extra)} of data appended after PNG IEND chunk — possible steganography or embedded payload`,
              severity: 'medium'
            });
            f.risk = 'medium';
          }
          break;
        }
      }
    }

    if (['jpg', 'jpeg'].includes(ext)) {
      // JPEG ends with FFD9
      let lastFFD9 = -1;
      for (let i = bytes.length - 2; i >= 2; i--) {
        if (bytes[i] === 0xFF && bytes[i + 1] === 0xD9) { lastFFD9 = i; break; }
      }
      if (lastFFD9 >= 0 && lastFFD9 + 2 < bytes.length) {
        const extra = bytes.length - lastFFD9 - 2;
        if (extra > 0) {
          f.externalRefs.push({
            type: IOC.PATTERN,
            url: `${this._fmtBytes(extra)} of data appended after JPEG EOI marker — possible steganography or embedded payload`,
            severity: 'medium'
          });
          f.risk = 'medium';
        }
      }
    }

    // Check for embedded PE header inside image
    for (let i = 16; i < bytes.length - 4; i++) {
      if (bytes[i] === 0x4D && bytes[i + 1] === 0x5A && bytes[i + 2] === 0x90 && bytes[i + 3] === 0x00) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `Embedded PE (MZ) header found at offset ${i} inside image — hidden executable`,
          severity: 'high'
        });
        f.risk = 'high';
        break;
      }
    }

    // Check for embedded ZIP inside image (polyglot)
    for (let i = 16; i < bytes.length - 4; i++) {
      if (bytes[i] === 0x50 && bytes[i + 1] === 0x4B && bytes[i + 2] === 0x03 && bytes[i + 3] === 0x04) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `Embedded ZIP archive found at offset ${i} inside image — polyglot file`,
          severity: 'medium'
        });
        if (f.risk === 'low') f.risk = 'medium';
        break;
      }
    }

    // ── EXIF / XMP / IPTC parsing via exifr ─────────────────────────────
    // exifr accepts ArrayBuffer / Uint8Array / Buffer synchronously via
    // `parseSync`, but the library only exposes a Promise-based API. We
    // therefore call it synchronously via the compiled parser so we stay
    // on the existing analyze-for-security sync contract (renderers must
    // return `f` immediately). The library's `parse()` API supports fully
    // synchronous extraction for raw-byte inputs; we guard every branch
    // so a missing / broken vendor load cannot crash analysis.
    if (typeof exifr !== 'undefined' && exifr && bytes.length) {
      try {
        // Prefer the raw-bytes path — takes a Uint8Array, returns a merged
        // object spanning IFD0, Exif, GPS, IPTC, XMP (via `parseSync`-like
        // synchronous entry). Supported formats: JPEG, HEIC, TIFF, PNG,
        // WebP. For anything else we fall back to the legacy byte scanner
        // below.
        const opts = {
          tiff: true, exif: true, gps: true, ifd0: true,
          iptc: true, xmp: true, icc: false, jfif: false,
          mergeOutput: true, translateKeys: true, translateValues: true,
          reviveValues: true, sanitize: true,
        };
        // Fully-synchronous path: exifr.parse() returns a Promise, but for
        // already-in-memory raw bytes the promise resolves in a microtask.
        // We grab its synchronous fallback `parseSync` if present, else
        // kick the promise and stash its result — analysis is allowed to
        // continue updating `f.metadata` from a then() callback because
        // the sidebar is re-rendered whenever findings change in the main
        // analyze loop. exifr v7 does NOT ship parseSync for images; we
        // therefore launch the async parse and post-process on resolve.
        const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        const p = exifr.parse(ab, opts);
        if (p && typeof p.then === 'function') {
          p.then(data => this._applyExifData(f, data))
           .catch(() => { /* swallow — exifr is best-effort */ });
        } else if (p && typeof p === 'object') {
          this._applyExifData(f, p);
        }
      } catch (_) { /* exifr optional */ }
    }

    // Legacy byte-scan EXIF fallback — preserved so images in unsupported
    // formats (or when exifr fails / is absent) still surface at least a
    // crude EXIF string, matching pre-v7 Loupe behaviour.
    if (!f.metadata.exif && ['jpg', 'jpeg'].includes(ext) && bytes[0] === 0xFF && bytes[1] === 0xD8) {
      for (let i = 2; i < Math.min(bytes.length - 10, 65535); i++) {
        if (bytes[i] === 0xFF && bytes[i + 1] === 0xE1) {
          const exifEnd = Math.min(i + 500, bytes.length);
          let str = '';
          for (let j = i + 4; j < exifEnd; j++) {
            const b = bytes[j];
            if (b >= 0x20 && b < 0x7F) str += String.fromCharCode(b);
            else if (str.length >= 6) { break; }
            else str = '';
          }
          if (str.length >= 6) {
            f.metadata.exif = str.slice(0, 100);
          }
          break;
        }
      }
    }

    f.metadata.format = ext.toUpperCase();
    f.metadata.size = bytes.length;

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  /**
   * Post-process an exifr result into:
   *   • `findings.metadata` — human-readable attribution info
   *   • `findings.interestingStrings` — classic pivots via pushIOC()
   *
   * Option-B policy: ONLY mirror fields that function as pivots
   *   ✔ GPS lat/lon/alt       → IOC.PATTERN (geographic pivot)
   *   ✔ Camera body serial    → IOC.HASH    (unique per-device identifier)
   *   ✔ Owner name/copyright  → IOC.USERNAME (attribution to a real person)
   *   ✔ Creator Tool / XMP software → IOC.PATTERN (tool fingerprint)
   *   ✔ XMP DocumentID / InstanceID → IOC.GUID (cross-file pivot)
   *   ✔ IPTC By-line / Contact → IOC.USERNAME / IOC.EMAIL
   *   ✘ Make / Model / Lens   → metadata-only (attribution fluff)
   *   ✘ DateTimeOriginal      → metadata-only (timeline, not a pivot)
   */
  _applyExifData(f, data) {
    if (!data || typeof data !== 'object') return;

    // ── Pure attribution → metadata only ──────────────────────────────
    if (data.Make)                f.metadata.exifMake = String(data.Make).trim();
    if (data.Model)               f.metadata.exifModel = String(data.Model).trim();
    if (data.LensModel)           f.metadata.exifLens = String(data.LensModel).trim();
    if (data.DateTimeOriginal)    f.metadata.exifDateTime = this._fmtExifDate(data.DateTimeOriginal);
    if (data.CreateDate)          f.metadata.exifCreateDate = this._fmtExifDate(data.CreateDate);
    if (data.ModifyDate)          f.metadata.exifModifyDate = this._fmtExifDate(data.ModifyDate);
    if (data.ImageWidth && data.ImageHeight) {
      f.metadata.exifDimensions = `${data.ImageWidth} × ${data.ImageHeight}`;
    }

    // ── GPS: geographic pivot, always surface as IOC ──────────────────
    if (typeof data.latitude === 'number' && typeof data.longitude === 'number') {
      const lat = data.latitude.toFixed(6);
      const lon = data.longitude.toFixed(6);
      const alt = typeof data.GPSAltitude === 'number' ? ` @ ${data.GPSAltitude.toFixed(1)}m` : '';
      const gpsStr = `${lat}, ${lon}${alt}`;
      f.metadata.gps = gpsStr;
      pushIOC(f, {
        type: IOC.PATTERN,
        value: `GPS: ${gpsStr}`,
        severity: 'medium',
        highlightText: gpsStr,
        note: 'EXIF GPS coordinates',
      });
      if (f.risk === 'low') f.risk = 'medium';
    }

    // ── Device serial: unique per-camera pivot ────────────────────────
    if (data.SerialNumber || data.BodySerialNumber || data.InternalSerialNumber) {
      const serial = String(data.SerialNumber || data.BodySerialNumber || data.InternalSerialNumber).trim();
      if (serial) {
        f.metadata.exifSerial = serial;
        pushIOC(f, {
          type: IOC.HASH,
          value: serial,
          severity: 'info',
          highlightText: serial,
          note: 'Camera serial number',
        });
      }
    }

    // ── Owner / Artist / Copyright: personal attribution ──────────────
    if (data.Artist) {
      const artist = String(data.Artist).trim();
      if (artist) {
        f.metadata.exifArtist = artist;
        pushIOC(f, {
          type: IOC.USERNAME, value: artist, severity: 'info',
          highlightText: artist, note: 'EXIF Artist',
        });
      }
    }
    if (data.OwnerName || data.CameraOwnerName) {
      const owner = String(data.OwnerName || data.CameraOwnerName).trim();
      if (owner) {
        f.metadata.exifOwner = owner;
        pushIOC(f, {
          type: IOC.USERNAME, value: owner, severity: 'info',
          highlightText: owner, note: 'EXIF Owner',
        });
      }
    }
    if (data.Copyright) {
      const cp = String(data.Copyright).trim();
      if (cp) f.metadata.exifCopyright = cp;
    }

    // ── Creator software: tool fingerprint ────────────────────────────
    if (data.Software) {
      const sw = String(data.Software).trim();
      if (sw) {
        f.metadata.exifSoftware = sw;
        pushIOC(f, {
          type: IOC.PATTERN, value: `Software: ${sw}`, severity: 'info',
          highlightText: sw, note: 'EXIF Software',
        });
      }
    }
    if (data.CreatorTool) {
      const ct = String(data.CreatorTool).trim();
      if (ct && ct !== f.metadata.exifSoftware) {
        f.metadata.xmpCreatorTool = ct;
        pushIOC(f, {
          type: IOC.PATTERN, value: `CreatorTool: ${ct}`, severity: 'info',
          highlightText: ct, note: 'XMP CreatorTool',
        });
      }
    }

    // ── XMP Document / Instance ID: pure cross-file pivots ────────────
    if (data.DocumentID) {
      const id = String(data.DocumentID).replace(/^(xmp\.did:|uuid:)/i, '').trim();
      if (id) {
        f.metadata.xmpDocumentID = id;
        pushIOC(f, {
          type: IOC.GUID, value: id, severity: 'info',
          highlightText: id, note: 'XMP DocumentID',
        });
      }
    }
    if (data.InstanceID) {
      const id = String(data.InstanceID).replace(/^(xmp\.iid:|uuid:)/i, '').trim();
      if (id) {
        f.metadata.xmpInstanceID = id;
        pushIOC(f, {
          type: IOC.GUID, value: id, severity: 'info',
          highlightText: id, note: 'XMP InstanceID',
        });
      }
    }

    // ── IPTC by-line / contact ─────────────────────────────────────────
    if (data.Byline || data['By-line']) {
      const by = String(data.Byline || data['By-line']).trim();
      if (by) {
        f.metadata.iptcByline = by;
        pushIOC(f, {
          type: IOC.USERNAME, value: by, severity: 'info',
          highlightText: by, note: 'IPTC By-line',
        });
      }
    }
    if (data.Credit) {
      f.metadata.iptcCredit = String(data.Credit).trim();
    }
  }

  _fmtExifDate(d) {
    if (!d) return '';
    if (d instanceof Date) {
      try { return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ''); }
      catch (_) { return String(d); }
    }
    return String(d);
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
