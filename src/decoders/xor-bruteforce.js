// ════════════════════════════════════════════════════════════════════════════
// xor-bruteforce.js — Single-byte XOR cipher detection.
//
// Real-world malware frequently wraps a Base64 / Hex / Char-Array payload in
// a final single-byte XOR layer to defeat naïve string-search detections:
//
//   var enc = [106,107,…];      // Char-Array → "jklm…" gibberish
//   var key = 7;
//   var dec = enc.map(c => String.fromCharCode(c ^ key)).join('');
//   eval(dec);                  // real cleartext is "console.log(...)" etc.
//
// or (block-14 of `examples/encoded-payloads/mixed-obfuscations.txt`):
//
//   $enc = [Convert]::FromBase64String("…");
//   $xor = 0x42;
//   $dec = $enc | % { [char]($_ -bxor $xor) };
//
// `_tryXorBruteforce(bytes)` brute-forces the 255 possible single-byte keys
// and returns the best-scoring cleartext (or `null` if the result is
// ambiguous — a clear winner must beat the 2nd-place score by > 1.5×).
//
// The public scoring function is intentionally simple:
//   + 4 per ASCII letter
//   + 2 per ASCII digit
//   + 1 per ASCII punctuation in the printable range
//   + 8 if the result contains an exec keyword
//   − 4 per control byte (excluding 0x09 / 0x0A / 0x0D)
//
// This finder is invoked from the Char-Array / Base64 / Hex paths when the
// surrounding source mentions an XOR operator (`^`, `bxor`, `-bxor`) — see
// the call-sites in `encoding-finders.js` and `base64-hex.js`.
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(EncodedContentDetector.prototype, {
  /**
   * Brute-force a single-byte XOR cipher over `bytes`. Returns the best
   * scoring cleartext, or `null` if the result is ambiguous / implausible.
   *
   * @param {Uint8Array} bytes  Suspected XOR-encoded bytes.
   * @returns {?{key: number, bytes: Uint8Array, score: number}}
   */
  _tryXorBruteforce(bytes) {
    if (!bytes || bytes.length < 24) return null;

    // Performance cap: 255 passes × N bytes. Beyond 64 KiB, sample the
    // first 16 KiB and the last 16 KiB; if the score on those two
    // windows agrees on the same top key, accept it.
    const HARD_CAP = 64 * 1024;
    const SAMPLE_WINDOW = 16 * 1024;

    let scoreSource = bytes;
    let dualWindow = null;
    if (bytes.length > HARD_CAP) {
      dualWindow = {
        head: bytes.subarray(0, SAMPLE_WINDOW),
        tail: bytes.subarray(bytes.length - SAMPLE_WINDOW),
      };
      scoreSource = dualWindow.head;
    }

    const _scoreAgainstKey = (src, key) => {
      let score = 0;
      let nonControl = 0;
      for (let i = 0; i < src.length; i++) {
        const b = src[i] ^ key;
        if (b >= 0x41 && b <= 0x5A) { score += 4; nonControl++; continue; }
        if (b >= 0x61 && b <= 0x7A) { score += 4; nonControl++; continue; }
        if (b >= 0x30 && b <= 0x39) { score += 2; nonControl++; continue; }
        if (b === 0x20)             { score += 1; nonControl++; continue; }
        if (b >= 0x21 && b <= 0x2F) { score += 1; nonControl++; continue; }
        if (b >= 0x3A && b <= 0x40) { score += 1; nonControl++; continue; }
        if (b >= 0x5B && b <= 0x60) { score += 1; nonControl++; continue; }
        if (b >= 0x7B && b <= 0x7E) { score += 1; nonControl++; continue; }
        if (b === 0x09 || b === 0x0A || b === 0x0D) { nonControl++; continue; }
        // Control byte penalty (DEL or anything < 0x20 that isn't whitespace).
        if (b < 0x20 || b === 0x7F) { score -= 4; continue; }
        // High bytes (>= 0x80) — neutral; could be UTF-8 continuation bytes.
      }
      // Exec-keyword bonus is computed once at the end (cheap when it hits).
      let textPart = '';
      try {
        textPart = String.fromCharCode.apply(null,
          Array.from(src.length > 256 ? src.subarray(0, 256) : src)
            .map(b => (b ^ key) & 0xFF));
      } catch (_) {
        textPart = '';
      }
      if (/(eval|exec|invoke|iex|console|alert|powershell|cmd\.exe|http|shell|write|import|require|fromCharCode|Output|Download)/i.test(textPart)) {
        score += 8;
      }
      return { score, nonControl };
    };

    let bestKey   = -1;
    let bestScore = -Infinity;
    let secondScore = -Infinity;

    for (let key = 1; key <= 255; key++) {
      const { score, nonControl } = _scoreAgainstKey(scoreSource, key);
      // Reject keys that produce mostly control bytes / high bytes —
      // we want a printable-text result, not random binary.
      if (nonControl < scoreSource.length * 0.7) continue;
      if (score > bestScore) {
        secondScore = bestScore;
        bestScore = score;
        bestKey   = key;
      } else if (score > secondScore) {
        secondScore = score;
      }
    }

    if (bestKey < 0) return null;
    if (bestScore <= 0) return null;
    // Require a clear winner: top score must beat 2nd-place by >1.5× and
    // be at least a positive score (otherwise random data wins by default).
    if (secondScore > 0 && bestScore < secondScore * 1.5) return null;

    // Dual-window cross-check: if the head and tail samples disagree on
    // the top key, treat the result as ambiguous.
    if (dualWindow) {
      let tailBest = -1;
      let tailScoreBest = -Infinity;
      for (let key = 1; key <= 255; key++) {
        const { score, nonControl } = _scoreAgainstKey(dualWindow.tail, key);
        if (nonControl < dualWindow.tail.length * 0.7) continue;
        if (score > tailScoreBest) {
          tailScoreBest = score;
          tailBest = key;
        }
      }
      if (tailBest !== bestKey) return null;
    }

    // Materialise the full cleartext.
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ bestKey;

    // Final plausibility — the cleartext must look like text (mostly
    // valid UTF-8 with low control-char density).
    const decoded = this._tryDecodeUTF8(out);
    if (!decoded || decoded.length < 8) return null;

    return { key: bestKey, bytes: out, score: bestScore };
  },

  /**
   * XOR-context regex used by the call-sites to gate the bruteforce.
   * Looks for `^ <var>`, `bxor`, `-bxor`, or `xor ` in the surrounding
   * source. Anchored / bounded — runs once per candidate.
   */
  _hasXorContext(text, offset, raw) {
    const region = text.substring(
      Math.max(0, offset - 200),
      Math.min(text.length, offset + (raw ? raw.length : 0) + 200)
    );
    return /(\^\s*\$?[a-zA-Z_]\w*|\bxor\b|-bxor\b|\bbxor\b|\^\s*0x[0-9a-fA-F]+|\^\s*\d+)/i.test(region);
  },

  // ──────────────────────────────────────────────────────────────────────
  // Multi-byte repeating-key XOR (kitchen-sink / bruteforce mode only).
  //
  // Tries every key of length L = 2, 3, 4 by independently brute-forcing
  // each column (the standard "single-byte XOR per column" trick used in
  // every CryptoPals walkthrough). Crib analysis: the recovered candidate
  // must contain at least one well-known executor / shell crib token
  // ('powershell', 'iex', 'cmd', 'http', 'eval', 'exec', 'invoke',
  // 'console', 'fromCharCode', 'shell') AFTER decoding — otherwise
  // statistical wins on random-looking text would carpet the analyst with
  // false positives.
  //
  // Capped at 16 KiB scoring window, key length ≤ 4. The whole search
  // space is at most 4 × 256 × 16 KiB = 16M byte ops — single-digit ms
  // even on a budget laptop. Returns the same `{key, bytes, score}` shape
  // as the single-byte path so the call site is uniform; `key` is encoded
  // as `0x<hex…>` of all key bytes joined.
  // ──────────────────────────────────────────────────────────────────────
  _tryXorBruteforceMulti(bytes) {
    if (!bytes || bytes.length < 24) return null;

    const SAMPLE = bytes.length > 16 * 1024 ? bytes.subarray(0, 16 * 1024) : bytes;

    // Score one byte against a candidate key — a stripped-down version of
    // the per-byte logic in `_tryXorBruteforce` so we can fold a column
    // independently.
    const _scoreByte = (b) => {
      if (b >= 0x41 && b <= 0x5A) return 4;            // A-Z
      if (b >= 0x61 && b <= 0x7A) return 4;            // a-z
      if (b >= 0x30 && b <= 0x39) return 2;            // 0-9
      if (b === 0x20)             return 1;            // space
      if (b >= 0x21 && b <= 0x2F) return 1;            // punct
      if (b >= 0x3A && b <= 0x40) return 1;
      if (b >= 0x5B && b <= 0x60) return 1;
      if (b >= 0x7B && b <= 0x7E) return 1;
      if (b === 0x09 || b === 0x0A || b === 0x0D) return 0;
      if (b < 0x20 || b === 0x7F) return -4;           // control byte
      return 0;                                         // high bytes — neutral
    };

    const _bestKeyForColumn = (column) => {
      let bestKey = -1;
      let bestScore = -Infinity;
      for (let key = 0; key <= 255; key++) {
        let score = 0;
        for (let i = 0; i < column.length; i++) {
          score += _scoreByte(column[i] ^ key);
        }
        if (score > bestScore) {
          bestScore = score;
          bestKey = key;
        }
      }
      return { key: bestKey, score: bestScore };
    };

    const _materialise = (keyBytes) => {
      const out = new Uint8Array(bytes.length);
      const L = keyBytes.length;
      for (let i = 0; i < bytes.length; i++) {
        out[i] = bytes[i] ^ keyBytes[i % L];
      }
      return out;
    };

    const _looksLikeCleartext = (txt) => {
      if (!txt || txt.length < 8) return false;
      // Crib analysis — the recovered cleartext must mention a real
      // executor / shell / web-fetch identifier. Bare "lots of letters"
      // doesn't qualify — at this width the column-independent solver
      // happily wins on random data.
      return /(powershell|iex|invoke[- ]?expression|cmd\.exe|cmd\b|http|https|eval|exec|shell|fromCharCode|console\.log|FromBase64|Download|Get-Item|Start-Process|System\.|Runtime\.)/i.test(txt);
    };

    let best = null;
    for (let L = 2; L <= 4; L++) {
      // Build L columns and find the best key byte for each.
      const keyBytes = new Uint8Array(L);
      let totalScore = 0;
      for (let col = 0; col < L; col++) {
        const colLen = Math.floor((SAMPLE.length - col + L - 1) / L);
        const column = new Uint8Array(colLen);
        for (let i = 0; i < colLen; i++) column[i] = SAMPLE[col + i * L];
        const { key, score } = _bestKeyForColumn(column);
        keyBytes[col] = key;
        totalScore += score;
      }
      if (totalScore <= 0) continue;
      const cleartext = _materialise(keyBytes);
      const txt = this._tryDecodeUTF8(cleartext);
      if (!_looksLikeCleartext(txt)) continue;
      // Score normalised per byte so longer keys don't artificially win.
      const norm = totalScore / SAMPLE.length;
      if (!best || norm > best.norm) {
        let keyHex = '';
        for (let i = 0; i < L; i++) {
          keyHex += keyBytes[i].toString(16).toUpperCase().padStart(2, '0');
        }
        best = {
          key: '0x' + keyHex,           // string, distinct from single-byte numeric `key`
          bytes: cleartext,
          score: totalScore,
          norm,
          keyLength: L,
        };
      }
    }

    return best;
  },
});
