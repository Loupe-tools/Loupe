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
});
