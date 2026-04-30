'use strict';
// ════════════════════════════════════════════════════════════════════════════
// vba-utils.js — Shared VBA binary decoding and pattern matching
// Used by: DocxParser, XlsxRenderer, PptxRenderer, SecurityAnalyzer
// ════════════════════════════════════════════════════════════════════════════

/**
 * Decode raw VBA binary (Uint8Array) into an array of module objects.
 * Each item is { name: string, source: string }.
 * Source may be empty when the binary cannot be decoded as printable text.
 *
 * @param {Uint8Array} data  Raw bytes of the vbaProject.bin stream.
 * @returns {{ name: string, source: string }[]}
 */
function parseVBAText(data) {
  const txt = new TextDecoder('latin1').decode(data);
  const mods = [];
  const nameRe = /Attribute VB_Name = "([^"]+)"/g;
  let m;
  while ((m = nameRe.exec(txt)) !== null) mods.push({ name: m[1], source: '' });

  // Extract runs of printable ASCII that look like VBA source lines
  const chunks = (txt.match(/[ -~\r\n\t]{40,}/g) || [])
    .filter(c => /\b(Sub |Function |End Sub|End Function|Dim |Set |If |Then|For |MsgBox|Shell|CreateObject|WScript|AutoOpen|Workbook_Open|Document_Open|Auto_Open)\b/i.test(c));
  const src = chunks.join('\n').trim();

  if (mods.length === 0 && src) mods.push({ name: '(extracted)', source: src });
  else if (mods.length > 0 && src) mods[0].source = src;
  return mods;
}

/**
 * Detect VBA stomping (T1564.007) by inspecting the raw vbaProject.bin bytes.
 *
 * VBA stomping (a.k.a. P-code injection / "PCode hijack") replaces the source
 * stream of a compiled VBA module with decoy text — usually nothing, a single
 * blank module, or an innocuous comment — while leaving the compiled P-code
 * intact in the `_VBA_PROJECT` performance cache. Office runs the P-code when
 * the host VBA version matches; static scanners that read source see only the
 * decoy and miss the payload entirely. See:
 *   - Walmart Labs / Carrera Pena, "Anti-Forensics: VBA Stomping"
 *   - oletools `olevba --vba-stomp-detection`
 *   - pcodedmp by Vesselin Bontchev
 *
 * Heuristic (matches the office-macros.yar Office_VBA_Stomping rule, but here
 * applied to the *inner* vbaProject.bin extracted from .docx/.xlsm/.pptx —
 * the YARA rule alone covers only the outer .doc/.xls OLE container):
 *
 *   • The performance-cache marker `_VBA_PROJECT` is present (UTF-16 LE),
 *     proving the file carries compiled P-code.
 *   • No source-module marker `Attribute VB_` appears anywhere. Every
 *     legitimate VBA module begins with at least
 *       `Attribute VB_Name = "<ModuleName>"`
 *     so its absence — when P-code IS present — is a strong stomping
 *     signature. Empty/zero-module projects are extremely rare in the wild.
 *
 * The check is a literal byte scan on the raw bin, no inner-CFB parse: this
 * keeps the helper cheap and resilient to malformed mini-streams that already
 * trip parsers like olevba. False-positive risk: a bug-free legitimate
 * project with the source streams *legitimately* zeroed (template-author
 * tooling stripping comments) — observed exclusively in Microsoft's own
 * sample tooling and not in real-world Office output.
 *
 * @param {Uint8Array} data  Raw bytes of the vbaProject.bin stream.
 * @returns {{stomped: boolean, hasPcode: boolean, hasSource: boolean,
 *            sourceMarkers: number}}
 */
function detectVbaStomping(data) {
  const out = { stomped: false, hasPcode: false, hasSource: false, sourceMarkers: 0 };
  if (!data || !data.length) return out;
  // Scan up to 4 MB — vbaProject.bin is typically <200 KB; an outsized blob
  // (>4 MB) is itself suspicious and we still scan the prefix.
  const SCAN_CAP = 4 * 1024 * 1024;
  const len = Math.min(data.length, SCAN_CAP);

  // 1. _VBA_PROJECT in UTF-16 LE: bytes "_\0V\0B\0A\0_\0P\0R\0O\0J\0E\0C\0T\0".
  //    We look for the ASCII run interleaved with NULs, byte-by-byte.
  const PCODE_TAG = '_VBA_PROJECT';
  outer: for (let i = 0; i + PCODE_TAG.length * 2 <= len; i++) {
    for (let j = 0; j < PCODE_TAG.length; j++) {
      if (data[i + j * 2] !== PCODE_TAG.charCodeAt(j) || data[i + j * 2 + 1] !== 0) continue outer;
    }
    out.hasPcode = true;
    break;
  }

  // 2. `Attribute VB_` in ASCII (decompressed source). Each module has at
  //    least one Attribute line so the count is a coarse module-source proxy.
  //    Stop at first hit for the boolean; a second pass counts up to a cap.
  const ATTR = 'Attribute VB_';
  const A0 = ATTR.charCodeAt(0); // 'A'
  let count = 0;
  scan: for (let i = 0; i + ATTR.length <= len; i++) {
    if (data[i] !== A0) continue;
    for (let j = 1; j < ATTR.length; j++) {
      if (data[i + j] !== ATTR.charCodeAt(j)) continue scan;
    }
    count++;
    if (count >= 64) break;
    i += ATTR.length - 1;
  }
  out.sourceMarkers = count;
  out.hasSource = count > 0;

  out.stomped = out.hasPcode && !out.hasSource;
  return out;
}

/**
 * Scan VBA source text for auto-execute hooks and dangerous API patterns.
 *
 * @param {string} src  Decoded VBA source text.
 * @returns {string[]}  Human-readable names of matched patterns.
 */
function autoExecPatterns(src) {
  const pats = [
    [/\bAutoOpen\b/i, 'AutoOpen (auto-execute)'],
    [/\bDocument_Open\b/i, 'Document_Open (auto-execute)'],
    [/\bAuto_Open\b/i, 'Auto_Open (auto-execute)'],
    [/\bWorkbook_Open\b/i, 'Workbook_Open (auto-execute)'],
    [/\bShell\s*\(/i, 'Shell()'],
    [/WScript\.Shell/i, 'WScript.Shell'],
    [/CreateObject\s*\(\s*["']WScript/i, 'CreateObject(WScript)'],
    [/CreateObject\s*\(\s*["']Scripting/i, 'CreateObject(Scripting)'],
    [/\bPowerShell\b/i, 'PowerShell'],
    [/cmd\.exe/i, 'cmd.exe'],
    [/cmd\s+\/c/i, 'cmd /c'],
    [/URLDownloadToFile/i, 'URLDownloadToFile'],
    [/XMLHTTP/i, 'XMLHTTP (network)'],
    [/WinHttpRequest/i, 'WinHttpRequest (network)'],
    [/\bRegWrite\b/i, 'RegWrite'],
    [/\bRegDelete\b/i, 'RegDelete'],
    [/\bKill\b/i, 'Kill (delete files)'],
    [/\bEnviron\b/i, 'Environ'],
    [/\bGetObject\b/i, 'GetObject'],
    [/\bCallByName\b/i, 'CallByName'],
  ];
  return pats.filter(([re]) => re.test(src)).map(([, name]) => name);
}
