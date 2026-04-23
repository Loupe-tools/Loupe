// binary-exports.js — Export-anomaly flags for native binaries.
//
// Shared-library exports carry three well-known triage signals that the
// PE / ELF / Mach-O renderers individually had no concept of:
//
//   1. **DLL side-loading targets.** Windows loads a handful of system
//      DLLs (version.dll, winmm.dll, uxtheme.dll, winhttp.dll, dbghelp.dll,
//      cryptbase.dll, …) by *filename* from the application's own
//      directory before falling back to %SystemRoot%. An attacker drops a
//      malicious DLL of the same name next to a legitimate signed EXE,
//      which then loads the attacker's code under the signer's identity.
//      This technique is MITRE T1574.002 and is the single most common
//      Authenticode-bypass pattern seen in the wild. When a sample is a
//      DLL *and* its filename matches one of these canonical names we
//      surface it as a high-severity pattern, regardless of what the
//      DLL exports.
//
//   2. **Forwarded / proxy DLL exports.** A PE export can be a
//      forwarder — instead of pointing at a function body, the function
//      RVA lands *inside* the export directory and yields a string of the
//      form `OtherDll.FuncName`. The loader resolves the forwarder
//      transparently at import time. Legitimate DLLs (kernelbase →
//      kernel32, api-ms-win-* sets) use this pattern; malicious proxy
//      DLLs abuse it as a side-loading amplifier — the attacker's DLL
//      forwards every legitimate export to the real system DLL *and*
//      runs a DllMain, so the victim application sees normal behaviour
//      while the loader also runs the attacker's code. Any forwarder in
//      a non-system path is suspicious; we emit each as a medium-
//      severity pattern.
//
//   3. **Ordinal-only exports.** A PE export with no name (only an
//      ordinal) is rare in modern compiler output and historically
//      signals either a packer/crypter stub, a shellcode loader, or a
//      hand-rolled DLL meant to hide its API surface. A few ordinal-
//      only exports is normal (Borland stubs, undocumented MS API);
//      a DLL where ≥ 50 % of exports are ordinal-only is a strong
//      obfuscation tell. We report the count and bump risk when the
//      ratio crosses the threshold.
//
// Contract
// --------
//   BinaryExports.emit(findings, {
//     isLib, fileName, exportNames, forwardedExports, ordinalOnlyCount
//   })
//     → { sideLoadHit: 0|1,
//         forwarderCount: number,
//         ordinalOnly: number,
//         ordinalOnlyRatio: number }
//
// `isLib` gates the side-loading check (we never want to warn about an
// EXE's filename matching `version.dll`). `fileName` is matched
// case-insensitively against the SIDE_LOADING set using the file's
// *basename only* — path prefixes are stripped. `exportNames` is only
// used to compute the denominator for `ordinalOnlyRatio`. `forwardedExports`
// is the list of forwarder target strings (e.g. `kernel32.ExitProcess`)
// — each becomes its own IOC.PATTERN row. `ordinalOnlyCount` is the
// caller-computed count of exports that have no name.
//
// Per-format applicability
// ------------------------
// • PE: all three signals apply.
// • Mach-O (MH_DYLIB): only the side-loading filename check and the
//   forwarder-ish concept (re-exported dylibs via LC_REEXPORT_DYLIB)
//   apply. No ordinal notion.
// • ELF (.so with DT_SONAME): only the side-loading filename check
//   applies in practice. ELF has no forwarded-export or ordinal
//   concept; the count of exported dynsym entries is informational.
//
// The helper is deliberately permissive on its input shape — missing
// fields just skip the corresponding check rather than throwing, so
// each renderer can pass the shape it already has without extra
// plumbing.

const BinaryExports = (() => {

  // ── Canonical side-loadable DLL target list ─────────────────────────
  //
  // Sources: MITRE T1574.002 sample corpus, HijackLibs project
  // (hijacklibs.net), and the first-party Microsoft known-DLLs list.
  // Kept lowercase for case-insensitive match against basename.
  //
  // Keep the list focused on *confirmed* side-loadable targets — a
  // noisy list (every system DLL ever) would fire on legitimate
  // installers that just happen to ship a cached copy of a Windows
  // redistributable. Every name here has documented real-world
  // side-loading abuse.
  const SIDE_LOADING = new Set([
    // Classic T1574.002 abuse surface
    'version.dll',
    'winmm.dll',
    'uxtheme.dll',
    'winhttp.dll',
    'dbghelp.dll',
    'cryptbase.dll',
    'wtsapi32.dll',
    'secur32.dll',
    'sspicli.dll',
    'userenv.dll',
    'profapi.dll',
    'netutils.dll',
    'netapi32.dll',
    'dwmapi.dll',
    'propsys.dll',
    'windowscodecs.dll',
    'wininet.dll',
    'urlmon.dll',
    'cryptsp.dll',
    'cscapi.dll',
    'dhcpcsvc.dll',
    'ntmarta.dll',
    'riched32.dll',
    'textshaping.dll',
    'wbemcomn.dll',
    'winnsi.dll',
    'vssapi.dll',
    'mscoree.dll',
    'msi.dll',
    // VC runtime redistributables — frequently dropped alongside a
    // legit EXE so the loader resolves from the application directory
    'vcruntime140.dll',
    'vcruntime140_1.dll',
    'msvcp140.dll',
    'msvcp140_1.dll',
    'msvcp140_2.dll',
    'concrt140.dll',
    // Image / Qt / openssl / libraries often side-loaded against
    // signed apps (Notepad++, 7-Zip installer variants, etc.)
    'libcurl.dll',
    'libcrypto-1_1.dll',
    'libssl-1_1.dll',
    'libeay32.dll',
    'ssleay32.dll',
  ]);

  // Ordinal-only ratio that flips us from "informational" to "anomaly".
  // Below this threshold the count is reported but no IOC is emitted —
  // legitimate DLLs from certain MSVC versions emit a handful of
  // ordinal-only stubs.
  const ORDINAL_ONLY_ANOMALY_RATIO = 0.5;

  // Minimum absolute ordinal-only count under which we never flag,
  // regardless of ratio. A 4-export DLL with 3 ordinal exports has a
  // 75 % ratio but is probably an inlined Delphi / Borland stub.
  const ORDINAL_ONLY_ABS_FLOOR = 4;

  function _basename(fileName) {
    if (!fileName) return '';
    const s = String(fileName);
    const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
    return (i >= 0 ? s.slice(i + 1) : s).toLowerCase();
  }

  function _looksLikeSystemPathForwarder(fwd) {
    // Forwarders that target the Windows API set (api-ms-win-* or
    // ext-ms-win-*) or that target a DLL in the set of known "platform"
    // DLLs are the legitimate pattern used by Windows' own
    // apisetschema forwarders and by kernelbase/kernel32. Suppress
    // those to keep the forwarder signal high-value.
    const t = String(fwd || '').toLowerCase();
    if (!t) return true;
    if (t.startsWith('api-ms-win-') || t.startsWith('ext-ms-win-')) return true;
    // Any forwarder to one of the Microsoft "platform core" DLLs
    // is near-certainly benign (kernelbase forwards to ntdll, etc.)
    const PLATFORM = /^(ntdll|kernel32|kernelbase|kernel|user32|gdi32|advapi32|combase|ole32|oleaut32|shlwapi|rpcrt4|sechost|bcrypt|bcryptprimitives|ucrtbase|msvcrt)\./;
    return PLATFORM.test(t);
  }

  /**
   * Emit export-anomaly IOCs.
   *
   * @param {object} findings  — as built by analyzeForSecurity
   * @param {object} shape     — {isLib, fileName, exportNames,
   *                              forwardedExports, ordinalOnlyCount}
   * @returns {{sideLoadHit:0|1, forwarderCount:number,
   *            ordinalOnly:number, ordinalOnlyRatio:number}}
   */
  function emit(findings, shape) {
    shape = shape || {};
    const isLib = !!shape.isLib;
    const base  = _basename(shape.fileName);
    const exportNames       = Array.isArray(shape.exportNames) ? shape.exportNames : [];
    const forwardedExports  = Array.isArray(shape.forwardedExports) ? shape.forwardedExports : [];
    const ordinalOnlyCount  = Math.max(0, Number(shape.ordinalOnlyCount) || 0);
    const totalExports      = exportNames.length + ordinalOnlyCount;
    const ordinalOnlyRatio  = totalExports > 0 ? ordinalOnlyCount / totalExports : 0;

    const out = {
      sideLoadHit: 0,
      forwarderCount: 0,
      ordinalOnly: ordinalOnlyCount,
      ordinalOnlyRatio,
    };

    if (typeof pushIOC !== 'function' || typeof IOC === 'undefined') return out;

    // ── 1. Side-loading host match ────────────────────────────────────
    //
    // Only fires for libraries (PE DLLs, MH_DYLIB, ELF ET_DYN with
    // SONAME). An executable named "version.dll" would be nonsensical
    // but harmless; the loader won't use it as a side-loading target.
    if (isLib && base && SIDE_LOADING.has(base)) {
      pushIOC(findings, {
        type: IOC.PATTERN,
        value: `DLL side-loading host — filename "${base}" is a documented T1574.002 target`,
        severity: 'high',
        note: 'Hijack-libs / MITRE T1574.002 — dropped beside a signed app to be loaded from the application directory ahead of %SystemRoot%',
        _noDomainSibling: true,
      });
      out.sideLoadHit = 1;
    }

    // ── 2. Forwarded / proxy-DLL exports ──────────────────────────────
    //
    // Cap at 30 — a legitimate platform DLL can have hundreds of
    // forwarders, but we only ever need a handful as evidence. Filter
    // out the Windows-platform forwarder targets (api-ms-win-*, kernel32,
    // ntdll, …) so the signal represents *unusual* proxying.
    const suspiciousForwarders = [];
    for (const fwd of forwardedExports) {
      if (!fwd || typeof fwd !== 'string') continue;
      if (_looksLikeSystemPathForwarder(fwd)) continue;
      suspiciousForwarders.push(fwd);
    }
    out.forwarderCount = suspiciousForwarders.length;

    const FWD_CAP = 60;
    for (const fwd of suspiciousForwarders.slice(0, FWD_CAP)) {
      pushIOC(findings, {
        type: IOC.PATTERN,
        value: `Forwarded export → ${fwd}`,
        severity: 'medium',
        note: 'Proxy-DLL technique — export is a forwarder string; resolves through the loader to another DLL. Classic side-loading amplifier (T1574.002).',
        highlightText: fwd,
        _noDomainSibling: true,
      });
    }
    if (suspiciousForwarders.length > FWD_CAP) {
      pushIOC(findings, {
        type: IOC.INFO,
        value: `Forwarded exports truncated at ${FWD_CAP} — binary contains ${suspiciousForwarders.length} non-platform forwarders`,
        severity: 'info',
      });
    }

    // ── 3. Ordinal-only exports ───────────────────────────────────────
    if (
      ordinalOnlyCount >= ORDINAL_ONLY_ABS_FLOOR &&
      ordinalOnlyRatio >= ORDINAL_ONLY_ANOMALY_RATIO
    ) {
      const pct = Math.round(ordinalOnlyRatio * 100);
      pushIOC(findings, {
        type: IOC.PATTERN,
        value: `Ordinal-only exports: ${ordinalOnlyCount} of ${totalExports} (${pct}%) have no names`,
        severity: 'medium',
        note: 'Unusually high ordinal-only ratio — packer / crypter stub or hand-rolled loader hiding its API surface (T1027)',
        _noDomainSibling: true,
      });
    }

    return out;
  }

  return { emit, SIDE_LOADING, ORDINAL_ONLY_ANOMALY_RATIO, ORDINAL_ONLY_ABS_FLOOR };
})();

if (typeof window !== 'undefined') window.BinaryExports = BinaryExports;
