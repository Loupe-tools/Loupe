// capabilities.js — Capability tagging for native binaries.
//
// Turns a wall of "140 suspicious APIs" into a short list of **named
// behaviours** with MITRE ATT&CK IDs. An analyst reading the sidebar
// gets "process injection + keylogging + persistence" instead of a
// 140-row API table they have to mentally cluster themselves. Think of
// this as a minimal, static, in-browser capa.
//
// Contract
// --------
//   Capabilities.detect({
//     imports,    // normalised list of lowercase symbol/API names
//     dylibs,     // lowercase basenames of linked libs / dylibs / DLLs
//     strings,    // array of ASCII + UTF-16LE strings extracted from the
//                 // binary (already collected by every renderer)
//   }) → [
//     { id, name, severity, mitre, evidence: [ ...matched tokens ],
//       description },
//     …
//   ]
//
// A capability fires when EVERY token in its required set is present
// in the combined (imports ∪ strings) corpus. Some capabilities only
// need ONE token (see `any:true`). String tokens match case-insensitively;
// import tokens match exactly (renderers lowercase before passing in).
//
// Severity drives the sidebar pill colour. `mitre` is the primary ATT&CK
// technique ID (one per capability — don't stuff a pseudo-grouping in
// here; the Summary table renders it verbatim).

const _CAPABILITIES = [
  // ── Process injection ────────────────────────────────────────────────
  {
    id: 'proc-injection-classic',
    name: 'Process Injection (CreateRemoteThread)',
    severity: 'high',
    mitre: 'T1055.002',
    description: 'Classic CreateRemoteThread injection pattern: allocate executable memory in a remote process, write shellcode, run it.',
    imports: ['virtualallocex', 'writeprocessmemory', 'createremotethread'],
  },
  {
    id: 'proc-hollowing',
    name: 'Process Hollowing',
    severity: 'high',
    mitre: 'T1055.012',
    description: 'Create a suspended process, unmap its image, replace with payload, and resume — classic hollowing.',
    imports: ['createprocess', 'ntunmapviewofsection', 'setthreadcontext', 'resumethread'],
    quorum: 3,
  },
  {
    id: 'proc-injection-apc',
    name: 'Process Injection (APC queue)',
    severity: 'high',
    mitre: 'T1055.004',
    description: 'Queue an asynchronous procedure call to a remote thread so it executes attacker code at the next alertable wait.',
    imports: ['queueuserapc', 'openthread'],
  },
  {
    id: 'proc-injection-reflective',
    name: 'Reflective DLL Injection (Manual Map)',
    severity: 'high',
    mitre: 'T1055.001',
    description: 'Manual DLL map: parse the PE in memory and invoke its entry point without LoadLibrary — bypasses image-load callbacks.',
    imports: ['virtualalloc', 'virtualprotect', 'createthread'],
    quorum: 3,
  },
  {
    id: 'proc-inject-ptrace',
    name: 'Process Injection (ptrace)',
    severity: 'high',
    mitre: 'T1055.008',
    description: 'ptrace-based process injection — attach to another process and write instructions into its address space (Linux).',
    imports: ['ptrace'],
    strings: ['ptrace_attach', 'ptrace_pokedata', 'ptrace_poketext'],
    stringsAny: true,
  },
  {
    id: 'proc-inject-mach',
    name: 'Process Injection (Mach task ports)',
    severity: 'high',
    mitre: 'T1055',
    description: 'Mach task-for-pid + mach_vm_write — the canonical macOS process-injection primitive.',
    imports: ['task_for_pid', 'mach_vm_write', 'mach_vm_allocate', 'thread_create_running'],
    quorum: 2,
  },

  // ── Anti-debug / anti-analysis ───────────────────────────────────────
  // Tightened (2026-04-29): a single anti-debug API in isolation is noise —
  // `IsDebuggerPresent` and `QueryPerformanceCounter` appear in essentially
  // every non-trivial Windows binary as part of CRT init. Require at least
  // TWO classic anti-debug primitives to co-occur; the high-signal subset
  // below excludes pure timing APIs (those are covered by
  // `sandbox-sleep-skip`). PEB-walk strings (BeingDebugged, NtGlobalFlag)
  // and the hide-from-debugger thread API push the signal further when
  // present, so the capability fires at quorum=2 over imports OR at
  // quorum=2 over the PEB string-hint set.
  {
    id: 'anti-debug-winapi',
    name: 'Anti-Debug (Windows)',
    severity: 'medium',
    mitre: 'T1622',
    description: 'Classic Win32 anti-debug API cluster — multiple primitives co-occur (IsDebuggerPresent + CheckRemoteDebuggerPresent / NtQueryInformationProcess(ProcessDebugPort) / NtSetInformationThread(HideFromDebugger) / RtlGetNtGlobalFlags).',
    imports: [
      'isdebuggerpresent', 'checkremotedebuggerpresent',
      'ntqueryinformationprocess', 'outputdebugstringa', 'outputdebugstringw',
      'ntsetinformationthread', 'rtlgetntglobalflags',
      'ntclose',                  // common in NtClose-with-invalid-handle anti-debug trick
    ],
    strings: [
      'beingdebugged', 'ntglobalflag', 'processheap.flags',
      'pt_deny_attach',           // macOS anti-debug variant — also matches here for cross-platform tooling
      'hidefromdebugger',
    ],
    quorum: 2,
  },
  {
    id: 'anti-debug-ptrace',
    name: 'Anti-Debug (ptrace self)',
    severity: 'medium',
    mitre: 'T1622',
    description: 'ptrace(PTRACE_TRACEME) — a process traces itself to block a debugger from attaching.',
    imports: ['ptrace'],
    strings: ['ptrace_traceme'],
    stringsAny: true,
  },
  {
    id: 'anti-debug-macos',
    name: 'Anti-Debug (macOS PT_DENY_ATTACH)',
    severity: 'medium',
    mitre: 'T1622',
    description: 'ptrace(PT_DENY_ATTACH) — kernel-enforced debugger-attach block on macOS.',
    imports: ['ptrace'],
    strings: ['pt_deny_attach'],
    stringsAny: true,
  },
  {
    id: 'sandbox-sleep-skip',
    name: 'Sandbox Evasion (timing)',
    severity: 'medium',
    mitre: 'T1497.003',
    description: 'Timing primitive (GetTickCount / QueryPerformanceCounter) paired with a stalling primitive (Sleep / SleepEx / WaitForSingleObject / NtDelayExecution). Single-API timing alone is benign CRT init.',
    imports: [
      'gettickcount', 'gettickcount64', 'queryperformancecounter',
      'sleep', 'sleepex', 'waitforsingleobject', 'waitforsingleobjectex',
      'waitformultipleobjects', 'ntdelayexecution',
    ],
    // True quorum needs both halves of the pair, not 2 of one half. This is
    // checked specially in `detectCapabilities` via `splitQuorum`.
    splitQuorum: {
      timing:   ['gettickcount', 'gettickcount64', 'queryperformancecounter'],
      stalling: ['sleep', 'sleepex', 'waitforsingleobject', 'waitforsingleobjectex',
                 'waitformultipleobjects', 'ntdelayexecution'],
    },
  },

  // ── Keylogging / surveillance ────────────────────────────────────────
  {
    id: 'keylog-hooks',
    name: 'Keylogging (Windows hook)',
    severity: 'high',
    mitre: 'T1056.001',
    description: 'SetWindowsHookEx + GetAsyncKeyState or GetKeyState — the canonical Win32 keylogger pattern.',
    imports: ['setwindowshookex', 'getasynckeystate', 'getkeystate'],
    quorum: 2,
  },
  {
    id: 'keylog-evtap',
    name: 'Keylogging (macOS event tap)',
    severity: 'high',
    mitre: 'T1056.001',
    description: 'CGEventTapCreate paired with a keyboard-event mask is the Cocoa-level keylogger primitive on macOS.',
    imports: ['cgeventtapcreate'],
  },
  {
    id: 'screencap-gdi',
    name: 'Screen Capture (GDI)',
    severity: 'high',
    mitre: 'T1113',
    description: 'BitBlt + GetDC pattern — the GDI-based screenshot primitive.',
    imports: ['bitblt', 'getdc', 'createcompatibledc'],
    quorum: 2,
  },
  {
    id: 'screencap-macos',
    name: 'Screen Capture (macOS)',
    severity: 'high',
    mitre: 'T1113',
    description: 'CGDisplayCreateImage / CGWindowListCreateImage — macOS screenshot primitives requiring Screen Recording TCC permission.',
    imports: ['cgdisplaycreateimage', 'cgwindowlistcreateimage'],
    any: true,
  },

  // ── Credential theft ─────────────────────────────────────────────────
  {
    id: 'creds-lsa',
    name: 'Credential Theft (LSA)',
    severity: 'critical',
    mitre: 'T1003.001',
    description: 'LSA API cluster — LsaEnumerateLogonSessions, LsaRetrievePrivateData, LsaOpenPolicy — classic credential-harvesting surface.',
    imports: ['lsaenumeratelogonsessions', 'lsaretrieveprivatedata', 'lsaopenpolicy'],
    any: true,
  },
  {
    id: 'creds-sam',
    name: 'Credential Theft (SAM/registry hives)',
    severity: 'critical',
    mitre: 'T1003.002',
    description: 'Direct access to SAM / SYSTEM registry hives is a hallmark of hash-dumping tools.',
    strings: ['sam', 'security', 'system', 'regsavekey'],
    stringsAny: false,
    stringsQuorum: 3,
  },
  {
    id: 'creds-dpapi',
    name: 'Credential Theft (DPAPI)',
    severity: 'high',
    mitre: 'T1555',
    description: 'CryptUnprotectData — decrypts DPAPI blobs where browsers / Windows secrets are stored.',
    imports: ['cryptunprotectdata'],
  },
  {
    id: 'creds-keychain',
    name: 'Credential Theft (Keychain)',
    severity: 'critical',
    mitre: 'T1555.001',
    description: 'macOS Keychain APIs — Atomic Stealer / MacStealer / Amos cluster.',
    imports: ['seckeychainfinditem', 'seckeychaincopysearchlist', 'seckeychainitemcopycontent'],
    any: true,
  },
  {
    id: 'creds-shadow',
    name: 'Credential Theft (/etc/shadow)',
    severity: 'high',
    mitre: 'T1003.008',
    description: 'String references to /etc/shadow — Linux password hash dumping.',
    strings: ['/etc/shadow'],
    stringsAny: true,
  },

  // ── Persistence ──────────────────────────────────────────────────────
  {
    id: 'persist-run-key',
    name: 'Persistence (Run key)',
    severity: 'high',
    mitre: 'T1547.001',
    description: 'String references to HKCU/HKLM Run / RunOnce keys — classic autorun persistence.',
    strings: [
      'software\\microsoft\\windows\\currentversion\\run',
      'software\\microsoft\\windows\\currentversion\\runonce',
    ],
    stringsAny: true,
  },
  {
    id: 'persist-schtasks',
    name: 'Persistence (Scheduled Task)',
    severity: 'high',
    mitre: 'T1053.005',
    description: 'schtasks.exe invocation or Task Scheduler API use for persistence.',
    strings: ['schtasks', 'taskscheduler.', 'itaskservice'],
    stringsAny: true,
  },
  {
    id: 'persist-service',
    name: 'Persistence (Service)',
    severity: 'high',
    mitre: 'T1543.003',
    description: 'CreateService / OpenSCManager pair — install a Windows service as persistence.',
    imports: ['createservice', 'openscmanager', 'startservice'],
    quorum: 2,
  },
  {
    id: 'persist-launchd',
    name: 'Persistence (launchd)',
    severity: 'high',
    mitre: 'T1543.001',
    description: 'LaunchAgent / LaunchDaemon plist paths — the canonical macOS user-space + system persistence.',
    strings: [
      '~/library/launchagents',
      '/library/launchagents',
      '/library/launchdaemons',
    ],
    stringsAny: true,
  },
  {
    id: 'persist-cron',
    name: 'Persistence (cron)',
    severity: 'medium',
    mitre: 'T1053.003',
    description: 'crontab / /etc/cron.* references — Linux persistence.',
    strings: ['/etc/crontab', '/etc/cron.', 'crontab -'],
    stringsAny: true,
  },
  {
    id: 'persist-systemd',
    name: 'Persistence (systemd unit)',
    severity: 'medium',
    mitre: 'T1543.002',
    description: 'systemd unit path references — install-as-service persistence.',
    strings: [
      '/etc/systemd/system/',
      '~/.config/systemd/user/',
    ],
    stringsAny: true,
  },
  {
    id: 'persist-ld-preload',
    name: 'Persistence (LD_PRELOAD)',
    severity: 'high',
    mitre: 'T1574.006',
    description: 'LD_PRELOAD / /etc/ld.so.preload references — hijack library loading for all child processes.',
    strings: ['ld_preload', '/etc/ld.so.preload'],
    stringsAny: true,
  },

  // ── Network / C2 ─────────────────────────────────────────────────────
  {
    id: 'network-winhttp',
    name: 'Network Client (WinHTTP/WinInet)',
    severity: 'medium',
    mitre: 'T1071.001',
    description: 'WinHTTP / WinInet / URLDownloadToFile — HTTP(S) client surface. Single-call use (e.g. one InternetOpen for a benign update check) is unactionable, so we require either a request+send pair or a download-to-file primitive.',
    imports: [
      'internetopen', 'internetopena', 'internetopenw',
      'internetopenurl', 'internetopenurla', 'internetopenurlw',
      'httpopenrequest', 'httpopenrequesta', 'httpopenrequestw',
      'httpsendrequest', 'httpsendrequesta', 'httpsendrequestw',
      'winhttpopen', 'winhttpopenrequest', 'winhttpsendrequest',
      'urldownloadtofile', 'urldownloadtofilea', 'urldownloadtofilew',
    ],
    quorum: 2,
  },
  {
    id: 'network-sockets',
    name: 'Network Client (raw sockets)',
    severity: 'medium',
    mitre: 'T1095',
    description: 'Raw sockets (WSAStartup/socket/connect) — custom protocol or non-HTTP C2.',
    imports: ['wsastartup', 'socket', 'connect', 'send', 'recv'],
    quorum: 3,
  },

  // ── Defense evasion ──────────────────────────────────────────────────
  {
    id: 'evasion-amsi-bypass',
    name: 'AMSI Bypass',
    severity: 'high',
    mitre: 'T1562.001',
    description: 'String references to AMSI internals (AmsiScanBuffer / amsi.dll) — typical in bypass loaders.',
    strings: ['amsiscanbuffer', 'amsi.dll', 'amsiinitialize'],
    stringsAny: true,
  },
  {
    id: 'evasion-etw-patch',
    name: 'ETW Patching',
    severity: 'high',
    mitre: 'T1562.006',
    description: 'String / import references to EtwEventWrite patching — disables Event Tracing for Windows telemetry.',
    strings: ['etweventwrite', 'ntdll!etweventwrite'],
    stringsAny: true,
  },

  // ── Ransomware / destructive ─────────────────────────────────────────
  {
    id: 'ransomware-crypto',
    name: 'File Encryption Capability',
    severity: 'high',
    mitre: 'T1486',
    description: 'CryptAcquireContext + CryptEncrypt (or equivalent) + recursive file enumeration — ransomware-class capability.',
    imports: ['cryptacquirecontext', 'cryptencrypt', 'cryptgenrandom', 'findfirstfile', 'findnextfile'],
    quorum: 3,
  },
  {
    id: 'shadow-copy-delete',
    name: 'Volume Shadow Copy Deletion',
    severity: 'critical',
    mitre: 'T1490',
    description: 'String references to vssadmin / wmic shadowcopy deletion — ransomware recovery inhibition.',
    strings: ['vssadmin delete shadows', 'wmic shadowcopy delete', 'bcdedit /set {default}'],
    stringsAny: true,
  },

  // ── Fileless execution ───────────────────────────────────────────────
  {
    id: 'fileless-memfd',
    name: 'Fileless Execution (memfd_create)',
    severity: 'high',
    mitre: 'T1620',
    description: 'memfd_create / fexecve — execute a binary from anonymous memory without touching disk (Linux).',
    imports: ['memfd_create', 'fexecve'],
    any: true,
  },
];

/**
 * Accept a mixed-case needle and haystack and return true iff the haystack
 * contains the needle case-insensitively. Fast path for the common case.
 */
function _containsCI(haystack, needle) {
  if (!haystack || !needle) return false;
  return haystack.toLowerCase().indexOf(needle.toLowerCase()) >= 0;
}

/**
 * True iff `importSet` contains `token` (already lower-cased). Callers pass
 * a Set of lowercase tokens so lookup is O(1).
 */
function _hasImport(importSet, token) {
  if (!importSet) return false;
  return importSet.has(token);
}

/**
 * Run the capability library against the triple (imports, dylibs, strings)
 * and return the list of fired capabilities. Intended to be called ONCE per
 * binary — renderers pass the result to the sidebar as IOC.PATTERN rows and
 * to `findings.autoExec` as human-readable issues.
 *
 * @param {{imports:string[], dylibs:string[], strings:string[]}} ctx
 * @returns {Array<{id,name,severity,mitre,evidence:string[],description}>}
 */
function detectCapabilities(ctx) {
  const ctxImports = (Array.isArray(ctx && ctx.imports) ? ctx.imports : [])
    .map(s => String(s || '').toLowerCase())
    .filter(Boolean);
  const importSet = new Set(ctxImports);
  // Concatenate strings once — a single `toLowerCase()` on the joined buffer
  // beats N calls for N capability×token pairs.
  const joinedStrings = (Array.isArray(ctx && ctx.strings) ? ctx.strings : [])
    .join('\n')
    .toLowerCase();

  const results = [];
  for (const cap of _CAPABILITIES) {
    const evidence = [];
    let importHits = 0, stringHits = 0;

    if (Array.isArray(cap.imports)) {
      for (const tok of cap.imports) {
        if (_hasImport(importSet, tok.toLowerCase())) {
          importHits++;
          evidence.push(tok);
        }
      }
    }
    if (Array.isArray(cap.strings)) {
      for (const tok of cap.strings) {
        if (_containsCI(joinedStrings, tok)) {
          stringHits++;
          evidence.push(tok);
        }
      }
    }

    let fired = false;
    if (cap.splitQuorum) {
      // Split-quorum: the capability needs at least one hit from EACH bucket
      // — used for "timing primitive AND stalling primitive" pairs where
      // 2-of-one-bucket should NOT fire (`Sleep`+`SleepEx` alone is benign).
      let allBucketsHit = true;
      for (const bucket of Object.values(cap.splitQuorum)) {
        const hit = bucket.some(tok => _hasImport(importSet, tok.toLowerCase()));
        if (!hit) { allBucketsHit = false; break; }
      }
      fired = allBucketsHit;
    } else if (cap.any) {
      fired = (importHits + stringHits) > 0;
    } else if (cap.stringsAny && stringHits > 0) {
      fired = true;
    } else if (cap.stringsQuorum && stringHits >= cap.stringsQuorum) {
      fired = true;
    } else if (cap.quorum) {
      fired = (importHits + stringHits) >= cap.quorum;
    } else {
      // Default: every listed token must be present (AND semantics within
      // each bucket, OR across buckets when both are populated).
      const impOK = !cap.imports || importHits === cap.imports.length;
      const strOK = !cap.strings || stringHits === cap.strings.length;
      if (cap.imports && cap.strings) fired = impOK && strOK;
      else fired = (cap.imports ? impOK : strOK);
    }

    if (fired) {
      results.push({
        id: cap.id,
        name: cap.name,
        severity: cap.severity,
        mitre: cap.mitre,
        description: cap.description,
        evidence,
      });
    }
  }
  return results;
}

// Expose as a namespace so the renderers can call `Capabilities.detect(...)`
// from app-scope. The build concatenates this file before the renderers, so
// the identifier is already in scope at parse time.
const Capabilities = Object.freeze({ detect: detectCapabilities });
