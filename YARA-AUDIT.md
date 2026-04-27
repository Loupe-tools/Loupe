# YARA Rule Audit

A review of all 21 rule files under `src/rules/` (~9,750 lines total) focused on
file-type gating, condition strictness, and false-positive surface. Audit only
— no source changes were made. References use `file:line` so each finding is
directly navigable.

## Scope and methodology

- Files reviewed: every `.yar` in `src/rules/`.
- Engine reviewed: `src/yara-engine.js` (parsing, scanning, condition evaluator),
  `src/workers/yara.worker.js` (host wrapper).
- Cross-checked against `AGENTS.md` (rules must contain no `//` comments) and
  `CONTRIBUTING.md` § Renderer Contract.

The engine has **no global file-type filter** (`yara-engine.js:268`). Every
rule is scanned against every file's bytes, latin-1 decoded for text matching
(`yara-engine.js:271-276`). Each rule must self-gate via:

1. an anchored magic-byte check (`uint16(0)`, `uint32(0)`, `$x at 0`,
   `$x in (filesize-512..filesize)`), or
2. a structural marker that strongly implies the file format (e.g.
   `[InternetShortcut]`, `Windows Registry Editor`, `manifest_version`), or
3. multiple co-occurring format-specific strings.

A rule that has none of these and uses `condition: any of them` (or a single
short string) will fire on documentation, source code, security tooling, and
log files. That is the dominant defect class in this audit.

Three engine quirks worth knowing when reading the findings:

- Hex-pattern jumps `[N-M]` are simplified to "minimum count of wildcards"
  (`yara-engine.js:533-551`) — they are weaker than they look.
- Regex strings are bounded by 1000 matches, 10 000 iterations, and a 250 ms
  wall-clock budget per string (`yara-engine.js:405-525`); the budget hit is
  silently truncated unless the worker passes an `errors` sink.
- The condition tokenizer is whitespace-/comma-tolerant but does not understand
  `for` quantifiers, `intXXbe`, or `defined`; rules using only the documented
  subset (`uint8/16/32`, `int8/16/32`, `at`, `in`, `#var`, `any/all/N of …`,
  boolean ops) will evaluate as expected.

---

## Tier 1 — Broken or near-certain false positive

These fire on benign content as written. They should be the highest-priority
fixes.

### `Embedded_PE_Header` — `src/rules/suspicious-patterns.yar:1`

```
strings:  $mz = { 4D 5A 90 00 }
condition: $mz
```

Every legitimate PE/EXE/DLL starts with these four bytes. The intent is
"PE bytes hidden inside a non-PE", but the rule never excludes the offset-0
case. Fix: `not ($mz at 0) and #mz > 0`, or gate on `uint16(0) != 0x5A4D`.
Severity is `critical`.

### `Embedded_ZIP_In_Non_Archive` — `src/rules/suspicious-patterns.yar:91`

```
strings:  $pk = { 50 4B 03 04 }
condition: #pk > 1
```

Every multi-file ZIP/JAR/DOCX/XPI/APK contains one PK\\x03\\x04 per stored
entry, so this hits every legitimate archive with two or more members.
Fix: `not ($pk at 0) and $pk` (or require `uint16(0) != 0x4B50`).

### `Suspicious_Null_Byte_Padding` — `src/rules/suspicious-patterns.yar:172`

```
$nop_sled = { 90 90 90 90 …16 of 0x90… }
$null_pad = { 00 00 …32 of 0x00… }
condition: $nop_sled or (#null_pad > 10)
```

NOP runs and zero-padded section alignment occur in essentially every PE
(.text padding) and ELF/Mach-O (.bss / page alignment). The rule fires on
the majority of legitimate binaries. Severity `medium`. Either drop or gate
to non-PE files.

### `Office_OLE_Embedded_Object` — `src/rules/office-macros.yar:349`

```
$d = { D0 CF 11 E0 A1 B1 1A E1 }   # CFB magic, NOT anchored
condition: $d and any of ($a, $b, $c)   # \object / \objdata / \objemb
```

The CFB header is at offset 0 of every legacy DOC/XLS/MSI. The rule wants
"embedded OLE inside an RTF/HTML wrapper", which requires the negation of
`$d at 0`. As written it duplicates `Office_DDE_AutoLink_Legacy` for any
legacy-Office file that mentions `\object`. Fix: anchor the negative case,
or rely on the `0x74725C7B` (`{\rt`) RTF gate.

### `AddIn_XLL_File` — `src/rules/office-macros.yar:557`

```
$mz = { 4D 5A }   # not anchored
condition: $mz and any of ($a, $b, $c)   # xlAuto* exports
```

Should be `$mz at 0`. As written, any binary blob containing `MZ` plus the
`xlAutoOpen` substring (e.g. an Office file referencing the export name)
triggers a `critical` match.

### `MSI_Installer_Suspicious` — `src/rules/windows-threats.yar:297`

### `MSIX_APPX_Installer` — `src/rules/windows-threats.yar:315`

Both gate on the format magic (`{ D0 CF 11 E0 … }` and `{ 50 4B 03 04 }`)
without an `at 0` anchor. They will hit on PST attachments, decompressed
memory dumps, security-research samples concatenated together, etc.
Fix: `$ole at 0` and `$pk at 0` respectively (matches the pattern used by
`MSI_Embedded_PE` at `windows-threats.yar:2236` which is correct).

### `IQY_Web_Query_File` — `src/rules/document-threats.yar:552`

```
$a = "WEB" nocase   # 3 chars, case-insensitive
$b = "http" nocase
$c = "1"            # declared but unreferenced
condition: $a at 0 and $b
```

Fires `critical` on any file starting with `web`/`Web`/`WEB` that contains
`http` anywhere — README files, blog drafts, HTTP server samples, IETF
drafts. The unused `$c` should be removed; `$a` should be ASCII-only and
the rule should require the IQY structural pattern (`WEB\n1\n…URL`) rather
than just the 3-byte prefix.

### LNK rules with under-specified anchors

- `LNK_Suspicious_CommandLine` — `windows-threats.yar:147`
- `LNK_Double_Extension` — `windows-threats.yar:172`
- `LNK_Environment_Variable_Abuse` — `windows-threats.yar:242`

All use `$lnk = { 4C 00 00 00 }` (4 bytes only) without `at 0`. The bytes
`4C 00 00 00` (a UTF-16-LE `L`, or any little-endian `0x4C` integer) appear
incidentally in many binaries. Compare with the correctly-anchored siblings:

- `LNK_Extended_LOLBins` — `windows-threats.yar:193` uses
  `{ 4C 00 00 00 01 14 02 00 } at 0`
- `LNK_Script_Target` — `windows-threats.yar:218` does the same.

Fix the three above to use the same 8-byte signature anchored at 0.

### `PowerShell_Encoded_Command` — `src/rules/script-threats.yar:261`

```
condition:
    ($ps and ($a or $b or $c)) or any of ($enc*) or $from
```

The `or $from` branch triggers the entire `critical` rule on a single
substring match for `FromBase64String`, which is a stock .NET API used by
thousands of legitimate utilities, installers, signing tools, and tutorials.
Fix: drop the standalone `$from` branch, or require it together with `$ps`
or one of `$enc*`.

### `General_Base64_With_Execution` — `src/rules/suspicious-patterns.yar:52`

```
any of ("base64" | "FromBase64String" | "atob(") and any of ("eval(" | "iex" | "Invoke-Expression" | "Execute(" | "ExecuteGlobal(" | "Function(")
```

`base64` + `eval(` matches Stack Overflow archives, web framework source,
minified bundles, and most JS testing libraries. Severity `high`, no file
gate. Either retire or require additional context (e.g. payload length,
script-tag presence, or single-line co-occurrence).

### `General_XOR_Decode_Loop` — `src/rules/suspicious-patterns.yar:34`

```
$a = "xor" nocase fullword
+ ("fromCharCode" | "Chr(" | "charCodeAt")
```

The `xor` keyword appears in CPU instruction docs, math articles, crypto
libraries, kernel source, and most binary-analysis tooling. Combined with
any JS string-builder it FPs widely. Recommend retiring or rewriting as a
`for ((c=0; c<n; c++)) buf[i] ^= …` loop regex.

### `Java_Obfuscation_ZKM` — `src/rules/jar-threats.yar:244`

```
$z1 = "ZKM" ascii   # 3 ASCII chars
condition: any of ($z1, $z2, $z3)
```

A 3-character ASCII match at `medium` severity. `ZKM` collides with random
binary data and abbreviations in unrelated content. The two longer strings
(`zelix`, `KlassMaster`) are sufficient by themselves; drop `$z1` or
require it in conjunction with one of them.

### Single-prefix base64 magic rules — `src/rules/encoding-threats.yar:358-433`

Five rules (`Encoded_Base64_PE_Header`, `Encoded_Base64_Gzip`,
`Encoded_Base64_OLE_Document`, `Encoded_Base64_PDF`, `Encoded_Base64_ZIP`)
each fire on a single 4-character base64 prefix:

| String | Decoded prefix | Severity |
|--------|----------------|----------|
| `TVqQ` | `4D 5A 90` (PE) | high |
| `TVpQ` | `4D 5A 50` | high |
| `TVro` | `4D 5A E8` | high |
| `H4sI` | `1F 8B 08` (gzip) | medium |
| `0M8R` | `D0 CF 11` (OLE) | medium |
| `JVBE` | `25 50 44` (PDF) | medium |
| `UEsD` | `50 4B 03` (ZIP) | medium |

Four characters of base64 will collide with random English text, log lines,
hashes, and CSS class names. `JVBE` and `UEsD` are particularly bad
(common letter trigrams). Fix: require the prefix immediately followed by
≥40 base64-charset characters, e.g. `/[\\W^]TVqQ[A-Za-z0-9+\\/]{40,}/`.

### `SVG_Base64_Script_Payload` — `src/rules/svg-threats.yar:99`

### `SVG_Data_URI_HTML` — `src/rules/svg-threats.yar:113`

Both file rules are about SVG, but neither requires the `<svg` content
marker. They match any HTML page, JS bundle, or Markdown document that
references `data:text/javascript;base64,` or `data:text/html;base64,`.
Sibling SVG rules (e.g. `SVG_Embedded_Script` at line 1) correctly include
`$svg = "<svg" nocase`. Fix: add `$svg` to both conditions.

### `SVG_XXE_Entity` — `src/rules/svg-threats.yar:217`

```
condition: $entity or ($system and $svg)
```

The first branch (`$entity = /<!ENTITY \w+/`) fires without an SVG context,
matching any DTD, XSD, DocBook, SGML, or XML schema file. Severity `high`.
Fix: require `$svg` on both branches.

---

## Tier 2 — Whole-file file-type gating gaps

Entire rule files lack a structural gate, so every rule in them fires on
documentation, security blog posts, source code, build artefacts, and
defender logs. The fix in each case is to add a top-level gate to the
condition of every rule.

### `src/rules/jar-threats.yar` (17 rules, 0 gated)

None of the rules check the JAR/class magic. Suggested gate at the top of
each condition:

```
(uint32(0) == 0x04034B50 or (uint8(0)==0xCA and uint8(1)==0xFE and uint8(2)==0xBA and uint8(3)==0xBE)) and …
```

(ZIP local-header for JAR/WAR/EAR, or `CAFEBABE` for raw `.class`).
High-impact unguarded rules:

- `Java_JNDI_Injection` (line 43) — single `${jndi:` substring → `critical`.
  Will FP on every Log4Shell write-up, security advisory, and WAF log.
- `Java_Deserialization_CommonsCollections` (line 1), `Java_Deserialization_Gadgets`
  (line 18) — public gadget class names appear in security tooling, blog
  posts, and signature files.
- `Java_Network_RAT` (line 185) — `Robot` + `Socket` matches Selenium,
  any AWT automation, and screen-share libraries.
- `Java_Data_Exfiltration` (line 327) — `getProperty + InetAddress + POST`
  matches every Java HTTP client that sends telemetry.
- `Java_File_Encryption_Ransomware` (line 299) — `Cipher + FileInputStream
  + "encrypted"` matches every legitimate at-rest encryption library.
- `Java_Credential_Theft` (line 276), `Java_Security_Manager_Bypass`
  (line 258) — match every Spring/SSL/keystore tutorial.

### `src/rules/plist-threats.yar` (20 rules, 0 gated)

Plists are either XML (`<?xml … <!DOCTYPE plist`) or binary (`bplist00` at 0).
Suggested gate:

```
(uint32(0) == 0x6C70783F /* "?xml" lower */ or $bplist at 0 or $plist_dtd) and …
```

Where `$plist_dtd = "<!DOCTYPE plist" nocase` and `$bplist = "bplist00"`.
Single-string criticals that need this gate urgently:

- `plist_dyld_insert_libraries` (line 129) — `condition: $dyld` (one
  string) → `critical`. Matches every dylib-hijacking blog and Apple
  documentation page.
- `plist_dyld_environment` (line 142) — three DYLD env vars, `any of them`.
- `plist_environment_variable_manipulation` (line 116) — `condition: $env`
  (one string) → `medium`. Matches macOS dev docs, sample plists, etc.
- `plist_watchpaths_monitoring` (line 192) — `condition: $watch`.
- `plist_login_item_hidden` (line 219) — `LSUIElement` or `LSBackgroundOnly`,
  i.e. every legitimate menubar/background-helper app.
- `plist_tcc_bypass_indicator` (line 265) — single TCC service name. Every
  Zoom/Slack/screen-recorder Info.plist will hit this.
- `plist_hidden_label` (line 36) — `<string>.` matches `<string>.cpp</string>`
  or any file extension referenced inside a `<string>` element.

### `src/rules/osascript-threats.yar` (16 rules, 0 gated)

There is no clean magic-byte test for plain-text AppleScript, but a
structural gate based on the AppleScript dialect markers is feasible:

```
$as_marker = /\b(tell\s+application|on\s+\w+\(|use\s+(framework|scripting\s+additions))\b/ nocase
+ optional shebang `"#!/usr/bin/osascript"` at 0
+ compiled OSAScript magic `{ 46 61 73 64 55 41 53 20 }` at 0
```

Highest-impact unguarded:

- `osascript_keychain_theft` (line 68) — `condition: any of them` over
  `security find-generic-password`, `dump-keychain`, etc. Every macOS
  forensics tutorial triggers this `critical` rule.
- `osascript_browser_credential_theft` (line 85) — `any of` over
  `Login Data` (10 generic chars), `Cookies` (7 chars), etc. → `critical`.
- `osascript_admin_shell_execution` (line 38) — two strings, no context.
- `osascript_login_item_persistence` (line 124) — `any of them` over
  `login item`, `Startup Items`. → `high`.
- `jxa_eval_dynamic_execution` (line 257) — `(eval | Function) and (ObjC | Application(`)
  matches every framework using `new Application(...)`.

### `src/rules/script-threats.yar` (PowerShell / JS / VBS / BAT / Python / Bash, ~30 rules)

There is no universal magic for these languages, but several rules can be
narrowed substantially with low FP cost:

- `PowerShell_AMSI_Bypass` (line 306) — three single substrings, `any of`
  → `critical`. Every AMSI write-up matches.
- `Shell_Curl_Wget_Pipe_Exec` (line 1126) — matches the standard
  `curl … | bash` install pattern published by Homebrew, Rust, Node Version
  Manager, oh-my-zsh, Volta, pnpm, Deno, …
- `BAT_Recursive_Copy_Drop` (line 457) — `(copy|move|xcopy)` + `%TEMP%`
  matches every legitimate Windows setup script.
- `BAT_Registry_Persistence` (line 478) — `reg add` + `CurrentVersion\\Run`
  matches any installer that legitimately registers an autostart entry.
- `PowerShell_Hidden_Window` (line 362) — `-WindowStyle` + `Hidden` matches
  documentation; could be tightened to require the flags appear together
  on one line or in a process-spawning context.
- `PowerShell_Credential_Theft` (line 381) — `2 of` from generic credential
  cmdlets used by every IT-automation script.
- `PowerShell_Reflective_Load` (line 323) — `2 of` from `Reflection.Assembly`,
  `MemoryStream`, `GZipStream`, etc.; matches PSReadLine, PSScriptAnalyzer,
  most signing utilities.

Suggested approach: where possible, require either a script-host marker
(`#!/usr/bin/env pwsh`, `#!/bin/bash`, `<#`, `param(`) or a process-spawn
pattern (`Start-Process`, `&` invocation operator) in addition to the
substring co-occurrence.

### `Standalone_*` rules in `src/rules/encoding-threats.yar`

Despite the name, the `Standalone_*` rules are co-occurrence rules with
no length/proximity/structural constraints. Notable:

- `Standalone_HTML_Suspicious_Elements` (line 164) — `<script` + `<form` etc.
  matches every non-trivial HTML page. Severity `info`, so noise rather than
  bug.
- `Standalone_HTML_Code_Execution` (line 203) — `eval`, `document.write`,
  `atob`, `fromCharCode` — common in minified JS bundles.
- `Standalone_LNK_Argument_Patterns` (line 339) — `2 of` PowerShell flag
  patterns. No LNK magic gate at all.
- `Standalone_RTF_OLE_Keywords` (line 276), `Standalone_RTF_Exploit_Patterns`
  (line 299), `Standalone_RTF_Obfuscation` (line 322) — use `$rtf = "{\\rtf"`
  without `at 0`. Compare correctly-anchored peers in `document-threats.yar`.
  Fix: `$rtf at 0`.

---

## Tier 3 — Severity calibration

These rules are mostly correct in shape but the severity is too high for
the precision of the underlying signal. A single substring match for a
public IOC URL is not `critical` evidence; it is `info`/`medium` lead.
Recommend re-scoring downwards (or requiring corroborating signals before
escalating).

| Rule | File:line | Current | Suggested | Reason |
|------|-----------|---------|-----------|--------|
| `Exfil_Telegram_Bot_API` | `network-indicators.yar:55` | high | medium / info | Single `api.telegram.org` URL — every Telegram bot tutorial triggers it. |
| `Credential_Dumping_Commands` | `network-indicators.yar:34` | critical | high | `procdump` + `lsass` substrings appear in every Sysmon/blue-team write-up. |
| `Java_JNDI_Injection` | `jar-threats.yar:43` | critical | medium | First branch is a single `${jndi:` match. |
| `Info_Mimikatz_Reference` | `windows-threats.yar:1293` | info | info ✓ | Already correct; flagging the `PE_Mimikatz_Indicators` (line 374) as `critical` for `2 of them` is reasonable for a PE, but the cross-format mention is correctly `info`. |
| `osascript_keychain_theft` | `osascript-threats.yar:68` | critical | high (and gated) | `any of` six security CLI substrings. |
| `osascript_browser_credential_theft` | `osascript-threats.yar:85` | critical | medium (and gated) | `any of` over generic strings like `Cookies`, `Login Data`. |
| `plist_dyld_insert_libraries` | `plist-threats.yar:129` | critical | medium (and gated) | One substring `DYLD_INSERT_LIBRARIES`. |
| `SSH_Private_Key_Reference` | `network-indicators.yar:106` | critical | medium | Fires on any `.pem`/`id_rsa` file, including legitimate key material in test fixtures. |
| `Exfil_Pastebin_Reference` | `network-indicators.yar:127` | medium | info | Single hostname match. |
| `Abuse_TLD_DDNS_Tunnel` | `network-indicators.yar:163` | medium | medium ✓ | Borderline acceptable. |

---

## Tier 4 — Cosmetic and structural inconsistencies

Low-risk cleanups that aid future maintenance:

- **RTF anchor inconsistency**. `RTF_Embedded_Object`
  (`document-threats.yar:191`), `RTF_Equation_Editor_Exploit` (line 209),
  `RTF_Obfuscated_Header` (line 224), `RTF_Large_Hex_Blob` (line 241),
  `RTF_Package_Object` (line 258) all use `$rtf at 0` correctly.
  `RTF_Nested_Objects` (line 838), `RTF_ObjUpdate_AutoExec` (line 757),
  `RTF_ObjClass_Exploit` (line 774) and the three `Standalone_RTF_*` rules
  use `$rtf` without anchor. Standardise on `at 0`.

- **OOXML magic is the bare ZIP magic**. `office-macros.yar` uses
  `uint16(0) == 0x4B50` to gate OOXML rules, which matches every ZIP
  including innocuous archives. Body strings discriminate, but tightening
  to also require an OOXML marker (`[Content_Types].xml`, `word/`,
  `xl/`, `ppt/`, or one of the `*.xml` part names) would eliminate the
  ZIP-overlap entirely.

- **`BrowserExt_NativeHost_Bridge`** (`browserext-threats.yar:152`) lacks
  the `manifest_version` gate that every other rule in the file uses. The
  current condition (`$ao and $path and ($type or $proto)`) leans on the
  generic JSON keys `"path"` and `"allowed_origins"`.

- **`BrowserExt_LegacyXUL_Bootstrap`** (`browserext-threats.yar:122`) has
  no manifest gate and no XPI/ZIP gate.

- **Dead string**: `IQY_Web_Query_File` declares `$c = "1"` (line 563) but
  never references it.

- **`Office_External_OLE_Link`** (`office-macros.yar:386`) has
  `condition: uint32(0)==0x04034B50 and all of them` where strings include
  `$c = "http"` (4 chars, ascii). The `http` substring is far too generic
  even in an OOXML context.

- **`Right_To_Left_Override`** (`encoding-threats.yar:27`) is `critical`
  with `any of them`. U+202E is rare enough that this is acceptable, but
  benign content with the byte sequence (Hebrew/Arabic UI strings, some
  emoji) will hit it.

- **`Info_DLL_Sideload_Indicators`** (`windows-threats.yar:761`) — `2 of`
  from `version.dll`, `winmm.dll`, etc. matches most Windows EXEs because
  these are common imports. Severity is `info`, so noise rather than bug,
  but mention-worthy.

- **`Info_Image_Only_HTML_Email`** (`windows-threats.yar:652`) uses
  `not $no_p and not $no_span` where `$no_p = "<p"` and
  `$no_span = "<span"`. The variable names are misleading (they are positive
  matches negated) but logic is correct. Worth renaming for clarity.

- **`Info_Email_Bulk_Precedence`** (`windows-threats.yar:571`) declares
  `$d = "X-Mailer:"` but never references it in the condition.

- **`HTA_Any_Presence`** (`windows-threats.yar:44`) is `medium` for a
  single substring. Reasonable because `<HTA:APPLICATION` is a strong
  marker, but worth confirming intent.

- **`SLK_Symbolic_Link_File`** (`document-threats.yar:569`) — `$a = "ID;P"
  nocase at 0`. Reasonable; SLK starts with `ID;P`. Note that lowercase
  is not actually a real-world variant — the format is canonically uppercase
  — but `nocase` is harmless.

- **`Info_Cobalt_Strike_Indicators`** (`windows-threats.yar:1234`)
  duplicates `PE_Cobalt_Strike_Indicators` (`pe-threats.yar:357`) without
  the PE gate. The latter is `critical` (correctly gated, 2 of beacon
  strings), the former is `info` and unguarded. Both can fire on the same
  PE file, producing two findings.

- **`Info_Metasploit_Indicators`** (`windows-threats.yar:1254`) — same
  duplication pattern with `PE_Metasploit_Payload` (`pe-threats.yar:391`).

---

## Cross-cutting issues

### Hex-jump simplification

The engine treats `[N-M]` as exactly `N` wildcard bytes (`yara-engine.js:543-549`),
not a variable run. Rules that rely on permissive hex jumps will under-match.
Rule audit did not find any rule that exercises this in a way that breaks
current detection — most hex patterns use fixed bytes — but worth recording
in `SECURITY.md` so future rule authors know.

### Duplicated detection between rule files

Two patterns produce double findings on the same file:

1. `Exfil_Discord_Webhook` (`network-indicators.yar:74`) and
   `Npm_Webhook_Beacon` (`npm-threats.yar:175`) both fire on
   `discord.com/api/webhooks/`.
2. `Exfil_Telegram_Bot_API` and `Npm_Webhook_Beacon` both fire on
   `api.telegram.org`.

Not a bug, but the side panel will show two `IOC.PATTERN` rows for the
same string. Either dedupe at the renderer (`app-yara.js`) or have the
npm rule require `package.json` context (`"name"`, `"version"`,
`"dependencies"`).

### "Standalone_" naming

`encoding-threats.yar` uses the prefix `Standalone_` to indicate
"intended to fire across file types". This intent collides with the
generic-string FP problem identified in Tier 2. Consider renaming or
re-scoping the prefix to mean "must require ≥3 co-occurring strong
indicators".

### Build-time `// @category:` injection (per `AGENTS.md`)

`scripts/build.py` injects `// @category: <name>` separators when
concatenating rule files. The in-browser engine tolerates these because
they are the only `//` lines it sees. **Any future rule edit must continue
to keep `.yar` files comment-free** (verified: none currently contain
`//`-style comments). This constraint applies to any remediation work.

---

## Suggested remediation order

If acted upon, the lowest-risk path is:

1. **Tier 1** — pure correctness fixes, each is local to a single rule and
   verifiable by re-scanning a known-good file from `examples/`. Most are
   one- or two-line changes.
2. **Tier 2 file-type gating** — bigger blast radius. For each file:
   1. Add the gate to a single rule first, run `python make.py` and the
      browser smoke test against fixtures of the relevant format (and a
      few unrelated files to confirm the rule no longer fires on them).
   2. Replicate the gate to siblings in the same file.
3. **Tier 3 severity tuning** — can land independently. Update
   `FEATURES.md` if any user-visible severity columns shift.
4. **Tier 4 cosmetic** — fold in opportunistically alongside related
   changes.

## Validation loop

Loupe has no automated test suite. Per `AGENTS.md` and `CONTRIBUTING.md`,
the validation steps for any rule edit are:

1. `python make.py` — runs `verify_vendored → build → codemap`. Must succeed.
2. `npx --yes eslint@9.39.4 --config eslint.config.mjs "src/**/*.js"` —
   must pass (only relevant if any `.js` is touched alongside rules).
3. Open the rebuilt `docs/index.html` in a browser, drop fixtures from
   `examples/`, and confirm:
   - Each fixed rule still fires on the threat fixtures it should.
   - Each fixed rule no longer fires on benign control files (write a
     handful: a vanilla README with `curl … | bash`, an Info.plist of a
     legitimate menubar app, a benign `package.json`, etc.).
4. Stage `src/` edits + regenerated `CODEMAP.md` only. Do not stage
   `docs/index.html`, `loupe.html*`, or `dist/`.

No infrastructure changes (no test harness, no fixture corpus) are
proposed in this audit; that decision is left to whoever performs the
remediation.
