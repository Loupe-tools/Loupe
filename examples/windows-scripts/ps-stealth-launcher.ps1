<#
    === Loupe Test File: PowerShell Stealth-Launcher Indicators ===

    This file aggregates the stealth-flag, credential-access, lateral-
    movement, and fileless-persistence indicators that Loupe's
    PowerShell rule pack detects. WARNING: this is a HARMLESS TEST
    FIXTURE — none of the lines below are syntactically wired up to an
    actual download or execution path. They exist as static strings so
    the YARA scan anchors the corresponding rules.

    Rules this fixture is intended to anchor (one source of truth —
    keep this list in lockstep with `expected.jsonl` /
    `yara-rules-fired.json`):

      * PowerShell_Execution_Policy_Bypass
      * PowerShell_Hidden_Window
      * PowerShell_Stealth_Flags_Combo
      * PowerShell_Credential_Theft
      * PowerShell_AddType_Inline_CSharp
      * PowerShell_Invoke_Command_Remote
      * PowerShell_WMI_Event_Persistence
      * PowerShell_AMSI_Bypass
      * PowerShell_Reflective_Load
      * PowerShell_Certutil_Combo

    The block-comment header + `[CmdletBinding()]` + `Set-StrictMode`
    + `$ErrorActionPreference` markers below force
    `RendererRegistry._sniffScriptKind` to tag this fixture as
    `formatTag: 'ps1'` — without those, the verb-noun cmdlet hints
    aren't enough to beat the `bash` score and the stealth rules
    (gated by `applies_to = "ps1, plaintext, decoded-payload"`)
    silently fail to fire.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Stub = 'placeholder'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VerbosePreference     = 'SilentlyContinue'

# ── Stealth flags (Execution_Policy_Bypass + Hidden_Window + Combo) ─────
Write-Host "[TEST] Stealth flags combo:"
$launcher = "powershell -nop -noni -w hidden -ExecutionPolicy Bypass -Command 'Write-Host launched'"
$alt      = "powershell -nop -ep bypass -WindowStyle Hidden"
Write-Host "Synthesised launcher (display only): $launcher"
Write-Host "Alt form (display only): $alt"

# ── Credential theft (Get-Credential + ConvertTo-SecureString) ──────────
Write-Host "[TEST] Credential-theft cmdlets:"
# Display-only — never invoke. The literal cmdlet names anchor
# `PowerShell_Credential_Theft`.
$ct = "Get-Credential -UserName 'svc-test' -Message 'TEST ONLY'"
$cs = "ConvertTo-SecureString 'placeholder' -AsPlainText -Force"
Write-Host "Display only: $ct ; $cs"

# ── Inline C# via Add-Type (loads native APIs through DllImport) ────────
Write-Host "[TEST] Add-Type inline C# (System.Runtime.InteropServices):"
$inlineCs = @"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class TestStub {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
'@
"@
Write-Host "Display only: $inlineCs"

# ── Lateral movement (Invoke-Command -ComputerName -ScriptBlock) ────────
Write-Host "[TEST] Invoke-Command remote pattern:"
$remote = "Invoke-Command -ComputerName host01 -ScriptBlock { Get-Process }"
Write-Host "Display only: $remote"

# ── Fileless WMI persistence (__EventFilter + CommandLineEventConsumer) ─
Write-Host "[TEST] WMI event-subscription persistence:"
$wmi = @"
__EventFilter -> __FilterToConsumerBinding -> CommandLineEventConsumer
Set-WmiInstance / Register-WmiEvent
"@
Write-Host "Display only: $wmi"

# ── AMSI bypass (AmsiUtils / amsiInitFailed) ────────────────────────────
Write-Host "[TEST] AMSI-bypass strings:"
$amsi = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"
Write-Host "Display only: $amsi"

# ── Reflective load (Reflection.Assembly + FromBase64String + MemoryStream) ──
Write-Host "[TEST] Reflective .NET load pattern:"
$ref = @"
[Reflection.Assembly]::Load([Convert]::FromBase64String(payload))
New-Object System.IO.MemoryStream
"@
Write-Host "Display only: $ref"

# ── Certutil-combo (certutil -decode + powershell) ──────────────────────
Write-Host "[TEST] Certutil-decode chain:"
$cert = "certutil -decode encoded.b64 stage.ps1 ; powershell -File stage.ps1"
Write-Host "Display only: $cert"

Write-Host ""
Write-Host "[DONE] Stealth-launcher indicator strings rendered."
